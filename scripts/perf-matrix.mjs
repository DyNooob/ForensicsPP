/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.forensicspp.com
 * Platform: DigiForensics.cn
 * Project: https://github.com/DyNooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

// Perf-matrix: builds the app to a temp dir, measures JS bundle sizes
// (raw + gzip) grouped by chunk category, and compares against a committed
// baseline so bundle-size regressions are detectable in CI / local runs.
//
// Usage:
//   node scripts/perf-matrix.mjs                 # measure + diff vs baseline (no fail)
//   node scripts/perf-matrix.mjs --write-baseline # measure + overwrite baseline
//   node scripts/perf-matrix.mjs --check          # measure + fail if over threshold
//
// Threshold (gzip growth allowed before --check fails) is configurable via
// the PERF_THRESHOLD env var (default 0.15 = 15%).

import { build } from "vite";
import { gzipSync } from "node:zlib";
import { rmSync, readFileSync, writeFileSync, existsSync, statSync, readdirSync, mkdirSync } from "node:fs";
import { join, relative, basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const BASELINE_PATH = join(__dirname, "perf-baseline.json");
const TMP_DIR = join(ROOT, "node_modules", ".fpp-perf");

const args = process.argv.slice(2);
const WRITE_BASELINE = args.includes("--write-baseline");
const CHECK = args.includes("--check");
const THRESHOLD = Number(process.env.PERF_THRESHOLD ?? "0.15");

/** @param {string} p */
function walkJs(p, out = []) {
  if (!existsSync(p)) return out;
  for (const entry of readdirSync(p)) {
    const full = join(p, entry);
    const st = statSync(full);
    if (st.isDirectory()) walkJs(full, out);
    else if (full.endsWith(".js") || full.endsWith(".mjs")) out.push(full);
  }
  return out;
}

/** @param {string} file */
function groupOf(file) {
  const name = basename(file);
  const rel = relative(ROOT, file).replace(/\\/g, "/");
  // CyberChef is a separately-shipped vendored iframe (public/cyberchef),
  // not part of the React app graph. Keep it in its own bucket so app-code
  // regressions stay visible and CyberChef version bumps are tracked alone.
  if (rel.includes("/cyberchef/")) return "vendor:cyberchef";
  const m = name.match(/vendor-([a-z0-9-]+)-/i);
  if (m) return `vendor:${m[1].toLowerCase()}`;
  if (name.startsWith("index-")) return "entry";
  if (name.toLowerCase().includes("worker")) return "worker";
  return "app"; // lazy tool chunks + misc app code
}

async function measure() {
  rmSync(TMP_DIR, { recursive: true, force: true });
  mkdirSync(TMP_DIR, { recursive: true });
  await build({
    root: ROOT,
    logLevel: "silent",
    build: {
      outDir: relative(ROOT, TMP_DIR),
      emptyOutDir: true,
      reportCompressedSize: false,
    },
  });

  const files = walkJs(TMP_DIR);
  const groups = new Map();
  let totalRaw = 0;
  let totalGzip = 0;
  const largest = [];

  for (const file of files) {
    const buf = readFileSync(file);
    const raw = buf.length;
    const gzip = gzipSync(buf).length;
    totalRaw += raw;
    totalGzip += gzip;
    const g = groupOf(file);
    const bucket = groups.get(g) ?? { raw: 0, gzip: 0, chunks: 0 };
    bucket.raw += raw;
    bucket.gzip += gzip;
    bucket.chunks += 1;
    groups.set(g, bucket);
    largest.push({ file: relative(ROOT, file), raw, gzip });
  }

  largest.sort((a, b) => b.gzip - a.gzip);
  const metric = {
    generatedAt: new Date().toISOString(),
    totalJsRaw: totalRaw,
    totalJsGzip: totalGzip,
    chunks: files.length,
    groups: Object.fromEntries(
      [...groups.entries()].sort((a, b) => b[1].gzip - a[1].gzip).map(([k, v]) => [k, {
        raw: v.raw,
        gzip: v.gzip,
        chunks: v.chunks,
      }])
    ),
    largest: largest.slice(0, 10).map((e) => ({ file: e.file, raw: e.raw, gzip: e.gzip })),
  };
  return metric;
}

function fmt(n) {
  return `${(n / 1024).toFixed(1)} kB`;
}

function print(metric) {
  console.log(`\nPerf matrix — total JS ${fmt(metric.totalJsRaw)} raw / ${fmt(metric.totalJsGzip)} gzip, ${metric.chunks} chunks\n`);
  console.log("Group".padEnd(16), "chunks".padStart(7), "raw".padStart(10), "gzip".padStart(10));
  for (const [name, v] of Object.entries(metric.groups)) {
    console.log(name.padEnd(16), String(v.chunks).padStart(7), fmt(v.raw).padStart(10), fmt(v.gzip).padStart(10));
  }
  console.log("\nTop chunks (by gzip):");
  for (const e of metric.largest) {
    console.log(" ", e.file, fmt(e.gzip));
  }
}

function readBaseline() {
  if (!existsSync(BASELINE_PATH)) return null;
  try {
    return JSON.parse(readFileSync(BASELINE_PATH, "utf8"));
  } catch {
    return null;
  }
}

function delta(cur, base) {
  if (!base) return null;
  const pct = base === 0 ? 0 : ((cur - base) / base) * 100;
  return pct;
}

async function main() {
  const metric = await measure();
  print(metric);

  const baseline = readBaseline();
  if (WRITE_BASELINE) {
    writeFileSync(BASELINE_PATH, JSON.stringify(metric, null, 2) + "\n", "utf8");
    console.log(`\nBaseline written to ${relative(ROOT, BASELINE_PATH)}`);
    rmSync(TMP_DIR, { recursive: true, force: true });
    return;
  }

  if (baseline) {
    const dTotal = delta(metric.totalJsGzip, baseline.totalJsGzip);
    console.log(`\nΔ total gzip vs baseline: ${dTotal == null ? "n/a" : (dTotal >= 0 ? "+" : "") + dTotal.toFixed(1) + "%"} (threshold ${(THRESHOLD * 100).toFixed(0)}%)`);
    const regressed = [];
    for (const [name, v] of Object.entries(metric.groups)) {
      const base = baseline.groups?.[name];
      if (!base) continue;
      const d = delta(v.gzip, base.gzip);
      if (d != null && d > THRESHOLD * 100) regressed.push({ name, pct: d, gzip: v.gzip, baseGzip: base.gzip });
    }
    if (dTotal != null && dTotal > THRESHOLD * 100) regressed.push({ name: "total", pct: dTotal, gzip: metric.totalJsGzip, baseGzip: baseline.totalJsGzip });

    if (regressed.length) {
      console.log("\nRegressions:");
      for (const r of regressed) {
        console.log(`  ${r.name}: +${r.pct.toFixed(1)}% (${fmt(r.gzip)} vs ${fmt(r.baseGzip)})`);
      }
      rmSync(TMP_DIR, { recursive: true, force: true });
      if (CHECK) {
        console.error(`\nperf-matrix: ${regressed.length} metric(s) exceeded threshold.`);
        process.exit(1);
      }
      return;
    }
    console.log("No regressions detected.");
  } else if (CHECK) {
    console.error("\nperf-matrix: --check requested but no baseline exists. Run with --write-baseline first.");
    process.exit(1);
  }

  rmSync(TMP_DIR, { recursive: true, force: true });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

#!/usr/bin/env node
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

// Production-like HTTP + real-Chrome smoke test for Forensics++ tool routes.
// Serves dist/ over a real static server (no Vite dev server) and asserts:
//   - each indexable tool URL returns HTTP 200 with per-tool static metadata
//   - JS hydrates from the sub-path and the correct ToolHost opens (no flash to home)
//   - refresh / back / forward behave sanely
//   - unknown tool route resolves to the in-app NotFound (app boots from fallback)
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { join, extname, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { SLUG_TO_TOOL } from "../src/seo/toolRoutes.mjs";

const require = createRequire(import.meta.url);
const puppeteer = require("puppeteer-core");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const root = join(fileURLToPath(import.meta.url), "..", "..", "dist");
const PORT = 8241;
const BASE = `http://127.0.0.1:${PORT}`;
const PUBLIC_BASE = "https://www.forensicspp.com";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".map": "application/json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

const VALID_SLUGS = new Set(Object.keys(SLUG_TO_TOOL));

// Alias (supplementary) slugs canonicalize to a sibling route instead of
// themselves — they must NOT be indexable duplicates. Mirrors the alias model
// in scripts/build-seo-pages.mjs (ALIAS_SLUGS) and src/seo/toolRoutes.mjs.
const ALIAS_CANONICAL = { "sqlite-wal-recovery": "sqlite-forensics" };
function canonicalSlugFor(slug) {
  return ALIAS_CANONICAL[slug] || slug;
}

async function resolveFile(urlPath) {
  const path = decodeURIComponent(urlPath.split("?")[0].split("#")[0]);
  if (path === "/") return join(root, "index.html");
  const base = join(root, normalize(path).replace(/^(\.\.[/\\])+/, ""));
  try {
    const s = await stat(base);
    if (s.isDirectory()) return join(base, "index.html");
    return base;
  } catch {
    try {
      if ((await stat(join(base, "index.html"))).isFile()) return join(base, "index.html");
    } catch {}
  }
  return null;
}

const server = createServer(async (req, res) => {
  const p = req.url.split("?")[0].split("#")[0];
  let file = await resolveFile(req.url);
  // SPA fallback (mirrors Nginx `try_files ... /index.html`): unknown
  // extension-less routes — including typo'd /tools/<slug>/ — serve the
  // app shell, which then renders the in-app NotFound (#14). Assets keep
  // root-absolute paths so the shell boots from any sub-path.
  if (!file && !extname(p)) file = join(root, "index.html");
  if (!file) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  try {
    const buf = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] || "application/octet-stream" });
    res.end(buf);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});

const TOOLS = [
  "evtx-viewer",
  "sqlite-forensics",
  "apk-signature-analyzer",
  "pcap-analyzer",
  "registry-forensics",
  "firmware-analyzer",
  "binary-file-analyzer",
  "windows-artifacts",
  "image-forensics",
];

let pass = 0, fail = 0;
const fails = [];
function check(cond, msg) {
  if (cond) { pass++; } else { fail++; fails.push(msg); console.log("  ✗ " + msg); }
}

await new Promise((resolve) => server.listen(PORT, "127.0.0.1", resolve));
console.log(`static server listening on ${BASE}`);

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--disable-setuid-sandbox"],
});
const page = await browser.newPage();
page.on("pageerror", (e) => { fail++; fails.push("pageerror: " + e.message); });

async function assertToolRoute(slug, canonicalId) {
  const resp = await page.goto(`${BASE}/tools/${slug}/`, { waitUntil: "networkidle0", timeout: 30000 });
  check(resp.status() === 200, `/tools/${slug}/ HTTP ${resp.status()} (want 200)`);

  // Static metadata read from the built artifact (runtime i18n overrides the
  // live <title>, so we assert the static source, not page.title()).
  const html = await readFile(join(root, "tools", slug, "index.html"), "utf8");
  const title = (html.match(/<title>([^<]*)<\/title>/) || [])[1] || "";
  check(title.length > 0, `/tools/${slug}/ static <title> present`);
  check(!/Forensics\+\+ Workbench/i.test(title), `/tools/${slug}/ title is per-tool, not generic ("${title}")`);
  const canonical = (html.match(/<link rel="canonical" href="([^"]*)"/) || [])[1] || "";
  const expectedCanonical = `${PUBLIC_BASE}/tools/${canonicalSlugFor(slug)}/`;
  check(canonical === expectedCanonical, `/tools/${slug}/ canonical=${canonical} (want ${expectedCanonical})`);
  const h1 = (html.match(/<h1>([^<]*)<\/h1>/) || [])[1] || "";
  check(h1.length > 0, `/tools/${slug}/ static <h1>="${h1}"`);

  // Runtime: app booted from the sub-path (the base:"/" fix).
  await page.waitForFunction(() => {
    const r = document.getElementById("root");
    return r && r.children.length > 0;
  }, { timeout: 15000 }).catch(() => {});
  const booted = await page.$eval("#root", (el) => el.children.length > 0).catch(() => false);
  check(booted, `/tools/${slug}/ SPA booted (#root has children)`);
  check(!(await page.$(".tool-notfound")), `/tools/${slug}/ is NOT the NotFound state`);
  const active = await page.$(`[data-tool-id="${canonicalId}"]:not([hidden])`);
  check(!!active, `/tools/${slug}/ active ToolHost = ${canonicalId}`);
  const url = page.url().replace(/\/+$/, "");
  check(url === `${BASE}/tools/${slug}`, `/tools/${slug}/ final URL=${url}`);

  // Refresh keeps the tool (no flash to home).
  await page.reload({ waitUntil: "networkidle0" });
  const url2 = page.url().replace(/\/+$/, "");
  check(url2 === `${BASE}/tools/${slug}`, `/tools/${slug}/ refresh keeps URL=${url2}`);
  const active2 = await page.$(`[data-tool-id="${canonicalId}"]:not([hidden])`);
  check(!!active2, `/tools/${slug}/ refresh keeps active ToolHost=${canonicalId}`);
}

console.log("=== Production HTTP + Chrome smoke ===");
for (const slug of TOOLS) {
  const id = SLUG_TO_TOOL[slug];
  console.log(`-- /tools/${slug}/`);
  await assertToolRoute(slug, id);
}

console.log("-- /");
{
  const resp = await page.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  check(resp.status() === 200, `/ HTTP ${resp.status()}`);
  const title = await page.title();
  check(title.includes("Forensics++"), `/ title="${title}"`);
  const h1 = await page.$eval("h1", (el) => el.textContent).catch(() => "");
  check(!/requires JavaScript/i.test(h1), `/ H1 is not "requires JavaScript" ("${h1}")`);
}

console.log("-- /tools/not-a-real-tool/  (expect in-app NotFound via SPA fallback)");
{
  const resp = await page.goto(`${BASE}/tools/not-a-real-tool/`, { waitUntil: "networkidle0" });
  // SPA fallback serves the shell (200); the app must render NotFound, NOT home.
  check(resp.status() === 200, `/tools/not-a-real-tool/ HTTP ${resp.status()} (SPA fallback)`);
  await page.waitForFunction(() => {
    const r = document.getElementById("root");
    return r && r.children.length > 0;
  }, { timeout: 15000 }).catch(() => {});
  const booted = await page.$eval("#root", (el) => el.children.length > 0).catch(() => false);
  check(booted, `/tools/not-a-real-tool/ SPA booted from fallback`);
  const notFound = await page.$(".tool-notfound");
  check(!!notFound, `/tools/not-a-real-tool/ renders in-app NotFound (not Home)`);
}

console.log("-- history back/forward");
{
  await page.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  await page.goto(`${BASE}/tools/evtx-viewer/`, { waitUntil: "networkidle0" });
  await page.goto(`${BASE}/tools/pcap-analyzer/`, { waitUntil: "networkidle0" });
  await page.goBack({ waitUntil: "networkidle0" });
  check(page.url().replace(/\/+$/, "") === `${BASE}/tools/evtx-viewer`, `back -> evtx (got ${page.url()})`);
  await page.goForward({ waitUntil: "networkidle0" });
  check(page.url().replace(/\/+$/, "") === `${BASE}/tools/pcap-analyzer`, `forward -> pcap (got ${page.url()})`);
}

console.log("-- viewport sanity (no horizontal overflow + sidebar/header present)");
{
  const viewports = [
    { name: "desktop 1440x900", width: 1440, height: 900 },
    { name: "laptop 1280x800", width: 1280, height: 800 },
    { name: "tablet 768x1024", width: 768, height: 1024 },
    { name: "mobile 390x844", width: 390, height: 844 },
  ];
  for (const vp of viewports) {
    await page.setViewport(vp);
    await page.goto(`${BASE}/tools/evtx-viewer/`, { waitUntil: "networkidle0" });
    await page.waitForFunction(() => { const r = document.getElementById("root"); return r && r.children.length > 0; }, { timeout: 15000 }).catch(() => {});
    const metrics = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      hasSidebar: !!document.querySelector(".app-sidebar"),
      hasHeader: !!document.querySelector(".app-topbar, header"),
    }));
    check(metrics.overflow <= 2, `${vp.name}: no horizontal overflow (scrollW-clientW=${metrics.overflow})`);
    check(metrics.hasHeader, `${vp.name}: app header present`);
  }
}

await browser.close();
server.close();

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("FAILURES:\n" + fails.map((f) => " - " + f).join("\n"));
  process.exit(1);
}

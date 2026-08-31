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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

// Content lint over the generated Static Search Discovery Layer.
// Fails if any forbidden AI-marketing term appears in the SEO HTML.
// Run: node scripts/lint-seo.mjs  (after `npm run build:seo`)

import { readFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { findForbidden, FORBIDDEN_EN, FORBIDDEN_ZH } from "../src/seo/forbiddenWords.mjs";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const distRoot = join(projectRoot, "dist");

async function walk(dir) {
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else if (e.name.endsWith(".html")) out.push(p);
  }
  return out;
}

async function main() {
  const dirs = [
    join(distRoot, "tools"),
    join(distRoot, "zh", "tools"),
    join(distRoot, "zh"),
  ];
  const files = (await Promise.all(dirs.map(walk))).flat();
  if (!files.length) {
    console.error("No SEO HTML found. Run `npm run build:seo` first.");
    process.exit(1);
  }

  let violations = 0;
  for (const f of files) {
    const html = await readFile(f, "utf8");
    // Strip <style>/<script> blocks to lint only visible copy.
    const copy = html
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<[^>]+>/g, " ");
    const bad = findForbidden(copy);
    if (bad.length) {
      violations++;
      console.error(`✗ ${f.replace(distRoot, "")} -> ${bad.join(", ")}`);
    }
  }

  if (violations) {
    console.error(`\nSEO content lint FAILED: ${violations} file(s) contain forbidden terms.`);
    console.error(`Forbidden EN: ${FORBIDDEN_EN.slice(0, 12).join(", ")} …`);
    console.error(`Forbidden ZH: ${FORBIDDEN_ZH.slice(0, 8).join(", ")} …`);
    process.exit(1);
  }
  console.log(`SEO content lint OK: ${files.length} pages checked, no marketing terms.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

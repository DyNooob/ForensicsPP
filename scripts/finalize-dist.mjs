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

import { readFile, writeFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const distRoot = join(projectRoot, "dist");
const packageJson = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8"));
const serviceWorkerPath = join(distRoot, "sw.js");
const serviceWorker = await readFile(serviceWorkerPath, "utf8");

// Deterministic fingerprint of the built asset set. Whenever the JS/CSS
// chunks change (a rebuild), this changes, so the Service Worker's
// activate handler purges the previous cache and serves fresh chunks.
// This is what stops a stale cached chunk (whose content hash no longer
// matches index.html) from breaking every lazily-loaded tool.
let fingerprint = "static";
try {
  const assetsDir = join(distRoot, "assets");
  const names = (await readdir(assetsDir)).filter((name) => /\.(js|css)$/.test(name)).sort();
  fingerprint = createHash("sha1").update(names.join("|")).digest("hex").slice(0, 10);
} catch {}
const expectedCacheVersion = `forensicspp-v${packageJson.version}-${fingerprint}`;
const finalized = serviceWorker.replace(
  /const CACHE_VERSION = "[^"]+";/,
  `const CACHE_VERSION = "${expectedCacheVersion}";`
);

if (!/const CACHE_VERSION = "[^"]+";/.test(serviceWorker)) {
  throw new Error("Could not find the Service Worker cache version marker in dist/sw.js");
}

if (finalized !== serviceWorker) await writeFile(serviceWorkerPath, finalized);
console.log(`Finalized dist/sw.js cache version: ${expectedCacheVersion}`);

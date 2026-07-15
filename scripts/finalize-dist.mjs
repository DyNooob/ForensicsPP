#!/usr/bin/env node
/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const distRoot = join(projectRoot, "dist");
const packageJson = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8"));
const serviceWorkerPath = join(distRoot, "sw.js");
const serviceWorker = await readFile(serviceWorkerPath, "utf8");
const expectedCacheVersion = `forensicspp-v${packageJson.version}`;
const finalized = serviceWorker.replace(
  /const CACHE_VERSION = "[^"]+";/,
  `const CACHE_VERSION = "${expectedCacheVersion}";`
);

if (!/const CACHE_VERSION = "[^"]+";/.test(serviceWorker)) {
  throw new Error("Could not find the Service Worker cache version marker in dist/sw.js");
}

if (finalized !== serviceWorker) await writeFile(serviceWorkerPath, finalized);
console.log(`Finalized dist/sw.js cache version: ${expectedCacheVersion}`);

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

import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAssetIdentity } from "./build-assets.mjs";
import { SITE } from "../src/seo/seoPages.mjs";
import { prepareResourceCdn } from "./resource-cdn.mjs";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const distRoot = join(projectRoot, "dist");
if (process.env.ASSET_CDN_URL && process.env.SINGLE_FILE !== "1") await prepareResourceCdn(distRoot);
const packageJson = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8"));
const serviceWorkerPath = join(distRoot, "sw.js");
const serviceWorker = await readFile(serviceWorkerPath, "utf8");

// ── Preview vs production indexing policy ──────────────────────────────────
const isPreview = process.env.VITE_PREVIEW === "1" || process.env.VITE_PREVIEW === "true";

const robotsTxt = isPreview
  ? "User-agent: *\nDisallow: /\n"
  : `User-agent: *\nAllow: /\n\nSitemap: ${SITE.base}/sitemap.xml\n`;
await writeFile(join(distRoot, "robots.txt"), robotsTxt, "utf8");
console.log(`Wrote dist/robots.txt (${isPreview ? "preview: Disallow /" : "production: Allow /"})`);

// For preview builds, point the root SPA entry's canonical + og:url at the
// preview host (env-aware SITE.base) and inject the noindex meta, so a raw
// `curl /` matches the route pages + sitemap (both already use SITE.base).
// Production keeps its www canonical and stays indexable.
const indexHtmlPath = join(distRoot, "index.html");
let indexHtml = await readFile(indexHtmlPath, "utf8");
if (isPreview) {
  const home = `${SITE.base}/`;
  indexHtml = indexHtml
    .replace(/<link rel="canonical" href="[^"]*" \/>/, `<link rel="canonical" href="${home}" />`)
    .replace(/<meta property="og:url" content="[^"]*" \/>/, `<meta property="og:url" content="${home}" />`);
  if (!/name="robots"/.test(indexHtml)) {
    indexHtml = indexHtml.replace("</head>", '<meta name="robots" content="noindex,nofollow,noarchive" />\n</head>');
    console.log("Injected noindex robots meta (preview)");
  }
  await writeFile(indexHtmlPath, indexHtml, "utf8");
  console.log("Rewrote root canonical + og:url to preview host");
}

const { fingerprint, bootstrap } = await buildAssetIdentity(distRoot);
const expectedCacheVersion = `forensicspp-v${packageJson.version}-${fingerprint}`;
if (!/const CACHE_VERSION = "[^"]+";/.test(serviceWorker) || !serviceWorker.includes("const BUILD_ASSETS = [];")) {
  throw new Error("Service Worker build markers are missing");
}
const finalized = serviceWorker
  .replace(/const CACHE_VERSION = "[^"]+";/, `const CACHE_VERSION = "${expectedCacheVersion}";`)
  .replace("const BUILD_ASSETS = [];", `const BUILD_ASSETS = ${JSON.stringify(bootstrap)};`);
await writeFile(serviceWorkerPath, finalized);
console.log(`Finalized dist/sw.js: ${expectedCacheVersion}; ${bootstrap.length} bootstrap assets`);

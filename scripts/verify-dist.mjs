#!/usr/bin/env node
/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import { access, readFile, readdir, stat } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const distRoot = join(projectRoot, "dist");
const copyrightMarker = "Forensics++ (ForensicsPP.com)";

const requiredFiles = [
  "index.html",
  "404.html",
  "CNAME",
  ".nojekyll",
  "favicon.svg",
  "legal.html",
  "og-image.png",
  "robots.txt",
  "site.webmanifest",
  "sitemap.xml",
  "sw.js",
  "cyberchef/CyberChef_v10.19.4.html"
];

const forbiddenNames = new Set([
  ".git",
  ".env",
  ".DS_Store",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "tsconfig.node.json",
  "vite.config.ts",
  "vitest.config.ts"
]);

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else files.push(path);
  }
  return files;
}

const errors = [];
for (const path of requiredFiles) {
  try {
    await access(join(distRoot, path));
  } catch {
    errors.push(`missing required file: ${path}`);
  }
}

let files = [];
try {
  files = await walk(distRoot);
} catch {
  errors.push("dist/ does not exist or cannot be read");
}

let totalBytes = 0;
for (const path of files) {
  const outputPath = relative(distRoot, path);
  const segments = outputPath.split(/[\\/]/);
  const fileStat = await stat(path);
  totalBytes += fileStat.size;

  if (segments.some((segment) => forbiddenNames.has(segment))) errors.push(`forbidden release path: ${outputPath}`);
  if ([".map", ".log", ".ts", ".tsx"].includes(extname(path))) errors.push(`forbidden release extension: ${outputPath}`);
  if (fileStat.size > 50 * 1024 * 1024) errors.push(`file exceeds 50 MiB: ${outputPath}`);
}

if (totalBytes > 100 * 1024 * 1024) errors.push("release artifact exceeds 100 MiB");

const generatedProjectAssets = files.filter((file) => {
  const outputPath = relative(distRoot, file);
  return /^assets\/(?:index-|(?:[A-Z][A-Za-z]+Tool|entropy\.worker)-).*\.js$/.test(outputPath)
    || /^assets\/index-.*\.css$/.test(outputPath);
});

for (const path of generatedProjectAssets) {
  const content = await readFile(path, "utf8");
  if (!content.includes(copyrightMarker)) errors.push(`generated asset is missing copyright banner: ${relative(distRoot, path)}`);
}

if (errors.length) {
  console.error(`Release artifact verification failed:\n${errors.map((error) => `- ${error}`).join("\n")}`);
  process.exit(1);
}

console.log(`Release artifact verified: ${files.length} files, ${(totalBytes / 1024 / 1024).toFixed(1)} MiB.`);

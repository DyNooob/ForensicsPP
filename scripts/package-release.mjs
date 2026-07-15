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

import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync } from "fflate";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageJson = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8"));
const version = packageJson.version;
const releaseRoot = join(projectRoot, "release");
const folderName = `ForensicsPP-v${version}-static`;
const stagingRoot = join(releaseRoot, folderName);
const zipPath = join(releaseRoot, `${folderName}.zip`);
const distRoot = join(projectRoot, "dist");

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

await stat(join(distRoot, "index.html"));
await rm(releaseRoot, { recursive: true, force: true });
await mkdir(stagingRoot, { recursive: true });
await cp(distRoot, stagingRoot, { recursive: true });

const packagedFiles = await walk(stagingRoot);
if (!packagedFiles.some((path) => basename(path) === "index.html")) throw new Error("Static package is missing index.html");

await rm(zipPath, { force: true });
const zipEntries = {};
for (const path of packagedFiles) {
  const outputPath = `${folderName}/${relative(stagingRoot, path).replaceAll("\\", "/")}`;
  zipEntries[outputPath] = new Uint8Array(await readFile(path));
}
await writeFile(zipPath, zipSync(zipEntries, { level: 9 }));

const zipBytes = await readFile(zipPath);
const sha256 = createHash("sha256").update(zipBytes).digest("hex");
const checksumLine = `${sha256}  ${basename(zipPath)}\n`;
await writeFile(join(releaseRoot, "SHA256SUMS.txt"), checksumLine, "utf8");

const totalBytes = packagedFiles.reduce(async (sumPromise, path) => (await sumPromise) + (await stat(path)).size, Promise.resolve(0));
console.log(`Static release package: ${relative(projectRoot, zipPath)}`);
console.log(`Files: ${packagedFiles.length}; unpacked: ${((await totalBytes) / 1024 / 1024).toFixed(1)} MiB; zip: ${(zipBytes.length / 1024 / 1024).toFixed(1)} MiB`);
console.log(`SHA-256: ${sha256}`);

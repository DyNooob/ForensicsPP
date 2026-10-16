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

import { readFile, readdir, mkdir, writeFile, copyFile } from "node:fs/promises";
import { resolve, join, relative } from "node:path";
import { createHash } from "node:crypto";
import { zipSync, strToU8 } from "fflate";

const root = resolve("dist");
const config = JSON.parse(await readFile(join(root, "resource-cdn.json"), "utf8"));
const prefix = new URL(config.base).pathname.replace(/^\//, "");
const archive = resolve("release/resource-cdn-assets");
const manifest = [];
async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path)); else files.push(path);
  }
  return files;
}
for (const directory of ["assets", "cyberchef"]) {
  for (const path of await walk(join(root, directory))) {
    const name = relative(root, path).replaceAll("\\", "/");
    const target = join(archive, prefix, name);
    await mkdir(resolve(target, ".."), { recursive: true });
    await copyFile(path, target);
    const bytes = await readFile(path);
    manifest.push({ path: `${prefix}/${name}`, url: `${config.base}/${name}`, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
}
// Preserve the currently deployed vendor-only build while staging the new one.
for (const path of await walk(resolve("release/vendor-cdn-assets"))) {
  const target = join(archive, relative(resolve("release/vendor-cdn-assets"), path));
  await mkdir(resolve(target, ".."), { recursive: true }); await copyFile(path, target);
}
const files = {};
for (const path of await walk(archive)) files[relative(archive, path).replaceAll("\\", "/")] = new Uint8Array(await readFile(path));
files["edgeone.json"] = strToU8(JSON.stringify({ headers: ["/assets/*", "/releases/*"].map(source => ({ source, headers: [
  { key: "Access-Control-Allow-Origin", value: "*" },
  { key: "Cache-Control", value: "public, max-age=31536000, immutable" },
  { key: "Cross-Origin-Resource-Policy", value: "cross-origin" }
] })) }, null, 2));
files["index.html"] = strToU8('<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Forensics++ Resources</title><h1>Forensics++ Resources</h1><a href="manifest.json">Resource manifest</a>');
const result = JSON.stringify({ base: config.base, files: manifest }, null, 2);
files["manifest.json"] = strToU8(result);
files["legal.html"] = new Uint8Array(await readFile(join(root, "legal.html")));
files["LICENSE"] = new Uint8Array(await readFile("LICENSE"));
await mkdir("release", { recursive: true });
await writeFile("release/resource-cdn-manifest.json", result);
const zip = zipSync(files, { level: 6 });
await writeFile("release/ForensicsPP-resource-cdn.zip", zip);
console.log(`Resource CDN package: ${manifest.length} files, ${(manifest.reduce((n,f)=>n+f.bytes,0)/1048576).toFixed(1)} MiB; ZIP ${(zip.length/1048576).toFixed(1)} MiB; ${config.base}`);

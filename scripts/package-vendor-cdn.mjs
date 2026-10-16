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

import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";
import { zipSync, strToU8 } from "fflate";

const root = resolve(process.env.CDN_DIST_DIR || "dist");
const html = await readFile(join(root, "index.html"), "utf8");
const cdn = [...html.matchAll(/(?:src|href)="(https:\/\/[^"\s]+)"/g)]
  .map((match) => match[1]).find((url) => /\/assets\/vendor-[\w-]+\.(?:js|css)$/.test(new URL(url).pathname));
if (!cdn) throw new Error("Build with VENDOR_CDN_URL before packaging vendor assets");
const vendorBase = cdn.slice(0, cdn.lastIndexOf("/assets/") + 1);
const files = {};
const manifest = [];
// Repeated local packages preserve earlier content hashes for open app tabs.
// CI or a fresh checkout must restore this directory before packaging if the
// resulting archive is going to replace a previous CDN deployment.
const archive = resolve("release/vendor-cdn-assets/assets");
await mkdir(archive, { recursive: true });
for (const name of (await readdir(join(root, "assets"))).sort()) {
  if (!/^vendor-[\w-]+\.(?:js|css)$/.test(name)) continue;
  const bytes = new Uint8Array(await readFile(join(root, "assets", name)));
  files[`assets/${name}`] = bytes;
  await writeFile(join(archive, name), bytes);
  manifest.push({ path: `assets/${name}`, url: `${vendorBase}assets/${name}`, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
}
for (const name of await readdir(archive)) {
  if (/^vendor-[\w-]+\.(?:js|css)$/.test(name) && !files[`assets/${name}`]) {
    files[`assets/${name}`] = new Uint8Array(await readFile(join(archive, name)));
  }
}
files["edgeone.json"] = strToU8(JSON.stringify({ headers: [{ source: "/assets/*", headers: [
  { key: "Access-Control-Allow-Origin", value: "*" },
  { key: "Cache-Control", value: "public, max-age=31536000, immutable" },
  { key: "Cross-Origin-Resource-Policy", value: "cross-origin" }
] }] }, null, 2));
files["manifest.json"] = strToU8(JSON.stringify({ base: vendorBase, files: manifest }, null, 2));
files["index.html"] = strToU8('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="robots" content="noindex"><title>Forensics++ Static Assets</title><h1>Forensics++ Static Assets</h1><p>Vendor resource package is deployed.</p><p><a href="manifest.json">Resource manifest</a> · <a href="legal.html">Open-source notices</a></p></html>');
files["legal.html"] = new Uint8Array(await readFile(join(root, "legal.html")));
files["LICENSE"] = new Uint8Array(await readFile("LICENSE"));
await mkdir("release", { recursive: true });
await writeFile("release/vendor-cdn-manifest.json", JSON.stringify({ base: vendorBase, files: manifest }, null, 2));
const path = resolve("release/ForensicsPP-vendor-cdn.zip");
await writeFile(path, zipSync(files));
console.log(`Vendor CDN package: ${path} (${manifest.length} resources, target ${vendorBase})`);

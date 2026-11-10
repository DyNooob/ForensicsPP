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

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";
import { unzipSync } from "fflate";

const index = process.argv.indexOf("--package");
if (index < 0 || !process.argv[index + 1]) throw new Error("Usage: npm run prepare:offline -- --package /path/to/ForensicsPP-offline-static.zip (no network access)");
const archive = await readFile(resolve(process.argv[index + 1]));
if (archive.length > 128 * 1024 * 1024) throw new Error("Offline input archive exceeds 128 MiB");
let expanded = 0;
const files = unzipSync(archive, { filter(entry) {
  const wanted = /\/(?:OFFLINE_MANIFEST\.json|lookup\/[^/]+|sources\/heic-sources\.tar\.gz)$/.test(entry.name);
  if (wanted) expanded += entry.originalSize;
  if (expanded > 64 * 1024 * 1024) throw new Error("Offline input expansion exceeds 64 MiB");
  return wanted;
} });
const names = Object.keys(files).filter((name) => name.endsWith("/OFFLINE_MANIFEST.json"));
if (names.length !== 1) throw new Error("Expected one offline distribution manifest");
const prefix = names[0].slice(0, -"OFFLINE_MANIFEST.json".length);
const manifest = JSON.parse(new TextDecoder().decode(files[names[0]]));
if (manifest.distribution !== "offline") throw new Error("Not an offline distribution");
const sources = JSON.parse(await readFile(new URL("../src/features/lookup/dataSources.json", import.meta.url), "utf8"));
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const validated = [];
for (const source of Object.values(sources)) {
  const bytes = files[prefix + source.path];
  if (!bytes || bytes.length !== source.bytes || digest(bytes) !== source.sha256) throw new Error(`Pinned lookup input mismatch: ${source.path}`);
  validated.push([join("release/lookup-data", source.sha256), bytes]);
}
const codec = files[prefix + "sources/heic-sources.tar.gz"];
if (!codec || digest(codec) !== manifest.heicSourcesSha256) throw new Error("HEIC source archive mismatch");
validated.push(["release/offline-inputs/heic-sources.tar.gz", codec]);
await mkdir("release/lookup-data", { recursive: true });
await mkdir("release/offline-inputs", { recursive: true });
for (const [path, bytes] of validated) await writeFile(path, bytes);
console.log("Prepared three pinned lookup inputs and HEIC corresponding sources from the local archive. No downloads performed.");

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

import { readFile, readdir, access } from "node:fs/promises";
import { resolve, join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

export async function verifyOfflineDistribution(root) {
  const manifest = JSON.parse(await readFile(join(root, "OFFLINE_MANIFEST.json"), "utf8"));
  if (manifest.distribution !== "offline" || manifest.externalRuntimeResources !== false) throw new Error("Not a verified offline distribution");
  for (const path of ["start_server.py", "Start-ForensicsPP.command", "Start-ForensicsPP.bat", "OFFLINE-README.txt", "LICENSE.txt", "THIRD_PARTY_NOTICES.txt", "licenses/DEPENDENCIES.json", "sources/heic-sources.tar.gz"]) await access(join(root, path));
  for (const pack of manifest.lookup) {
    const bytes = await readFile(join(root, pack.path));
    if (bytes.length !== pack.bytes || createHash("sha256").update(bytes).digest("hex") !== pack.sha256) throw new Error(`Offline data checksum mismatch: ${pack.path}`);
  }
  const sources = await readFile(join(root, "sources/heic-sources.tar.gz"));
  if (createHash("sha256").update(sources).digest("hex") !== manifest.heicSourcesSha256) throw new Error("HEIC source checksum mismatch");
  let checked = 0;
  const visit = async (folder) => {
    for (const entry of await readdir(folder, { withFileTypes: true })) {
      const path = join(folder, entry.name);
      if (entry.isDirectory()) { await visit(path); continue; }
      if (!/\.(html|css|js)$/.test(entry.name)) continue;
      const text = await readFile(path, "utf8");
      checked++;
      if (entry.name.endsWith(".html")) {
        if (!text.includes('name="distribution" content="offline"') || !text.includes('http-equiv="Content-Security-Policy"')) throw new Error(`Offline policy missing in ${relative(root, path)}`);
        for (const match of text.matchAll(/<(script|link|iframe|img|source)\b[^>]*(?:src|href)=["']([^"']+)["'][^>]*>/gi)) {
          if (/^(?:https?:)?\/\//i.test(match[2]) && !/rel=["'](?:canonical|alternate)["']/i.test(match[0])) throw new Error(`Remote resource in ${relative(root, path)}: ${match[2]}`);
        }
        if (/<meta name="(?:asset-cdn|vendor-cdn)" content="https?:/i.test(text)) throw new Error("CDN metadata present in offline HTML");
      }
      if (entry.name.endsWith(".css") && /(?:url\(\s*["']?(?:https?:)?\/\/|@import\s+["'](?:https?:)?\/\/)/i.test(text)) throw new Error(`Remote stylesheet resource: ${relative(root, path)}`);
      if (entry.name.endsWith(".js") && /\bimport\s*\(\s*["']https?:\/\//i.test(text)) throw new Error(`Remote JS import: ${relative(root, path)}`);
    }
  };
  await visit(root);
  console.log(`Offline distribution verified: ${checked} code/style documents; ${manifest.lookup.length} checksum-verified local data packs; local licenses and HEIC sources.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await verifyOfflineDistribution(resolve(process.argv[2] || "dist"));

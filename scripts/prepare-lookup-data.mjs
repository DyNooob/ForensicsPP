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

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";

const sources = JSON.parse(await readFile(new URL("../src/features/lookup/dataSources.json", import.meta.url), "utf8"));
const digest = data => createHash("sha256").update(data).digest("hex");
export async function prepareLookupData(root) {
  const cache = resolve("release/lookup-data");
  await mkdir(cache, { recursive: true });
  await mkdir(join(root, "lookup"), { recursive: true });
  for (const [id, source] of Object.entries(sources)) {
    let bytes = await readFile(join(cache, source.sha256)).catch(() => null);
    if (!bytes || bytes.length !== source.bytes || digest(bytes) !== source.sha256) {
      bytes = null;
      const raw = source.upstream.replace("https://cdn.jsdelivr.net/gh/", "https://raw.githubusercontent.com/").replace("@", "/");
      for (const url of [raw, source.upstream]) {
        try {
          const response = await fetch(url, { signal: AbortSignal.timeout(90000) });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const data = new Uint8Array(await response.arrayBuffer());
          if (data.length !== source.bytes || digest(data) !== source.sha256) throw new Error("Checksum mismatch");
          bytes = data; break;
        } catch (error) { console.warn(`Lookup source ${id}: ${error.message}`); }
      }
      if (!bytes) throw new Error(`Could not obtain the pinned ${id} lookup data. Build stopped.`);
      await writeFile(join(cache, source.sha256), bytes);
    }
    await writeFile(join(root, source.path), bytes);
    console.log(`Lookup data verified: ${id}, ${bytes.length} bytes, SHA-256 ${source.sha256}`);
  }
  await writeFile(join(root, "lookup", "SOURCES.json"), JSON.stringify(sources, null, 2));
}

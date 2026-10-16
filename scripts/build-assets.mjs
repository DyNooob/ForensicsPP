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

import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

export async function buildAssetIdentity(distRoot) {
  const html = await readFile(join(distRoot, "index.html"), "utf8");
  const names = await readdir(join(distRoot, "assets")).catch(() => []);
  const rootNames = await readdir(distRoot);
  const assets = [...names.map((name) => `assets/${name}`), ...rootNames]
    .filter((name) => /\.(js|css|wasm)$/.test(name)).sort();
  // Include the shell: standalone app JS is inlined, and metadata-only changes
  // also need a fresh cache even when chunk filenames remain unchanged.
  const fingerprint = createHash("sha1").update(html).update(assets.join("|")).digest("hex").slice(0, 10);
  const markup = html.replace(/(<script\b[^>]*>)[\s\S]*?<\/script>/gi, "$1</script>");
  const bootstrap = [...new Set(Array.from(markup.matchAll(/(?:src|href)="([^"\s]*assets\/[^"\s]+\.(?:js|css))"/g), (match) => match[1]))];
  return { fingerprint, bootstrap };
}

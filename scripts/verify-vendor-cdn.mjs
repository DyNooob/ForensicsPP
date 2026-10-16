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

import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const manifest = JSON.parse(await readFile("release/vendor-cdn-manifest.json", "utf8"));
for (const file of manifest.files) {
  const response = await fetch(file.url, { signal: AbortSignal.timeout(15000), headers: { Origin: "https://www.forensicspp.com" } })
    .catch((error) => { throw new Error(`${file.url}: ${error.cause?.code || error.message}; check DNS and HTTPS certificate`); });
  if (!response.ok) throw new Error(`${file.url}: HTTP ${response.status}`);
  const cors = response.headers.get("access-control-allow-origin");
  if (cors !== "*" && cors !== "https://www.forensicspp.com") throw new Error(`${file.url}: missing module CORS header`);
  const mime = response.headers.get("content-type") || "";
  if (file.path.endsWith(".js") ? !/(?:javascript|ecmascript)/i.test(mime) : !/text\/css/i.test(mime)) throw new Error(`${file.url}: invalid MIME type ${mime}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (createHash("sha256").update(bytes).digest("hex") !== file.sha256) throw new Error(`${file.url}: file does not match this build`);
  console.log(`OK ${file.path}`);
}
console.log(`Verified ${manifest.files.length} vendor CDN resources.`);

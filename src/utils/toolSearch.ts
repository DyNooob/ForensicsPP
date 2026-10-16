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

import { copy } from "../i18n";
import { tools, type ToolDefinition } from "../config/app";

const hashKeywords = "MD5 SHA-1 SHA1 SHA-256 SHA256 SHA-512 SHA512 SHA3 SM3 checksum 校验 摘要";
export function toolMatchesQuery(tool: ToolDefinition, query: string) {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const aliases = tools.filter((item) => item.mergedInto === tool.id).map((item) => item.id);
  const text = [tool.id, copy.zh[tool.name], copy.en[tool.name], copy.zh[tool.desc], copy.en[tool.desc],
    copy.zh[tool.category], copy.en[tool.category], ...(tool.accepts ?? []), ...(tool.capabilities ?? []), ...aliases,
    tool.id === "hash" ? hashKeywords : ""].join(" ").toLowerCase();
  return terms.every((term) => text.includes(term));
}

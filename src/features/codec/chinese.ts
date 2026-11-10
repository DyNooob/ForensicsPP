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

import { Converter } from "opencc-js";

export type ChineseRegion = "t" | "tw" | "twp" | "hk";
export type ChineseRequest = { input: string; direction: "toSimplified" | "toTraditional"; region: ChineseRegion };

export function convertChinese({ input, direction, region }: ChineseRequest) {
  if (new TextEncoder().encode(input).byteLength > 2 * 1024 * 1024) throw new Error("Input exceeds 2 MiB / 输入超过 2 MiB");
  if (!["t", "tw", "twp", "hk"].includes(region) || !["toSimplified", "toTraditional"].includes(direction)) throw new Error("Invalid conversion mode");
  return Converter(direction === "toSimplified" ? { from: region, to: "cn" } : { from: "cn", to: region })(input);
}

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

import { luhnCheck, parseIpv4, validateChineseId, validatePhone } from "../features/lookup/rules";

export const textLaunchTools = ["lookup", "urltool", "hash", "timestamp", "json", "ioc", "jwt", "http"] as const;
export type TextLaunchTool = (typeof textLaunchTools)[number];

function isLookupValue(value: string) {
  return Boolean(parseIpv4(value) || validatePhone(value).valid || validateChineseId(value).valid
    || (/^\d{12,19}$/.test(value.replace(/[\s-]/g, "")) && luhnCheck(value).valid));
}

/** Recommend a tool; ambiguous numeric inputs can always be overridden by the user. */
export function launchTarget(value: string): TextLaunchTool {
  const input = value.trim();
  if (input.length > 65_536) return /^[{[]/.test(input) ? "json" : "ioc";
  if (!input) return "ioc";
  if (/^(?:[A-Z]+\s+\S+\s+HTTP\/\d|HTTP\/\d)/.test(input)) return "http";
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(input.replace(/^Bearer\s+/i, ""))) return "jwt";
  if (/^(?:h(?:tt|xx)ps?|ftp)(?::|\[:\])\/\//i.test(input)
    || /^(?:[\w-]+(?:\.|\[\.\]))+[a-z]{2,}(?:[/:?#]|$)/i.test(input)) return "urltool";
  if (/^[a-f\d]+$/i.test(input) && [32, 40, 64, 128].includes(input.length)) return "hash";
  if (validateChineseId(input).valid || validatePhone(input).valid || parseIpv4(input)) return "lookup";
  if (/^-?\d{9,19}(?:\.\d+)?$/.test(input)) {
    if (/^\d{12,19}$/.test(input) && ![10, 13].includes(input.length) && luhnCheck(input).valid) return "lookup";
    if (/^\d{6}(?:18|19|20)\d{10}$/.test(input)) return "lookup"; // ID-shaped input with a bad checksum.
    return "timestamp";
  }
  if (/^\d{4}-\d{2}-\d{2}(?:[T ]|$)/.test(input) && Number.isFinite(Date.parse(input))) return "timestamp";
  const lines = input.split(/[\r\n,;，；\t]+/).map((item) => item.trim()).filter(Boolean);
  if (lines.length && lines.every(isLookupValue)) return "lookup";
  if (/^\d{17}[\dXx]$/.test(input)) return "lookup"; // Allow rule checks on invalid IDs.
  if (/^[{[]/.test(input)) {
    try { JSON.parse(input); return "json"; } catch { /* Keep logs/text in IOC. */ }
  }
  return "ioc";
}

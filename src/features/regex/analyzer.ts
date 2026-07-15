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

export type RegexMatch = {
  order: number;
  index: number;
  end: number;
  line: number;
  length: number;
  value: string;
  groups: string[];
  namedGroups: Record<string, string>;
  context: string;
};

export type RegexAnalysis = {
  matches: RegexMatch[];
  replaced: string;
  error: string;
  flags: string;
};

function normalizeFlags(flags: string) {
  const allowed = new Set(["d", "g", "i", "m", "s", "u", "v", "y"]);
  const normalized: string[] = [];
  for (const flag of flags.trim()) {
    if (!allowed.has(flag)) throw new Error(`Unsupported regex flag: ${flag}`);
    if (!normalized.includes(flag)) normalized.push(flag);
  }
  if (!normalized.includes("g")) normalized.push("g");
  return normalized.join("");
}

export function analyzeRegex(pattern: string, flags: string, source: string, replacement: string): RegexAnalysis {
  if (!pattern.trim()) return { matches: [], replaced: source, error: "", flags: "" };
  try {
    const normalizedFlags = normalizeFlags(flags);
    const expression = new RegExp(pattern, normalizedFlags);
    const matches = Array.from(source.matchAll(expression)).slice(0, 1000).map((match, index) => {
      const start = match.index ?? 0;
      const value = match[0];
      const end = start + value.length;
      const line = source.slice(0, start).split(/\r\n|\r|\n/).length;
      return {
        order: index + 1,
        index: start,
        end,
        line,
        length: value.length,
        value,
        groups: match.slice(1).map((item) => item ?? ""),
        namedGroups: Object.fromEntries(Object.entries(match.groups ?? {}).map(([key, item]) => [key, item ?? ""])),
        context: source.slice(Math.max(0, start - 80), Math.min(source.length, end + 80)).replace(/\s+/g, " ").trim()
      };
    });
    return { matches, replaced: source.replace(expression, replacement), error: "", flags: normalizedFlags };
  } catch (error) {
    return { matches: [], replaced: source, error: error instanceof Error ? error.message : String(error), flags: "" };
  }
}

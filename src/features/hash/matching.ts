/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import type { BatchHashRow } from "../../models";

function normalizeExpectedHash(value: string) {
  const trimmed = value.trim();
  const extracted = trimmed.match(/\b[a-fA-F0-9]{32,128}\b/)?.[0] ?? trimmed;
  return extracted.replace(/\s+/g, "").toLowerCase();
}

export function parseExpectedHashSet(value: string) {
  const seen = new Set<string>();
  const rows: Array<{ hash: string; label: string }> = [];
  value.split(/\r?\n|[,;]/).forEach((line, index) => {
    const matches = line.match(/\b[a-fA-F0-9]{32,128}\b/g) ?? [];
    matches.forEach((match) => {
      const hash = match.toLowerCase();
      if (seen.has(hash)) return;
      seen.add(hash);
      const label = line
        .replace(match, "")
        .replace(/\b(?:md5|sha1|sha-?256|sha-?512|sha3|sm3)\b/gi, "")
        .replace(/^[\s:=,"\-]+|[\s:=,"\-]+$/g, "")
        .trim();
      rows.push({ hash, label: label || `target-${index + 1}` });
    });
  });
  if (!rows.length) {
    const normalized = normalizeExpectedHash(value);
    if (/^[a-f0-9]{32,128}$/.test(normalized)) rows.push({ hash: normalized, label: "target-1" });
  }
  return rows;
}

export function annotateBatchHashMatches(rows: BatchHashRow[], expectedHash: string) {
  const targets = parseExpectedHashSet(expectedHash);
  if (!targets.length) return rows.map((row) => ({ ...row, matched: undefined, matchedAlgorithms: [], matchedExpectedHashes: [], matchedExpectedLabels: [] }));
  const algorithms = ["md5", "sha1", "sha256", "sha512", "sha3", "sm3"] as const;
  return rows.map((row) => {
    const matchedTargets = targets.filter((target) => algorithms.some((algorithm) => (row[algorithm] ?? "").toLowerCase() === target.hash));
    const matchedAlgorithms = algorithms.filter((algorithm) => targets.some((target) => (row[algorithm] ?? "").toLowerCase() === target.hash));
    return {
      ...row,
      matched: matchedAlgorithms.length > 0,
      matchedAlgorithms,
      matchedExpectedHashes: matchedTargets.map((target) => target.hash),
      matchedExpectedLabels: matchedTargets.map((target) => target.label)
    };
  });
}

/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import type { CaseEvidenceFile } from "../../models";

export type EvidenceVerificationStatus = "match" | "mismatch" | "missing" | "unverified";

export type EvidenceVerificationRow = {
  registered: CaseEvidenceFile;
  uploaded?: CaseEvidenceFile;
  status: EvidenceVerificationStatus;
};

export type EvidenceVerificationResult = {
  rows: EvidenceVerificationRow[];
  unregisteredCount: number;
  matchedCount: number;
  mismatchCount: number;
  missingCount: number;
  unverifiedCount: number;
};

function fileNameKey(value: string) {
  return value.trim().replace(/^\*+/, "").replace(/\\/g, "/").split("/").pop()?.toLowerCase() ?? "";
}

function fileKey(file: CaseEvidenceFile) {
  return `${fileNameKey(file.name)}\u0000${file.size}\u0000${file.sha256 ?? ""}`;
}

export function verifyEvidenceRegister(registered: CaseEvidenceFile[], uploaded: CaseEvidenceFile[]): EvidenceVerificationResult {
  const byName = new Map<string, CaseEvidenceFile[]>();
  uploaded.forEach((file) => {
    const key = fileNameKey(file.name);
    const current = byName.get(key) ?? [];
    current.push(file);
    byName.set(key, current);
  });
  const used = new Set<string>();
  const rows = registered.map((item) => {
    const candidates = byName.get(fileNameKey(item.name)) ?? [];
    const candidate = candidates.find((file) => file.size === item.size && !used.has(fileKey(file))) ?? candidates.find((file) => !used.has(fileKey(file)));
    if (!candidate) return { registered: item, status: "missing" as const };
    used.add(fileKey(candidate));
    if (!item.sha256 || !candidate.sha256) return { registered: item, uploaded: candidate, status: "unverified" as const };
    return {
      registered: item,
      uploaded: candidate,
      status: item.size === candidate.size && item.sha256.toLowerCase() === candidate.sha256.toLowerCase() ? "match" as const : "mismatch" as const
    };
  });
  const matchedCount = rows.filter((row) => row.status === "match").length;
  const mismatchCount = rows.filter((row) => row.status === "mismatch").length;
  const missingCount = rows.filter((row) => row.status === "missing").length;
  const unverifiedCount = rows.filter((row) => row.status === "unverified").length;
  return {
    rows,
    unregisteredCount: uploaded.filter((file) => !used.has(fileKey(file))).length,
    matchedCount,
    mismatchCount,
    missingCount,
    unverifiedCount
  };
}

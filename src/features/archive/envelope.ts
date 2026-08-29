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

import { appVersion } from "../../config/app";
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisLimitation } from "../analysis/result";
import type { ZipDirectoryEntry } from "./zipDirectory";

export type ArchiveEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

export type ArchiveAnalysis = {
  name: string;
  size: number;
  kind: string;
  entries: ZipDirectoryEntry[];
  skipped: number;
};

const ENCRYPTED_ENTRY_CAP = 200;

function methodLabel(method: number) {
  if (method === 0) return "Stored";
  if (method === 8) return "Deflate";
  return String(method);
}

/**
 * Map a parsed archive (ZIP family) to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * The workbench reads only the central directory (no inflation), so the envelope
 * summarizes the entry map, flags encrypted entries, directory truncation, and
 * suspicious compression ratios (the zip-bomb guard signal).
 */
export function buildArchiveEnvelope(analysis: ArchiveAnalysis, meta: ArchiveEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const entries = analysis.entries ?? [];
  const fileCount = entries.filter((entry) => !entry.name.endsWith("/")).length;
  const dirCount = entries.filter((entry) => entry.name.endsWith("/")).length;
  const encryptedEntries = entries.filter((entry) => entry.encrypted);
  const totalUncompressed = entries.reduce((sum, entry) => sum + entry.uncompressed, 0);
  const totalCompressed = entries.reduce((sum, entry) => sum + entry.compressed, 0);
  const ratio = totalCompressed > 0 ? totalUncompressed / totalCompressed : totalUncompressed > 0 ? Number.POSITIVE_INFINITY : 0;

  const findings: AnalysisFinding[] = [];
  if (analysis.skipped > 0) {
    findings.push({
      level: "info",
      title: "Directory truncated",
      detail: `${analysis.skipped} declared central-directory entry/entries could not be listed (too many entries, Zip64, or a malformed archive).`,
      category: "archive-truncated",
      confidence: "high"
    });
  }
  if (encryptedEntries.length > 0) {
    findings.push({
      level: "warn",
      title: "Encrypted entries",
      detail: `${encryptedEntries.length} entry/entries are encrypted (general-purpose bit 0); content cannot be previewed without a password.`,
      category: "archive-encrypted",
      confidence: "high",
      review: true
    });
  }
  if (totalUncompressed > 0 && ratio > 500) {
    findings.push({
      level: "warn",
      title: "Suspicious compression ratio",
      detail: `Archive expands ${ratio > 1 ? ratio.toFixed(0) : ratio.toFixed(1)}:1 (${totalUncompressed.toLocaleString()} bytes uncompressed from ${totalCompressed.toLocaleString()}); review for zip-bomb behavior.`,
      category: "archive-zipbomb",
      confidence: "medium"
    });
  } else if (totalUncompressed > 0 && ratio > 100) {
    findings.push({
      level: "info",
      title: "High compression ratio",
      detail: `Archive expands ${ratio.toFixed(0)}:1 (${totalUncompressed.toLocaleString()} bytes uncompressed); benign for compressed payloads but worth noting.`,
      category: "archive-zipbomb",
      confidence: "low"
    });
  }

  const artifacts: AnalysisArtifact[] = [
    {
      id: "archive",
      label: `${analysis.name} · ${analysis.kind}`,
      kind: "archive",
      size: analysis.size,
      confidence: "high"
    },
    ...encryptedEntries.slice(0, ENCRYPTED_ENTRY_CAP).map((entry, index) => ({
      id: `encrypted-${index}`,
      label: entry.name,
      kind: "archive-encrypted-entry",
      size: entry.uncompressed,
      confidence: "high" as const
    }))
  ];

  const limitations: AnalysisLimitation[] = [
    { code: "ARCHIVE_DIRECTORY_ONLY", detail: "Only the ZIP central directory is parsed; entry content is not inflated unless explicitly extracted for preview." }
  ];

  const source: CaseEvidenceFile = {
    name: analysis.name,
    size: analysis.size,
    type: "application/zip",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `archive-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "archive", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { kind: analysis.kind } },
    summary: {
      title: "Archive (ZIP family) analysis",
      text: `${analysis.kind} container with ${entries.length.toLocaleString()} central-directory entries (${fileCount} files, ${dirCount} directories).`,
      metrics: [
        { label: "Type", value: analysis.kind },
        { label: "Size", value: `${analysis.size.toLocaleString()} B` },
        { label: "Entries", value: String(entries.length) },
        { label: "Files", value: String(fileCount) },
        { label: "Directories", value: String(dirCount) },
        { label: "Encrypted", value: String(encryptedEntries.length) },
        { label: "Uncompressed", value: totalUncompressed.toLocaleString() },
        { label: "Ratio", value: Number.isFinite(ratio) ? `${ratio.toFixed(1)}:1` : "∞" }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "archive.finding" })),
    indicators: [],
    artifacts,
    timeline: [],
    limitations,
    data: {
      name: analysis.name,
      size: analysis.size,
      kind: analysis.kind,
      entryCount: entries.length,
      fileCount,
      dirCount,
      encryptedCount: encryptedEntries.length,
      totalUncompressed,
      totalCompressed,
      skipped: analysis.skipped,
      compressionRatio: Number.isFinite(ratio) ? Number(ratio.toFixed(2)) : null
    }
  };
}

export { methodLabel };

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
import type { SqliteForensicAnalysis } from "./forensic";

export type SqliteEnvelopeMeta = {
  name: string;
  size: number;
  wal?: boolean;
  startedAt?: string;
  completedAt?: string;
};

/**
 * Map a SQLite forensic analysis to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * The envelope captures what matters for case reporting without copying the
 * full in-memory database: deleted-record recovery, WAL replay state, freelist
 * / fragment recovery, and the file header as metrics. Large worker output is
 * intentionally summarized in `data` so the result store stays bounded.
 */
export function buildSqliteEnvelope(analysis: SqliteForensicAnalysis, meta: SqliteEnvelopeMeta): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const header = analysis.header;
  const recoveredRecords = analysis.recoveredRecords ?? [];
  const recoveredCount = recoveredRecords.length;
  const fragmentCount = analysis.fragments.length;
  const walFrames = analysis.wal?.info.committedFrames ?? 0;
  const areas = Array.from(new Set(recoveredRecords.map((record) => record.area).filter(Boolean)));

  const findings: AnalysisFinding[] = [];
  if (recoveredCount > 0) {
    findings.push({
      level: "warn",
      title: "Deleted record recovery",
      detail: `${recoveredCount} record(s) recovered from ${areas.join(", ") || "free/unallocated"} space. Boundaries are reconstructed heuristically and must be verified before evidentiary use.`,
      category: "sqlite-recovery",
      confidence: "medium"
    });
  }
  if (analysis.wal) {
    findings.push({
      level: walFrames > 0 ? "warn" : "info",
      title: "WAL present",
      detail: walFrames > 0
        ? `WAL replayed with ${walFrames} committed frame(s); results reflect the post-commit database state.`
        : "WAL attached but no committed frames were applied to the main database.",
      category: "sqlite-wal",
      confidence: "high"
    });
  }
  if (analysis.walError) {
    findings.push({ level: "error", title: "WAL error", detail: analysis.walError, category: "sqlite-wal", confidence: "high" });
  }
  if (fragmentCount > 0) {
    findings.push({
      level: "info",
      title: "Recovered fragments",
      detail: `${fragmentCount} text fragment(s) recovered from free/unallocated space.`,
      category: "sqlite-fragments",
      confidence: "low"
    });
  }

  const artifacts: AnalysisArtifact[] = recoveredRecords.slice(0, 500).map((record, index) => ({
    id: `recovered-${index}`,
    label: `Recovered record · page ${record.pageNumber} · ${record.area}`,
    kind: "recovered-record",
    offset: record.offset,
    size: record.payloadSize,
    confidence: record.confidence
  }));

  const limitations: AnalysisLimitation[] = [
    { code: "SQLITE_MEMORY_LIMIT", detail: "Databases up to 256 MiB (320 MiB with WAL/SHM) are analyzed in memory; larger files are rejected by the workbench." }
  ];
  if (recoveredCount > 0) {
    limitations.push({
      code: "SQLITE_RECOVERY_HEURISTIC",
      detail: "Recovered records are reconstructed heuristically from freelist/freeblock/unallocated pages; verify offsets and content before evidentiary use."
    });
  }

  const source: CaseEvidenceFile = {
    name: meta.name,
    size: meta.size,
    type: "application/x-sqlite3",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `sqlite-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "sqlite", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { wal: Boolean(meta.wal) } },
    summary: {
      title: "SQLite forensic analysis",
      text: recoveredCount > 0
        ? `Recovered ${recoveredCount} deleted record(s); WAL ${walFrames > 0 ? `replayed (${walFrames} frames)` : analysis.wal ? "present, no committed frames" : "not attached"}.`
        : `No deleted records recovered${analysis.wal ? `; WAL ${walFrames > 0 ? `replayed (${walFrames} frames)` : "present, no committed frames"}` : ""}.`,
      metrics: [
        { label: "Page size", value: `${header.pageSize} B` },
        { label: "Pages", value: String(header.filePages) },
        { label: "Encoding", value: header.encoding },
        { label: "User version", value: String(header.userVersion) },
        { label: "Application id", value: `0x${header.applicationId.toString(16)}` },
        { label: "SQLite version", value: String(header.sqliteVersion) },
        { label: "Freelist pages", value: String(header.freelistPages) },
        { label: "Recovered records", value: String(recoveredCount) },
        { label: "WAL frames", value: String(walFrames) },
        { label: "Fragments", value: String(fragmentCount) }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "sqlite.finding" })),
    indicators: [],
    artifacts,
    timeline: [],
    limitations,
    data: {
      header,
      recoveredRecordCount: recoveredCount,
      recoveredAreas: areas,
      walFrames,
      fragmentCount,
      pageCount: analysis.pages.length
    }
  };
}

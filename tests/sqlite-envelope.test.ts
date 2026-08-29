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

import { describe, expect, it } from "vitest";
import { buildSqliteEnvelope } from "../src/features/sqlite/envelope";
import type { SqliteForensicAnalysis, SqliteRecoveredRecord } from "../src/features/sqlite/forensic";
import { currentAnalysisResult, analysisResultHistory, clearAnalysisResults, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeAnalysis(overrides: Partial<SqliteForensicAnalysis> = {}): SqliteForensicAnalysis {
  const base: SqliteForensicAnalysis = {
    header: {
      pageSize: 4096,
      filePages: 100,
      headerPages: 1,
      changeCounter: 5,
      schemaCookie: 3,
      schemaFormat: 4,
      freelistFirstPage: 0,
      freelistPages: 0,
      encoding: "UTF-8",
      userVersion: 12,
      applicationId: 0,
      sqliteVersion: 3034002
    },
    pages: [],
    fragments: [],
    recoveredRecords: [],
    wal: null,
    walError: null
  };
  return { ...base, ...overrides };
}

function makeRecovered(count: number): SqliteRecoveredRecord[] {
  return Array.from({ length: count }, (_, index) => ({
    pageNumber: index + 1,
    offset: index * 16,
    payloadOffset: index * 16 + 2,
    source: "main" as const,
    area: "freelist" as const,
    walFrame: null,
    recovery: "cell" as const,
    rowid: String(index),
    payloadSize: 64,
    columnCount: 3,
    values: [],
    confidence: "medium" as const
  }));
}

describe("buildSqliteEnvelope", () => {
  it("produces a schema-valid envelope for a clean database", () => {
    const envelope = buildSqliteEnvelope(makeAnalysis(), { name: "app.db", size: 409600 });
    expect(envelope.schemaVersion).toBe("1");
    expect(envelope.analyzer.id).toBe("sqlite");
    expect(envelope.source).toHaveLength(1);
    expect(envelope.source[0].name).toBe("app.db");
    expect(envelope.source[0].size).toBe(409600);
    expect(envelope.timeline).toHaveLength(0);
    expect(envelope.indicators).toHaveLength(0);
    expect(envelope.findings).toHaveLength(0);
    expect(envelope.data.recoveredRecordCount).toBe(0);
  });

  it("surfaces deleted-record recovery as a finding and artifacts", () => {
    const analysis = makeAnalysis({ recoveredRecords: makeRecovered(7) });
    const envelope = buildSqliteEnvelope(analysis, { name: "recovered.db", size: 8192 });
    const recovery = envelope.findings.find((finding) => finding.category === "sqlite-recovery");
    expect(recovery).toBeDefined();
    expect(recovery?.level).toBe("warn");
    expect(envelope.artifacts).toHaveLength(7);
    expect(envelope.artifacts[0].kind).toBe("recovered-record");
    expect(envelope.data.recoveredRecordCount).toBe(7);
    expect(envelope.limitations.some((item) => item.code === "SQLITE_RECOVERY_HEURISTIC")).toBe(true);
  });

  it("reports WAL replay state and errors", () => {
    const withWal = buildSqliteEnvelope(
      makeAnalysis({ wal: { info: { committedFrames: 9 } as never, frames: [], trailingBytes: 0 }, recoveredRecords: makeRecovered(2) }),
      { name: "wal.db", size: 1024 }
    );
    expect(withWal.findings.some((finding) => finding.title === "WAL present")).toBe(true);
    expect(withWal.summary.metrics.some((metric) => metric.label === "WAL frames" && metric.value === "9")).toBe(true);

    const withError = buildSqliteEnvelope(makeAnalysis({ walError: "checksum mismatch" }), { name: "bad.db", size: 512 });
    expect(withError.findings.some((finding) => finding.title === "WAL error" && finding.level === "error")).toBe(true);
  });

  it("caps recovered-record artifacts at 500", () => {
    const envelope = buildSqliteEnvelope(makeAnalysis({ recoveredRecords: makeRecovered(800) }), { name: "big.db", size: 1 });
    expect(envelope.artifacts).toHaveLength(500);
  });
});

describe("sqlite envelope result store integration", () => {
  it("groups runs per evidence identity and keeps history", () => {
    clearAnalysisResults();
    const a = buildSqliteEnvelope(makeAnalysis({ recoveredRecords: makeRecovered(3) }), { name: "a.db", size: 100 });
    const b = buildSqliteEnvelope(makeAnalysis({ recoveredRecords: makeRecovered(1) }), { name: "b.db", size: 200 });
    const aAgain = buildSqliteEnvelope(makeAnalysis({ recoveredRecords: makeRecovered(5) }), { name: "a.db", size: 100 });
    publishAnalysisResult("sqlite", a);
    publishAnalysisResult("sqlite", b);
    publishAnalysisResult("sqlite", aAgain);
    expect(currentAnalysisResult("sqlite")?.data.recoveredRecordCount).toBe(5);
    expect(analysisResultHistory("sqlite")).toHaveLength(3);
    clearAnalysisResults();
  });
});

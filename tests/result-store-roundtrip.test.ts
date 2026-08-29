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

import { beforeEach, describe, expect, it } from "vitest";
import {
  analysisResultHistory,
  analysisResultSnapshots,
  clearAnalysisResults,
  currentAnalysisResult,
  restoreAnalysisResultSnapshots,
  publishAnalysisResult,
  type AnalysisEnvelope,
  type AnalysisSource
} from "../src/features/analysis/resultStore";

function makeResult(toolId: "binary", source: AnalysisSource[], label: string): AnalysisEnvelope {
  return {
    schemaVersion: "1",
    id: `${toolId}-${label}`,
    analyzer: { id: toolId, version: "test" },
    source,
    run: { startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:00:01.000Z" },
    summary: { title: label, text: "" },
    findings: [],
    indicators: [],
    artifacts: [],
    timeline: [],
    limitations: [],
    data: null
  };
}

const evidence: AnalysisSource[] = [{ name: "a.bin", size: 10, type: "application/octet-stream", sha256: "a".repeat(64) }];
const key = `sha256:${"a".repeat(64)}`;

describe("result store — multi-run export / import (beta.6 §10)", () => {
  beforeEach(() => clearAnalysisResults());

  it("exports the full run history, not just the latest per tool", () => {
    publishAnalysisResult("binary", makeResult("binary", evidence, "r1"));
    publishAnalysisResult("binary", makeResult("binary", evidence, "r2"));
    publishAnalysisResult("binary", makeResult("binary", evidence, "r3"));
    const snapshots = analysisResultSnapshots();
    expect(snapshots).toHaveLength(3);
    expect(snapshots.every((row) => row.toolId === "binary")).toBe(true);
  });

  it("preserves runId and sequence across a case round-trip", () => {
    publishAnalysisResult("binary", makeResult("binary", evidence, "r1"));
    publishAnalysisResult("binary", makeResult("binary", evidence, "r2"));
    publishAnalysisResult("binary", makeResult("binary", evidence, "r3"));
    const snapshots = analysisResultSnapshots();

    clearAnalysisResults();
    expect(analysisResultHistory("binary")).toHaveLength(0);

    const restored = restoreAnalysisResultSnapshots(snapshots);
    expect(restored).toBe(3);

    const history = analysisResultHistory("binary");
    expect(history).toHaveLength(3);
    expect(history.map((r) => r.run.sequence)).toEqual([3, 2, 1]);
    expect(history.map((r) => r.run.runId)).toEqual([
      `${key}/binary#3`,
      `${key}/binary#2`,
      `${key}/binary#1`
    ]);
    // The most recent run remains current after restore.
    expect(currentAnalysisResult("binary")?.id).toBe("binary-r3");
  });

  it("keeps only the last MAX_HISTORY_PER_TOOL runs and documents the retention", () => {
    for (let i = 1; i <= 10; i += 1) {
      publishAnalysisResult("binary", makeResult("binary", evidence, `r${i}`));
    }
    const history = analysisResultHistory("binary");
    expect(history).toHaveLength(8);
    expect(history[0]?.run.sequence).toBe(10);
    expect(history[history.length - 1]?.run.sequence).toBe(3);
  });
});

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
import type { AnalysisEnvelope, AnalysisSource } from "../src/features/analysis/result";
import {
  analysisResultHistory,
  clearAnalysisHistory,
  clearAnalysisResult,
  clearAnalysisResults,
  currentAnalysisResult,
  currentAnalysisResults,
  publishAnalysisResult
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

const evidenceA: AnalysisSource[] = [{ name: "a.bin", size: 10, type: "application/octet-stream", sha256: "a".repeat(64) }];
const evidenceB: AnalysisSource[] = [{ name: "b.bin", size: 20, type: "application/octet-stream", sha256: "b".repeat(64) }];

describe("result store — evidence + run dimensions (beta.6 P0-4)", () => {
  beforeEach(() => clearAnalysisResults());

  it("keeps runs of different evidence separate instead of collapsing history", () => {
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "run-a"));
    publishAnalysisResult("binary", makeResult("binary", evidenceB, "run-b"));
    expect(currentAnalysisResult("binary")?.id).toBe("binary-run-b");
    expect(analysisResultHistory("binary")).toHaveLength(2);
  });

  it("numbers repeated runs of the same evidence and stamps a stable runId", () => {
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r1"));
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r2"));
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r3"));
    const history = analysisResultHistory("binary");
    expect(history).toHaveLength(3);
    expect(history.map((r) => r.run.sequence)).toEqual([3, 2, 1]);
    expect(history[0]?.run.runId).toBe(`sha256:${"a".repeat(64)}/binary#3`);
    expect(currentAnalysisResult("binary")?.run.sequence).toBe(3);
  });

  it("clearAnalysisResult drops the current but preserves run history", () => {
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r1"));
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r2"));
    clearAnalysisResult("binary");
    expect(currentAnalysisResult("binary")).toBeNull();
    expect(analysisResultHistory("binary")).toHaveLength(2);
  });

  it("clearAnalysisHistory retains the current result but empties history", () => {
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r1"));
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "r2"));
    clearAnalysisHistory("binary");
    expect(currentAnalysisResult("binary")?.id).toBe("binary-r2");
    expect(analysisResultHistory("binary")).toHaveLength(0);
  });

  it("currentAnalysisResults reflects only the latest per tool", () => {
    publishAnalysisResult("binary", makeResult("binary", evidenceA, "a"));
    publishAnalysisResult("binary", makeResult("binary", evidenceB, "b"));
    const latest = currentAnalysisResults().find((row) => row.toolId === "binary");
    expect(latest?.result.id).toBe("binary-b");
  });
});

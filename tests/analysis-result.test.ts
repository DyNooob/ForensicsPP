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
import { analysisResultText, type AnalysisEnvelope } from "../src/features/analysis/result";
import { clearAnalysisResult, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

describe("structured analysis result", () => {
  it("publishes a result independently from the rendered DOM", () => {
    const result: AnalysisEnvelope<{ value: number }> = {
      schemaVersion: "1",
      id: "test-result",
      analyzer: { id: "binary", version: "test" },
      source: [],
      run: { startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:00:01.000Z" },
      summary: { title: "Binary analysis", text: "One embedded object", metrics: [{ label: "Objects", value: "1" }] },
      findings: [{ level: "warn", title: "Embedded", detail: "ZIP at 0x20" }],
      indicators: [],
      artifacts: [{ id: "a1", label: "ZIP", kind: "embedded-file", offset: 32, size: 64 }],
      timeline: [],
      limitations: [],
      data: { value: 1 }
    };
    publishAnalysisResult("binary", result);
    expect(currentAnalysisResult("binary")?.id).toBe("test-result");
    expect(analysisResultText(result)).toContain("ZIP @ 0x20");
    clearAnalysisResult("binary");
    expect(currentAnalysisResult("binary")).toBeNull();
  });
});

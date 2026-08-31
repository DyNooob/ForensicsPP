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
import type { PlistValue } from "../src/features/plist/analyzer";
import { buildPlistEnvelope } from "../src/features/plist/envelope";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

// A literal PlistValue (parsed form) — exercises the envelope builder directly.
// The parser itself is covered by structured-browsers.test.ts.
const value: PlistValue = {
  LastUsedDate: new Date("2024-01-15T10:30:00Z"),
  BundleId: "com.example.app",
  LaunchCount: 7
};

describe("buildPlistEnvelope", () => {
  it("maps top-level entries to artifacts and an NSDate to a timeline event", () => {
    const envelope = buildPlistEnvelope({ format: "xml", value, name: "com.example.plist", size: 256 });
    expect(envelope.analyzer.id).toBe("plist");
    expect(envelope.artifacts.length).toBe(3);
    expect(envelope.artifacts.every((artifact) => artifact.kind === "plist-entry")).toBe(true);
    expect(envelope.timeline.length).toBe(1);
    expect(envelope.timeline[0].format).toBe("apple-nsdate");
    expect(envelope.timeline[0].context).toBe("$.LastUsedDate");
    expect(envelope.limitations.some((limitation) => limitation.code === "PLIST_GENERIC_PARSER")).toBe(true);
  });

  it("reports format and timestamp counts in the summary", () => {
    const envelope = buildPlistEnvelope({ format: "binary", value, name: "x.plist", size: 10 });
    expect(envelope.summary.metrics.some((metric) => metric.label === "Format" && metric.value === "BINARY")).toBe(true);
    expect(envelope.summary.metrics.some((metric) => metric.label === "Timestamps")).toBe(true);
  });

  it("publishes under the plist tool key with the analyzed source attached", () => {
    clearAnalysisResults();
    const envelope = buildPlistEnvelope({ format: "xml", value, name: "preferences.plist", size: 512 });
    expect(envelope.source[0].name).toBe("preferences.plist");
    publishAnalysisResult("plist", envelope);
    const stored = currentAnalysisResult("plist");
    expect(stored).not.toBeNull();
    expect(stored?.run.runId).toContain("/plist#");
    clearAnalysisResults();
  });
});

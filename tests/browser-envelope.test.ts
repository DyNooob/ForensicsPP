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
import { buildBrowserArtifactEnvelope } from "../src/features/browserArtifacts/envelope";
import type { BrowserArtifactAnalysis, BrowserArtifactRecord } from "../src/models";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeRecord(overrides: Partial<BrowserArtifactRecord> = {}): BrowserArtifactRecord {
  return {
    id: "r1",
    category: "visits",
    browser: "Chrome",
    profile: "Default",
    source: "History",
    time: "2026-01-02T03:04:05.000Z",
    primary: "https://example.com/page",
    secondary: "",
    detail: "",
    url: "https://example.com/page",
    path: "",
    recordId: "1",
    ...overrides
  };
}

function makeAnalysis(overrides: Partial<BrowserArtifactAnalysis> = {}): BrowserArtifactAnalysis {
  return {
    files: [{ path: "History", size: 1024, browser: "Chrome", profile: "Default", artifact: "History", records: 1, truncated: false, status: "parsed", detail: "" }],
    records: [makeRecord()],
    counts: { visits: 1, downloads: 0, cookies: 0, logins: 0, autofill: 0, extensions: 0 },
    browsers: ["Chrome"],
    profiles: ["Default"],
    firstTime: "2026-01-02T03:04:05.000Z",
    lastTime: "2026-01-03T03:04:05.000Z",
    ...overrides
  };
}

describe("buildBrowserArtifactEnvelope", () => {
  it("maps timestamped records to a CaseTimeline and visited URLs to indicators", () => {
    const analysis = makeAnalysis({ records: [makeRecord(), makeRecord({ id: "r2", url: "https://evil.example.ru/x", primary: "https://evil.example.ru/x" })] });
    const envelope = buildBrowserArtifactEnvelope(analysis);
    expect(envelope.timeline.length).toBe(2);
    expect(envelope.timeline[0].iso).toBe("2026-01-02T03:04:05.000Z");
    expect(envelope.indicators.filter((indicator) => indicator.type === "url").length).toBe(2);
    expect(envelope.findings.some((finding) => finding.title === "Browser data parsed")).toBe(true);
    expect(envelope.findings.every((finding) => finding.code)).toBe(true);
  });

  it("surfaces record truncation as a review finding and limitation", () => {
    const analysis = makeAnalysis({
      files: [
        { path: "History", size: 1024, browser: "Chrome", profile: "Default", artifact: "History", records: 50001, truncated: true, status: "parsed", detail: "limit" }
      ]
    });
    const envelope = buildBrowserArtifactEnvelope(analysis);
    const truncated = envelope.findings.find((finding) => finding.title === "Records truncated");
    expect(truncated?.level).toBe("warn");
    expect(truncated?.review).toBe(true);
    expect(envelope.limitations.some((item) => item.code === "BROWSER_SNAPSHOT_TRIMMED")).toBe(true);
  });

  it("publishes under the browserartifacts tool key across multiple source files", () => {
    clearAnalysisResults();
    const analysis = makeAnalysis({
      files: [
        { path: "History", size: 1024, browser: "Chrome", profile: "Default", artifact: "History", records: 1, truncated: false, status: "parsed", detail: "" },
        { path: "Cookies", size: 512, browser: "Chrome", profile: "Default", artifact: "Cookies", records: 1, truncated: false, status: "parsed", detail: "" }
      ]
    });
    const envelope = buildBrowserArtifactEnvelope(analysis);
    expect(envelope.source.length).toBe(2);
    publishAnalysisResult("browserartifacts", envelope);
    const stored = currentAnalysisResult("browserartifacts");
    expect(stored).not.toBeNull();
    expect(stored?.run.runId).toContain("/browserartifacts#");
    expect(stored?.run.sequence).toBe(1);
    clearAnalysisResults();
  });
});

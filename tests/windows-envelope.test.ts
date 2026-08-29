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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { describe, expect, it } from "vitest";
import { buildWindowsEnvelope } from "../src/features/windows/envelope";
import type { ExtractedStringRow, TimelineEvent, WindowsArtifactAnalysis, WindowsArtifactRecord } from "../src/models";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeEvent(overrides: Partial<TimelineEvent> = {}): TimelineEvent {
  return {
    id: "evt-1",
    iso: "2026-01-02T03:04:05.000Z",
    local: "1/2/2026 3:04:05 AM",
    raw: "20260102030405",
    format: "Windows FILETIME",
    line: 0,
    source: "evidence.lnk",
    context: "Target modified",
    ...overrides
  };
}

function makeString(overrides: Partial<ExtractedStringRow> = {}): ExtractedStringRow {
  return {
    id: "s1", offset: 0, encoding: "ASCII", length: 10, value: "C:\\Windows\\System32\\cmd.exe", detectedType: "Path", risk: [],
    ...overrides
  };
}

function makeRecord(overrides: Partial<WindowsArtifactRecord> = {}): WindowsArtifactRecord {
  return { id: "mft-5-1", kind: "MFT", fields: { Record: "5", State: "in-use" }, ...overrides };
}

function makeAnalysis(overrides: Partial<WindowsArtifactAnalysis> = {}): WindowsArtifactAnalysis {
  return {
    name: "evidence.lnk",
    size: 1024,
    artifactType: "Windows Shell Link (.lnk)",
    rows: [["Name", "evidence.lnk"]],
    timeline: [],
    strings: [],
    textPreview: "",
    ...overrides
  };
}

describe("buildWindowsEnvelope", () => {
  it("maps timeline events to CaseTimelineEvent and caps at 5000", () => {
    const events = Array.from({ length: 6000 }, (_, index) => makeEvent({ id: `evt-${index}`, iso: `2026-01-${String((index % 28) + 1).padStart(2, "0")}T00:00:00.000Z` }));
    const envelope = buildWindowsEnvelope(makeAnalysis({ timeline: events }));
    expect(envelope.timeline.length).toBeLessThanOrEqual(5000);
    expect(envelope.timeline[0].format).toBe("Windows FILETIME");
    expect(envelope.timeline[0].source).toBe("evidence.lnk");
    expect(envelope.limitations.some((item) => item.code === "WINDOWS_TIMELINE_TRIM")).toBe(true);
  });

  it("maps structured records to artifacts", () => {
    const envelope = buildWindowsEnvelope(makeAnalysis({
      artifactType: "NTFS $MFT",
      records: [makeRecord(), makeRecord({ id: "mft-6-1" })]
    }));
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "windows-record")).toHaveLength(2);
    expect(envelope.findings.some((finding) => finding.title === "Structured records parsed")).toBe(true);
  });

  it("extracts network indicators from classified strings", () => {
    const envelope = buildWindowsEnvelope(makeAnalysis({
      strings: [
        makeString({ value: "https://c2.example.io/beacon", detectedType: "URL" }),
        makeString({ value: "203.0.113.45", detectedType: "IPv4" }),
        makeString({ value: "admin@evil.example.ru", detectedType: "Email" }),
        makeString({ value: "C:\\Windows\\System32\\cmd.exe", detectedType: "Path" })
      ]
    }));
    const types = envelope.indicators.map((indicator) => indicator.type);
    expect(types).toContain("url");
    expect(types).toContain("ipv4");
    expect(types).toContain("email");
    expect(types).toContain("domain");
    expect(envelope.indicators.find((indicator) => indicator.type === "ipv4")?.value).toBe("203.0.113.45");
    expect(envelope.findings.some((finding) => finding.title === "Network indicators in strings" && finding.level === "warn")).toBe(true);
  });

  it("adds artifact-type forensic relevance findings", () => {
    const envelope = buildWindowsEnvelope(makeAnalysis({ artifactType: "Windows Prefetch (.pf)", timeline: [makeEvent()] }));
    expect(envelope.findings.some((finding) => finding.title === "Artifact: Windows Prefetch (.pf)")).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "Timeline parsed")).toBe(true);
  });
});

describe("windows envelope result store integration", () => {
  it("publishes under the windows tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("windows", buildWindowsEnvelope(makeAnalysis({ name: "a.lnk", size: 1 })));
    expect(currentAnalysisResult("windows")).not.toBeNull();
    clearAnalysisResults();
  });
});

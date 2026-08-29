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
import { buildEvtxEnvelope } from "../src/features/evtx/envelope";
import type { EvtxEvent, EvtxFileAnalysis } from "../src/features/evtx/analyzer";
import { currentAnalysisResult, analysisResultHistory, clearAnalysisResults, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeEvent(overrides: Partial<EvtxEvent> = {}): EvtxEvent {
  return {
    id: "1",
    source: "System",
    recordId: "1",
    timestamp: "2026-01-02T03:04:05.000Z",
    provider: "Microsoft-Windows-Security-Auditing",
    providerGuid: "{guid}",
    eventId: 4625,
    level: 2,
    levelName: "Error",
    channel: "Security",
    computer: "WIN-ABC",
    processId: "0",
    threadId: "0",
    userId: "S-1-5-18",
    task: "Logon",
    opcode: "Info",
    keywords: "0x0",
    data: {},
    message: "An account failed to log on.",
    xml: "<event/>",
    ...overrides
  };
}

function makeFile(overrides: Partial<EvtxFileAnalysis> = {}): EvtxFileAnalysis {
  return {
    source: "security.evtx",
    size: 1024,
    chunkCount: 1,
    nextRecordNumber: "10",
    dirty: false,
    full: true,
    version: "3.1",
    parsedRecords: 0,
    skippedRecords: 0,
    truncated: false,
    events: [],
    ...overrides
  };
}

describe("buildEvtxEnvelope", () => {
  it("maps events to timeline and summarizes the file", () => {
    const file = makeFile({
      events: [makeEvent({ recordId: "1", timestamp: "2026-01-01T00:00:00.000Z" }), makeEvent({ recordId: "2", timestamp: "2026-01-02T00:00:00.000Z" })]
    });
    const envelope = buildEvtxEnvelope(file);
    expect(envelope.schemaVersion).toBe("1");
    expect(envelope.analyzer.id).toBe("evtx");
    expect(envelope.source[0].name).toBe("security.evtx");
    expect(envelope.timeline).toHaveLength(2);
    expect(envelope.timeline[0].format).toBe("evtx");
    expect(envelope.timeline[0].source).toBe("security.evtx");
    expect(envelope.data.eventCount).toBe(2);
    expect(envelope.findings.some((finding) => finding.category === "evtx-severity")).toBe(true);
  });

  it("extracts IOC indicators from event content", () => {
    const file = makeFile({
      events: [
        makeEvent({ message: "Connection to https://c2.example.io/path from 203.0.113.45 succeeded." }),
        makeEvent({ message: "Resolved evil-domain.ru over DNS." })
      ]
    });
    const envelope = buildEvtxEnvelope(file);
    const types = envelope.indicators.map((indicator) => indicator.type);
    expect(types).toContain("url");
    expect(types).toContain("ipv4");
    expect(types).toContain("domain");
    expect(envelope.indicators.find((indicator) => indicator.type === "ipv4")?.value).toBe("203.0.113.45");
  });

  it("flags truncation and dirty state", () => {
    const truncated = buildEvtxEnvelope(makeFile({ truncated: true, events: [makeEvent()] }));
    expect(truncated.findings.some((finding) => finding.title === "Record limit reached")).toBe(true);
    expect(truncated.limitations.some((item) => item.code === "EVTX_TIMELINE_TRIM")).toBe(false);

    const dirty = buildEvtxEnvelope(makeFile({ dirty: true, full: false, events: [makeEvent()] }));
    expect(dirty.findings.some((finding) => finding.title === "Log not cleanly closed")).toBe(true);
  });

  it("trims the timeline to the per-file cap", () => {
    const events = Array.from({ length: 6000 }, (_, index) => makeEvent({ recordId: String(index + 1), timestamp: `2026-01-${String((index % 28) + 1).padStart(2, "0")}T00:00:00.000Z` }));
    const envelope = buildEvtxEnvelope(makeFile({ events }));
    expect(envelope.timeline.length).toBeLessThanOrEqual(5000);
    expect(envelope.limitations.some((item) => item.code === "EVTX_TIMELINE_TRIM")).toBe(true);
  });
});

describe("evtx envelope result store integration", () => {
  it("publishes per-file envelopes under a single tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("evtx", buildEvtxEnvelope(makeFile({ source: "security.evtx", events: [makeEvent()] })));
    publishAnalysisResult("evtx", buildEvtxEnvelope(makeFile({ source: "system.evtx", events: [makeEvent()] })));
    expect(currentAnalysisResult("evtx")).not.toBeNull();
    expect(analysisResultHistory("evtx")).toHaveLength(2);
    clearAnalysisResults();
  });
});

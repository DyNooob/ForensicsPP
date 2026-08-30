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
import { buildIocEnvelope } from "../src/features/ioc/envelope";
import type { IocAnalysis, IocRecord } from "../src/models";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeRecord(overrides: Partial<IocRecord> = {}): IocRecord {
  return {
    id: "i1",
    type: "url",
    value: "https://c2.example.io/beacon",
    normalized: "https://c2.example.io/beacon",
    line: 1,
    lines: [1],
    count: 3,
    context: "beacon callout",
    contexts: ["beacon callout"],
    defanged: "hxxps://c2.example.io/beacon",
    risk: [],
    ...overrides
  };
}

function makeAnalysis(overrides: Partial<IocAnalysis> = {}): IocAnalysis {
  const records = overrides.records ?? [makeRecord()];
  const grouped: Record<string, number> = {};
  for (const record of records) grouped[record.type] = (grouped[record.type] ?? 0) + 1;
  return {
    rows: [],
    records,
    findings: [],
    grouped,
    ...overrides
  };
}

describe("buildIocEnvelope", () => {
  it("maps each record to an indicator with stable codes", () => {
    const envelope = buildIocEnvelope(makeAnalysis({ records: [makeRecord(), makeRecord({ id: "i2", type: "ipv4", value: "203.0.113.45", normalized: "203.0.113.45" })] }));
    expect(envelope.indicators).toHaveLength(2);
    expect(envelope.indicators.map((indicator) => indicator.type)).toEqual(expect.arrayContaining(["url", "ipv4"]));
    expect(envelope.findings.every((finding) => finding.code)).toBe(true);
    expect(envelope.summary.metrics.some((metric) => metric.label === "Unique indicators")).toBe(true);
  });

  it("surfaces risk-flagged indicators as a review finding", () => {
    const envelope = buildIocEnvelope(makeAnalysis({ records: [makeRecord({ risk: ["malware"] })] }));
    const finding = envelope.findings.find((item) => item.title === "Risk-flagged indicators");
    expect(finding?.level).toBe("warn");
    expect(finding?.review).toBe(true);
  });

  it("publishes under the ioc tool key with the analyzed source attached", () => {
    clearAnalysisResults();
    const envelope = buildIocEnvelope(makeAnalysis(), { sourceName: "indicators.log", sourceSize: 256 });
    expect(envelope.source[0].name).toBe("indicators.log");
    publishAnalysisResult("ioc", envelope);
    const stored = currentAnalysisResult("ioc");
    expect(stored).not.toBeNull();
    expect(stored?.run.runId).toContain("/ioc#");
    clearAnalysisResults();
  });
});

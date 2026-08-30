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
import { buildEmailEnvelope } from "../src/features/email/envelope";
import type { EmailAnalysis } from "../src/models";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeAnalysis(overrides: Partial<EmailAnalysis> = {}): EmailAnalysis {
  return {
    rawSize: 4096,
    rows: [["From", "attacker@example.ru"], ["Subject", "Invoice"]],
    headers: [["From", "attacker@example.ru"], ["Subject", "Invoice"]],
    received: ["from a.example via b.example"],
    receivedHops: [{ index: 1, from: "mail.attacker.example", by: "mx.victim.example", ip: "203.0.113.45", date: "2026-01-02T03:04:05.000Z", raw: "Received: ...", risk: [] }],
    attachments: [{ filename: "invoice.exe", contentType: "application/x-msdownload", size: 1024, extension: "exe", signature: "", content: new Uint8Array([0x4d, 0x5a]) }],
    authAssessments: [{ mechanism: "spf", result: "pass", domain: "example.ru", aligned: "yes", source: "example.ru", verdict: "pass" }],
    bodyText: "please open the invoice",
    bodyHtml: "<p>please open the invoice</p>",
    ...overrides
  };
}

describe("buildEmailEnvelope", () => {
  it("builds a routing timeline and extracts relay IP indicators", () => {
    const envelope = buildEmailEnvelope(makeAnalysis());
    expect(envelope.timeline).toHaveLength(1);
    expect(envelope.timeline[0].iso).toBe("2026-01-02T03:04:05.000Z");
    expect(envelope.indicators.some((indicator) => indicator.type === "ipv4" && indicator.value === "203.0.113.45")).toBe(true);
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "email-attachment")).toHaveLength(1);
  });

  it("flags authentication failure and risky hops as review findings", () => {
    const envelope = buildEmailEnvelope(makeAnalysis({
      authAssessments: [{ mechanism: "dkim", result: "fail", domain: "example.ru", aligned: "no", source: "example.ru", verdict: "fail" }],
      receivedHops: [{ index: 1, from: "x", by: "y", ip: "198.51.100.7", date: "2026-01-02T03:04:05.000Z", raw: "r", risk: ["spoofed"] }]
    }));
    expect(envelope.findings.some((finding) => finding.title === "Authentication check failed" && finding.review)).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "Risky routing hop" && finding.review)).toBe(true);
  });

  it("publishes under the email tool key with format in run parameters", () => {
    clearAnalysisResults();
    publishAnalysisResult("email", buildEmailEnvelope(makeAnalysis(), { sourceName: "phish.eml", sourceSize: 4096, format: "eml" }));
    const stored = currentAnalysisResult("email");
    expect(stored).not.toBeNull();
    expect(stored?.run.parameters?.format).toBe("eml");
    expect(stored?.run.sequence).toBe(1);
    clearAnalysisResults();
  });
});

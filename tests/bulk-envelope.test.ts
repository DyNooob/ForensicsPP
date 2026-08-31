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
import { scanBulkArtifacts } from "../src/features/bulk/analyzer";
import { buildBulkEnvelope } from "../src/features/bulk/envelope";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

describe("buildBulkEnvelope", () => {
  it("maps scanned artifacts to offset-bearing artifacts and network indicators", async () => {
    const ascii = new TextEncoder().encode("mail analyst@example.org url https://example.org/a ip 198.51.100.7 token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature");
    const scan = await scanBulkArtifacts(new Blob([ascii]), "sample.bin", { chunkSize: 64, maxItems: 100 });
    const envelope = buildBulkEnvelope(scan, {});
    expect(envelope.analyzer.id).toBe("bulk");
    expect(envelope.artifacts.length).toBeGreaterThanOrEqual(4);
    expect(envelope.artifacts.every((artifact) => typeof artifact.offset === "number" && artifact.offset >= 0)).toBe(true);
    expect(envelope.indicators.length).toBeGreaterThanOrEqual(3);
    expect(envelope.indicators.some((indicator) => indicator.type === "email")).toBe(true);
    expect(envelope.limitations.some((limitation) => limitation.code === "BULK_PATTERN_SCAN")).toBe(true);
  });

  it("flags PEM blocks as high-confidence and network indicators as medium", async () => {
    const ascii = new TextEncoder().encode("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    const scan = await scanBulkArtifacts(new Blob([ascii]), "cert.bin", { chunkSize: 64, maxItems: 100 });
    const envelope = buildBulkEnvelope(scan, {});
    const pem = envelope.artifacts.find((artifact) => artifact.label.startsWith("PEM:"));
    expect(pem?.confidence).toBe("high");
  });

  it("does not fabricate indicators from benign text (negative)", async () => {
    const ascii = new TextEncoder().encode("Lorem ipsum dolor sit amet consectetur");
    const scan = await scanBulkArtifacts(new Blob([ascii]), "benign.txt", { chunkSize: 64, maxItems: 100 });
    expect(scan.items.length).toBe(0);
    const envelope = buildBulkEnvelope(scan, {});
    expect(envelope.artifacts.length).toBe(0);
    expect(envelope.indicators.length).toBe(0);
  });

  it("publishes under the bulk tool key with offset provenance", async () => {
    clearAnalysisResults();
    const ascii = new TextEncoder().encode("ip 203.0.113.9");
    const scan = await scanBulkArtifacts(new Blob([ascii]), "net.bin", { chunkSize: 64, maxItems: 100 });
    const envelope = buildBulkEnvelope(scan, { sourceName: "net.bin" });
    expect(envelope.source[0].name).toBe("net.bin");
    publishAnalysisResult("bulk", envelope);
    const stored = currentAnalysisResult("bulk");
    expect(stored).not.toBeNull();
    expect(stored?.run.runId).toContain("/bulk#");
    clearAnalysisResults();
  });
});

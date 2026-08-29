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
import { buildArchiveEnvelope, type ArchiveAnalysis } from "../src/features/archive/envelope";
import type { ZipDirectoryEntry } from "../src/features/archive/zipDirectory";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeEntry(overrides: Partial<ZipDirectoryEntry> = {}): ZipDirectoryEntry {
  return { name: "file.txt", method: 8, compressed: 10, uncompressed: 100, encrypted: false, ...overrides };
}

function makeAnalysis(overrides: Partial<ArchiveAnalysis> = {}): ArchiveAnalysis {
  return {
    name: "sample.zip",
    size: 2048,
    kind: "ZIP",
    entries: [makeEntry()],
    skipped: 0,
    ...overrides
  };
}

describe("buildArchiveEnvelope", () => {
  it("summarizes a clean archive without risky findings", () => {
    const envelope = buildArchiveEnvelope(makeAnalysis({
      entries: [makeEntry({ name: "a.txt" }), makeEntry({ name: "dir/", uncompressed: 0 })]
    }));
    expect(envelope.schemaVersion).toBe("1");
    expect(envelope.analyzer.id).toBe("archive");
    expect(envelope.summary.metrics.some((metric) => metric.label === "Files" && metric.value === "1")).toBe(true);
    expect(envelope.summary.metrics.some((metric) => metric.label === "Directories" && metric.value === "1")).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "Encrypted entries")).toBe(false);
    expect(envelope.findings.some((finding) => finding.title === "Directory truncated")).toBe(false);
    expect(envelope.source[0].name).toBe("sample.zip");
  });

  it("flags encrypted entries as a warning and lists them as artifacts", () => {
    const envelope = buildArchiveEnvelope(makeAnalysis({
      entries: [makeEntry({ name: "secret.bin", encrypted: true }), makeEntry({ name: "ok.txt" })]
    }));
    expect(envelope.findings.some((finding) => finding.title === "Encrypted entries" && finding.level === "warn")).toBe(true);
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "archive-encrypted-entry")).toHaveLength(1);
  });

  it("flags directory truncation when entries are skipped", () => {
    const envelope = buildArchiveEnvelope(makeAnalysis({ skipped: 12 }));
    expect(envelope.findings.some((finding) => finding.title === "Directory truncated")).toBe(true);
  });

  it("warns on a suspicious compression ratio", () => {
    const envelope = buildArchiveEnvelope(makeAnalysis({
      entries: [makeEntry({ compressed: 1, uncompressed: 5000 })]
    }));
    expect(envelope.findings.some((finding) => finding.title === "Suspicious compression ratio")).toBe(true);
  });
});

describe("archive envelope result store integration", () => {
  it("publishes under the archive tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("archive", buildArchiveEnvelope(makeAnalysis({ name: "a.zip", size: 1 })));
    expect(currentAnalysisResult("archive")).not.toBeNull();
    clearAnalysisResults();
  });
});

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
import { buildDiskImageEnvelope } from "../src/features/disk/envelope";
import type { DiskAnalysis, DiskPartition } from "../src/features/disk/analyzer";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makePartition(overrides: Partial<DiskPartition> = {}): DiskPartition {
  return {
    index: 0,
    scheme: "MBR",
    type: "0x83",
    typeCode: "0x83",
    name: "Linux",
    bootable: false,
    startLba: 0,
    sectors: 100,
    startOffset: 0,
    size: 51200,
    filesystem: "ext4",
    rows: [],
    entries: [],
    ...overrides
  };
}

function makeAnalysis(overrides: Partial<DiskAnalysis> = {}): DiskAnalysis {
  return {
    name: "disk.dd",
    size: 51200,
    sectorSize: 512,
    scheme: "MBR",
    rows: [],
    partitions: [],
    warnings: [],
    ...overrides
  };
}

describe("buildDiskImageEnvelope", () => {
  it("summarizes a partition map without deleted entries", () => {
    const analysis = makeAnalysis({ partitions: [makePartition({ name: "Linux", filesystem: "ext4" })] });
    const envelope = buildDiskImageEnvelope(analysis);
    expect(envelope.schemaVersion).toBe("1");
    expect(envelope.analyzer.id).toBe("disk");
    expect(envelope.summary.metrics.some((metric) => metric.label === "Partitions" && metric.value === "1")).toBe(true);
    expect(envelope.artifacts.some((artifact) => artifact.kind === "partition")).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "Deleted entries found")).toBe(false);
  });

  it("surfaces deleted entries as a finding and artifacts", () => {
    const analysis = makeAnalysis({
      partitions: [makePartition({
        entries: [
          { name: "secret.txt", kind: "file", size: 128, cluster: 5, deleted: true },
          { name: "keep.txt", kind: "file", size: 64, cluster: 6, deleted: false }
        ]
      })]
    });
    const envelope = buildDiskImageEnvelope(analysis);
    expect(envelope.findings.some((finding) => finding.title === "Deleted entries found")).toBe(true);
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "deleted-entry")).toHaveLength(1);
  });

  it("maps warnings to findings", () => {
    const envelope = buildDiskImageEnvelope(makeAnalysis({ warnings: ["Sector size unusual"] }));
    expect(envelope.findings.some((finding) => finding.title === "Disk analysis warning")).toBe(true);
  });
});

describe("disk envelope result store integration", () => {
  it("publishes under the disk tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("disk", buildDiskImageEnvelope(makeAnalysis({ name: "a.dd", size: 1 })));
    expect(currentAnalysisResult("disk")).not.toBeNull();
    clearAnalysisResults();
  });
});

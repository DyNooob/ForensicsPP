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
import { parseRegistryHive } from "../src/features/registry/analyzer";
import { buildRegistryEnvelope } from "../src/features/registry/envelope";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

// Minimal valid regf/hbin hive: a ROOT key with one REG_DWORD value "Test".
function makeHive(sequence2 = 1, lastWriteTicks?: bigint) {
  const bytes = new Uint8Array(0x2000);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("regf"));
  view.setUint32(0x04, 1, true);
  view.setUint32(0x08, sequence2, true);
  view.setUint32(0x14, 1, true);
  view.setUint32(0x18, 5, true);
  view.setUint32(0x1c, 0, true);
  view.setUint32(0x20, 1, true);
  view.setUint32(0x24, 0x20, true);
  view.setUint32(0x28, 0x1000, true);
  bytes.set(new TextEncoder().encode("hbin"), 0x1000);
  view.setUint32(0x1004, 0, true);
  view.setUint32(0x1008, 0x1000, true);
  const root = 0x1020;
  view.setInt32(root, -0x80, true);
  bytes.set(new TextEncoder().encode("nk"), root + 4);
  view.setUint16(root + 6, 0x20, true);
  view.setUint32(root + 4 + 28, 0xffffffff, true);
  view.setUint32(root + 4 + 36, 1, true);
  view.setUint32(root + 4 + 40, 0xa0, true);
  view.setUint16(root + 4 + 72, 4, true);
  bytes.set(new TextEncoder().encode("ROOT"), root + 4 + 76);
  if (lastWriteTicks !== undefined) view.setBigUint64(root + 4 + 4, lastWriteTicks, true);
  const valueList = 0x10a0;
  view.setInt32(valueList, -0x10, true);
  view.setUint32(valueList + 4, 0xb0, true);
  const value = 0x10b0;
  view.setInt32(value, -0x28, true);
  bytes.set(new TextEncoder().encode("vk"), value + 4);
  view.setUint16(value + 6, 4, true);
  view.setUint32(value + 8, 0x80000004, true);
  view.setUint32(value + 12, 42, true);
  view.setUint32(value + 16, 4, true);
  view.setUint16(value + 20, 1, true);
  bytes.set(new TextEncoder().encode("Test"), value + 24);
  let headerChecksum = 0;
  for (let offset = 0; offset < 0x1fc; offset += 4) headerChecksum = (headerChecksum ^ view.getUint32(offset, true)) >>> 0;
  view.setUint32(0x1fc, headerChecksum, true);
  return bytes;
}

describe("buildRegistryEnvelope", () => {
  it("maps a parsed hive to findings, key-path artifacts, and logical-location limitations", () => {
    const hive = parseRegistryHive(makeHive());
    const envelope = buildRegistryEnvelope(hive, { sourceName: "NTUSER.DAT", sourceSize: 8192 });
    expect(envelope.analyzer.id).toBe("registry");
    expect(envelope.findings.some((finding) => finding.category === "registry-structure")).toBe(true);
    expect(envelope.artifacts.length).toBeGreaterThanOrEqual(1);
    expect(envelope.artifacts.every((artifact) => artifact.kind === "registry-key" && artifact.label.length > 0)).toBe(true);
    expect(envelope.indicators).toEqual([]);
    expect(envelope.limitations.some((limitation) => limitation.code === "REGISTRY_LOGICAL_LOCATION")).toBe(true);
    expect(envelope.summary.metrics.some((metric) => metric.label === "Keys")).toBe(true);
  });

  it("surfaces a dirty hive as a review finding", () => {
    const hive = parseRegistryHive(makeHive(2));
    const envelope = buildRegistryEnvelope(hive, {});
    expect(hive.dirty).toBe(true);
    const finding = envelope.findings.find((item) => item.category === "registry-dirty");
    expect(finding?.level).toBe("warn");
    expect(finding?.review).toBe(true);
    expect(envelope.limitations.some((limitation) => limitation.code === "REGISTRY_TRANSACTION_LOG")).toBe(true);
  });

  it("emits a timeline event from a valid key lastWrite timestamp", () => {
    const ticks = 133485408000000000n; // ~2024-01-01 UTC
    const hive = parseRegistryHive(makeHive(1, ticks));
    const envelope = buildRegistryEnvelope(hive, {});
    expect(envelope.timeline.length).toBe(1);
    expect(envelope.timeline[0].format).toBe("windows-registry-lastWrite");
    expect(envelope.timeline[0].epochMs).toBeGreaterThan(0);
  });

  it("publishes under the registry tool key with the analyzed source attached", () => {
    clearAnalysisResults();
    const hive = parseRegistryHive(makeHive());
    const envelope = buildRegistryEnvelope(hive, { sourceName: "SOFTWARE", sourceSize: 4096 });
    expect(envelope.source[0].name).toBe("SOFTWARE");
    publishAnalysisResult("registry", envelope);
    const stored = currentAnalysisResult("registry");
    expect(stored).not.toBeNull();
    expect(stored?.run.runId).toContain("/registry#");
    clearAnalysisResults();
  });
});

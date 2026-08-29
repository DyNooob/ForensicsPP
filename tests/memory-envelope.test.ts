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
import { buildMemoryEnvelope } from "../src/features/memory/envelope";
import type { MemoryTriage } from "../src/features/memory/analyzer";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeTriage(overrides: Partial<MemoryTriage> = {}): MemoryTriage {
  return {
    name: "dump.dmp",
    size: 1024,
    format: "Windows Minidump",
    rows: [],
    modules: [],
    peHits: [],
    warnings: ["Memory triage parses Minidump metadata and performs bounded PE-header discovery; it is not a Volatility-compatible kernel object parser."],
    ...overrides
  };
}

describe("buildMemoryEnvelope", () => {
  it("reports scope warning for a clean minidump", () => {
    const envelope = buildMemoryEnvelope(makeTriage());
    expect(envelope.analyzer.id).toBe("memory");
    expect(envelope.findings.some((finding) => finding.category === "memory-scope")).toBe(true);
    expect(envelope.summary.metrics.some((metric) => metric.label === "PE headers" && metric.value === "0")).toBe(true);
  });

  it("flags discovered PE headers and maps them to artifacts", () => {
    const envelope = buildMemoryEnvelope(makeTriage({
      peHits: [
        { offset: 4096, peOffset: 4096, machine: "x64", sections: 5 },
        { offset: 8192, peOffset: 8192, machine: "x86", sections: 3 }
      ]
    }));
    expect(envelope.findings.some((finding) => finding.title === "PE headers discovered")).toBe(true);
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "pe-header")).toHaveLength(2);
    expect(envelope.data.peHitCount).toBe(2);
  });

  it("lists loaded modules", () => {
    const envelope = buildMemoryEnvelope(makeTriage({ modules: [{ base: "0x1000", size: 4096, timestamp: "2026", name: "ntdll.dll" }] }));
    expect(envelope.findings.some((finding) => finding.title === "Loaded modules")).toBe(true);
    expect(envelope.data.moduleCount).toBe(1);
  });
});

describe("memory envelope result store integration", () => {
  it("publishes under the memory tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("memory", buildMemoryEnvelope(makeTriage({ name: "x.dmp", size: 2 })));
    expect(currentAnalysisResult("memory")).not.toBeNull();
    clearAnalysisResults();
  });
});

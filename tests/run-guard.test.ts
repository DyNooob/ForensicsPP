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

import { beforeEach, describe, expect, it } from "vitest";
import { createRunGuard } from "../src/core/runtime/runGuard";
import {
  clearAnalysisResults,
  currentAnalysisResult,
  publishAnalysisResult,
  type AnalysisEnvelope,
  type AnalysisSource
} from "../src/features/analysis/resultStore";

function makeEnvelope(toolId: "disk", source: AnalysisSource[], label: string): AnalysisEnvelope {
  return {
    schemaVersion: "1",
    id: `${toolId}-${label}`,
    analyzer: { id: toolId, version: "test" },
    source,
    run: { startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:00:01.000Z" },
    summary: { title: label, text: "" },
    findings: [],
    indicators: [],
    artifacts: [],
    timeline: [],
    limitations: [],
    data: null
  };
}

const evidence: AnalysisSource[] = [{ name: "x.bin", size: 1, type: "application/octet-stream", sha256: "f".repeat(64) }];

describe("run guard (beta.6 §11 stale-run race)", () => {
  it("commit runs the side effect only for the current, active run", () => {
    const active = { value: true };
    const guard = createRunGuard(() => active.value);
    const id = guard.next();
    expect(guard.current()).toBe(id);
    expect(guard.isCurrent(id)).toBe(true);
    let ran = 0;
    expect(guard.commit(id, () => {
      ran += 1;
      return 7;
    })).toBe(7);
    expect(ran).toBe(1);
  });

  it("drops a superseded run's publish (R1 late-complete cannot overwrite R2)", () => {
    const guard = createRunGuard(() => true);
    const r1 = guard.next();
    const r2 = guard.next();
    expect(guard.isCurrent(r1)).toBe(false);
    expect(guard.isCurrent(r2)).toBe(true);
    let published = 0;
    // R1 finishes late and tries to publish — must be dropped.
    expect(guard.commit(r1, () => { published += 1; })).toBeUndefined();
    expect(published).toBe(0);
    // R2 still publishes.
    expect(guard.commit(r2, () => { published += 1; })).toBeUndefined();
    expect(published).toBe(1);
  });

  it("discards a late result/error when the tool is no longer active", () => {
    const active = { value: false };
    const guard = createRunGuard(() => active.value);
    const id = guard.next();
    expect(guard.isCurrent(id)).toBe(false);
    let ran = 0;
    expect(guard.commit(id, () => { ran += 1; })).toBeUndefined();
    expect(ran).toBe(0);
  });

  it("current() reflects the latest request id", () => {
    const guard = createRunGuard(() => true);
    expect(guard.current()).toBe(0);
    const a = guard.next();
    expect(guard.current()).toBe(a);
    const b = guard.next();
    expect(guard.current()).toBe(b);
  });
});

describe("stale-run contract at the result store (beta.6 §11)", () => {
  beforeEach(() => clearAnalysisResults());

  it("a superseded run cannot overwrite the current published result", () => {
    const guard = createRunGuard(() => true);
    const r1 = guard.next();
    const r2 = guard.next();
    // R2 publishes first and becomes the current result.
    guard.commit(r2, () => publishAnalysisResult("disk", makeEnvelope("disk", evidence, "r2")));
    // R1 late-completes and attempts to publish — dropped, current unchanged.
    guard.commit(r1, () => publishAnalysisResult("disk", makeEnvelope("disk", evidence, "r1")));
    expect(currentAnalysisResult("disk")?.id).toBe("disk-r2");
  });
});

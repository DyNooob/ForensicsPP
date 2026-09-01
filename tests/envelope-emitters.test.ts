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

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { tools } from "../src/config/app";

/**
 * Acceptance gate for structured results. `emitsEnvelope: true` is the single
 * source of truth for "this tool publishes a canonical AnalysisEnvelope". If a
 * tool claims it but never calls `publishAnalysisResult`, the Reporter / Case
 * export will silently receive nothing for that tool — a structural gap that
 * no per-tool test would catch. This contract test fails the moment a tool
 * declares `emitsEnvelope` without actually publishing.
 */
describe("envelope emitters stay in sync with publishing", () => {
  const emitters = tools
    .filter((tool) => tool.emitsEnvelope && !tool.hidden)
    .map((tool) => tool.id);

  const publishers = new Set<string>();
  const toolsDir = join(__dirname, "..", "src", "tools");
  for (const file of readdirSync(toolsDir)) {
    if (!/\.tsx?$/.test(file)) continue;
    const source = readFileSync(join(toolsDir, file), "utf8");
    const pattern = /publishAnalysisResult\(\s*["']([\w-]+)["']/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(source)) !== null) {
      publishers.add(match[1]);
    }
  }

  it("every declared envelope emitter actually publishes", () => {
    expect(emitters.length).toBeGreaterThan(0);
    for (const id of emitters) {
      expect(
        publishers.has(id),
        `config sets emitsEnvelope for "${id}" but no tool calls publishAnalysisResult("${id}")`
      ).toBe(true);
    }
  });

  it("every tool that publishes is declared as an envelope emitter", () => {
    for (const id of publishers) {
      const def = tools.find((tool) => tool.id === id);
      expect(
        def?.emitsEnvelope,
        `tool calls publishAnalysisResult("${id}") but config does not set emitsEnvelope`
      ).toBe(true);
    }
  });
});

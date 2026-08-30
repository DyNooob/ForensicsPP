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
import { tools, visibleTools, getToolDefinitionById, type ToolDefinition } from "../src/config/app";

const TIERS = ["workbench", "utility", "featured"] as const;
const MATURITIES = ["validated", "stable", "triage", "experimental"] as const;

describe("tool registry hierarchy (beta.6)", () => {
  it("every tool declares a tier and a maturity", () => {
    for (const tool of tools) {
      expect(tool.tier, `${tool.id} should declare a tier`).toBeDefined();
      expect(TIERS, `${tool.id} tier must be valid`).toContain(tool.tier);
      expect(tool.maturity, `${tool.id} should declare a maturity`).toBeDefined();
      expect(MATURITIES, `${tool.id} maturity must be valid`).toContain(tool.maturity);
    }
  });

  it("every visible tool declares a tier and a maturity", () => {
    for (const tool of visibleTools) {
      expect(tool.tier).toBeDefined();
      expect(tool.maturity).toBeDefined();
    }
  });

  it("hidden tools inherit the tier of the tool they merge into", () => {
    for (const tool of tools) {
      if (!tool.hidden || !tool.mergedInto) continue;
      const parent = getToolDefinitionById(tool.mergedInto);
      expect(parent, `${tool.id} mergedInto ${tool.mergedInto} must exist`).not.toBeNull();
      expect(tool.tier, `${tool.id} tier should match ${tool.mergedInto}`).toBe(parent?.tier);
    }
  });

  it("tier values are consistent with the workbench/utility split", () => {
    const workbenches = tools.filter((tool) => tool.tier === "workbench");
    const utilities = tools.filter((tool) => tool.tier === "utility");
    // Deep forensic analyzers must be workbenches, not level with utilities.
    expect(workbenches.length).toBeGreaterThan(utilities.length);
    for (const tool of workbenches as ToolDefinition[]) {
      // Hidden aliases inherit their parent's surface; skip them here.
      if (tool.hidden) continue;
      // A workbench should take evidence or expose an analyzer surface.
      const isAnalyzer =
        tool.supportsEvidence ||
        tool.supportsResult ||
        tool.heavy ||
        (tool.capabilities?.length ?? 0) > 0 ||
        (tool.accepts?.length ?? 0) > 0;
      expect(isAnalyzer, `${tool.id} claims workbench but exposes no analyzer surface`).toBe(true);
    }
  });
});

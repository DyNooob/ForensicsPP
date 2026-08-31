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
import {
  tools,
  visibleTools,
  getToolDefinitionById,
  canonicalForensicAnalyzers,
  type ToolDefinition
} from "../src/config/app";

const CATEGORIES = ["analysis", "transform", "network", "system", "integration"] as const;
const MATURITIES = ["stable", "triage", "experimental"] as const;
const VALIDATIONS = ["unvalidated", "unit-tested", "fixture-validated", "cross-validated"] as const;

// The 18 canonical forensic analyzers that genuinely publish a structured
// AnalysisEnvelope (verified by grepping `publishAnalysisResult` calls in
// src/tools). `bulk` sets supportsResult:false but DOES publish an envelope, so it
// is included; its envelope carries real byte-offset provenance for scanned artifacts.
const EXPECTED_ENVELOPE_EMITTERS = [
  "android",
  "archive",
  "disk",
  "documentforensics",
  "email",
  "evtx",
  "image",
  "ioc",
  "memory",
  "sqlite",
  "windows",
  "browserartifacts",
  "binary",
  "firmware",
  "pcap",
  "registry",
  "plist",
  "bulk"
];

describe("tool registry metadata model (beta.6 correction)", () => {
  it("category is an orthogonal semantic domain and never 'featured'", () => {
    for (const tool of tools) {
      expect(CATEGORIES, `${tool.id} category must be a valid domain`).toContain(tool.category);
      expect(tool.category, `${tool.id} must not use 'featured' as a category`).not.toBe("featured");
    }
  });

  it("home is a system/launcher tool, not a forensic workbench", () => {
    const home = getToolDefinitionById("home");
    expect(home?.category, "home must be classified as system").toBe("system");
    expect(canonicalForensicAnalyzers().some((t) => t.id === "home"), "home must not count as a forensic analyzer").toBe(false);
  });

  it("cyberchef is expressed as an external/integration tool, not a forensic workbench", () => {
    const cyberchef = getToolDefinitionById("cyberchef");
    expect(cyberchef?.category, "cyberchef must be classified as integration").toBe("integration");
    expect(canonicalForensicAnalyzers().some((t) => t.id === "cyberchef"), "cyberchef must not count as a forensic analyzer").toBe(false);
  });

  it("featured is a boolean display flag orthogonal to category", () => {
    const home = getToolDefinitionById("home");
    const cyberchef = getToolDefinitionById("cyberchef");
    expect(home?.featured, "home is a featured launcher").toBe(true);
    expect(cyberchef?.featured, "cyberchef is a featured suite").toBe(true);
    for (const tool of tools) {
      if (tool.featured !== undefined) expect(typeof tool.featured, `${tool.id} featured must be boolean`).toBe("boolean");
    }
    // A non-featured forensic analyzer is still an analyzer — featured is not a tier.
    const image = getToolDefinitionById("image");
    expect(image?.featured, "image is not featured").not.toBe(true);
    expect(canonicalForensicAnalyzers().some((t) => t.id === "image"), "image is still a forensic analyzer").toBe(true);
  });

  it("hidden aliases are excluded from counts and inherit their parent category", () => {
    const hidden = tools.filter((t) => t.hidden);
    expect(hidden.length, "there must be hidden alias tools").toBeGreaterThan(0);
    for (const tool of hidden) {
      expect(tool.mergedInto, `${tool.id} hidden alias must declare mergedInto`).toBeDefined();
      const parent = getToolDefinitionById(tool.mergedInto as ToolDefinition["id"]);
      expect(parent, `${tool.id} mergedInto ${tool.mergedInto} must exist`).not.toBeNull();
      expect(tool.category, `${tool.id} must inherit parent category`).toBe(parent?.category);
    }
    for (const tool of hidden) {
      expect(visibleTools.some((t) => t.id === tool.id), `${tool.id} hidden alias must not be visible`).toBe(false);
      expect(canonicalForensicAnalyzers().some((t) => t.id === tool.id), `${tool.id} hidden alias must not inflate analyzer count`).toBe(false);
    }
  });

  it("maturity and validation are two independent, orthogonal dimensions", () => {
    for (const tool of tools) {
      if (tool.maturity !== undefined) {
        expect(MATURITIES, `${tool.id} maturity must be valid`).toContain(tool.maturity);
        expect(tool.maturity, `${tool.id} must not mix validation into maturity`).not.toBe("validated");
      }
      if (tool.validation !== undefined) {
        expect(VALIDATIONS, `${tool.id} validation must be valid`).toContain(tool.validation);
      }
    }
  });

  it("envelope emission is explicit and truthful (X of Y canonical forensic analyzers)", () => {
    const emitters = tools.filter((t) => t.emitsEnvelope === true).map((t) => t.id);
    expect(emitters.sort()).toEqual([...EXPECTED_ENVELOPE_EMITTERS].sort());
    // bulk publishes an envelope (real byte-offset provenance) despite supportsResult:false.
    expect(getToolDefinitionById("bulk")?.emitsEnvelope, "bulk must be counted as an envelope emitter").toBe(true);
    // Every emitter is a canonical forensic analyzer.
    const analyzerIds = new Set(canonicalForensicAnalyzers().map((t) => t.id));
    for (const id of emitters) {
      expect(analyzerIds.has(id), `${id} emits an envelope so it must be a forensic analyzer`).toBe(true);
    }
    // Honest metric: X of Y canonical forensic analyzers emit an AnalysisEnvelope.
    // After B6-B1, all 18 canonical analyzers (including registry/plist/bulk) migrate.
    expect(emitters.length, "envelope emitter count (X)").toBe(18);
    expect(canonicalForensicAnalyzers().length, "canonical forensic analyzer count (Y)").toBe(18);
  });
});

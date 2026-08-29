/**
 * Forensics++ (ForensicsPP.com)
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { describe, expect, it } from "vitest";
import { getToolDefinitionById } from "../src/config/app";
import {
  isDisposeOnSwitch,
  isHeavyTool,
  policyOf,
  resolveResourceProfile
} from "../src/core/runtime/resourcePolicy";

function def(id: string) {
  const found = getToolDefinitionById(id as never);
  if (!found) throw new Error(`missing tool definition: ${id}`);
  return found;
}

describe("resource profile resolution (beta.6 P1 heavy-tool governance)", () => {
  it("honors explicit dispose-on-switch for heavy tools", () => {
    const profile = resolveResourceProfile(def("firmware"));
    expect(profile.policy).toBe("dispose-on-switch");
    expect(profile.heavy).toBe(true);
    expect(profile.supportsEvidence).toBe(true);
    expect(profile.supportsResult).toBe(true);
    expect(profile.supportsHandoff).toBe(true);
  });

  it("derives suspendable from accepts when not explicit", () => {
    const profile = resolveResourceProfile(def("windows"));
    expect(profile.policy).toBe("suspendable");
    expect(profile.supportsEvidence).toBe(true);
  });

  it("derives retain for transform tools without accepts", () => {
    const profile = resolveResourceProfile(def("json"));
    expect(profile.policy).toBe("retain");
    expect(profile.supportsPersistence).toBe(true);
    expect(profile.supportsResult).toBe(false);
  });

  it("policyOf mirrors explicit annotations on the registry", () => {
    expect(policyOf("firmware")).toBe("dispose-on-switch");
    expect(policyOf("disk")).toBe("dispose-on-switch");
    expect(policyOf("memory")).toBe("dispose-on-switch");
    expect(policyOf("bulk")).toBe("dispose-on-switch");
    expect(policyOf("sqlite")).toBe("suspendable");
    expect(policyOf("pcap")).toBe("suspendable");
    expect(policyOf("binary")).toBe("suspendable");
    expect(policyOf("json")).toBe("retain");
    expect(isDisposeOnSwitch("firmware")).toBe(true);
    expect(isHeavyTool("pcap")).toBe(true);
    expect(isHeavyTool("json")).toBe(false);
  });

  it("falls back to retain for unknown tool", () => {
    expect(resolveResourceProfile(null).policy).toBe("retain");
  });
});

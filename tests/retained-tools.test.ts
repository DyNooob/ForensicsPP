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
import { resolveRetainedTools } from "../src/core/runtime/retainedTools";

describe("resolveRetainedTools (beta.6 P1 heavy-tool governance)", () => {
  it("always keeps the active tool mounted", () => {
    const result = resolveRetainedTools("binary", ["binary", "image", "json"], 8);
    expect(result).toContain("binary");
    expect(result[0]).toBe("binary");
  });

  it("evicts non-active dispose-on-switch tools immediately", () => {
    // firmware/disk/memory/bulk are dispose-on-switch; when binary is active they drop.
    const mounted = ["firmware", "disk", "binary", "image"];
    const result = resolveRetainedTools("binary", mounted, 8);
    expect(result).not.toContain("firmware");
    expect(result).not.toContain("disk");
    expect(result).toEqual(["binary", "image"]);
  });

  it("keeps a dispose-on-switch tool while it is active", () => {
    const result = resolveRetainedTools("firmware", ["firmware", "binary", "image"], 8);
    expect(result).toContain("firmware");
    expect(result).toContain("binary");
  });

  it("retains suspendable/retain tools even when inactive", () => {
    const mounted = ["sqlite", "pcap", "binary", "image"];
    const result = resolveRetainedTools("binary", mounted, 8);
    expect(result).toEqual(expect.arrayContaining(["sqlite", "pcap", "binary", "image"]));
  });

  it("drops the oldest non-active tools when over maxMounted", () => {
    const mounted = [
      "binary",
      "image",
      "json",
      "sqlite",
      "pcap",
      "windows",
      "evtx",
      "registry",
      "plist",
      "browserartifacts"
    ];
    const result = resolveRetainedTools("binary", mounted, 8);
    expect(result).toHaveLength(8);
    expect(result).toContain("binary");
    expect(result).toContain("browserartifacts");
    // oldest non-active tools (image, json) must be dropped first
    expect(result).not.toContain("image");
    expect(result).not.toContain("json");
  });

  it("prefers evicting dispose-on-switch tools before trimming retain/suspendable", () => {
    const mounted = [
      "firmware",
      "disk",
      "memory",
      "bulk",
      "binary",
      "image",
      "json",
      "sqlite",
      "pcap",
      "windows"
    ];
    const result = resolveRetainedTools("binary", mounted, 8);
    // dispose-on-switch tools are gone regardless of maxMounted pressure
    expect(result).not.toContain("firmware");
    expect(result).not.toContain("disk");
    expect(result).not.toContain("memory");
    expect(result).not.toContain("bulk");
    // retain/suspendable tools remain because the disposal-on-switch eviction freed the budget
    expect(result).toContain("binary");
    expect(result).toContain("image");
    expect(result).toContain("sqlite");
    expect(result).toContain("pcap");
  });
});

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

// Auto-verifies the unified route contract (P0):
//   - a known `/tools/<slug>/` resolves to the canonical tool (not a 404)
//   - an unknown `/tools/<x>/` is explicitly "unknown" so the SPA can render
//     a real 404 instead of silently falling back to Home
//   - `/` (and any non-tool path) is Home, not a 404
//   - legacy/alias slugs canonicalize to the owning tool
//   - standalone (file://) falls back to the hash

import { describe, it, expect } from "vitest";

import {
  resolveToolPath,
  resolveRoute,
  toolToPrettyUrl,
  toolToHashUrl,
  isStandalone,
  isPreview,
} from "../src/core/routeAdapter";

describe("resolveToolPath (online pretty-URL resolution)", () => {
  it("resolves a known slug to its canonical toolId", () => {
    const r = resolveToolPath("/tools/evtx-viewer/");
    expect(r).toEqual({ toolId: "evtx", unknown: false });
    expect(resolveToolPath("/tools/evtx-viewer")).toEqual({ toolId: "evtx", unknown: false });
  });

  it("resolves a legacy/alias slug to its owning tool", () => {
    expect(resolveToolPath("/tools/sqlite-wal-recovery/")).toEqual({ toolId: "sqlite", unknown: false });
    expect(resolveToolPath("/tools/apk-signature-analyzer/")).toEqual({ toolId: "android", unknown: false });
  });

  it("flags an unknown slug as unknown (drives a real 404)", () => {
    const r = resolveToolPath("/tools/not-a-real-tool/");
    expect(r).toEqual({ toolId: null, unknown: true });
  });

  it("treats non-tool paths as 'no tool' (Home), not unknown", () => {
    expect(resolveToolPath("/")).toEqual({ toolId: null, unknown: false });
    expect(resolveToolPath("/legal.html")).toEqual({ toolId: null, unknown: false });
    expect(resolveToolPath("/tools/")).toEqual({ toolId: null, unknown: false });
  });
});

describe("resolveRoute (full location resolution)", () => {
  it("online: known slug → tool, via path", () => {
    const r = resolveRoute({ protocol: "https:", pathname: "/tools/image-forensics/" });
    expect(r).toEqual({ toolId: "image", unknown: false, via: "path", raw: "/tools/image-forensics/" });
  });

  it("online: unknown slug → unknown (404), not Home", () => {
    const r = resolveRoute({ protocol: "https:", pathname: "/tools/zzz/" });
    expect(r.unknown).toBe(true);
    expect(r.toolId).toBeNull();
    expect(r.via).toBe("path");
  });

  it("online: home path → no tool, not unknown", () => {
    const r = resolveRoute({ protocol: "https:", pathname: "/" });
    expect(r.toolId).toBeNull();
    expect(r.unknown).toBe(false);
  });

  it("standalone (file://): falls back to the hash", () => {
    const r = resolveRoute({ protocol: "file:", hash: "#evtx" });
    expect(r).toEqual({ toolId: "evtx", unknown: false, via: "hash", raw: "#evtx" });
  });

  it("standalone: a legacy hash that is not a real tool id stays unresolved", () => {
    const r = resolveRoute({ protocol: "file:", hash: "#wal" });
    expect(r.toolId).toBeNull();
    expect(r.unknown).toBe(false);
  });

  it("online with a non-tool path but a hash still resolves via hash", () => {
    const r = resolveRoute({ protocol: "https:", pathname: "/", hash: "#sqlite" });
    expect(r.toolId).toBe("sqlite");
    expect(r.via).toBe("hash");
  });
});

describe("shareable URL builders", () => {
  it("toolToPrettyUrl maps home → / and tools → /tools/<slug>/", () => {
    expect(toolToPrettyUrl("home")).toBe("/");
    expect(toolToPrettyUrl("evtx")).toBe("/tools/evtx-viewer/");
    expect(toolToPrettyUrl("sqlite")).toBe("/tools/sqlite-forensics/");
  });

  it("toolToHashUrl is the standalone-compatible form", () => {
    expect(toolToHashUrl("evtx")).toBe("#evtx");
    expect(toolToHashUrl("android")).toBe("#android");
  });
});

describe("environment helpers", () => {
  it("isStandalone reflects the protocol, not window", () => {
    expect(isStandalone({ protocol: "file:" })).toBe(true);
    expect(isStandalone({ protocol: "https:" })).toBe(false);
  });

  it("isPreview mirrors the VITE_PREVIEW build flag", () => {
    // Mode-aware: this suite is run both with and without VITE_PREVIEW=1 (the
    // built-artifact assertions are mode-sensitive), so mirror the flag rather
    // than hardcoding one environment.
    const expected = process.env.VITE_PREVIEW === "1" || process.env.VITE_PREVIEW === "true";
    expect(isPreview()).toBe(expected);
  });
});

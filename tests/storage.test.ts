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

import { describe, expect, it, vi } from "vitest";
import { clearToolSessions, writeToolSession } from "../src/utils/toolSessions";
import { isStoredValueCompatible, parseStoredState, shouldUseIndexedState } from "../src/utils/storage";

describe("browser state persistence", () => {
  it("keeps small values in localStorage and routes large values to IndexedDB", () => {
    expect(shouldUseIndexedState("x".repeat(128 * 1024))).toBe(false);
    expect(shouldUseIndexedState("x".repeat(128 * 1024 + 1))).toBe(true);
  });

  it("treats malformed local values as absent so IndexedDB can be used as a fallback", () => {
    expect(parseStoredState<{ value: string }>("not-json")).toEqual({ found: false });
    expect(parseStoredState<{ value: string }>(JSON.stringify({ value: "restored" }))).toEqual({
      found: true,
      value: { value: "restored" }
    });
  });

  it("rejects valid JSON with an obsolete or unexpected shape", () => {
    const isString = (value: unknown): value is string => typeof value === "string";
    expect(parseStoredState<string>(JSON.stringify({ value: "old" }), isString)).toEqual({ found: false });
    expect(parseStoredState<string>(JSON.stringify("current"), isString)).toEqual({ found: true, value: "current" });
  });

  it("infers a safe primitive or collection shape when no validator is supplied", () => {
    expect(isStoredValueCompatible("10", 10)).toBe(false);
    expect(isStoredValueCompatible(10, 10)).toBe(true);
    expect(isStoredValueCompatible({}, [])).toBe(false);
    expect(isStoredValueCompatible([], [])).toBe(true);
    expect(isStoredValueCompatible({ value: "ready" }, { value: "" })).toBe(true);
  });

  it("does not permanently disable IndexedDB writes after clearing without IndexedDB", async () => {
    const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
    await clearToolSessions();

    const open = vi.fn();
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: { open } });
    await expect(writeToolSession("storage-test", { value: "after-clear" })).rejects.toThrow();
    expect(open).toHaveBeenCalledTimes(1);

    if (originalDescriptor) Object.defineProperty(globalThis, "indexedDB", originalDescriptor);
    else delete (globalThis as { indexedDB?: unknown }).indexedDB;
  });
});

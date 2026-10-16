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

import { afterEach, describe, expect, it, vi } from "vitest";
import { randomBytes } from "../src/shims/node-crypto-browser";

afterEach(() => vi.unstubAllGlobals());

describe("browser crypto fallback", () => {
  it("uses secure randomness in bounded chunks even for large requests", () => {
    const getRandomValues = vi.fn((bytes: Uint8Array) => {
      expect(bytes.length).toBeLessThanOrEqual(65_536);
      return bytes.fill(42);
    });
    vi.stubGlobal("crypto", { getRandomValues });
    const bytes = randomBytes(70_000);
    expect(bytes.length).toBe(70_000);
    expect(bytes.every((byte) => byte === 42)).toBe(true);
    expect(getRandomValues).toHaveBeenCalledTimes(2);
  });

  it("fails explicitly when secure randomness is unavailable", () => {
    vi.stubGlobal("crypto", undefined);
    expect(() => randomBytes(16)).toThrow("Secure random");
  });

  it("rejects negative, fractional and non-finite byte counts", () => {
    for (const size of [-1, 1.5, NaN, Infinity]) expect(() => randomBytes(size)).toThrow(RangeError);
  });
});

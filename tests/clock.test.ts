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
import { estimateClockOffset } from "../src/utils/clock";

const serverTime = Date.parse("2026-10-12T12:00:00Z");
const headers = new Headers({ date: new Date(serverTime).toUTCString() });
describe("HTTP clock estimate", () => {
  it("accounts for round-trip latency when estimating clock skew", () => {
    expect(estimateClockOffset(headers, serverTime - 5_000, serverTime - 4_800, 200)).toBe(4_900);
  });
  it("rejects slow responses and computer clock jumps", () => {
    expect(() => estimateClockOffset(headers, serverTime, serverTime + 3_000, 3_000)).toThrow("unreliable");
    expect(() => estimateClockOffset(headers, serverTime, serverTime + 60_000, 200)).toThrow("unreliable");
  });
  it("rejects cached dates and missing/invalid date headers", () => {
    expect(() => estimateClockOffset(new Headers({ date: headers.get("date")!, age: "30" }), serverTime, serverTime + 100, 100)).toThrow();
    expect(() => estimateClockOffset(new Headers(), serverTime, serverTime + 100, 100)).toThrow();
    expect(() => estimateClockOffset(new Headers({ date: "invalid" }), serverTime, serverTime + 100, 100)).toThrow();
  });
});

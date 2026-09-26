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
  calculateChineseIdCheckCode,
  cardNetwork,
  classifySpecialIpv4,
  detectLookupKind,
  luhnCheck,
  parseIpv4,
  splitLookupInput,
  validateChineseId,
  validatePhone
} from "../src/features/lookup/rules";

describe("lookup rules", () => {
  it("validates GB 11643 checksums and dates", () => {
    const valid = validateChineseId("11010519491231002X");
    expect(valid.valid).toBe(true);
    expect(valid.birthDate).toBe("1949-12-31");
    expect(valid.gender).toBe("female");
    expect(calculateChineseIdCheckCode("11010519491231002")).toBe("X");
    expect(validateChineseId("11010519490231002X").reason).toBe("invalid-birth-date");
    expect(validateChineseId("110105194912310021").reason).toBe("invalid-checksum");
  });

  it("converts valid legacy 15-digit IDs", () => {
    const result = validateChineseId("130503670401001");
    expect(result.valid).toBe(true);
    expect(result.legacy).toBe(true);
    expect(result.normalized).toMatch(/^13050319670401001[\dX]$/);
  });

  it("validates mobile and card-number rules", () => {
    expect(validatePhone("+86 138-0013-8000")).toEqual({ normalized: "13800138000", valid: true });
    expect(luhnCheck("4111 1111 1111 1111").valid).toBe(true);
    expect(luhnCheck("4111 1111 1111 1112").valid).toBe(false);
    expect(cardNetwork("6222021001116240533")).toBe("UnionPay");
    expect(cardNetwork("4111111111111111")).toBe("Visa");
  });

  it("detects lookup kinds and special IPv4 ranges", () => {
    expect(detectLookupKind("192.168.1.1")).toBe("ip");
    expect(detectLookupKind("13800138000")).toBe("phone");
    expect(detectLookupKind("11010519491231002X")).toBe("id");
    expect(detectLookupKind("4111111111111111")).toBe("bank");
    const privateIp = parseIpv4("192.168.1.1");
    expect(privateIp && classifySpecialIpv4(privateIp)).toContain("Private");
    expect(parseIpv4("01.2.3.4")).toBeNull();
  });

  it("deduplicates batch input", () => {
    expect(splitLookupInput("8.8.8.8\n8.8.8.8, 1.1.1.1")).toEqual(["8.8.8.8", "1.1.1.1"]);
  });
});

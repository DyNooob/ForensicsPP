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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import CryptoJS from "crypto-js";
import { describe, expect, it } from "vitest";
import { mysqlNativePassword, passwordRowsToCsv, verifyPasswordCandidates } from "../src/features/password/analyzer";

describe("password analyzer", () => {
  it("mysqlNativePassword computes SHA1(SHA1(password)) star-prefixed uppercase", () => {
    const inner = CryptoJS.SHA1("abc");
    const outer = CryptoJS.SHA1(inner).toString().toUpperCase();
    expect(mysqlNativePassword("abc")).toBe(`*${outer}`);
    expect(mysqlNativePassword("abc")).toMatch(/^\*[A-F0-9]{40}$/);
  });

  it("passwordRowsToCsv emits a header and escapes commas/quotes", () => {
    const csv = passwordRowsToCsv([
      { candidate: "a,b", hashType: "MD5", matched: true, detail: 'he said "hi"', risk: ["MATCHED"] },
      { candidate: "x", hashType: "SHA1", matched: false, detail: "no", risk: [] }
    ]);
    const lines = csv.split("\n");
    expect(lines[0]).toBe("candidate,hash_type,matched,risk,detail");
    expect(lines[1]).toContain('"a,b"');
    expect(lines[1]).toContain('"he said ""hi"""');
  });

  it("verifyPasswordCandidates matches MD5/SHA1/SHA256/MySQL native and reports non-matches", async () => {
    const md5 = CryptoJS.MD5("password123").toString();
    const sha1 = CryptoJS.SHA1("password123").toString();
    const sha256 = CryptoJS.SHA256("password123").toString();
    const mysql = mysqlNativePassword("hunter2");

    const md5Rows = await verifyPasswordCandidates(md5, ["password123", "wrong"]);
    expect(md5Rows.find((r) => r.candidate === "password123")?.matched).toBe(true);
    expect(md5Rows.find((r) => r.candidate === "wrong")?.matched).toBe(false);

    const sha1Rows = await verifyPasswordCandidates(sha1, ["password123"]);
    expect(sha1Rows[0].matched).toBe(true);
    expect(sha1Rows[0].hashType).toContain("SHA1");

    const sha256Rows = await verifyPasswordCandidates(sha256, ["password123"]);
    expect(sha256Rows[0].matched).toBe(true);

    const mysqlRows = await verifyPasswordCandidates(mysql, ["hunter2", "nope"]);
    expect(mysqlRows.find((r) => r.candidate === "hunter2")?.matched).toBe(true);
    expect(mysqlRows.find((r) => r.candidate === "nope")?.matched).toBe(false);
  });

  it("verifyPasswordCandidates flags common/short candidates as risk", async () => {
    const md5 = CryptoJS.MD5("123456").toString();
    const rows = await verifyPasswordCandidates(md5, ["123456"]);
    expect(rows[0].matched).toBe(true);
    expect(rows[0].risk.join(";")).toMatch(/common password|short password/);
  });
});

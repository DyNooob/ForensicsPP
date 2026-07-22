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
import { assessPasswordStrength, identifyHash } from "../src/utils/hashIdentify";

describe("identifyHash", () => {
  it("returns empty for blank input", () => {
    const result = identifyHash("   ");
    expect(result.kind).toBe("empty");
    expect(result.candidates).toHaveLength(0);
  });

  it("identifies a bcrypt hash with the bcrypt generate hint", () => {
    const result = identifyHash("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW");
    expect(result.kind).toBe("hash");
    const bcrypt = result.candidates.find((c) => c.id === "bcrypt");
    expect(bcrypt).toBeTruthy();
    expect(bcrypt?.generateHint).toBe("bcrypt");
    expect(bcrypt?.hashcat).toBe("3200");
  });

  it("identifies a Django PBKDF2 hash with the pbkdf2 generate hint", () => {
    const result = identifyHash("pbkdf2_sha256$390000$abcSalt123$3G3G0+abcdefghijklmnopqrstuvwxyzABCDEFGH=");
    expect(result.kind).toBe("hash");
    expect(result.candidates[0].id).toBe("django-pbkdf2-sha256");
    expect(result.candidates[0].generateHint).toBe("pbkdf2");
  });

  it("identifies MySQL native password with the leading asterisk", () => {
    const result = identifyHash("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19");
    expect(result.kind).toBe("hash");
    expect(result.candidates[0].id).toBe("mysql41");
    expect(result.candidates[0].generateHint).toBe("common");
  });

  it("ranks MD5 first but also flags NTLM for a 32-char hex string", () => {
    const result = identifyHash("5f4dcc3b5aa765d61d8327deb882cf99");
    expect(result.kind).toBe("hash");
    expect(result.candidates[0].id).toBe("md5");
    expect(result.candidates.some((c) => c.id === "ntlm")).toBe(true);
    expect(result.candidates.find((c) => c.id === "md5")?.confidence).toBe("high");
  });

  it("offers SHA-1 and RIPEMD-160 for a 40-char hex string", () => {
    const result = identifyHash("a".repeat(40));
    expect(result.candidates[0].id).toBe("sha1");
    expect(result.candidates.some((c) => c.id === "ripemd160")).toBe(true);
  });

  it("identifies SHA-256 length hashes", () => {
    const result = identifyHash("a".repeat(64));
    expect(result.candidates[0].id).toBe("sha256");
    expect(result.candidates.some((c) => c.id === "sm3")).toBe(true);
  });

  it("identifies sha512crypt shadow entries", () => {
    const result = identifyHash("$6$rounds=5000$salt$abcdefghijklmnop");
    expect(result.candidates[0].id).toBe("sha512crypt");
    expect(result.candidates[0].hashcat).toBe("1800");
  });

  it("identifies phpass/WordPress hashes", () => {
    const result = identifyHash("$P$B9c8d7e6f5g4h3i2j1k0lmnopqrstuv");
    expect(result.candidates[0].id).toBe("phpass");
  });

  it("treats a spaced human phrase as plaintext and scores it", () => {
    const result = identifyHash("correct horse battery staple");
    expect(result.kind).toBe("plaintext");
    expect(result.strength).toBeTruthy();
  });

  it("treats a short non-hex string as plaintext", () => {
    const result = identifyHash("Sup3r!");
    expect(result.kind).toBe("plaintext");
  });
});

describe("assessPasswordStrength", () => {
  it("flags common weak passwords as very weak", () => {
    const strength = assessPasswordStrength("password");
    expect(strength.score).toBe(0);
    expect(strength.notesEn.some((note) => /weak-password list/i.test(note))).toBe(true);
  });

  it("flags digit-only passwords", () => {
    const strength = assessPasswordStrength("12345678");
    expect(strength.notesEn.some((note) => /Digits only/i.test(note))).toBe(true);
  });

  it("scores a long mixed password highly", () => {
    const strength = assessPasswordStrength("Tr0ub4dor&3xtraLongPhrase");
    expect(strength.score).toBeGreaterThanOrEqual(3);
    expect(strength.hasUpper && strength.hasLower && strength.hasDigit && strength.hasSymbol).toBe(true);
  });
});

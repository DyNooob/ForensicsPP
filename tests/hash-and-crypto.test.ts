/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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
import { atbash, caesar, morseDecode, morseEncode, railFence, railFenceDecode, vigenere } from "../src/features/crypto/algorithms";
import { detectHashType, formatHashCase, hashBytes } from "../src/utils/hash";

describe("standard digest vectors", () => {
  const input = new TextEncoder().encode("abc");
  const hashes = hashBytes(input);

  it("matches MD5, SHA-1, SHA-256 and SHA-512 vectors", () => {
    expect(hashes.md5).toBe("900150983cd24fb0d6963f7d28e17f72");
    expect(hashes.sha1).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
    expect(hashes.sha256).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hashes.sha512).toBe("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  });

  it("matches the SM3 abc vector", () => {
    expect(hashes.sm3).toBe("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
  });

  it("formats and detects common hash representations", () => {
    expect(formatHashCase(hashes.sha256, "upper")).toBe(hashes.sha256.toUpperCase());
    expect(detectHashType(hashes.md5)).toBe("MD5-like");
    expect(detectHashType(hashes.sha256)).toBe("SHA256-like");
    expect(detectHashType(`*${hashes.sha1.toUpperCase()}`)).toBe("MySQL native password");
  });
});

describe("classical cipher round trips", () => {
  it("handles Caesar and Atbash", () => {
    expect(caesar("Attack at Dawn", 3)).toBe("Dwwdfn dw Gdzq");
    expect(atbash(atbash("ForensicsPP"))).toBe("ForensicsPP");
  });

  it("matches the Vigenere reference vector", () => {
    const encrypted = vigenere("ATTACKATDAWN", "LEMON");
    expect(encrypted).toBe("LXFOPVEFRNHR");
    expect(vigenere(encrypted, "LEMON", true)).toBe("ATTACKATDAWN");
  });

  it("round-trips Morse and rail fence", () => {
    expect(morseDecode(morseEncode("SOS TEST"))).toBe("SOS TEST");
    const encrypted = railFence("WEAREDISCOVEREDFLEEATONCE", 3);
    expect(encrypted).toBe("WECRLTEERDSOEEFEAOCAIVDEN");
    expect(railFenceDecode(encrypted, 3)).toBe("WEAREDISCOVEREDFLEEATONCE");
  });
});

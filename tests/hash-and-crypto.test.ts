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
import { atbash, caesar, morseDecode, morseEncode, railFence, railFenceDecode, vigenere } from "../src/features/crypto/algorithms";
import { annotateBatchHashMatches, parseExpectedHashSet } from "../src/features/hash/matching";
import { detectHashType, formatHashCase, hashBytes, hashSelectedFile, normalizeHashAlgorithms, SM3_FILE_SIZE_LIMIT } from "../src/utils/hash";

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

  it("ignores stale or unsupported persisted algorithm selections", () => {
    expect(normalizeHashAlgorithms(["SHA256", "legacy", "sha256", "SM3"])).toEqual(["sha256", "sm3"]);
    expect(normalizeHashAlgorithms(["legacy"])).toEqual(["sha256"]);
  });
});

describe("checksum manifest matching", () => {
  it("matches a labeled checksum only against its named file", () => {
    const first = "a".repeat(64);
    const second = "b".repeat(64);
    const targets = parseExpectedHashSet(`${first}  evidence.bin\n${second}  other.bin`);
    const rows = annotateBatchHashMatches([
      { name: "evidence.bin", size: 1, sha256: first },
      { name: "other.bin", size: 1, sha256: second },
      { name: "wrong.bin", size: 1, sha256: first }
    ], `${first}  evidence.bin\n${second}  other.bin`);

    expect(targets[0]).toMatchObject({ hash: first, fileName: "evidence.bin" });
    expect(rows.map((row) => row.matched)).toEqual([true, true, false]);
  });

  it("keeps a standalone digest as a global target", () => {
    const digest = "c".repeat(64);
    const rows = annotateBatchHashMatches([
      { name: "one.bin", size: 1, sha256: digest },
      { name: "two.bin", size: 1, sha256: digest }
    ], digest);

    expect(rows.every((row) => row.matched)).toBe(true);
  });
});

describe("streamed file hashing", () => {
  it("matches in-memory hashes across small chunks", async () => {
    const bytes = new TextEncoder().encode("abc".repeat(5000));
    const expected = hashBytes(bytes);
    const progress: number[] = [];
    const actual = await hashSelectedFile(new Blob([bytes]), ["md5", "sha1", "sha256", "sha512", "sha3", "sm3"], {
      chunkSize: 1024,
      onProgress: ({ loaded }) => progress.push(loaded)
    });
    expect(actual).toEqual(expected);
    expect(progress.at(-1)).toBe(bytes.length);
  });

  it("supports cancellation between chunks", async () => {
    const controller = new AbortController();
    const hashing = hashSelectedFile(new Blob([new Uint8Array(256 * 1024)]), ["sha256"], {
      chunkSize: 64 * 1024,
      signal: controller.signal,
      onProgress: ({ loaded }) => {
        if (loaded >= 64 * 1024) controller.abort();
      }
    });
    await expect(hashing).rejects.toMatchObject({ name: "AbortError" });
  });

  it("rejects oversized SM3 files before reading them", async () => {
    const oversized = { size: SM3_FILE_SIZE_LIMIT + 1, slice: () => new Blob() } as Blob;
    await expect(hashSelectedFile(oversized, ["sm3"])).rejects.toThrow("SM3_FILE_TOO_LARGE");
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

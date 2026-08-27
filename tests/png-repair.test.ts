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
import { crc32 } from "../src/utils/binary";
import { findPngCandidates, locatePngStart, repairPng } from "../src/features/file/pngRepair";
import { scanCarvableObjects } from "../src/features/file/carver";

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

function chunk(type: string, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + data.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, data.length, false);
  for (let index = 0; index < 4; index += 1) out[4 + index] = type.charCodeAt(index);
  out.set(data, 8);
  view.setUint32(8 + data.length, crc32(out.slice(4, 8 + data.length)), false);
  return out;
}

// Minimal but structurally valid IHDR (1x1 RGBA, 8-bit, no interlace).
const IHDR_DATA = new Uint8Array([0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
const IHDR = chunk("IHDR", IHDR_DATA);
const IDAT = chunk("IDAT", new Uint8Array([0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]));
const IEND = chunk("IEND", new Uint8Array([]));

function png(chunks: Uint8Array[], opts: { corruptSignature?: boolean } = {}): Uint8Array {
  const sig = opts.corruptSignature
    ? new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0])
    : new Uint8Array(PNG_SIGNATURE);
  const parts = [sig, ...chunks];
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

describe("pngRepair", () => {
  it("leaves a clean PNG untouched (no repair needed)", () => {
    const bytes = png([IHDR, IDAT, IEND]);
    const result = repairPng(bytes);
    expect(result.located).toBe(true);
    expect(result.signatureRepaired).toBe(false);
    expect(result.truncated).toBe(false);
    expect([...result.bytes.slice(0, 8)]).toEqual([...PNG_SIGNATURE]);
  });

  it("rebuilds a corrupted/missing PNG signature via IHDR structure", () => {
    const bytes = png([IHDR, IDAT, IEND], { corruptSignature: true });
    expect(locatePngStart(bytes)).toBe(0);
    const result = repairPng(bytes);
    expect(result.located).toBe(true);
    expect(result.signatureRepaired).toBe(true);
    expect([...result.bytes.slice(0, 8)]).toEqual([...PNG_SIGNATURE]);
  });

  it("carves a truncated PNG that lost its IEND and part of its IDAT", () => {
    // Build a PNG with no IEND, then cut the tail off the IDAT so the declared
    // length runs past EOF — the exact scenario that used to slip through.
    const full = png([IHDR, IDAT]);
    const truncated = full.slice(0, full.length - 3);
    expect(truncated.length).toBeLessThan(full.length);
    const result = repairPng(truncated);
    expect(result.located).toBe(true);
    expect(result.truncated).toBe(true);
    expect(result.bytes.length).toBeGreaterThan(0);
    // Output is still a well-formed PNG (signature + IHDR + IDAT + fresh IEND).
    expect([...result.bytes.slice(0, 8)]).toEqual([...PNG_SIGNATURE]);
    const tail = result.bytes.slice(result.bytes.length - 12);
    expect([...tail.slice(4, 8)]).toEqual([0x49, 0x45, 0x4e, 0x44]); // "IEND"
  });

  it("recomputes a mismatched CRC on repair", () => {
    const idatBad = chunk("IDAT", new Uint8Array([0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]));
    idatBad[idatBad.length - 1] ^= 0xff; // corrupt one CRC byte
    const bytes = png([IHDR, idatBad, IEND]);
    const result = repairPng(bytes);
    expect(result.located).toBe(true);
    expect(result.notes.some((note) => /CRC/.test(note))).toBe(true);
  });

  it("requires an IDAT and refuses a lone IHDR", () => {
    const buf = new Uint8Array(64);
    buf.set(new Uint8Array(PNG_SIGNATURE), 0);
    buf.set(IHDR, 8);
    const result = repairPng(buf);
    expect(result.located).toBe(false);
  });

  it("does not carve arbitrary data that merely contains 'IHDR'", () => {
    const junk = new Uint8Array(512).fill(0x41);
    junk.set([0x49, 0x48, 0x44, 0x52], 100); // "IHDR"
    const result = repairPng(junk);
    expect(result.located).toBe(false);
  });
});

describe("findPngCandidates", () => {
  it("tags a clean embedded PNG as exact", () => {
    const bytes = png([IHDR, IDAT, IEND]);
    const buffer = new Uint8Array(2048).fill(0x00);
    buffer.set(bytes, 500);
    const candidates = findPngCandidates(buffer, 0, 4);
    expect(candidates.length).toBe(1);
    expect(candidates[0].offset).toBe(500);
    expect(candidates[0].repaired).toBe(false);
    expect(candidates[0].extent).toBe("exact");
  });

  it("recovers a truncated/damaged PNG embedded in junk", () => {
    const full = png([IHDR, IDAT]);
    const truncated = full.slice(0, full.length - 3);
    const buffer = new Uint8Array(4096).fill(0xff);
    buffer.set(truncated, 1000);
    const candidates = findPngCandidates(buffer, 0, 8);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    const hit = candidates[0];
    expect(hit.offset).toBe(1000);
    expect(hit.repaired).toBe(true);
    expect(hit.repairedBytes.length).toBeGreaterThan(0);
  });
});

describe("scanCarvableObjects PNG repair integration", () => {
  it("returns repaired bytes for a damaged PNG", () => {
    const full = png([IHDR, IDAT]);
    const truncated = full.slice(0, full.length - 3);
    const buffer = new Uint8Array(4096).fill(0xff);
    buffer.set(truncated, 1000);
    const hits = scanCarvableObjects(buffer, { maxHits: 8 });
    const pngHit = hits.find((hit) => hit.label === "PNG" && hit.offset === 1000);
    expect(pngHit).toBeDefined();
    expect(pngHit!.repaired).toBe(true);
    expect(pngHit!.repairedBytes && pngHit!.repairedBytes.length).toBeGreaterThan(0);
  });

  it("does not skip a corrupted PNG that precedes a valid-signature PNG", () => {
    // Regression: locatePngStart previously ran a signature scan that returned
    // the first *valid* signature, so a signature-damaged PNG sitting before a
    // second, intact PNG was never located and never carved.
    const corrupted = png([IHDR, IDAT, IEND], { corruptSignature: true });
    const intact = png([IHDR, IDAT, IEND]);
    const buffer = new Uint8Array(4096).fill(0xaa);
    buffer.set(corrupted, 100);
    buffer.set(intact, 300);
    const candidates = findPngCandidates(buffer, 0, 8);
    expect(candidates.length).toBeGreaterThanOrEqual(2);
    expect(candidates[0].offset).toBe(100);
    expect(candidates[0].repaired).toBe(true);
    expect(candidates.some((c) => c.offset === 300 && c.repaired === false)).toBe(true);
  });
});

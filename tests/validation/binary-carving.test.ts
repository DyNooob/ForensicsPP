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

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { carverFormats, scanCarvableObjects } from "../../src/features/file/carver";

type Bytes = number[] | Uint8Array;

function concatU8(parts: Bytes[]): Uint8Array {
  const flattened = parts.map((part) => (part instanceof Uint8Array ? part : new Uint8Array(part)));
  const total = flattened.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of flattened) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function le32(value: number): number[] {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Synthetic PNG. `pngExtent` walks chunk lengths until IEND and never validates
 * CRCs, so arbitrary (consistent) payload is sufficient for the carver to
 * compute an exact byte length. The IHDR + IDAT chunks are required so the
 * corruption-tolerant PNG path also accepts it as a located image.
 */
function buildPng(idatPayload: Uint8Array): Uint8Array {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  const ihdr = concatU8([[0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52], new Uint8Array(13), [0, 0, 0, 0]]);
  const idat = concatU8([[0, 0, 0, idatPayload.length, 0x49, 0x44, 0x41, 0x54], idatPayload, [0, 0, 0, 0]]);
  const iend = [0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0];
  return concatU8([signature, ihdr, idat, iend]);
}

function buildWebp(payload: Uint8Array): Uint8Array {
  return concatU8([[0x52, 0x49, 0x46, 0x46], le32(4 + payload.length), [0x57, 0x45, 0x42, 0x50], payload]);
}

function deterministicFiller(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < size; index += 1) bytes[index] = (index * 31 + 7) & 0xff;
  return bytes;
}

function findHit(hits: ReturnType<typeof scanCarvableObjects>, label: string, offset: number) {
  return hits.find((candidate) => candidate.label === label && candidate.offset === offset);
}

describe("validation: binary/file carving — provenance (signature detection + offset)", () => {
  it("recovers embedded signatures at their exact source offsets", () => {
    // NOTE: this is a *provenance* test (signature detection + offset accuracy),
    // not a claim of full carving correctness. Magic-only formats are chosen so
    // the synthetic fixture is unambiguous.
    const chosen = carverFormats
      .filter((format) => !format.validate && (format.magicOffset ?? 0) === 0 && format.magic.length >= 3)
      .slice(0, 3);
    expect(chosen.length).toBeGreaterThanOrEqual(2);

    const size = 4096;
    const bytes = new Uint8Array(size);
    bytes.set(deterministicFiller(size));

    const offsets = [64, 768, 2048];
    const embedded = chosen.map((format, index) => {
      const offset = offsets[index];
      bytes.set(format.magic, offset);
      return { label: format.label, offset };
    });

    const hits = scanCarvableObjects(bytes);
    for (const target of embedded) {
      const hit = findHit(hits, target.label, target.offset);
      expect(hit, `expected "${target.label}" carved at 0x${target.offset.toString(16)}`).toBeDefined();
      expect(hit?.offset).toBe(target.offset);
      expect(hit?.confidence, `${target.label} should report a confidence`).toBeDefined();
    }
  });

  it("does not fabricate offsets or claim validated carves on unknown filler", () => {
    const bytes = deterministicFiller(2048);
    const hits = scanCarvableObjects(bytes);
    for (const hit of hits) {
      expect(hit.offset).toBeGreaterThanOrEqual(0);
      expect(hit.offset).toBeLessThan(bytes.length);
      // Deterministic non-magic filler must never produce a structurally
      // validated or repaired carve — that would be a false positive.
      expect(hit.extent).not.toBe("exact");
      expect(hit.extent).not.toBe("structural");
      expect(hit.repaired).not.toBe(true);
    }
  });
});

describe("validation: binary/file carving — artifact length (exact extent)", () => {
  it("reports a PNG's exact byte length and exact extent", () => {
    const png = buildPng(new Uint8Array(64));
    const bytes = new Uint8Array(4096);
    bytes.set(deterministicFiller(bytes.length));
    const offset = 512;
    bytes.set(png, offset);

    const hit = findHit(scanCarvableObjects(bytes), "PNG", offset);
    expect(hit, "PNG must be carved").toBeDefined();
    expect(hit?.extent).toBe("exact");
    expect(hit?.size).toBe(png.length);
  });

  it("reports a RIFF/WEBP container's exact byte length and exact extent", () => {
    const webp = buildWebp(new Uint8Array(96));
    const bytes = new Uint8Array(4096);
    bytes.set(deterministicFiller(bytes.length));
    const offset = 1024;
    bytes.set(webp, offset);

    const hit = findHit(scanCarvableObjects(bytes), "WEBP", offset);
    expect(hit, "WEBP must be carved").toBeDefined();
    expect(hit?.extent).toBe("exact");
    expect(hit?.size).toBe(webp.length);
  });
});

describe("validation: binary/file carving — extraction SHA-256 integrity", () => {
  it("extracts a clean PNG byte-for-byte (slice SHA-256 == source SHA-256)", () => {
    const png = buildPng(new Uint8Array(128));
    const bytes = new Uint8Array(4096);
    bytes.set(deterministicFiller(bytes.length));
    const offset = 768;
    bytes.set(png, offset);

    const hits = scanCarvableObjects(bytes);
    const hit = findHit(hits, "PNG", offset);
    expect(hit, "PNG must be carved").toBeDefined();
    expect(hit?.size).toBe(png.length);

    const extracted = bytes.subarray(hit!.offset, hit!.offset + hit!.size);
    expect(sha256Hex(extracted)).toBe(sha256Hex(png));
    expect(extracted.byteLength).toBe(png.length);
  });
});

describe("validation: binary/file carving — nested / overlap (container hierarchy)", () => {
  it("attributes an embedded PNG to its WEBP parent and computes depth", () => {
    const png = buildPng(new Uint8Array(64));
    const webp = buildWebp(png);
    const bytes = new Uint8Array(4096);
    bytes.set(deterministicFiller(bytes.length));
    const containerOffset = 256;
    bytes.set(webp, containerOffset);
    const embeddedOffset = containerOffset + 12;

    const hits = scanCarvableObjects(bytes);
    const parent = findHit(hits, "WEBP", containerOffset);
    const child = findHit(hits, "PNG", embeddedOffset);
    expect(parent, "WEBP container must be carved").toBeDefined();
    expect(child, "embedded PNG must be carved").toBeDefined();

    expect(child?.parentOffset).toBe(containerOffset);
    expect(child?.depth).toBeGreaterThanOrEqual(1);
    expect(parent?.depth).toBe(0);
  });

  it("keeps a nested object's extent within its enclosing container (no overflow)", () => {
    const png = buildPng(new Uint8Array(64));
    const webp = buildWebp(png);
    const bytes = new Uint8Array(4096);
    bytes.set(deterministicFiller(bytes.length));
    const containerOffset = 256;
    bytes.set(webp, containerOffset);
    const embeddedOffset = containerOffset + 12;

    const hits = scanCarvableObjects(bytes);
    const parent = findHit(hits, "WEBP", containerOffset)!;
    const child = findHit(hits, "PNG", embeddedOffset)!;

    const childEnd = child.offset + child.size;
    const containerEnd = parent.offset + parent.size;
    expect(childEnd).toBeLessThanOrEqual(containerEnd);
  });
});

describe("validation: binary/file carving — truncated signature (honest non-completeness)", () => {
  it("salvages a truncated PNG to an exact-length repaired image", () => {
    // PNG cut off before its IEND chunk.
    const full = buildPng(new Uint8Array(64));
    const iendStart = full.length - 12; // last 12 bytes are the IEND chunk
    const truncated = full.subarray(0, iendStart);

    const bytes = new Uint8Array(512);
    bytes.set(deterministicFiller(bytes.length));
    const offset = 64;
    bytes.set(truncated, offset);
    // A trailing byte that makes the next chunk's declared length exceed the
    // 2 GiB limit, so the tolerant walker stops cleanly at IDAT and salvages
    // exactly the real image rather than over-consuming trailing bytes.
    bytes[offset + truncated.length] = 0xff;

    const hit = findHit(scanCarvableObjects(bytes), "PNG", offset);
    expect(hit, "truncated PNG must still be located").toBeDefined();
    // The decisive honesty property: never reported as a complete exact carve.
    expect(hit?.extent).toBe("repaired");
    expect(hit?.extent).not.toBe("exact");
    expect(hit?.repaired).toBe(true);
    expect(hit?.repairedBytes).toBeInstanceOf(Uint8Array);

    // The salvaged artifact is the real extraction: a decoder-valid PNG whose
    // length equals the complete image (the truncated source plus the IEND the
    // walker had to append).
    const salvage = hit?.repairedBytes;
    expect(salvage?.length ?? 0).toBe(full.length);
    const reCarve = findHit(scanCarvableObjects(salvage!), "PNG", 0);
    expect(reCarve?.extent).toBe("exact");
    expect(reCarve?.size).toBe(full.length);
    expect(hit?.size).toBeLessThanOrEqual(bytes.length);
  });

  it("reports a truncated PNG followed by filler as repaired (never exact) and never overflows", () => {
    const full = buildPng(new Uint8Array(64));
    const truncated = full.subarray(0, full.length - 12);

    const bytes = new Uint8Array(2048);
    bytes.set(deterministicFiller(bytes.length));
    const offset = 200;
    bytes.set(truncated, offset);
    // No clean stop byte: the tolerant walker may over-consume trailing filler
    // as fake chunks, but it must NEVER claim an exact carve or overflow.

    const hit = findHit(scanCarvableObjects(bytes), "PNG", offset);
    expect(hit, "truncated PNG must still be located").toBeDefined();
    expect(hit?.extent).toBe("repaired");
    expect(hit?.extent).not.toBe("exact");
    expect(hit?.repaired).toBe(true);
    // Reported region must never be fabricated past the buffer end.
    expect(hit?.size).toBeLessThanOrEqual(bytes.length);
  });

  it("refuses a truncated ZIP (local header only, no EOCD) as a complete carve", () => {
    const localHeader = concatU8([[0x50, 0x4b, 0x03, 0x04], new Uint8Array(40)]);
    const bytes = new Uint8Array(2048);
    bytes.set(deterministicFiller(bytes.length));
    bytes.set(localHeader, 128);

    const hits = scanCarvableObjects(bytes);
    // ZIP's structural validator requires a valid EOCD + central directory; a
    // header-only fragment must not be reported as a carved archive.
    expect(hits.filter((hit) => hit.label === "ZIP").length).toBe(0);
  });
});

describe("validation: binary/file carving — false-positive guard (random data)", () => {
  it("produces no exact/structural/repaired carve from high-entropy random bytes", () => {
    const bytes = new Uint8Array(65536);
    // crypto.getRandomValues is available in the Node test environment.
    globalThis.crypto.getRandomValues(bytes);

    const hits = scanCarvableObjects(bytes);
    const validated = hits.filter((hit) => hit.extent === "exact" || hit.extent === "structural" || hit.repaired === true);
    expect(validated.length, "random data must not yield structurally validated or repaired carves").toBe(0);
  });
});

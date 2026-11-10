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

import { crc32 } from "../../utils/binary";
import { parsePngFile } from "./parser";

export type PngDimensionCandidate = {
  width: number; height: number; crcMatch: boolean; bytes: Uint8Array;
};
export type PngDimensionRecovery = {
  status: "not-png" | "consistent" | "recovered" | "ambiguous" | "unavailable";
  reason: string;
  declaredWidth: number; declaredHeight: number;
  inflatedBytes: number; searchedWidth: number; candidateCount: number;
  candidates: PngDimensionCandidate[];
};
const MAX_WIDTH = 65535;
const MAX_PIXELS = 50_000_000;
const MAX_INFLATED = 64 * 1024 * 1024;
const PASSES = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];

/** Layout follows W3C PNG sections 8, 9 and 11.2.1, including packed samples and Adam7. */
function layout(width: number, height: number, bits: number, interlace: number) {
  return (interlace ? PASSES : [[0, 0, 1, 1]]).map(([x, y, dx, dy]) => {
    const w = Math.max(0, Math.ceil((width - x) / dx));
    const h = Math.max(0, Math.ceil((height - y) / dy));
    return { stride: Math.ceil(w * bits / 8) + 1, rows: w ? h : 0 };
  });
}

async function inflateBounded(parts: Uint8Array[]) {
  // Native streaming inflation checks the zlib/Adler stream and bounds retained output.
  const input = new Blob(parts.map((part) => part.slice().buffer as ArrayBuffer));
  const reader = input.stream().pipeThrough(new DecompressionStream("deflate")).getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_INFLATED) throw new Error("inflate-limit");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
  return bytes;
}

/** Invert the 32 CRC influence vectors for the four height bytes once.
 * Each width then requires one CRC and four table lookups, rather than a 2-D loop.
 * Bit tags encode bytes in little-endian order; PNG integers are big-endian.
 */
function heightSolver(message: Uint8Array) {
  const base = message.slice();
  base.fill(0, 8, 12);
  const initial = crc32(base);
  const vectors = new Uint32Array(32);
  const tags = new Uint32Array(32);
  for (let bit = 0; bit < 32; bit++) {
    const probe = base.slice();
    probe[8 + (bit >>> 3)] ^= 1 << (bit & 7);
    let vector = (crc32(probe) ^ initial) >>> 0;
    let tag = (1 << bit) >>> 0;
    for (let pivot = 31; pivot >= 0; pivot--) {
      if (!((vector >>> pivot) & 1)) continue;
      if (vectors[pivot]) { vector = (vector ^ vectors[pivot]) >>> 0; tag = (tag ^ tags[pivot]) >>> 0; }
      else { vectors[pivot] = vector; tags[pivot] = tag; break; }
    }
  }
  const solve = (delta: number) => {
    let answer = 0;
    for (let pivot = 31; pivot >= 0; pivot--) if ((delta >>> pivot) & 1) {
      delta = (delta ^ vectors[pivot]) >>> 0;
      answer = (answer ^ tags[pivot]) >>> 0;
    }
    return answer;
  };
  const tables = Array.from({ length: 4 }, (_, byte) => Uint32Array.from({ length: 256 }, (_, value) => solve(value << (8 * byte))));
  return (delta: number) => {
    const tag = tables[0][delta & 255] ^ tables[1][(delta >>> 8) & 255] ^ tables[2][(delta >>> 16) & 255] ^ tables[3][delta >>> 24];
    return ((tag & 255) * 0x1000000 + ((tag >>> 8) & 255) * 0x10000 + ((tag >>> 16) & 255) * 0x100 + (tag >>> 24)) >>> 0;
  };
}

export async function recoverPngDimensions(bytes: Uint8Array): Promise<PngDimensionRecovery> {
  const result: PngDimensionRecovery = { status: "not-png", reason: "not-png", declaredWidth: 0, declaredHeight: 0, inflatedBytes: 0, searchedWidth: 0, candidateCount: 0, candidates: [] };
  if (bytes.length < 8 || bytes[0] !== 137 || String.fromCharCode(...bytes.subarray(1, 4)) !== "PNG") return result;
  result.status = "unavailable";
  let parsed: ReturnType<typeof parsePngFile>;
  try { parsed = parsePngFile(bytes); } catch { return { ...result, reason: "invalid-container" }; }
  const ihdr = parsed.chunks.find((chunk) => chunk.type === "IHDR");
  const idats = parsed.chunks.filter((chunk) => chunk.type === "IDAT");
  if (!ihdr || ihdr.length !== 13 || !idats.length) return { ...result, reason: "missing-critical" };
  const start = ihdr.dataOffset;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  result.declaredWidth = view.getUint32(start); result.declaredHeight = view.getUint32(start + 4);
  const depth = bytes[start + 8], color = bytes[start + 9], interlace = bytes[start + 12];
  const channels: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
  const depths: Record<number, number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
  if (!depths[color]?.includes(depth) || bytes[start + 10] !== 0 || bytes[start + 11] !== 0 || interlace > 1) return { ...result, reason: "unsupported-header" };
  const bits = channels[color] * depth;
  let pixels: Uint8Array;
  try { pixels = await inflateBounded(idats.map((chunk) => bytes.subarray(chunk.dataOffset, chunk.dataOffset + chunk.length))); }
  catch (error) { return { ...result, reason: error instanceof Error && error.message === "inflate-limit" ? "inflate-limit" : "invalid-idat" }; }
  result.inflatedBytes = pixels.length;
  let checks = 0;
  const valid = (width: number, height: number) => {
    if (!width || !height || width > MAX_WIDTH || height > MAX_WIDTH || width * height > MAX_PIXELS) return false;
    const passes = layout(width, height, bits, interlace);
    if (passes.reduce((size, pass) => size + pass.stride * pass.rows, 0) !== pixels.length) return false;
    let offset = 0;
    for (const pass of passes) for (let row = 0; row < pass.rows; row++, offset += pass.stride) {
      if (++checks > 8_000_000 || pixels[offset] > 4) return false;
    }
    return true;
  };
  const currentValid = valid(result.declaredWidth, result.declaredHeight);
  if (ihdr.ok && currentValid) return { ...result, status: "consistent", reason: "consistent" };
  const message = bytes.slice(start - 4, start + 13);
  message.fill(0, 8, 12);
  const messageView = new DataView(message.buffer);
  const solve = heightSolver(message);
  const originalCrc = Number.parseInt(ihdr.crc.slice(2), 16);
  const matches: Array<{ width: number; height: number; crcMatch: boolean }> = [];
  for (let width = 1; width <= MAX_WIDTH; width++) {
    messageView.setUint32(4, width);
    const height = solve((originalCrc ^ crc32(message)) >>> 0);
    if (valid(width, height)) matches.push({ width, height, crcMatch: true });
  }
  result.searchedWidth = MAX_WIDTH;
  // If the original CRC was overwritten, filtered scanline lengths constrain dimensions.
  // Interlaced fallback uses monotonic byte counts to derive height for each width.
  if (!matches.length) for (let width = 1; width <= MAX_WIDTH; width++) {
    let height: number;
    if (!interlace) {
      const stride = Math.ceil(width * bits / 8) + 1;
      if (pixels.length % stride) continue;
      height = pixels.length / stride;
    } else {
      let low = 1, high = Math.min(MAX_WIDTH, Math.floor(MAX_PIXELS / width));
      while (low < high) {
        const mid = Math.floor((low + high) / 2);
        const length = layout(width, mid, bits, interlace).reduce((size, pass) => size + pass.stride * pass.rows, 0);
        if (length < pixels.length) low = mid + 1; else high = mid;
      }
      height = low;
    }
    if (valid(width, height)) matches.push({ width, height, crcMatch: false });
    if (checks > 8_000_000) break;
  }
  result.candidateCount = matches.length;
  const ranked = matches.sort((a, b) => Number(b.width === result.declaredWidth || b.height === result.declaredHeight) - Number(a.width === result.declaredWidth || a.height === result.declaredHeight));
  const copyLimit = Math.min(8, Math.max(1, Math.floor(MAX_INFLATED / Math.max(bytes.length, 1))));
  result.candidates = ranked.slice(0, copyLimit).map((candidate) => {
    const output = bytes.slice(); // preserve ancillary chunks, compressed pixels and appended evidence
    const outputView = new DataView(output.buffer);
    outputView.setUint32(start, candidate.width); outputView.setUint32(start + 4, candidate.height);
    outputView.setUint32(start + 13, crc32(output.subarray(start - 4, start + 13)));
    return { ...candidate, bytes: output };
  });
  result.status = matches.length ? (matches.length === 1 && matches[0].crcMatch ? "recovered" : "ambiguous") : "unavailable";
  result.reason = matches.length ? (matches[0].crcMatch ? "crc-and-scanlines" : "scanlines-only") : checks > 8_000_000 ? "search-limit" : "no-match";
  return result;
}

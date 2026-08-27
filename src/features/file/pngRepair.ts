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

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

export type PngRepairResult = {
  located: boolean;
  bytes: Uint8Array;
  notes: string[];
  signatureRepaired: boolean;
  truncated: boolean;
  /** Offset in the source buffer just past the last valid PNG chunk. */
  consumedEnd: number;
};

function viewOf(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function asciiAt(bytes: Uint8Array, offset: number, length: number) {
  let text = "";
  for (let index = 0; index < length; index += 1) text += String.fromCharCode(bytes[offset + index]);
  return text;
}

function isPngSignature(bytes: Uint8Array, offset: number) {
  return PNG_SIGNATURE.every((byte, index) => bytes[offset + index] === byte);
}

/**
 * Locate a PNG start inside an arbitrary buffer. Tolerant of a corrupted or
 * missing 8-byte signature: a PNG whose signature was zeroed/overwritten is
 * still found through its IHDR chunk, because IHDR is always the first chunk
 * and is immediately preceded by its 4-byte length (0x0000000D) and the
 * 8-byte signature region. This is the key to carving PNGs that other tools
 * report as "data" because their header was damaged.
 */
export function locatePngStart(bytes: Uint8Array, fromOffset = 0): number {
  const limit = Math.max(0, fromOffset);
  const view = viewOf(bytes);
  // Single ascending pass that checks BOTH a valid 8-byte signature and the
  // IHDR-based heuristic at each position. A valid-signature PNG is returned
  // directly; otherwise a corrupted/missing-signature PNG is found through its
  // IHDR chunk. Interleaving the two checks (instead of two separate loops)
  // is essential: a second, signature-valid PNG sitting *after* a corrupted one
  // must not be returned first, or the earlier corrupted PNG would be skipped
  // and never carved.
  for (let position = limit; position + 8 <= bytes.length; position += 1) {
    if (isPngSignature(bytes, position)) return position;
    // The IHDR heuristic reads up to position + 16 (interlace byte), so it
    // needs a slightly wider window; skip the IHDR branch near EOF.
    if (position + 17 > bytes.length) continue;
    if (bytes[position] !== 0x49 || bytes[position + 1] !== 0x48 || bytes[position + 2] !== 0x44 || bytes[position + 3] !== 0x52) continue;
    const chunkStart = position - 4;
    if (chunkStart < 8) continue;
    const length = view.getUint32(chunkStart);
    if (length !== 13) continue;
    const start = chunkStart - 8;
    // Never return a start that sits behind the search window. Doing so lets a
    // caller that advances by `start + 1` re-locate the *same* IHDR on every
    // pass and loop forever on buffers holding a spurious "IHDR" string that
    // repairPng rejects. A real PNG at/after `limit` always has its IHDR text
    // at `limit + 12` or later, so this never skips an in-window candidate.
    if (start < limit) continue;
    const dataStart = position + 4;
    const bitDepth = bytes[dataStart + 8];
    const colorType = bytes[dataStart + 9];
    const compression = bytes[dataStart + 10];
    const interlace = bytes[dataStart + 12];
    if (compression !== 0 || (interlace !== 0 && interlace !== 1)) continue;
    if (![0, 2, 3, 4, 6].includes(colorType)) continue;
    if (![1, 2, 4, 8, 16].includes(bitDepth)) continue;
    return start;
  }
  return -1;
}

function buildChunk(type: string, data: Uint8Array): Uint8Array {
  const output = new Uint8Array(12 + data.length);
  const view = new DataView(output.buffer);
  view.setUint32(0, data.length, false);
  for (let index = 0; index < 4; index += 1) output[4 + index] = type.charCodeAt(index);
  output.set(data, 8);
  view.setUint32(8 + data.length, crc32(output.slice(4, 8 + data.length)), false);
  return output;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

/**
 * Normalize a (possibly corrupted) PNG into a decoder-valid PNG:
 *  - rebuild the 8-byte signature when it was corrupted/missing;
 *  - recompute CRCs for any chunk with a mismatch;
 *  - append a fresh IEND when the file was truncated before its logical end;
 *  - drop trailing garbage after the regenerated IEND.
 * Refuses to emit output unless IHDR + IDAT are present, so random "IHDR"
 * text inside arbitrary data cannot produce a false-positive carve.
 */
export function repairPng(source: Uint8Array, startArg?: number): PngRepairResult {
  const start = startArg ?? locatePngStart(source);
  if (start < 0) {
    return { located: false, bytes: new Uint8Array(), notes: [], signatureRepaired: false, truncated: false, consumedEnd: 0 };
  }
  const view = viewOf(source);
  const signatureRepaired = !isPngSignature(source, start);
  const chunks: Array<{ type: string; data: Uint8Array }> = [];
  let cursor = start + 8;
  let sawIhdr = false;
  let sawIdat = false;
  let sawIend = false;
  let badCrc = 0;
  let consumedEnd = start + 8;
  walk: while (cursor + 12 <= source.length) {
    const length = view.getUint32(cursor);
    // A chunk length above 2 GiB is impossible in a conformant PNG. If we have
    // not yet seen the minimum IHDR+IDAT, the stream is simply not a coherent
    // PNG — refuse to emit. If we already have IHDR+IDAT, this is just the
    // corrupt/truncated tail of a capture that was cut off mid-stream, so stop
    // here (it becomes a truncated PNG) instead of discarding good data or
    // allocating based on an absurd length.
    if (length > 0x7fffffff) {
      if (sawIhdr && sawIdat) {
        consumedEnd = cursor;
        break walk;
      }
      return {
        located: false,
        bytes: new Uint8Array(),
        notes: ["PNG chunk length exceeds the 2 GiB limit; the structure is not a coherent PNG."],
        signatureRepaired,
        truncated: false,
        consumedEnd: start + 8
      };
    }
    const type = asciiAt(source, cursor + 4, 4);
    const dataStart = cursor + 8;
    const dataEnd = dataStart + length;
    // A complete chunk needs data + its 4-byte CRC to fit inside the buffer.
    // If either the data or the trailing CRC runs past EOF, treat this as the
    // truncated final chunk and absorb whatever bytes ARE present, so a cut-off
    // IHDR/IDAT is never silently dropped. The rebuilt CRC is recomputed over
    // the clamped data, so the output is still a well-formed PNG.
    if (dataEnd + 4 > source.length) {
      const data = source.slice(dataStart, source.length);
      if (type === "IHDR") sawIhdr = true;
      if (type === "IDAT") sawIdat = true;
      if (type === "IEND") sawIend = true;
      chunks.push({ type, data });
      consumedEnd = source.length;
      break walk;
    }
    const data = source.slice(dataStart, dataEnd);
    const stored = view.getUint32(dataEnd);
    const computed = crc32(source.slice(cursor + 4, dataEnd));
    if (stored !== computed) badCrc += 1;
    if (type === "IHDR") sawIhdr = true;
    if (type === "IDAT") sawIdat = true;
    if (type === "IEND") {
      sawIend = true;
      chunks.push({ type, data });
      consumedEnd = dataEnd + 4;
      break walk;
    }
    chunks.push({ type, data });
    cursor = dataEnd + 4;
    consumedEnd = cursor;
  }
  if (!sawIhdr || !sawIdat) {
    return {
      located: false,
      bytes: new Uint8Array(),
      notes: ["PNG IHDR/IDAT not found; refusing to emit a false-positive carve."],
      signatureRepaired,
      truncated: false,
      consumedEnd: start + 8
    };
  }
  const parts: Uint8Array[] = [new Uint8Array(PNG_SIGNATURE)];
  for (const chunk of chunks) parts.push(buildChunk(chunk.type, chunk.data));
  if (!sawIend) parts.push(buildChunk("IEND", new Uint8Array()));
  const rebuilt = concatBytes(parts);
  const notes: string[] = [];
  if (signatureRepaired) notes.push("Rebuilt the 8-byte PNG signature (original was corrupted or missing).");
  if (badCrc) notes.push(`Recomputed CRC for ${badCrc} chunk(s) with mismatched CRC.`);
  if (!sawIend) notes.push("Appended a fresh IEND chunk; the source PNG was truncated before its logical end.");
  return { located: true, bytes: rebuilt, notes, signatureRepaired, truncated: !sawIend, consumedEnd };
}

export type PngCandidate = {
  offset: number;
  size: number;
  extent: "exact" | "repaired";
  confidence: "medium" | "high";
  repaired: boolean;
  repairNote: string;
  repairedBytes: Uint8Array;
};

/**
 * Scan a buffer for PNG objects (signature-valid or signature-corrupted) and
 * return repair-ready candidates. Continues past each found PNG so multiple
 * embedded PNGs are all recovered.
 */
export function findPngCandidates(bytes: Uint8Array, fromOffset = 0, maxHits = 64): PngCandidate[] {
  const output: PngCandidate[] = [];
  let search = Math.max(0, fromOffset);
  while (output.length < maxHits && search + 8 <= bytes.length) {
    const start = locatePngStart(bytes, search);
    if (start < 0) break;
    const repair = repairPng(bytes, start);
    if (!repair.located) {
      search = start + 1;
      continue;
    }
    const signatureValid = isPngSignature(bytes, start);
    const exact = signatureValid && !repair.truncated;
    const size = repair.consumedEnd > start ? repair.consumedEnd - start : bytes.length - start;
    output.push({
      offset: start,
      size,
      extent: exact ? "exact" : "repaired",
      confidence: exact ? "high" : "medium",
      repaired: repair.signatureRepaired || repair.truncated || badCrcIn(repair.notes),
      repairNote: repair.notes.join(" "),
      repairedBytes: repair.bytes
    });
    search = repair.consumedEnd > start ? repair.consumedEnd : start + 1;
  }
  return output;
}

function badCrcIn(notes: string[]) {
  return notes.some((note) => /CRC/.test(note));
}

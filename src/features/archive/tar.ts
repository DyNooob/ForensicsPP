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

export type TarEntryKind = "file" | "directory" | "symlink" | "hardlink" | "other";

export type TarEntry = {
  name: string;
  mode: number;
  uid: number;
  gid: number;
  mtime: number;
  size: number;
  kind: TarEntryKind;
  linkTarget: string;
  dataOffset: number;
  dataLength: number;
};

export type TarParseResult = {
  entries: TarEntry[];
  skipped: number;
};

const BLOCK = 512;

function readOctalOrBase256(bytes: Uint8Array, start: number, length: number): number | null {
  if (length <= 0) return 0;
  const high = bytes[start];
  if (high & 0x80) {
    let value = 0;
    for (let index = 0; index < length; index += 1) {
      value = value * 256 + bytes[start + index];
    }
    return value;
  }
  let acc = 0;
  let foundDigit = false;
  for (let index = 0; index < length; index += 1) {
    const byte = bytes[start + index];
    if (byte === 0x20 || byte === 0) {
      if (!foundDigit) continue;
      break;
    }
    if (byte < 0x30 || byte > 0x37) return null;
    foundDigit = true;
    acc = acc * 8 + (byte - 0x30);
  }
  return foundDigit ? acc : 0;
}

function readString(bytes: Uint8Array, start: number, length: number): string {
  let end = start;
  const limit = start + length;
  while (end < limit && bytes[end] !== 0) end += 1;
  return new TextDecoder().decode(bytes.subarray(start, end));
}

function readPaxRecords(block: Uint8Array): Record<string, string> {
  const text = new TextDecoder().decode(block);
  const records: Record<string, string> = {};
  let index = 0;
  while (index < text.length) {
    const space = text.indexOf(" ", index);
    if (space < 0) break;
    const length = Number.parseInt(text.slice(index, space), 10);
    if (!Number.isFinite(length) || length <= 0) break;
    const entry = text.slice(space + 1, index + length - 1);
    const eq = entry.indexOf("=");
    if (eq > 0) records[entry.slice(0, eq)] = entry.slice(eq + 1);
    index += length;
  }
  return records;
}

function classify(typeFlag: string, mode: number): TarEntryKind {
  if (typeFlag === "5") return "directory";
  if (typeFlag === "2") return "symlink";
  if (typeFlag === "1") return "hardlink";
  if (typeFlag === "0" || typeFlag === "7" || typeFlag === "\0" || typeFlag === "") return "file";
  return "other";
}

function computeChecksum(header: Uint8Array): number | null {
  let expected = 0;
  for (let index = 0; index < BLOCK; index += 1) {
    expected += header[index];
  }
  const stored = readOctalOrBase256(header, 148, 8);
  if (stored === null) return null;
  let signed = 0;
  for (let index = 0; index < BLOCK; index += 1) {
    signed += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (stored === expected || stored === signed) return stored;
  return null;
}

function isTarBlock(bytes: Uint8Array, offset: number): boolean {
  if (offset + BLOCK > bytes.length) return false;
  const header = bytes.subarray(offset, offset + BLOCK);
  const checksum = computeChecksum(header);
  if (checksum === null) return false;
  const typeFlag = String.fromCharCode(header[156] || 0);
  const kind = classify(typeFlag, 0);
  if (kind === "other" && typeFlag !== "L" && typeFlag !== "K" && typeFlag !== "x" && typeFlag !== "g" && typeFlag !== "V") return false;
  const size = readOctalOrBase256(header, 124, 12);
  if (size === null) return false;
  return true;
}

/**
 * Parse a (classic/ustar/POSIX/GNU) tar container without inflating entry data.
 * GNU long names (type 'L'/'K') and pax extended headers (type 'x') are honored.
 */
export function parseTar(bytes: Uint8Array, maxEntries = 2000): TarParseResult {
  const entries: TarEntry[] = [];
  let skipped = 0;
  if (bytes.length < BLOCK) return { entries, skipped };
  let offset = 0;
  let pendingLongName: string | null = null;
  let pendingLongLink: string | null = null;
  let pendingPax: Record<string, string> | null = null;

  while (offset + BLOCK <= bytes.length) {
    const header = bytes.subarray(offset, offset + BLOCK);
    const nameRaw = readString(header, 0, 100);
    if (nameRaw.length === 0 && header[0] === 0) {
      const allZero = header.every((value) => value === 0);
      if (allZero) break;
    }
    if (!isTarBlock(bytes, offset)) break;

    const typeFlag = String.fromCharCode(header[156] || 0);
    const size = readOctalOrBase256(header, 124, 12) ?? 0;
    const dataStart = offset + BLOCK;
    const dataLength = Number.isFinite(size) ? size : 0;
    const blocks = Math.ceil(dataLength / BLOCK) || 0;
    const nextOffset = dataStart + blocks * BLOCK;

    if (typeFlag === "L") {
      pendingLongName = new TextDecoder().decode(bytes.subarray(dataStart, dataStart + dataLength)).replace(/\0+$/, "");
      offset = nextOffset;
      continue;
    }
    if (typeFlag === "K") {
      pendingLongLink = new TextDecoder().decode(bytes.subarray(dataStart, dataStart + dataLength)).replace(/\0+$/, "");
      offset = nextOffset;
      continue;
    }
    if (typeFlag === "x" || typeFlag === "g") {
      pendingPax = readPaxRecords(bytes.subarray(dataStart, dataStart + dataLength));
      offset = nextOffset;
      continue;
    }

    let name = pendingLongName ?? nameRaw;
    let entrySize = dataLength;
    let entryMode = readOctalOrBase256(header, 100, 8) ?? 0;
    let entryMtime = readOctalOrBase256(header, 136, 12) ?? 0;
    if (pendingPax) {
      if (pendingPax.path) name = pendingPax.path;
      if (pendingPax.size) entrySize = Number.parseInt(pendingPax.size, 10) || entrySize;
      if (pendingPax.mtime) entryMtime = Number.parseInt(pendingPax.mtime, 10) || entryMtime;
      if (pendingPax.mode) entryMode = Number.parseInt(pendingPax.mode, 8) || entryMode;
    }

    const kind = classify(typeFlag, entryMode);
    const linkTarget = pendingLongLink ?? readString(header, 157, 100);
    pendingLongName = null;
    pendingLongLink = null;
    pendingPax = null;

    if (kind === "other") {
      skipped += 1;
      offset = nextOffset;
      continue;
    }
    if (entries.length < maxEntries) {
      entries.push({
        name,
        mode: entryMode,
        uid: readOctalOrBase256(header, 108, 8) ?? 0,
        gid: readOctalOrBase256(header, 116, 8) ?? 0,
        mtime: entryMtime,
        size: entrySize,
        kind,
        linkTarget,
        dataOffset: dataStart,
        dataLength: entrySize
      });
    } else {
      skipped += 1;
    }
    offset = nextOffset;
  }

  return { entries, skipped };
}

export function detectTar(bytes: Uint8Array): boolean {
  if (bytes.length < BLOCK) return false;
  return isTarBlock(bytes, 0);
}

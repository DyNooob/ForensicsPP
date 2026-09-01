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

export type CpioEntryKind = "file" | "directory" | "symlink" | "other";

export type CpioEntry = {
  name: string;
  mode: number;
  mtime: number;
  size: number;
  kind: CpioEntryKind;
  dataOffset: number;
  dataLength: number;
};

export type CpioParseResult = {
  entries: CpioEntry[];
  skipped: number;
};

const S_IFMT = 0xf000;
const S_IFDIR = 0x4000;
const S_IFLNK = 0xa000;
const S_IFREG = 0x8000;

function classify(mode: number): CpioEntryKind {
  const type = mode & S_IFMT;
  if (type === S_IFDIR) return "directory";
  if (type === S_IFLNK) return "symlink";
  if (type === S_IFREG) return "file";
  return "other";
}

function decodeName(bytes: Uint8Array, start: number, length: number): string {
  const end = start + Math.max(0, length - 1);
  return new TextDecoder().decode(bytes.subarray(start, end));
}

function readHex(bytes: Uint8Array, start: number, length: number): number {
  let value = 0;
  for (let index = 0; index < length; index += 1) {
    const byte = bytes[start + index];
    const digit =
      byte >= 0x30 && byte <= 0x39 ? byte - 0x30 :
      byte >= 0x61 && byte <= 0x66 ? byte - 0x61 + 10 :
      byte >= 0x41 && byte <= 0x46 ? byte - 0x41 + 10 : 0;
    value = value * 16 + digit;
  }
  return value;
}

function readOctal(bytes: Uint8Array, start: number, length: number): number {
  let value = 0;
  let found = false;
  for (let index = 0; index < length; index += 1) {
    const byte = bytes[start + index];
    if (byte === 0x20 || byte === 0) {
      if (!found) continue;
      break;
    }
    if (byte < 0x30 || byte > 0x37) break;
    found = true;
    value = value * 8 + (byte - 0x30);
  }
  return found ? value : 0;
}

function padToBoundary(value: number, boundary: number): number {
  const remainder = value % boundary;
  return remainder === 0 ? 0 : boundary - remainder;
}

/**
 * Parse a cpio container (newc/SVR4 070701/070702 and ASCII odc 070707) without
 * inflating entry data. The trailing "TRAILER!!!" marker ends the archive.
 */
export function parseCpio(bytes: Uint8Array, maxEntries = 2000): CpioParseResult {
  const entries: CpioEntry[] = [];
  let skipped = 0;
  let offset = 0;

  while (offset + 6 <= bytes.length) {
    const magic = String.fromCharCode(
      bytes[offset],
      bytes[offset + 1],
      bytes[offset + 2],
      bytes[offset + 3],
      bytes[offset + 4],
      bytes[offset + 5]
    );

    if (magic === "070701" || magic === "070702") {
      let cursor = offset + 6;
      const fields: number[] = [];
      for (let index = 0; index < 13; index += 1) {
        fields.push(readHex(bytes, cursor, 8));
        cursor += 8;
      }
      const [mode, mtime, filesize, namesize] = [fields[1], fields[5], fields[6], fields[11]];
      const name = decodeName(bytes, cursor, namesize);
      cursor += namesize + padToBoundary(cursor + namesize, 4);
      const dataOffset = cursor;
      const dataLength = filesize;
      cursor += filesize + padToBoundary(filesize, 4);

      if (name === "TRAILER!!!") break;
      const kind = classify(mode);
      const entryName = kind === "directory" && !name.endsWith("/") ? `${name}/` : name;
      if (entries.length < maxEntries) {
        entries.push({ name: entryName, mode, mtime, size: dataLength, kind, dataOffset, dataLength });
      } else {
        skipped += 1;
      }
      offset = cursor;
    } else if (magic === "070707") {
      let cursor = offset + 6;
      const skip = (count: number) => {
        const value = readOctal(bytes, cursor, count);
        cursor += count;
        return value;
      };
      skip(6);
      skip(6);
      const mode = skip(6);
      skip(6);
      skip(6);
      skip(6);
      skip(6);
      const mtime = skip(11);
      const namesize = skip(6);
      const filesize = skip(11);
      const name = decodeName(bytes, cursor, namesize);
      cursor += namesize + padToBoundary(cursor + namesize, 2);
      const dataOffset = cursor;
      const dataLength = filesize;
      cursor += filesize + padToBoundary(filesize, 2);

      if (name === "TRAILER!!!") break;
      const kind = classify(mode);
      const entryName = kind === "directory" && !name.endsWith("/") ? `${name}/` : name;
      if (entries.length < maxEntries) {
        entries.push({ name: entryName, mode, mtime, size: dataLength, kind, dataOffset, dataLength });
      } else {
        skipped += 1;
      }
      offset = cursor;
    } else {
      break;
    }
  }

  return { entries, skipped };
}

export function detectCpio(bytes: Uint8Array): boolean {
  if (bytes.length < 6) return false;
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
  return magic === "070701" || magic === "070702" || magic === "070707";
}

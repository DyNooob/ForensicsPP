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

export type ZipDirectoryEntry = {
  name: string;
  method: number;
  compressed: number;
  uncompressed: number;
  encrypted: boolean;
};

export type ZipDirectory = {
  entries: ZipDirectoryEntry[];
  skipped: number;
  declaredEntries: number;
  totalCompressed: number;
  totalUncompressed: number;
  eocdOffset: number;
};

export type ZipExpansionPolicy = {
  maxEntries: number;
  maxEntryUncompressed: number;
  maxTotalUncompressed: number;
  maxCompressionRatio: number;
  ratioGuardMinimum: number;
};

function decodeEntryName(nameBytes: Uint8Array, utf8: boolean) {
  if (utf8) return new TextDecoder().decode(nameBytes);
  try {
    return new TextDecoder("windows-1252").decode(nameBytes);
  } catch {
    return new TextDecoder().decode(nameBytes);
  }
}

/**
 * Parses the classic ZIP central directory without inflating entry data.
 * Zip64 archives are intentionally not accepted by this lightweight parser.
 */
export function parseZipCentralDirectory(bytes: Uint8Array, maxEntries = 20_000): ZipDirectory | null {
  if (bytes.length < 22) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocdOffset = -1;
  const searchStart = Math.max(0, bytes.length - 65_557);
  for (let offset = searchStart; offset + 22 <= bytes.length; offset += 1) {
    if (view.getUint32(offset, true) === 0x06054b50) eocdOffset = offset;
  }
  if (eocdOffset < 0) return null;

  const diskNumber = view.getUint16(eocdOffset + 4, true);
  const directoryDisk = view.getUint16(eocdOffset + 6, true);
  const declaredEntries = view.getUint16(eocdOffset + 10, true);
  const directorySize = view.getUint32(eocdOffset + 12, true);
  const directoryOffset = view.getUint32(eocdOffset + 16, true);
  if (diskNumber !== 0 || directoryDisk !== 0) return null;
  if (declaredEntries === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) return null;
  if (directoryOffset > bytes.length || directoryOffset + directorySize > bytes.length) return null;

  const entries: ZipDirectoryEntry[] = [];
  let offset = directoryOffset;
  const directoryEnd = Math.min(eocdOffset, directoryOffset + directorySize);
  let totalCompressed = 0;
  let totalUncompressed = 0;
  while (offset + 46 <= directoryEnd && entries.length < maxEntries) {
    if (view.getUint32(offset, true) !== 0x02014b50) break;
    const flags = view.getUint16(offset + 8, true);
    const method = view.getUint16(offset + 10, true);
    const compressed = view.getUint32(offset + 20, true);
    const uncompressed = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const nameOffset = offset + 46;
    const nextOffset = nameOffset + nameLength + extraLength + commentLength;
    if (nextOffset > directoryEnd || nextOffset > bytes.length) break;
    const name = decodeEntryName(bytes.subarray(nameOffset, nameOffset + nameLength), Boolean(flags & 0x800));
    entries.push({ name, method, compressed, uncompressed, encrypted: Boolean(flags & 1) });
    totalCompressed += compressed;
    totalUncompressed += uncompressed;
    offset = nextOffset;
  }

  return {
    entries,
    skipped: Math.max(0, declaredEntries - entries.length),
    declaredEntries,
    totalCompressed,
    totalUncompressed,
    eocdOffset
  };
}

export function validateZipExpansion(bytes: Uint8Array, policy: ZipExpansionPolicy) {
  const directory = parseZipCentralDirectory(bytes, policy.maxEntries);
  if (!directory) throw new Error("ZIP central directory is malformed, unsupported, or Zip64.");
  if (directory.declaredEntries > policy.maxEntries || directory.skipped > 0) {
    throw new Error(`ZIP contains too many entries (${directory.declaredEntries}; limit ${policy.maxEntries}).`);
  }
  if (directory.totalUncompressed > policy.maxTotalUncompressed) {
    throw new Error(`ZIP expands to ${directory.totalUncompressed} bytes; browser safety limit is ${policy.maxTotalUncompressed} bytes.`);
  }
  for (const entry of directory.entries) {
    if (entry.uncompressed > policy.maxEntryUncompressed) {
      throw new Error(`ZIP entry ${entry.name} expands to ${entry.uncompressed} bytes; per-entry safety limit is ${policy.maxEntryUncompressed} bytes.`);
    }
    const ratio = entry.compressed > 0 ? entry.uncompressed / entry.compressed : entry.uncompressed ? Number.POSITIVE_INFINITY : 0;
    if (entry.uncompressed >= policy.ratioGuardMinimum && ratio > policy.maxCompressionRatio) {
      throw new Error(`ZIP entry ${entry.name} has suspicious compression ratio ${ratio.toFixed(1)}:1.`);
    }
  }
  return directory;
}

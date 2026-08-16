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

import { gunzipSync, unzipSync, unzlibSync } from "fflate";
import { validateZipExpansion } from "../archive/zipDirectory";

export type ExpandedContainerEntry = {
  name: string;
  bytes: Uint8Array;
  sourceKind: "zip" | "gzip" | "zlib" | "tar" | "cpio";
};

export type ContainerExpansionLimits = {
  maxEntries: number;
  maxEntryBytes: number;
  maxTotalBytes: number;
  maxCompressionRatio?: number;
};

function ascii(bytes: Uint8Array, offset: number, length: number) {
  if (offset < 0 || offset + length > bytes.length) return "";
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(offset, offset + length));
}

function safeName(name: string) {
  return name.replace(/\\/g, "/").replace(/^\/+/, "").replace(/(?:^|\/)\.\.(?=\/|$)/g, "_").slice(0, 1024) || "entry.bin";
}

function isZip(bytes: Uint8Array) {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && [0x03, 0x05, 0x07].includes(bytes[2]);
}

function isGzip(bytes: Uint8Array) {
  return bytes.length >= 3 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 0x08;
}

function isZlib(bytes: Uint8Array) {
  if (bytes.length < 2) return false;
  const header = (bytes[0] << 8) | bytes[1];
  return (bytes[0] & 0x0f) === 8 && header % 31 === 0;
}

function isTar(bytes: Uint8Array) {
  return bytes.length >= 512 && ascii(bytes, 257, 5) === "ustar";
}

function isCpioNewc(bytes: Uint8Array) {
  const magic = ascii(bytes, 0, 6);
  return magic === "070701" || magic === "070702";
}

function parseTar(bytes: Uint8Array, limits: ContainerExpansionLimits) {
  const output: ExpandedContainerEntry[] = [];
  let total = 0;
  let cursor = 0;
  for (let index = 0; index < limits.maxEntries && cursor + 512 <= bytes.length; index += 1) {
    const header = bytes.subarray(cursor, cursor + 512);
    if (header.every((value) => value === 0)) break;
    const rawName = ascii(bytes, cursor, 100).replace(/\0.*$/, "");
    const prefix = ascii(bytes, cursor + 345, 155).replace(/\0.*$/, "");
    const name = safeName(prefix ? `${prefix}/${rawName}` : rawName);
    const rawSize = ascii(bytes, cursor + 124, 12).replace(/\0.*$/, "").trim();
    const size = Number.parseInt(rawSize || "0", 8);
    if (!Number.isFinite(size) || size < 0) break;
    const type = bytes[cursor + 156];
    const dataStart = cursor + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) break;
    if ((type === 0 || type === 0x30) && size > 0 && size <= limits.maxEntryBytes && total + size <= limits.maxTotalBytes) {
      const entryBytes = bytes.slice(dataStart, dataEnd);
      output.push({ name, bytes: entryBytes, sourceKind: "tar" });
      total += entryBytes.length;
    }
    cursor = dataStart + Math.ceil(size / 512) * 512;
  }
  return output;
}

function parseCpio(bytes: Uint8Array, limits: ContainerExpansionLimits) {
  const output: ExpandedContainerEntry[] = [];
  let total = 0;
  let cursor = 0;
  for (let index = 0; index < limits.maxEntries && cursor + 110 <= bytes.length; index += 1) {
    const magic = ascii(bytes, cursor, 6);
    if (magic !== "070701" && magic !== "070702") break;
    const fileSize = Number.parseInt(ascii(bytes, cursor + 54, 8), 16);
    const nameSize = Number.parseInt(ascii(bytes, cursor + 94, 8), 16);
    if (!Number.isFinite(fileSize) || !Number.isFinite(nameSize) || fileSize < 0 || nameSize <= 0) break;
    const nameStart = cursor + 110;
    const nameEnd = nameStart + nameSize;
    if (nameEnd > bytes.length) break;
    const name = safeName(ascii(bytes, nameStart, Math.max(0, nameSize - 1)));
    const dataStart = (nameEnd + 3) & ~3;
    const dataEnd = dataStart + fileSize;
    if (dataEnd > bytes.length) break;
    if (name === "TRAILER!!!") break;
    if (fileSize > 0 && fileSize <= limits.maxEntryBytes && total + fileSize <= limits.maxTotalBytes) {
      const entryBytes = bytes.slice(dataStart, dataEnd);
      output.push({ name, bytes: entryBytes, sourceKind: "cpio" });
      total += entryBytes.length;
    }
    cursor = (dataEnd + 3) & ~3;
  }
  return output;
}

export function containerKind(bytes: Uint8Array): ExpandedContainerEntry["sourceKind"] | null {
  if (isZip(bytes)) return "zip";
  if (isGzip(bytes)) return "gzip";
  if (isTar(bytes)) return "tar";
  if (isCpioNewc(bytes)) return "cpio";
  if (isZlib(bytes)) return "zlib";
  return null;
}

export function expandContainer(bytes: Uint8Array, limits: ContainerExpansionLimits): ExpandedContainerEntry[] {
  const kind = containerKind(bytes);
  if (!kind) return [];
  if (kind === "zip") {
    validateZipExpansion(bytes, {
      maxEntries: limits.maxEntries,
      maxEntryUncompressed: limits.maxEntryBytes,
      maxTotalUncompressed: limits.maxTotalBytes,
      maxCompressionRatio: limits.maxCompressionRatio ?? 250,
      ratioGuardMinimum: 1024 * 1024
    });
    const entries = unzipSync(bytes) as Record<string, Uint8Array>;
    const output: ExpandedContainerEntry[] = [];
    let total = 0;
    for (const [rawName, entryBytes] of Object.entries(entries)) {
      if (output.length >= limits.maxEntries) break;
      if (!entryBytes.length || entryBytes.length > limits.maxEntryBytes || total + entryBytes.length > limits.maxTotalBytes) continue;
      output.push({ name: safeName(rawName), bytes: entryBytes.slice(), sourceKind: "zip" });
      total += entryBytes.length;
    }
    return output;
  }
  if (kind === "gzip" || kind === "zlib") {
    const inflated = kind === "gzip" ? gunzipSync(bytes) : unzlibSync(bytes);
    if (!inflated.length || inflated.length > limits.maxEntryBytes || inflated.length > limits.maxTotalBytes) return [];
    return [{ name: kind === "gzip" ? "gunzip.bin" : "unzlib.bin", bytes: inflated.slice(), sourceKind: kind }];
  }
  if (kind === "tar") return parseTar(bytes, limits);
  return parseCpio(bytes, limits);
}

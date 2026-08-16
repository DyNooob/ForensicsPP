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

import CryptoJS from "crypto-js";
import type { EvidenceReader } from "../../core/evidence/reader";
import { analyzerForArtifact } from "../../core/analyzerRouting";
import type { ToolId } from "../../config/app";
import { bytesToWordArray, sha256BytesAsync } from "../../utils/hash";
import { carverFormats, scanCarvableObjects, type CarverConfidence, type CarverExtent } from "../file/carver";
import { scanRecursiveCarvableObjects } from "../file/recursiveCarver";

export type FirmwareEntropyBlock = {
  offset: number;
  endOffset: number;
  size: number;
  entropy: number;
  classification: "sparse" | "structured" | "high" | "very-high";
};

export type FirmwareObject = {
  id: string;
  label: string;
  offset: number;
  size: number;
  endOffset: number;
  extension: string;
  mime: string;
  confidence: CarverConfidence;
  extent: CarverExtent;
  detail: string;
  depth: number;
  parentId?: string;
  virtualPath: string;
  origin: "signature" | "archive-entry" | "decompressed";
  sha256?: string;
  architecture?: string;
  analyzer: ToolId;
  metadata?: Record<string, string>;
};

export type FirmwareAnalysis = {
  name: string;
  size: number;
  sha256: string;
  scannedBytes: number;
  chunkSize: number;
  objects: FirmwareObject[];
  entropy: FirmwareEntropyBlock[];
  counts: Record<string, number>;
  categories: Record<string, number>;
  architectures: Record<string, number>;
  interestingPaths: string[];
  warnings: string[];
  recursive: boolean;
  truncated: boolean;
};

export type FirmwareAnalysisSession = { analysis: FirmwareAnalysis; retained: Map<string, Uint8Array> };

export type FirmwareAnalyzeOptions = {
  signal?: AbortSignal;
  chunkSize?: number;
  maxObjects?: number;
  maxRecursiveBytes?: number;
  maxHashedObjects?: number;
  maxObjectHashBytes?: number;
  onProgress?: (loaded: number, total: number, phase: "scan" | "resolve" | "recursive") => void;
};

type Candidate = {
  label: string;
  offset: number;
  extension: string;
  mime: string;
  formatIndex: number;
};

const DEFAULT_CHUNK = 4 * 1024 * 1024;
const DEFAULT_MAX_OBJECTS = 2048;
const DEFAULT_RECURSIVE_BYTES = 128 * 1024 * 1024;
const MAX_PROBE = 8 * 1024 * 1024;
const MAX_HASH_OBJECT = 32 * 1024 * 1024;
const DEFAULT_MAX_OBJECT_HASH_BYTES = 256 * 1024 * 1024;

function abortError() {
  return new DOMException("Firmware analysis cancelled", "AbortError");
}

function concatBytes(left: Uint8Array, right: Uint8Array) {
  const output = new Uint8Array(left.length + right.length);
  output.set(left, 0);
  output.set(right, left.length);
  return output;
}

function matchAt(bytes: Uint8Array, offset: number, magic: number[]) {
  if (offset < 0 || offset + magic.length > bytes.length) return false;
  for (let index = 0; index < magic.length; index += 1) if (bytes[offset + index] !== magic[index]) return false;
  return true;
}

function entropyOf(bytes: Uint8Array) {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (const value of bytes) counts[value] += 1;
  let entropy = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function entropyClass(value: number, bytes: Uint8Array): FirmwareEntropyBlock["classification"] {
  let zero = 0;
  for (const byte of bytes) if (byte === 0) zero += 1;
  if (value <= 1 || zero / Math.max(1, bytes.length) >= 0.72) return "sparse";
  if (value >= 7.65) return "very-high";
  if (value >= 7.25) return "high";
  return "structured";
}

function view(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function structuralExtent(label: string, bytes: Uint8Array, sourceRemaining: number) {
  try {
    const data = view(bytes);
    let size = 0;
    let detail = "";
    if (label === "SQLite" && bytes.length >= 100) {
      const rawPageSize = data.getUint16(16, false);
      const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
      const pages = data.getUint32(28, false);
      if (pageSize >= 512 && pageSize <= 65536 && pages) {
        size = pageSize * pages;
        detail = "SQLite page size × database page count";
      }
    } else if (label === "SquashFS" && bytes.length >= 96) {
      size = Number(data.getBigUint64(40, true));
      detail = "SquashFS bytes_used";
    } else if (label === "U-Boot uImage" && bytes.length >= 64) {
      size = 64 + data.getUint32(12, false);
      detail = "U-Boot header + payload size";
    } else if (label === "Device Tree Blob" && bytes.length >= 40) {
      size = data.getUint32(4, false);
      detail = "DTB totalsize";
    } else if (label === "7z" && bytes.length >= 32) {
      size = 32 + Number(data.getBigUint64(12, true)) + Number(data.getBigUint64(20, true));
      detail = "7z next-header range";
    } else if (/FAT12\/16|FAT32/.test(label) && bytes.length >= 512) {
      const bps = data.getUint16(11, true);
      const sectors = data.getUint16(19, true) || data.getUint32(32, true);
      size = bps * sectors;
      detail = "FAT BPB total sectors × bytes/sector";
    } else if (label === "exFAT volume" && bytes.length >= 512) {
      const sectorShift = bytes[108];
      const sectors = Number(data.getBigUint64(72, true));
      if (sectorShift >= 9 && sectorShift <= 12) size = sectors * (2 ** sectorShift);
      detail = "exFAT volume length × bytes/sector";
    } else if (label === "NTFS volume" && bytes.length >= 512) {
      const bps = data.getUint16(11, true);
      const sectors = Number(data.getBigUint64(40, true));
      size = bps * sectors;
      detail = "NTFS total sectors × bytes/sector";
    } else if (label === "EXT filesystem" && bytes.length >= 1400) {
      const superblock = 1024;
      if (data.getUint16(superblock + 56, true) === 0xef53) {
        const logBlockSize = data.getUint32(superblock + 24, true);
        const blockSize = 1024 * (2 ** logBlockSize);
        const low = BigInt(data.getUint32(superblock + 4, true));
        const incompat = data.getUint32(superblock + 96, true);
        const high = incompat & 0x80 ? BigInt(data.getUint32(superblock + 336, true)) : 0n;
        const total = ((high << 32n) | low) * BigInt(blockSize);
        if (total <= BigInt(Number.MAX_SAFE_INTEGER)) size = Number(total);
        detail = "EXT superblock block count × block size";
      }
    } else if (label === "ISO9660" && bytes.length >= 0x8800) {
      const descriptor = 0x8000;
      const blocks = data.getUint32(descriptor + 80, true);
      const blockSize = data.getUint16(descriptor + 128, true);
      size = blocks * blockSize;
      detail = "ISO9660 volume space × logical block size";
    }
    if (Number.isSafeInteger(size) && size > 0 && size <= sourceRemaining) return { size, detail };
  } catch {
    // Malformed headers remain low-confidence signature evidence.
  }
  return null;
}

function architectureFromHeader(label: string, bytes: Uint8Array) {
  const mapElf: Record<number, string> = { 3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V" };
  const mapPe: Record<number, string> = { 0x014c: "x86", 0x8664: "x86-64", 0x01c0: "ARM", 0x01c4: "ARMv7", 0xaa64: "AArch64" };
  try {
    const data = view(bytes);
    if (label === "ELF" && bytes.length >= 20) {
      const little = bytes[5] === 1;
      return mapElf[data.getUint16(18, little)] ?? `ELF machine ${data.getUint16(18, little)}`;
    }
    if (label === "PE" && bytes.length >= 0x40) {
      const pe = data.getUint32(0x3c, true);
      if (pe + 6 <= bytes.length) return mapPe[data.getUint16(pe + 4, true)] ?? `PE machine 0x${data.getUint16(pe + 4, true).toString(16)}`;
    }
    if (label === "U-Boot uImage" && bytes.length >= 30) {
      const map: Record<number, string> = { 2: "ARM", 3: "x86", 5: "MIPS", 7: "PowerPC", 22: "AArch64", 26: "RISC-V" };
      return map[bytes[29]] ?? "";
    }
  } catch {
    return "";
  }
  return "";
}

function headerMetadata(label: string, bytes: Uint8Array) {
  const output: Record<string, string> = {};
  try {
    const data = view(bytes);
    if (label === "U-Boot uImage" && bytes.length >= 64) {
      const osMap: Record<number, string> = { 5: "Linux", 17: "VxWorks", 18: "QNX" };
      const archMap: Record<number, string> = { 2: "ARM", 3: "x86", 5: "MIPS", 7: "PowerPC", 22: "AArch64", 26: "RISC-V" };
      const typeMap: Record<number, string> = { 2: "Kernel", 3: "RAMDisk", 4: "Multi-File", 5: "Firmware", 6: "Script", 8: "Flat Device Tree", 14: "Kernel no-load" };
      const compMap: Record<number, string> = { 0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd" };
      output.Name = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(32, 64)).replace(/\0.*$/, "").trim() || "--";
      output["Data size"] = String(data.getUint32(12, false));
      output["Load address"] = `0x${data.getUint32(16, false).toString(16).toUpperCase()}`;
      output["Entry point"] = `0x${data.getUint32(20, false).toString(16).toUpperCase()}`;
      output.OS = osMap[bytes[28]] ?? String(bytes[28]);
      output.Architecture = archMap[bytes[29]] ?? String(bytes[29]);
      output.Type = typeMap[bytes[30]] ?? String(bytes[30]);
      output.Compression = compMap[bytes[31]] ?? String(bytes[31]);
    } else if (label === "SquashFS" && bytes.length >= 96) {
      const compression: Record<number, string> = { 1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd" };
      output.Inodes = String(data.getUint32(4, true));
      output["Block size"] = String(data.getUint32(12, true));
      output.Compression = compression[data.getUint16(20, true)] ?? String(data.getUint16(20, true));
      output.Version = `${data.getUint16(28, true)}.${data.getUint16(30, true)}`;
      output["Bytes used"] = String(Number(data.getBigUint64(40, true)));
    } else if (label === "Device Tree Blob" && bytes.length >= 40) {
      output["Total size"] = String(data.getUint32(4, false));
      output["Structure offset"] = `0x${data.getUint32(8, false).toString(16).toUpperCase()}`;
      output["Strings offset"] = `0x${data.getUint32(12, false).toString(16).toUpperCase()}`;
      output.Version = String(data.getUint32(20, false));
      output["Last compatible"] = String(data.getUint32(24, false));
    } else if (label === "Android boot image" && bytes.length >= 48) {
      output["Kernel size"] = String(data.getUint32(8, true));
      output["Ramdisk size"] = String(data.getUint32(16, true));
      const maybeHeaderVersion = data.getUint32(40, true);
      output["Header version"] = String(maybeHeaderVersion);
      const pageSize = data.getUint32(36, true);
      if (pageSize >= 2048 && pageSize <= 65536) output["Page size"] = String(pageSize);
    } else if (label === "Android sparse image" && bytes.length >= 28) {
      output.Version = `${data.getUint16(4, true)}.${data.getUint16(6, true)}`;
      output["File header"] = String(data.getUint16(8, true));
      output["Chunk header"] = String(data.getUint16(10, true));
      output["Block size"] = String(data.getUint32(12, true));
      output["Output blocks"] = String(data.getUint32(16, true));
      output.Chunks = String(data.getUint32(20, true));
    } else if (label === "UBI erase-count header" && bytes.length >= 64) {
      output.Version = String(bytes[4]);
      output["Erase counter"] = String(data.getBigUint64(8, false));
      output["VID header offset"] = `0x${data.getUint32(16, false).toString(16).toUpperCase()}`;
      output["Data offset"] = `0x${data.getUint32(20, false).toString(16).toUpperCase()}`;
      output["Image sequence"] = String(data.getUint32(24, false));
    } else if (label === "JFFS2 node" && bytes.length >= 12) {
      output["Node type"] = `0x${data.getUint16(2, true).toString(16).padStart(4, "0").toUpperCase()}`;
      output["Node length"] = String(data.getUint32(4, true));
      output["Header CRC"] = `0x${data.getUint32(8, true).toString(16).padStart(8, "0").toUpperCase()}`;
    }
  } catch {
    return output;
  }
  return output;
}

function categoryFor(label: string) {
  if (/SquashFS|JFFS2|UBI|FAT|exFAT|EXT filesystem|NTFS|ISO9660/.test(label)) return "Filesystem";
  if (/ELF|PE/.test(label)) return "Executable";
  if (/ZIP|Gzip|Zlib|Bzip2|XZ|Zstandard|7z|RAR|TAR|CPIO/.test(label)) return "Container";
  if (/Android|U-Boot|Device Tree/.test(label)) return "Firmware structure";
  if (/SQLite/.test(label)) return "Database";
  if (/PNG|JPEG|GIF|WEBP|BMP|PDF|OLE/.test(label)) return "Document / media";
  if (/PEM|certificate/i.test(label)) return "Certificate / key";
  return "Other";
}

function interestingPath(path: string) {
  return /(?:^|\/)(?:etc\/(?:passwd|shadow|config|hosts)|dropbear|ssh|private|certificate|\.pem$|\.key$|config\.(?:json|xml|db)|\.sqlite3?$|\.db$|rc\.local|init\.d|www\/|htdocs\/|cgi-bin)/i.test(path);
}

export async function analyzeFirmware(reader: EvidenceReader, name: string, options: FirmwareAnalyzeOptions = {}): Promise<FirmwareAnalysisSession> {
  const chunkSize = Math.max(256 * 1024, Math.min(32 * 1024 * 1024, options.chunkSize ?? DEFAULT_CHUNK));
  const maxObjects = Math.max(1, Math.min(10_000, options.maxObjects ?? DEFAULT_MAX_OBJECTS));
  const maxRecursiveBytes = Math.max(1024 * 1024, options.maxRecursiveBytes ?? DEFAULT_RECURSIVE_BYTES);
  const maxHashedObjects = Math.max(0, Math.min(512, options.maxHashedObjects ?? 96));
  const maxObjectHashBytes = Math.max(0, Math.min(2 * 1024 * 1024 * 1024, options.maxObjectHashBytes ?? DEFAULT_MAX_OBJECT_HASH_BYTES));
  const overlap = Math.min(128 * 1024, Math.max(...carverFormats.map((format) => (format.magicOffset ?? 0) + format.magic.length), 4096));
  const byFirst = new Map<number, Array<{ formatIndex: number; format: (typeof carverFormats)[number] }>>();
  carverFormats.forEach((format, formatIndex) => {
    const rows = byFirst.get(format.magic[0]) ?? [];
    rows.push({ formatIndex, format });
    byFirst.set(format.magic[0], rows);
  });

  const candidates: Candidate[] = [];
  const retained = new Map<string, Uint8Array>();
  let retainedBytes = 0;
  const maxRetainedBytes = 64 * 1024 * 1024;
  const seen = new Set<string>();
  const entropy: FirmwareEntropyBlock[] = [];
  const entropyBlockSize = Math.max(64 * 1024, Math.min(1024 * 1024, 2 ** Math.ceil(Math.log2(Math.max(64 * 1024, reader.size / 4096)))));
  const sha = CryptoJS.algo.SHA256.create();
  let previousTail = new Uint8Array();
  let loaded = 0;
  let entropyCarry = new Uint8Array();
  let entropyCarryOffset = 0;
  let truncated = false;

  while (loaded < reader.size) {
    if (options.signal?.aborted) throw abortError();
    const fresh = await reader.read(loaded, Math.min(chunkSize, reader.size - loaded), { signal: options.signal });
    sha.update(bytesToWordArray(fresh));
    const scanBytes = previousTail.length ? concatBytes(previousTail, fresh) : fresh;
    const baseOffset = loaded - previousTail.length;
    for (let position = 0; position < scanBytes.length && candidates.length < maxObjects; position += 1) {
      const rows = byFirst.get(scanBytes[position]);
      if (!rows) continue;
      for (const { format, formatIndex } of rows) {
        if (!matchAt(scanBytes, position, format.magic)) continue;
        const localObjectOffset = position - (format.magicOffset ?? 0);
        const globalOffset = baseOffset + localObjectOffset;
        if (localObjectOffset < 0 || globalOffset < 0 || globalOffset >= reader.size) continue;
        const key = `${formatIndex}:${globalOffset}`;
        if (seen.has(key)) continue;
        if (format.label !== "ZIP" && format.validate && !format.validate(scanBytes, localObjectOffset)) continue;
        seen.add(key);
        candidates.push({ label: format.label, offset: globalOffset, extension: format.extension, mime: format.mime, formatIndex });
        if (candidates.length >= maxObjects) { truncated = true; break; }
      }
    }

    let entropyBytes = fresh;
    let entropyBase = loaded;
    if (entropyCarry.length) {
      entropyBytes = concatBytes(entropyCarry, fresh);
      entropyBase = entropyCarryOffset;
    }
    let entropyCursor = 0;
    while (entropyCursor + entropyBlockSize <= entropyBytes.length) {
      const block = entropyBytes.subarray(entropyCursor, entropyCursor + entropyBlockSize);
      const value = entropyOf(block);
      entropy.push({ offset: entropyBase + entropyCursor, endOffset: entropyBase + entropyCursor + block.length, size: block.length, entropy: value, classification: entropyClass(value, block) });
      entropyCursor += entropyBlockSize;
    }
    entropyCarry = entropyBytes.slice(entropyCursor);
    entropyCarryOffset = entropyBase + entropyCursor;
    loaded += fresh.length;
    previousTail = scanBytes.slice(Math.max(0, scanBytes.length - overlap));
    options.onProgress?.(loaded, reader.size, "scan");
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  if (entropyCarry.length) {
    const value = entropyOf(entropyCarry);
    entropy.push({ offset: entropyCarryOffset, endOffset: entropyCarryOffset + entropyCarry.length, size: entropyCarry.length, entropy: value, classification: entropyClass(value, entropyCarry) });
  }

  candidates.sort((left, right) => left.offset - right.offset || left.formatIndex - right.formatIndex);
  const resolved: FirmwareObject[] = [];
  let hashed = 0;
  let hashedBytes = 0;
  const nextDistinctOffset = new Array<number | undefined>(candidates.length);
  let nextOffsetValue: number | undefined;
  for (let index = candidates.length - 1; index >= 0;) {
    const offset = candidates[index].offset;
    let groupStart = index;
    while (groupStart > 0 && candidates[groupStart - 1].offset === offset) groupStart -= 1;
    for (let cursor = groupStart; cursor <= index; cursor += 1) nextDistinctOffset[cursor] = nextOffsetValue;
    nextOffsetValue = offset;
    index = groupStart - 1;
  }
  for (let index = 0; index < candidates.length; index += 1) {
    if (options.signal?.aborted) throw abortError();
    const candidate = candidates[index];
    const remaining = reader.size - candidate.offset;
    const probeLength = Math.min(remaining, Math.max(128 * 1024, Math.min(MAX_PROBE, remaining)));
    const probe = await reader.read(candidate.offset, probeLength, { signal: options.signal });
    const structural = structuralExtent(candidate.label, probe, remaining);
    const localHit = scanCarvableObjects(probe, { maxHits: 64 }).find((hit) => hit.offset === 0 && hit.label === candidate.label);
    const nextOffset = nextDistinctOffset[index];
    let size = structural?.size ?? localHit?.size ?? Math.max(0, (nextOffset ?? reader.size) - candidate.offset);
    let extent: CarverExtent = structural ? "structural" : localHit?.extent ?? (nextOffset ? "heuristic" : "unknown");
    let confidence: CarverConfidence = structural ? "high" : localHit?.confidence ?? "low";
    let detail = structural?.detail ?? localHit?.detail ?? (nextOffset ? "Boundary stops at the next recognized object." : "Boundary reaches the end of the source; verify before evidentiary use.");
    if (!Number.isSafeInteger(size) || size <= 0 || size > remaining) {
      size = Math.max(0, (nextOffset ?? reader.size) - candidate.offset);
      extent = nextOffset ? "heuristic" : "unknown";
      confidence = "low";
      detail = nextOffset ? "Invalid structural size; constrained by next recognized object." : "Invalid structural size; constrained by source end.";
    }
    const header = probe.subarray(0, Math.min(probe.length, 1024 * 1024));
    const architecture = architectureFromHeader(candidate.label, header);
    let sha256: string | undefined;
    if (hashed < maxHashedObjects && size > 0 && size <= MAX_HASH_OBJECT && hashedBytes + size <= maxObjectHashBytes) {
      const bytes = size <= probe.length ? probe.subarray(0, size) : await reader.read(candidate.offset, size, { signal: options.signal });
      sha256 = await sha256BytesAsync(bytes);
      hashed += 1;
      hashedBytes += size;
    }
    const base: FirmwareObject = {
      id: `fw-${index}-${candidate.offset}`,
      label: candidate.label,
      offset: candidate.offset,
      size,
      endOffset: candidate.offset + size,
      extension: candidate.extension,
      mime: candidate.mime,
      confidence,
      extent,
      detail,
      depth: 0,
      virtualPath: `source::${candidate.label}@0x${candidate.offset.toString(16).toUpperCase()}`,
      origin: "signature",
      ...(sha256 ? { sha256 } : {}),
      ...(architecture ? { architecture } : {}),
      analyzer: analyzerForArtifact({ label: candidate.label, extension: candidate.extension, mime: candidate.mime, bytes: probe.subarray(0, Math.min(probe.length, 2 * 1024 * 1024)) }),
      metadata: headerMetadata(candidate.label, header)
    };
    resolved.push(base);
    options.onProgress?.(index + 1, candidates.length, "resolve");
  }

  // Establish parent relationships only when a parent's boundary is at least structural/known.
  for (const object of resolved) {
    const parent = resolved
      .filter((candidate) => candidate !== object && candidate.offset < object.offset && candidate.extent !== "unknown" && candidate.endOffset >= object.endOffset)
      .sort((left, right) => left.size - right.size)[0];
    if (parent) {
      object.parentId = parent.id;
      object.depth = Math.min(16, parent.depth + 1);
    }
  }

  const interestingPaths: string[] = [];
  if (reader.size <= maxRecursiveBytes && reader.size <= Number.MAX_SAFE_INTEGER) {
    options.onProgress?.(0, reader.size, "recursive");
    const whole = await reader.read(0, reader.size, { signal: options.signal });
    const recursive = scanRecursiveCarvableObjects(whole, { maxDepth: 5, maxObjects: Math.min(1024, maxObjects), maxExpandedBytes: 192 * 1024 * 1024, maxObjectBytes: 48 * 1024 * 1024 });
    for (const item of recursive) {
      if (item.origin === "signature") continue;
      if (interestingPath(item.virtualPath) && interestingPaths.length < 200) interestingPaths.push(item.virtualPath);
      if (resolved.length >= maxObjects) { truncated = true; break; }
      const canHash = item.bytes.length > 0 && item.bytes.length <= MAX_HASH_OBJECT && hashed < maxHashedObjects && hashedBytes + item.bytes.length <= maxObjectHashBytes;
      const sha256 = canHash ? await sha256BytesAsync(item.bytes) : undefined;
      if (sha256) { hashed += 1; hashedBytes += item.bytes.length; }
      const recursiveId = `fw-rec-${resolved.length}-${item.depth}`;
      if (item.bytes.length && retainedBytes + item.bytes.length <= maxRetainedBytes) {
        retained.set(recursiveId, item.bytes.slice());
        retainedBytes += item.bytes.length;
      }
      resolved.push({
        id: recursiveId,
        label: item.label,
        offset: item.offset,
        size: item.size,
        endOffset: item.offset + item.size,
        extension: item.extension,
        mime: item.mime,
        confidence: item.confidence,
        extent: item.extent,
        detail: item.detail ?? "Expanded nested object",
        depth: item.depth,
        virtualPath: item.virtualPath,
        origin: item.origin,
        ...(sha256 ? { sha256 } : {}),
        analyzer: analyzerForArtifact({ label: item.label, extension: item.extension, mime: item.mime, bytes: item.bytes })
      });
    }
    options.onProgress?.(reader.size, reader.size, "recursive");
  }

  const counts: Record<string, number> = {};
  const categories: Record<string, number> = {};
  const architectures: Record<string, number> = {};
  for (const object of resolved) {
    counts[object.label] = (counts[object.label] ?? 0) + 1;
    const category = categoryFor(object.label);
    categories[category] = (categories[category] ?? 0) + 1;
    if (object.architecture) architectures[object.architecture] = (architectures[object.architecture] ?? 0) + 1;
  }
  const warnings: string[] = [];
  if (resolved.some((object) => object.extent === "heuristic" || object.extent === "unknown")) warnings.push("Some object boundaries are heuristic or unresolved; verify them before relying on carved bytes as evidence.");
  if (reader.size > maxRecursiveBytes) warnings.push(`Automatic recursive expansion is limited to sources up to ${maxRecursiveBytes} bytes; large-source objects can still be carved and sent to analyzers individually.`);
  if (truncated) warnings.push(`Object list reached the configured limit (${maxObjects}).`);
  if (hashed >= maxHashedObjects || hashedBytes >= maxObjectHashBytes) warnings.push(`Per-object SHA-256 hashing stopped at the configured budget (${hashed} object(s), ${hashedBytes} bytes); source SHA-256 remains complete.`);

  const analysis: FirmwareAnalysis = {
    name,
    size: reader.size,
    sha256: sha.finalize().toString(),
    scannedBytes: loaded,
    chunkSize,
    objects: resolved,
    entropy,
    counts,
    categories,
    architectures,
    interestingPaths: Array.from(new Set(interestingPaths)),
    warnings,
    recursive: reader.size <= maxRecursiveBytes,
    truncated
  };
  return { analysis, retained };
}

export async function materializeFirmwareObject(reader: EvidenceReader, session: FirmwareAnalysisSession, object: FirmwareObject, signal?: AbortSignal) {
  const retained = session.retained.get(object.id);
  if (retained) return retained.slice();
  if (object.origin !== "signature" || object.size <= 0 || object.offset < 0 || object.offset + object.size > reader.size) return null;
  return reader.read(object.offset, object.size, { signal });
}

export function buildFirmwareManifest(analysis: FirmwareAnalysis) {
  return {
    schema: "forensicspp.firmware-manifest/v1",
    generatedAt: new Date().toISOString(),
    source: { name: analysis.name, size: analysis.size, sha256: analysis.sha256 },
    scan: { chunkSize: analysis.chunkSize, recursive: analysis.recursive, truncated: analysis.truncated },
    objects: analysis.objects.map(({ id, label, offset, size, endOffset, extension, mime, confidence, extent, detail, depth, parentId, virtualPath, origin, sha256, architecture, analyzer, metadata }) => ({
      id, label, offset, hexOffset: `0x${offset.toString(16).toUpperCase()}`, size, endOffset, extension, mime, confidence, extent, detail, depth, parentId, virtualPath, origin, sha256, architecture, analyzer, metadata
    })),
    entropy: analysis.entropy,
    warnings: analysis.warnings
  };
}

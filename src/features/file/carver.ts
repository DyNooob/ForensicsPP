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

export type CarverConfidence = "low" | "medium" | "high";
export type CarverExtent = "exact" | "structural" | "heuristic" | "unknown";

export type CarverHit = {
  label: string;
  offset: number;
  size: number;
  extension: string;
  mime: string;
  confidence: CarverConfidence;
  extent: CarverExtent;
  detail?: string;
  parentOffset?: number;
  depth: number;
};

export type CarverFormatDefinition = {
  label: string;
  magic: number[];
  magicOffset?: number;
  extension: string;
  mime: string;
  validate?: (bytes: Uint8Array, offset: number) => boolean;
  extent?: (bytes: Uint8Array, offset: number) => { size: number; extent: CarverExtent; confidence?: CarverConfidence; detail?: string } | null;
};

function viewFor(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function ascii(bytes: Uint8Array, offset: number, length: number) {
  if (offset < 0 || offset + length > bytes.length) return "";
  return String.fromCharCode(...bytes.subarray(offset, offset + length));
}

function matchAt(bytes: Uint8Array, offset: number, magic: number[]) {
  return offset >= 0 && offset + magic.length <= bytes.length && magic.every((byte, index) => bytes[offset + index] === byte);
}

function findSequence(bytes: Uint8Array, sequence: number[], start: number, maxEnd = bytes.length) {
  const end = Math.min(bytes.length, maxEnd);
  outer: for (let offset = Math.max(0, start); offset + sequence.length <= end; offset += 1) {
    for (let index = 0; index < sequence.length; index += 1) {
      if (bytes[offset + index] !== sequence[index]) continue outer;
    }
    return offset;
  }
  return -1;
}

function pngExtent(bytes: Uint8Array, offset: number) {
  if (!matchAt(bytes, offset, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return null;
  const view = viewFor(bytes);
  let cursor = offset + 8;
  for (let chunks = 0; chunks < 100_000 && cursor + 12 <= bytes.length; chunks += 1) {
    const length = view.getUint32(cursor, false);
    if (length > 0x7fffffff || cursor + 12 + length > bytes.length) return null;
    const type = ascii(bytes, cursor + 4, 4);
    cursor += 12 + length;
    if (type === "IEND") return { size: cursor - offset, extent: "exact" as const };
  }
  return null;
}

function jpegExtent(bytes: Uint8Array, offset: number) {
  const end = findSequence(bytes, [0xff, 0xd9], offset + 2);
  return end >= 0 ? { size: end + 2 - offset, extent: "heuristic" as const, confidence: "medium" as const, detail: "JPEG EOI marker" } : null;
}

function gifExtent(bytes: Uint8Array, offset: number) {
  const end = findSequence(bytes, [0x3b], offset + 13);
  return end >= 0 ? { size: end + 1 - offset, extent: "heuristic" as const, confidence: "medium" as const, detail: "GIF trailer marker" } : null;
}

function riffExtent(bytes: Uint8Array, offset: number) {
  if (offset + 12 > bytes.length) return null;
  const size = viewFor(bytes).getUint32(offset + 4, true) + 8;
  return size >= 12 && offset + size <= bytes.length ? { size, extent: "exact" as const } : null;
}

function bmpExtent(bytes: Uint8Array, offset: number) {
  if (offset + 6 > bytes.length) return null;
  const size = viewFor(bytes).getUint32(offset + 2, true);
  return size >= 14 && offset + size <= bytes.length ? { size, extent: "exact" as const } : null;
}

function pdfExtent(bytes: Uint8Array, offset: number) {
  const marker = [0x25, 0x25, 0x45, 0x4f, 0x46];
  const end = findSequence(bytes, marker, offset + 5);
  if (end < 0) return null;
  let cursor = end + marker.length;
  while (cursor < bytes.length && cursor < end + marker.length + 2 && (bytes[cursor] === 0x0d || bytes[cursor] === 0x0a)) cursor += 1;
  return { size: cursor - offset, extent: "heuristic" as const, confidence: "medium" as const, detail: "First PDF EOF marker" };
}

function zipExtent(bytes: Uint8Array, offset: number) {
  const view = viewFor(bytes);
  let cursor = offset + 4;
  const searchEnd = Math.min(bytes.length, offset + 512 * 1024 * 1024);
  while (cursor + 22 <= searchEnd) {
    const eocd = findSequence(bytes, [0x50, 0x4b, 0x05, 0x06], cursor, searchEnd);
    if (eocd < 0) return null;
    const commentLength = view.getUint16(eocd + 20, true);
    const centralDirectorySize = view.getUint32(eocd + 12, true);
    const centralDirectoryOffset = view.getUint32(eocd + 16, true);
    const end = eocd + 22 + commentLength;
    const centralDirectoryStart = offset + centralDirectoryOffset;
    const centralDirectoryEnd = centralDirectoryStart + centralDirectorySize;
    // EOCD offsets are relative to the beginning of this ZIP. Requiring the
    // central-directory range to resolve from the candidate start prevents
    // arbitrary PK\x03\x04 local-file headers inside a larger ZIP from being
    // misreported as independent embedded archives.
    const centralDirectoryLooksValid = centralDirectorySize === 0
      ? centralDirectoryStart === eocd
      : centralDirectoryStart >= offset + 4
        && centralDirectoryEnd <= eocd
        && matchAt(bytes, centralDirectoryStart, [0x50, 0x4b, 0x01, 0x02]);
    if (end <= bytes.length && centralDirectoryLooksValid) {
      return { size: end - offset, extent: "exact" as const };
    }
    cursor = eocd + 4;
  }
  return null;
}

function sqliteExtent(bytes: Uint8Array, offset: number) {
  if (offset + 100 > bytes.length) return null;
  const view = viewFor(bytes);
  const rawPageSize = view.getUint16(offset + 16, false);
  const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
  const pages = view.getUint32(offset + 28, false);
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0 || !pages) return null;
  const size = pageSize * pages;
  return Number.isSafeInteger(size) && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "SQLite page size × database page count" }
    : null;
}

function squashFsExtent(bytes: Uint8Array, offset: number) {
  if (offset + 96 > bytes.length) return null;
  const view = viewFor(bytes);
  const size = Number(view.getBigUint64(offset + 40, true));
  return Number.isSafeInteger(size) && size >= 96 && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "SquashFS bytes_used" }
    : null;
}

function uImageExtent(bytes: Uint8Array, offset: number) {
  if (offset + 64 > bytes.length) return null;
  const payload = viewFor(bytes).getUint32(offset + 12, false);
  const size = 64 + payload;
  return size >= 64 && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "U-Boot header + payload size" }
    : null;
}

function dtbExtent(bytes: Uint8Array, offset: number) {
  if (offset + 8 > bytes.length) return null;
  const size = viewFor(bytes).getUint32(offset + 4, false);
  return size >= 40 && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "DTB totalsize" }
    : null;
}

function sevenZipExtent(bytes: Uint8Array, offset: number) {
  if (offset + 32 > bytes.length) return null;
  const view = viewFor(bytes);
  const nextOffset = Number(view.getBigUint64(offset + 12, true));
  const nextSize = Number(view.getBigUint64(offset + 20, true));
  const size = 32 + nextOffset + nextSize;
  return Number.isSafeInteger(size) && size >= 32 && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "7z start header next-header range" }
    : null;
}

function peExtent(bytes: Uint8Array, offset: number) {
  if (offset + 0x40 > bytes.length) return null;
  const view = viewFor(bytes);
  const peOffset = view.getUint32(offset + 0x3c, true);
  if (peOffset < 0x40 || peOffset > 0x100000 || offset + peOffset + 24 > bytes.length || ascii(bytes, offset + peOffset, 4) !== "PE\0\0") return null;
  const sections = view.getUint16(offset + peOffset + 6, true);
  const optionalSize = view.getUint16(offset + peOffset + 20, true);
  const sectionTable = offset + peOffset + 24 + optionalSize;
  if (sections > 512 || sectionTable + sections * 40 > bytes.length) return null;
  let end = peOffset + 24 + optionalSize + sections * 40;
  for (let index = 0; index < sections; index += 1) {
    const row = sectionTable + index * 40;
    const rawSize = view.getUint32(row + 16, true);
    const rawOffset = view.getUint32(row + 20, true);
    end = Math.max(end, rawOffset + rawSize);
  }
  return end > 0 && offset + end <= bytes.length
    ? { size: end, extent: "structural" as const, confidence: "medium" as const, detail: "PE section-backed extent; overlay is not included" }
    : null;
}

function elfExtent(bytes: Uint8Array, offset: number) {
  if (offset + 52 > bytes.length) return null;
  const view = viewFor(bytes);
  const is64 = bytes[offset + 4] === 2;
  const little = bytes[offset + 5] === 1;
  if (!(is64 || bytes[offset + 4] === 1) || !(little || bytes[offset + 5] === 2)) return null;
  const number = (relative: number, width: 4 | 8) => width === 8 ? Number(view.getBigUint64(offset + relative, little)) : view.getUint32(offset + relative, little);
  const phoff = number(is64 ? 32 : 28, is64 ? 8 : 4);
  const shoff = number(is64 ? 40 : 32, is64 ? 8 : 4);
  const phentsize = view.getUint16(offset + (is64 ? 54 : 42), little);
  const phnum = view.getUint16(offset + (is64 ? 56 : 44), little);
  const shentsize = view.getUint16(offset + (is64 ? 58 : 46), little);
  const shnum = view.getUint16(offset + (is64 ? 60 : 48), little);
  if (phnum > 4096 || shnum > 65535) return null;
  let end = Math.max(is64 ? 64 : 52, phoff + phentsize * phnum, shoff + shentsize * shnum);
  if (phoff && phentsize && phoff + phentsize * phnum <= bytes.length - offset) {
    for (let index = 0; index < phnum; index += 1) {
      const row = offset + phoff + index * phentsize;
      const fileOffset = is64 ? Number(view.getBigUint64(row + 8, little)) : view.getUint32(row + 4, little);
      const fileSize = is64 ? Number(view.getBigUint64(row + 32, little)) : view.getUint32(row + 16, little);
      end = Math.max(end, fileOffset + fileSize);
    }
  }
  return Number.isSafeInteger(end) && end > 0 && offset + end <= bytes.length
    ? { size: end, extent: "structural" as const, confidence: "medium" as const, detail: "ELF program/section-backed extent" }
    : null;
}


function fatExtent(bytes: Uint8Array, offset: number) {
  if (offset + 512 > bytes.length) return null;
  const view = viewFor(bytes);
  const bytesPerSector = view.getUint16(offset + 11, true);
  const sectors16 = view.getUint16(offset + 19, true);
  const sectors32 = view.getUint32(offset + 32, true);
  const sectors = sectors16 || sectors32;
  const size = bytesPerSector * sectors;
  return bytesPerSector >= 512 && bytesPerSector <= 4096 && (bytesPerSector & (bytesPerSector - 1)) === 0
    && sectors > 0 && Number.isSafeInteger(size) && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "FAT BPB total sectors × bytes/sector" }
    : null;
}

function exfatExtent(bytes: Uint8Array, offset: number) {
  if (offset + 512 > bytes.length) return null;
  const view = viewFor(bytes);
  const sectors = Number(view.getBigUint64(offset + 72, true));
  const sectorShift = bytes[offset + 108];
  if (sectorShift < 9 || sectorShift > 12 || !Number.isSafeInteger(sectors) || sectors <= 0) return null;
  const bytesPerSector = 2 ** sectorShift;
  const size = sectors * bytesPerSector;
  return Number.isSafeInteger(size) && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "exFAT volume length × bytes/sector" }
    : null;
}

function extFsExtent(bytes: Uint8Array, offset: number) {
  const superblock = offset + 1024;
  if (superblock + 340 > bytes.length) return null;
  const view = viewFor(bytes);
  if (view.getUint16(superblock + 56, true) !== 0xef53) return null;
  const logBlockSize = view.getUint32(superblock + 24, true);
  if (logBlockSize > 6) return null;
  const blockSize = 1024 * (2 ** logBlockSize);
  const blocksLow = BigInt(view.getUint32(superblock + 4, true));
  const incompat = view.getUint32(superblock + 96, true);
  const blocksHigh = incompat & 0x80 ? BigInt(view.getUint32(superblock + 336, true)) : 0n;
  const blocks = (blocksHigh << 32n) | blocksLow;
  const sizeBig = blocks * BigInt(blockSize);
  if (sizeBig <= 0n || sizeBig > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const size = Number(sizeBig);
  return offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "EXT superblock block count × block size" }
    : null;
}

function cpioNewcExtent(bytes: Uint8Array, offset: number) {
  let cursor = offset;
  for (let entries = 0; entries < 100_000 && cursor + 110 <= bytes.length; entries += 1) {
    if (ascii(bytes, cursor, 6) !== "070701" && ascii(bytes, cursor, 6) !== "070702") return null;
    const fileSize = Number.parseInt(ascii(bytes, cursor + 54, 8), 16);
    const nameSize = Number.parseInt(ascii(bytes, cursor + 94, 8), 16);
    if (!Number.isFinite(fileSize) || !Number.isFinite(nameSize) || fileSize < 0 || nameSize <= 0 || nameSize > 1_048_576) return null;
    const nameStart = cursor + 110;
    const nameEnd = nameStart + nameSize;
    if (nameEnd > bytes.length) return null;
    const name = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(nameStart, Math.max(nameStart, nameEnd - 1)));
    const dataStart = (nameEnd + 3) & ~3;
    const next = (dataStart + fileSize + 3) & ~3;
    if (next > bytes.length) return null;
    cursor = next;
    if (name === "TRAILER!!!") {
      return { size: cursor - offset, extent: "structural" as const, confidence: "high" as const, detail: "CPIO newc TRAILER!!! record" };
    }
  }
  return null;
}

function ntfsExtent(bytes: Uint8Array, offset: number) {
  if (offset + 512 > bytes.length) return null;
  const view = viewFor(bytes);
  const bytesPerSector = view.getUint16(offset + 11, true);
  const sectors = Number(view.getBigUint64(offset + 40, true));
  const size = bytesPerSector * sectors;
  return bytesPerSector >= 512 && bytesPerSector <= 4096 && Number.isSafeInteger(size) && size > 0 && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "NTFS total sectors × bytes/sector" }
    : null;
}

function isoExtent(bytes: Uint8Array, offset: number) {
  const descriptor = offset + 0x8000;
  if (descriptor + 2048 > bytes.length || ascii(bytes, descriptor + 1, 5) !== "CD001") return null;
  const view = viewFor(bytes);
  const blocks = view.getUint32(descriptor + 80, true);
  const blockSize = view.getUint16(descriptor + 128, true);
  const size = blocks * blockSize;
  return blockSize >= 512 && Number.isSafeInteger(size) && size > 0 && offset + size <= bytes.length
    ? { size, extent: "structural" as const, confidence: "high" as const, detail: "ISO9660 volume space × logical block size" }
    : null;
}

function pemExtent(bytes: Uint8Array, offset: number, endMarker: string) {
  const sequence = Array.from(endMarker, (value) => value.charCodeAt(0));
  const end = findSequence(bytes, sequence, offset + 16);
  if (end < 0) return null;
  let cursor = end + sequence.length;
  while (cursor < bytes.length && (bytes[cursor] === 0x0d || bytes[cursor] === 0x0a)) cursor += 1;
  return { size: cursor - offset, extent: "exact" as const, confidence: "high" as const, detail: `${endMarker} terminator` };
}

function tarExtent(bytes: Uint8Array, offset: number) {
  if (offset + 512 > bytes.length || ascii(bytes, offset + 257, 5) !== "ustar") return null;
  let cursor = offset;
  while (cursor + 1024 <= bytes.length) {
    let zero = true;
    for (let index = 0; index < 1024; index += 1) {
      if (bytes[cursor + index] !== 0) { zero = false; break; }
    }
    if (zero) return { size: cursor + 1024 - offset, extent: "heuristic" as const, confidence: "medium" as const, detail: "TAR two-zero-block terminator" };
    const sizeText = ascii(bytes, cursor + 124, 12).replace(/\0.*$/, "").trim();
    const fileSize = Number.parseInt(sizeText, 8);
    if (!Number.isFinite(fileSize) || fileSize < 0) return null;
    cursor += 512 + Math.ceil(fileSize / 512) * 512;
  }
  return null;
}

export const carverFormats: CarverFormatDefinition[] = [
  { label: "PNG", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], extension: "png", mime: "image/png", extent: pngExtent },
  { label: "JPEG", magic: [0xff, 0xd8, 0xff], extension: "jpg", mime: "image/jpeg", extent: jpegExtent },
  { label: "GIF", magic: [0x47, 0x49, 0x46, 0x38], extension: "gif", mime: "image/gif", extent: gifExtent },
  { label: "WEBP", magic: [0x52, 0x49, 0x46, 0x46], extension: "webp", mime: "image/webp", validate: (bytes, offset) => ascii(bytes, offset + 8, 4) === "WEBP", extent: riffExtent },
  { label: "WAV", magic: [0x52, 0x49, 0x46, 0x46], extension: "wav", mime: "audio/wav", validate: (bytes, offset) => ascii(bytes, offset + 8, 4) === "WAVE", extent: riffExtent },
  { label: "BMP", magic: [0x42, 0x4d], extension: "bmp", mime: "image/bmp", extent: bmpExtent },
  { label: "PDF", magic: [0x25, 0x50, 0x44, 0x46, 0x2d], extension: "pdf", mime: "application/pdf", extent: pdfExtent },
  { label: "ZIP", magic: [0x50, 0x4b, 0x03, 0x04], extension: "zip", mime: "application/zip", validate: (bytes, offset) => zipExtent(bytes, offset) != null, extent: zipExtent },
  { label: "Gzip", magic: [0x1f, 0x8b, 0x08], extension: "gz", mime: "application/gzip" },
  { label: "Zlib", magic: [0x78, 0x01], extension: "zlib", mime: "application/zlib" },
  { label: "Zlib", magic: [0x78, 0x5e], extension: "zlib", mime: "application/zlib" },
  { label: "Zlib", magic: [0x78, 0x9c], extension: "zlib", mime: "application/zlib" },
  { label: "Zlib", magic: [0x78, 0xda], extension: "zlib", mime: "application/zlib" },
  { label: "Bzip2", magic: [0x42, 0x5a, 0x68], extension: "bz2", mime: "application/x-bzip2" },
  { label: "LZMA (common header)", magic: [0x5d, 0x00, 0x00, 0x80, 0x00], extension: "lzma", mime: "application/x-lzma" },
  { label: "XZ", magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], extension: "xz", mime: "application/x-xz" },
  { label: "Zstandard", magic: [0x28, 0xb5, 0x2f, 0xfd], extension: "zst", mime: "application/zstd" },
  { label: "7z", magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], extension: "7z", mime: "application/x-7z-compressed", extent: sevenZipExtent },
  { label: "RAR", magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], extension: "rar", mime: "application/vnd.rar" },
  { label: "PE", magic: [0x4d, 0x5a], extension: "exe", mime: "application/vnd.microsoft.portable-executable", extent: peExtent },
  { label: "ELF", magic: [0x7f, 0x45, 0x4c, 0x46], extension: "elf", mime: "application/x-elf", extent: elfExtent },
  { label: "SQLite", magic: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], extension: "sqlite", mime: "application/vnd.sqlite3", extent: sqliteExtent },
  { label: "OLE", magic: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], extension: "ole", mime: "application/x-ole-storage" },
  { label: "SquashFS", magic: [0x68, 0x73, 0x71, 0x73], extension: "squashfs", mime: "application/octet-stream", extent: squashFsExtent },
  { label: "U-Boot uImage", magic: [0x27, 0x05, 0x19, 0x56], extension: "uimg", mime: "application/octet-stream", extent: uImageExtent },
  { label: "Device Tree Blob", magic: [0xd0, 0x0d, 0xfe, 0xed], extension: "dtb", mime: "application/octet-stream", extent: dtbExtent },
  { label: "Android boot image", magic: [0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21], extension: "img", mime: "application/octet-stream" },
  { label: "Android vendor_boot image", magic: [0x56, 0x4e, 0x44, 0x52, 0x42, 0x4f, 0x4f, 0x54], extension: "img", mime: "application/octet-stream" },
  { label: "Android sparse image", magic: [0x3a, 0xff, 0x26, 0xed], extension: "img", mime: "application/octet-stream" },
  { label: "UBI erase-count header", magic: [0x55, 0x42, 0x49, 0x23], extension: "ubi", mime: "application/octet-stream" },
  { label: "UBIFS node", magic: [0x31, 0x18, 0x10, 0x06], extension: "ubifs", mime: "application/octet-stream" },
  { label: "CPIO newc", magic: [0x30, 0x37, 0x30, 0x37, 0x30, 0x31], extension: "cpio", mime: "application/x-cpio", extent: cpioNewcExtent },
  { label: "TAR", magic: [0x75, 0x73, 0x74, 0x61, 0x72], magicOffset: 257, extension: "tar", mime: "application/x-tar", extent: tarExtent },
  { label: "ISO9660", magic: [0x43, 0x44, 0x30, 0x30, 0x31], magicOffset: 0x8001, extension: "iso", mime: "application/x-iso9660-image", extent: isoExtent },
  { label: "FAT12/16 volume", magic: [0x46, 0x41, 0x54], magicOffset: 54, extension: "img", mime: "application/octet-stream", validate: (bytes, offset) => /FAT1[26]/.test(ascii(bytes, offset + 54, 8)), extent: fatExtent },
  { label: "FAT32 volume", magic: [0x46, 0x41, 0x54, 0x33, 0x32], magicOffset: 82, extension: "img", mime: "application/octet-stream", extent: fatExtent },
  { label: "exFAT volume", magic: [0x45, 0x58, 0x46, 0x41, 0x54, 0x20, 0x20, 0x20], magicOffset: 3, extension: "img", mime: "application/octet-stream", extent: exfatExtent },
  { label: "EXT filesystem", magic: [0x53, 0xef], magicOffset: 1080, extension: "img", mime: "application/octet-stream", extent: extFsExtent },
  { label: "NTFS volume", magic: [0x4e, 0x54, 0x46, 0x53, 0x20, 0x20, 0x20, 0x20], magicOffset: 3, extension: "img", mime: "application/octet-stream", extent: ntfsExtent },
  { label: "JFFS2 node", magic: [0x85, 0x19], extension: "jffs2", mime: "application/octet-stream" },
  { label: "PEM certificate", magic: Array.from("-----BEGIN CERTIFICATE-----", (value) => value.charCodeAt(0)), extension: "pem", mime: "application/x-pem-file", extent: (bytes, offset) => pemExtent(bytes, offset, "-----END CERTIFICATE-----") },
  { label: "PEM private key", magic: Array.from("-----BEGIN PRIVATE KEY-----", (value) => value.charCodeAt(0)), extension: "pem", mime: "application/x-pem-file", extent: (bytes, offset) => pemExtent(bytes, offset, "-----END PRIVATE KEY-----") },
  { label: "PEM RSA private key", magic: Array.from("-----BEGIN RSA PRIVATE KEY-----", (value) => value.charCodeAt(0)), extension: "pem", mime: "application/x-pem-file", extent: (bytes, offset) => pemExtent(bytes, offset, "-----END RSA PRIVATE KEY-----") }
];

export type ScanCarverOptions = {
  startOffset?: number;
  maxHits?: number;
};

export function scanCarvableObjects(bytes: Uint8Array, options: ScanCarverOptions = {}) {
  const startOffset = Math.max(0, options.startOffset ?? 0);
  const maxHits = Math.max(1, Math.min(4096, options.maxHits ?? 256));
  const byFirstByte = new Map<number, CarverFormatDefinition[]>();
  for (const format of carverFormats) {
    const rows = byFirstByte.get(format.magic[0]) ?? [];
    rows.push(format);
    byFirstByte.set(format.magic[0], rows);
  }
  const candidates: Array<{ format: CarverFormatDefinition; offset: number }> = [];
  const seen = new Set<string>();
  for (let magicPosition = startOffset; magicPosition < bytes.length && candidates.length < maxHits; magicPosition += 1) {
    const rows = byFirstByte.get(bytes[magicPosition]);
    if (!rows) continue;
    for (const format of rows) {
      const offset = magicPosition - (format.magicOffset ?? 0);
      if (offset < startOffset || !matchAt(bytes, magicPosition, format.magic)) continue;
      const key = `${format.label}:${offset}`;
      if (seen.has(key) || (format.validate && !format.validate(bytes, offset))) continue;
      seen.add(key);
      candidates.push({ format, offset });
      if (candidates.length >= maxHits) break;
    }
  }
  candidates.sort((left, right) => left.offset - right.offset || right.format.magic.length - left.format.magic.length);
  const resolvedExtents = candidates.map(({ format, offset }) => format.extent?.(bytes, offset) ?? null);
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
  const hits = candidates.map(({ format, offset }, index): CarverHit => {
    const resolved = resolvedExtents[index];
    if (resolved) {
      return {
        label: format.label,
        offset,
        size: resolved.size,
        extension: format.extension,
        mime: format.mime,
        confidence: resolved.confidence ?? "high",
        extent: resolved.extent,
        detail: resolved.detail,
        depth: 0
      };
    }
    const nextOffset = nextDistinctOffset[index];
    const enclosingEnd = candidates.reduce<number | undefined>((best, candidate, candidateIndex) => {
      const known = resolvedExtents[candidateIndex];
      if (!known || candidate.offset >= offset || candidate.offset + known.size <= offset) return best;
      const end = candidate.offset + known.size;
      return best == null || end < best ? end : best;
    }, undefined);
    const boundary = Math.min(nextOffset ?? bytes.length, enclosingEnd ?? bytes.length, bytes.length);
    const heuristicSize = boundary - offset;
    const hasBoundary = nextOffset != null || enclosingEnd != null;
    return {
      label: format.label,
      offset,
      size: Math.max(0, heuristicSize),
      extension: format.extension,
      mime: format.mime,
      confidence: "low",
      extent: hasBoundary ? "heuristic" : "unknown",
      detail: enclosingEnd != null && boundary === enclosingEnd
        ? "Format boundary is not resolved; size is constrained by the enclosing structured object."
        : nextOffset != null
          ? "Format boundary is not resolved; size stops at the next recognized object."
          : "Format boundary is not resolved; size reaches the end of the supplied buffer.",
      depth: 0
    };
  });
  for (const hit of hits) {
    const containers = hits.filter((candidate) => candidate !== hit
      && candidate.offset < hit.offset
      && candidate.size > 0
      && candidate.extent !== "unknown"
      && candidate.offset + candidate.size >= hit.offset + Math.max(1, hit.size));
    const parent = containers.sort((left, right) => left.size - right.size)[0];
    if (parent) hit.parentOffset = parent.offset;
  }
  const byOffset = new Map(hits.map((hit) => [hit.offset, hit]));
  const depthFor = (hit: CarverHit, seen = new Set<number>()): number => {
    if (hit.parentOffset == null || seen.has(hit.parentOffset)) return 0;
    seen.add(hit.parentOffset);
    const parent = byOffset.get(hit.parentOffset);
    return parent ? Math.min(16, 1 + depthFor(parent, seen)) : 1;
  };
  hits.forEach((hit) => { hit.depth = depthFor(hit); });
  return hits;
}

export function carverFormatMetadata() {
  return carverFormats.map((format) => ({
    label: format.label,
    magic: format.magic.slice(),
    magicOffset: format.magicOffset ?? 0,
    extension: format.extension,
    mime: format.mime
  }));
}

export function carverFormatCount() {
  return carverFormats.length;
}

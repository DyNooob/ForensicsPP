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

import { hexPreview, readAscii } from "../../utils/binary";
import { parsePngFile } from "../png/parser";

type ImageMetadata = Record<string, unknown> | number;

function imageMetadataFieldCount(metadata: ImageMetadata) {
  return typeof metadata === "number" ? metadata : Object.keys(metadata).length;
}

function findJpegEnd(bytes: Uint8Array) {
  for (let index = bytes.length - 2; index >= 0; index -= 1) {
    if (bytes[index] === 0xff && bytes[index + 1] === 0xd9) return index + 2;
  }
  return -1;
}

function findGifEnd(bytes: Uint8Array) {
  const index = bytes.lastIndexOf(0x3b);
  return index >= 0 ? index + 1 : -1;
}

function findBmpEnd(bytes: Uint8Array) {
  if (bytes.length < 6 || bytes[0] !== 0x42 || bytes[1] !== 0x4d) return -1;
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(2, true);
  return size >= 14 && size <= bytes.length ? size : -1;
}

function findPngEnd(bytes: Uint8Array) {
  try {
    const parsed = parsePngFile(bytes);
    const iend = parsed.chunks.find((chunk) => chunk.type === "IEND");
    return iend ? iend.offset + 12 + iend.length : -1;
  } catch {
    return -1;
  }
}

function detectImageFormat(bytes: Uint8Array, fileType: string) {
  const head = hexPreview(bytes, 16);
  if (head.startsWith("89 50 4E 47 0D 0A 1A 0A")) return "PNG";
  if (head.startsWith("FF D8 FF")) return "JPEG";
  if (readAscii(bytes, 0, 6) === "GIF87a" || readAscii(bytes, 0, 6) === "GIF89a") return "GIF";
  if (readAscii(bytes, 0, 4) === "RIFF" && readAscii(bytes, 8, 4) === "WEBP") return "WEBP";
  if (head.startsWith("42 4D")) return "BMP";
  if (head.startsWith("49 49 2A 00") || head.startsWith("4D 4D 00 2A")) return "TIFF";
  if (readAscii(bytes, 4, 4) === "ftyp" && /heic|heix|hevc|hevx|mif1|msf1|avif/i.test(readAscii(bytes, 8, 16))) return "HEIF/AVIF";
  return fileType || "unknown";
}

function imageMimeForFormat(format: string, fallback = "application/octet-stream") {
  if (format === "JPEG") return "image/jpeg";
  if (format === "PNG") return "image/png";
  if (format === "GIF") return "image/gif";
  if (format === "WEBP") return "image/webp";
  if (format === "BMP") return "image/bmp";
  if (format === "TIFF") return "image/tiff";
  if (format === "HEIF/AVIF") return "image/heif";
  return fallback;
}

function imageExtensionForMime(mime: string, fallback = "bin") {
  if (/png/i.test(mime)) return "png";
  if (/jpe?g/i.test(mime)) return "jpg";
  if (/gif/i.test(mime)) return "gif";
  if (/webp/i.test(mime)) return "webp";
  if (/bmp/i.test(mime)) return "bmp";
  if (/tiff?/i.test(mime)) return "tiff";
  if (/hei[cf]|avif/i.test(mime)) return "heif";
  return fallback;
}

function getImageLogicalEnd(bytes: Uint8Array, format: string) {
  if (format === "PNG") return findPngEnd(bytes);
  if (format === "JPEG") return findJpegEnd(bytes);
  if (format === "GIF") return findGifEnd(bytes);
  if (format === "WEBP" && bytes.length >= 12) {
    const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(4, true) + 8;
    return size <= bytes.length ? size : -1;
  }
  if (format === "BMP") return findBmpEnd(bytes);
  if (format === "HEIF/AVIF" && bytes.length >= 8) {
    const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
    return size >= 8 && size <= bytes.length ? size : -1;
  }
  return -1;
}

function findImageSignatureOffset(bytes: Uint8Array) {
  const signatures = [
    { format: "PNG", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
    { format: "JPEG", bytes: [0xff, 0xd8, 0xff] },
    { format: "GIF", bytes: [0x47, 0x49, 0x46, 0x38] },
    { format: "BMP", bytes: [0x42, 0x4d] },
    { format: "TIFF", bytes: [0x49, 0x49, 0x2a, 0x00] },
    { format: "TIFF", bytes: [0x4d, 0x4d, 0x00, 0x2a] },
    { format: "WEBP", bytes: [0x52, 0x49, 0x46, 0x46] }
  ];
  const limit = Math.min(bytes.length, 1024 * 1024);
  for (let offset = 1; offset < limit; offset += 1) {
    for (const signature of signatures) {
      if (offset + signature.bytes.length > bytes.length) continue;
      if (!signature.bytes.every((byte, index) => bytes[offset + index] === byte)) continue;
      if (signature.format === "WEBP" && readAscii(bytes, offset + 8, 4) !== "WEBP") continue;
      if (signature.format === "BMP") {
        if (offset + 6 > bytes.length) continue;
        const declaredSize = new DataView(bytes.buffer, bytes.byteOffset + offset, bytes.byteLength - offset).getUint32(2, true);
        if (declaredSize < 14 || offset + declaredSize > bytes.length) continue;
      }
      return { offset, format: signature.format };
    }
  }
  return null;
}

function findZipEnd(bytes: Uint8Array) {
  for (let offset = bytes.length - 22; offset >= 0 && offset > bytes.length - 65580; offset -= 1) {
    if (bytes[offset] === 0x50 && bytes[offset + 1] === 0x4b && bytes[offset + 2] === 0x05 && bytes[offset + 3] === 0x06) {
      if (offset + 22 > bytes.length) continue;
      const commentLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset + 20, true);
      const end = offset + 22 + commentLength;
      if (end <= bytes.length) return end;
    }
  }
  return -1;
}

function findPdfEnd(bytes: Uint8Array) {
  const marker = new TextEncoder().encode("%%EOF");
  for (let offset = bytes.length - marker.length; offset >= 0; offset -= 1) {
    if (marker.every((byte, index) => bytes[offset + index] === byte)) {
      let end = offset + marker.length;
      while (end < bytes.length && [0x0a, 0x0d, 0x20, 0x09, 0x00].includes(bytes[end])) end += 1;
      return end;
    }
  }
  return -1;
}

function findRiffEnd(bytes: Uint8Array, expectedType = "") {
  if (bytes.length < 12 || readAscii(bytes, 0, 4) !== "RIFF") return -1;
  if (expectedType && readAscii(bytes, 8, 4) !== expectedType) return -1;
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(4, true) + 8;
  return size >= 12 && size <= bytes.length ? size : -1;
}

export {
  detectImageFormat,
  imageMimeForFormat,
  imageExtensionForMime,
  getImageLogicalEnd,
  findJpegEnd,
  findGifEnd,
  findBmpEnd,
  findPngEnd,
  findImageSignatureOffset,
  findZipEnd,
  findPdfEnd,
  findRiffEnd,
  imageMetadataFieldCount
};

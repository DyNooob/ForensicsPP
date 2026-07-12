/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import { decompressSync, strFromU8 } from "fflate";
import type { ImageDecodedSignal, ImageInfo, IocRecord, PngChunkInfo, PngTextEntry, QrAnalysis } from "../../models";
import { crc32, findEmbeddedFileSignatures, hexPreview, previewText, readAscii, shannonEntropy } from "../../utils/binary";
import { formatBytes, limitReportText } from "../../utils/files";
import { sha256Bytes } from "../../utils/hash";
import { analyzeCodecCandidates } from "../codec/analyzer";
import { analyzeIocs } from "../ioc/analyzer";
import { knownPngChunks, parsePngFile, pngCriticalChunks } from "../png/parser";
import { classifyQrPayload, parseQrPayloadDetails, qrGeometryRows } from "../qr/analyzer";
import { analyzeUrl } from "../url/analyzer";

const imageObjectUrls = new Set<string>();

function revokeImageObjectUrls() {
  imageObjectUrls.forEach((url) => URL.revokeObjectURL(url));
  imageObjectUrls.clear();
}

function bytesToDataUrl(bytes: Uint8Array, type: string) {
  const source = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? bytes.buffer as ArrayBuffer
    : bytes.slice().buffer;
  const blob = new Blob([source], { type });
  if (bytes.byteLength > 4 * 1024 * 1024) {
    const url = URL.createObjectURL(blob);
    imageObjectUrls.add(url);
    return Promise.resolve(url);
  }
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
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

function imagePlaceholderDataUrl(title: string, detail: string, tone: "info" | "warn" | "danger" = "info") {
  const colors = {
    info: ["#E8F2FF", "#0061A4", "#0E2A3F"],
    warn: ["#FFF4D8", "#8A5B00", "#332200"],
    danger: ["#FFF4D8", "#8A5B00", "#332200"]
  }[tone];
  const escape = (value: string) => value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="640" viewBox="0 0 960 640">`,
    `<rect width="960" height="640" fill="${colors[0]}"/>`,
    `<rect x="56" y="56" width="848" height="528" rx="18" fill="white" stroke="${colors[1]}" stroke-width="4"/>`,
    `<path d="M210 388h540L610 234 500 346l-68-78-222 120z" fill="${colors[1]}" opacity=".18"/>`,
    `<circle cx="292" cy="212" r="42" fill="${colors[1]}" opacity=".25"/>`,
    `<text x="96" y="118" font-family="Arial, sans-serif" font-size="34" font-weight="700" fill="${colors[2]}">${escape(title)}</text>`,
    `<foreignObject x="96" y="148" width="768" height="210">`,
    `<div xmlns="http://www.w3.org/1999/xhtml" style="font-family:Arial,sans-serif;font-size:22px;line-height:1.45;color:${colors[2]};overflow-wrap:anywhere">${escape(detail)}</div>`,
    `</foreignObject>`,
    `<text x="96" y="540" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="${colors[1]}">Forensics++ Image Workbench</text>`,
    `</svg>`
  ].join("");
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function emptyImageChannels(src: string): ImageInfo["channelDataUrls"] {
  return {
    red: src,
    green: src,
    blue: src,
    alpha: src,
    lsb: src,
    lsbRed: src,
    lsbGreen: src,
    lsbBlue: src,
    lowBitHeatmap: src,
    noiseMap: src,
    bitPlanes: [
      "R bit 0",
      "G bit 0",
      "B bit 0",
      "A bit 0",
      "R bit 1",
      "G bit 1",
      "B bit 1",
      "A bit 1"
    ].map((label) => ({ label, src }))
  };
}

function guessImageDimensions(bytes: Uint8Array, format: string) {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (format === "PNG" && bytes.length >= 24) return { width: view.getUint32(16), height: view.getUint32(20) };
    if (format === "GIF" && bytes.length >= 10) return { width: view.getUint16(6, true), height: view.getUint16(8, true) };
    if (format === "BMP" && bytes.length >= 26) return { width: Math.abs(view.getInt32(18, true)), height: Math.abs(view.getInt32(22, true)) };
    if (format === "WEBP" && readAscii(bytes, 0, 4) === "RIFF") {
      let offset = 12;
      while (offset + 8 <= bytes.length) {
        const type = readAscii(bytes, offset, 4);
        const size = view.getUint32(offset + 4, true);
        if (type === "VP8X" && offset + 18 <= bytes.length) {
          return {
            width: 1 + bytes[offset + 12] + (bytes[offset + 13] << 8) + (bytes[offset + 14] << 16),
            height: 1 + bytes[offset + 15] + (bytes[offset + 16] << 8) + (bytes[offset + 17] << 16)
          };
        }
        offset += 8 + size + (size % 2);
      }
    }
    if (format === "JPEG" && bytes[0] === 0xff && bytes[1] === 0xd8) {
      let offset = 2;
      while (offset + 9 < bytes.length) {
        while (offset < bytes.length && bytes[offset] !== 0xff) offset += 1;
        while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
        const marker = bytes[offset];
        if (marker === 0xda || marker === 0xd9) break;
        if (offset + 2 >= bytes.length) break;
        const length = view.getUint16(offset + 1);
        if (length < 2 || offset + 1 + length > bytes.length) break;
        if ((marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7) || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf)) {
          return { width: view.getUint16(offset + 6), height: view.getUint16(offset + 4) };
        }
        offset += 1 + length;
      }
    }
  } catch {
    // Dimension guessing is best-effort; structure findings carry the real evidence.
  }
  return { width: 0, height: 0 };
}

function imageAnalysisDimensions(width: number, height: number, maxPixels = 2_000_000) {
  const pixels = Math.max(1, width * height);
  const scale = pixels > maxPixels ? Math.sqrt(maxPixels / pixels) : 1;
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
    scale
  };
}

function createNormalizedImageDataUrl(image: HTMLImageElement) {
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Canvas is not available");
  const dimensions = imageAnalysisDimensions(image.naturalWidth, image.naturalHeight, 3_000_000);
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL("image/png");
}

function buildPngChunk(type: string, data: Uint8Array) {
  const output = new Uint8Array(12 + data.length);
  const view = new DataView(output.buffer);
  view.setUint32(0, data.length);
  for (let index = 0; index < 4; index += 1) output[4 + index] = type.charCodeAt(index);
  output.set(data, 8);
  view.setUint32(8 + data.length, crc32(output.slice(4, 8 + data.length)));
  return output;
}

function concatBytes(parts: Uint8Array[]) {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function tryRebuildPngContainer(bytes: Uint8Array) {
  if (hexPreview(bytes, 8) !== "89 50 4E 47 0D 0A 1A 0A") return null;
  try {
    const parsed = parsePngFile(bytes);
    const critical = parsed.chunks.filter((chunk) => ["IHDR", "PLTE", "IDAT"].includes(chunk.type));
    if (!critical.some((chunk) => chunk.type === "IHDR") || !critical.some((chunk) => chunk.type === "IDAT")) return null;
    const signature = bytes.slice(0, 8);
    const chunks = critical.map((chunk) => buildPngChunk(chunk.type, bytes.slice(chunk.dataOffset, chunk.dataOffset + chunk.length)));
    chunks.push(buildPngChunk("IEND", new Uint8Array()));
    const rebuilt = concatBytes([signature, ...chunks]);
    const removedAncillary = parsed.chunks.filter((chunk) => !["IHDR", "PLTE", "IDAT", "IEND"].includes(chunk.type));
    const badChunks = parsed.chunks.filter((chunk) => !chunk.ok);
    const notes = [
      "Rebuilt a PNG candidate from IHDR/PLTE/IDAT and a fresh IEND chunk.",
      badChunks.length ? `Recomputed CRC for ${badChunks.length} chunk(s) with mismatched CRC.` : "",
      removedAncillary.length ? `Removed ${removedAncillary.length} ancillary/unknown chunk(s), including metadata chunks if present.` : "",
      parsed.trailer.length ? `Removed ${formatBytes(parsed.trailer.length)} after IEND.` : ""
    ].filter(Boolean);
    return { bytes: rebuilt, notes };
  } catch {
    return null;
  }
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

function buildImageRepairCandidates(bytes: Uint8Array, format: string) {
  const candidates: Array<{ label: string; bytes: Uint8Array; mime: string; note: string }> = [];
  const embeddedImage = findImageSignatureOffset(bytes);
  if (embeddedImage) {
    candidates.push({
      label: `Removed ${embeddedImage.offset} leading byte(s) before ${embeddedImage.format} signature`,
      bytes: bytes.slice(embeddedImage.offset),
      mime: imageMimeForFormat(embeddedImage.format),
      note: `Found a ${embeddedImage.format} signature at offset ${embeddedImage.offset}; created a display candidate by removing leading bytes before the signature.`
    });
  }
  const logicalEnd = getImageLogicalEnd(bytes, format);
  if (logicalEnd > 0 && logicalEnd < bytes.length) {
    candidates.push({
      label: "Trimmed at logical image end",
      bytes: bytes.slice(0, logicalEnd),
      mime: imageMimeForFormat(format),
      note: `Removed ${formatBytes(bytes.length - logicalEnd)} after the logical ${format} end marker.`
    });
  }
  if (format === "JPEG" && logicalEnd < 0 && bytes.length > 2 && bytes[0] === 0xff && bytes[1] === 0xd8) {
    candidates.push({
      label: "Appended JPEG EOI marker",
      bytes: concatBytes([bytes, new Uint8Array([0xff, 0xd9])]),
      mime: "image/jpeg",
      note: "Added a missing JPEG EOI marker (FF D9) so decoders can attempt to display the remaining scan data."
    });
  }
  if (format === "GIF" && logicalEnd < 0 && readAscii(bytes, 0, 3) === "GIF") {
    candidates.push({
      label: "Appended GIF trailer",
      bytes: concatBytes([bytes, new Uint8Array([0x3b])]),
      mime: "image/gif",
      note: "Added a missing GIF trailer byte (3B) for display recovery."
    });
  }
  if (format === "PNG" && logicalEnd < 0 && hexPreview(bytes, 8) === "89 50 4E 47 0D 0A 1A 0A") {
    candidates.push({
      label: "Appended PNG IEND chunk",
      bytes: concatBytes([bytes, buildPngChunk("IEND", new Uint8Array())]),
      mime: "image/png",
      note: "Added a fresh PNG IEND chunk so decoders can attempt to display a PNG that appears truncated before its logical end."
    });
  }
  return candidates;
}

function decodeBitsToText(bits: number[], bitOrder: "msb" | "lsb", maxChars: number) {
  const bytes: number[] = [];
  for (let index = 0; index + 7 < bits.length && bytes.length < maxChars; index += 8) {
    let value = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      if (bitOrder === "msb") value = (value << 1) | bits[index + bit];
      else value |= bits[index + bit] << bit;
    }
    bytes.push(value);
  }
  const text = new TextDecoder().decode(new Uint8Array(bytes)).replace(/\u0000/g, "");
  const printable = text.match(/[\t\n\r -~\u00a0-\uffff]/g)?.join("") ?? "";
  const asciiPrintable = text.match(/[\t\n\r -~]/g)?.join("") ?? "";
  const printableRatio = text.length ? printable.length / text.length : 0;
  const asciiRatio = text.length ? asciiPrintable.length / text.length : 0;
  const replacementRatio = text.length ? (text.match(/\ufffd/g)?.length ?? 0) / text.length : 0;
  const signal = /(https?:\/\/|flag\{|ctf|password|secret|key=|PK\x03\x04|%PDF|MZ|BEGIN [A-Z ]+KEY|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i.test(printable);
  const plainTextLike = asciiPrintable.length > 96
    && asciiRatio > 0.9
    && printableRatio > 0.9
    && replacementRatio < 0.02
    && /[A-Za-z]{3,}/.test(asciiPrintable)
    && /[\s:;,.=_-]/.test(asciiPrintable);
  if (signal) return printable.slice(0, maxChars);
  if (plainTextLike) return asciiPrintable.slice(0, maxChars);
  return "";
}

function extractLsbCandidatesFromImageData(source: ImageData, maxChars = 4096) {
  const channelSets: Array<{ mode: string; indexes: number[] }> = [
    { mode: "RGB", indexes: [0, 1, 2] },
    { mode: "R", indexes: [0] },
    { mode: "G", indexes: [1] },
    { mode: "B", indexes: [2] },
    { mode: "A", indexes: [3] },
    { mode: "RGBA", indexes: [0, 1, 2, 3] }
  ];
  const candidates: Array<{ mode: string; text: string }> = [];
  const seen = new Set<string>();
  const maxPixels = Math.min(source.width * source.height, Math.ceil((maxChars * 8) / 3) + 4096);
  for (const channelSet of channelSets) {
    for (const bitPlane of [0, 1] as const) {
      const bits: number[] = [];
      for (let pixel = 0; pixel < maxPixels; pixel += 1) {
        const base = pixel * 4;
        for (const channel of channelSet.indexes) bits.push((source.data[base + channel] >> bitPlane) & 1);
      }
      for (const order of ["msb", "lsb"] as const) {
        const text = decodeBitsToText(bits, order, maxChars);
        const normalized = text.replace(/\s+/g, " ").slice(0, 200);
        if (text && !seen.has(normalized)) {
          seen.add(normalized);
          candidates.push({ mode: `${channelSet.mode} bit ${bitPlane} ${order.toUpperCase()}`, text });
        }
      }
    }
  }
  return candidates.slice(0, 8);
}

function payloadMetaForSignature(label: string) {
  const normalized = label.replace(/^Trailer\s+/i, "").replace(/^PNG chunk\s+/i, "").replace(/^LSB .*? (ZIP empty|ZIP spanned|ZIP|RAR|7z|PDF|EXE\/DLL|ELF|SQLite|OLE|PNG|JPEG|GIF|WEBP|BMP|TIFF|ISO BMFF \/ MP4)$/i, "$1");
  const map: Record<string, { extension: string; mime: string }> = {
    ZIP: { extension: "zip", mime: "application/zip" },
    "ZIP empty": { extension: "zip", mime: "application/zip" },
    "ZIP spanned": { extension: "zip", mime: "application/zip" },
    RAR: { extension: "rar", mime: "application/vnd.rar" },
    "7z": { extension: "7z", mime: "application/x-7z-compressed" },
    PDF: { extension: "pdf", mime: "application/pdf" },
    "EXE/DLL": { extension: "bin", mime: "application/octet-stream" },
    ELF: { extension: "elf", mime: "application/octet-stream" },
    SQLite: { extension: "sqlite", mime: "application/vnd.sqlite3" },
    OLE: { extension: "ole", mime: "application/octet-stream" },
    PNG: { extension: "png", mime: "image/png" },
    JPEG: { extension: "jpg", mime: "image/jpeg" },
    GIF: { extension: "gif", mime: "image/gif" },
    WEBP: { extension: "webp", mime: "image/webp" },
    BMP: { extension: "bmp", mime: "image/bmp" },
    TIFF: { extension: "tiff", mime: "image/tiff" },
    "ISO BMFF / MP4": { extension: "mp4", mime: "video/mp4" }
  };
  return map[normalized] ?? { extension: "bin", mime: "application/octet-stream" };
}

function inferPayloadLabel(bytes: Uint8Array) {
  return findEmbeddedFileSignatures(bytes, 0)[0]?.label ?? "Binary";
}

function normalizedEmbeddedOffset(label: string, offset: number) {
  if (label === "ISO BMFF / MP4" && offset >= 4) return offset - 4;
  return offset;
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

function carvePayloadBytes(label: string, bytes: Uint8Array) {
  const normalized = label.replace(/^Trailer\s+/i, "").replace(/^LSB .*? (ZIP empty|ZIP spanned|ZIP|RAR|7z|PDF|EXE\/DLL|ELF|SQLite|OLE|PNG|JPEG|GIF|WEBP|BMP|TIFF|ISO BMFF \/ MP4)$/i, "$1");
  let end = -1;
  if (normalized === "PNG") end = findPngEnd(bytes);
  if (normalized === "JPEG") end = findJpegEnd(bytes);
  if (normalized === "GIF") end = findGifEnd(bytes);
  if (normalized === "WEBP") end = findRiffEnd(bytes, "WEBP");
  if (normalized === "BMP") end = findBmpEnd(bytes);
  if (normalized === "ZIP" || normalized === "ZIP empty" || normalized === "ZIP spanned" || normalized === "OLE") end = findZipEnd(bytes);
  if (normalized === "PDF") end = findPdfEnd(bytes);
  if (normalized === "ISO BMFF / MP4" && bytes.length >= 8) {
    const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
    end = size >= 8 && size <= bytes.length ? size : -1;
  }
  return end > 0 ? bytes.subarray(0, end) : bytes;
}

function collectHiddenPayloads(bytes: Uint8Array, logicalEnd: number, trailer: Uint8Array, embeddedHits: Array<{ label: string; offset: number }>) {
  const payloads: ImageInfo["hiddenPayloads"] = [];
  const addPayload = (label: string, source: string, offset: number, payloadBytes: Uint8Array) => {
    if (!payloadBytes.length) return;
    const carvedBytes = carvePayloadBytes(label, payloadBytes);
    if (payloads.some((item) => item.source === source && item.offset === offset && item.size === carvedBytes.length)) return;
    const meta = payloadMetaForSignature(label);
    payloads.push({
      label,
      source,
      offset,
      size: carvedBytes.length,
      sha256: sha256Bytes(carvedBytes),
      extension: meta.extension,
      mime: meta.mime,
      preview: previewText(carvedBytes, 4096),
      bytes: carvedBytes
    });
  };
  if (trailer.length && logicalEnd >= 0) addPayload(`Trailer ${inferPayloadLabel(trailer)}`, "Container trailer", logicalEnd, trailer);
  for (const hit of embeddedHits.slice(0, 12)) {
    const offset = normalizedEmbeddedOffset(hit.label, hit.offset);
    if (offset <= 16) continue;
    addPayload(hit.label, "Embedded container bytes", offset, bytes.subarray(offset));
  }
  return payloads;
}

function collectPngChunkPayloads(bytes: Uint8Array, chunks: PngChunkInfo[]) {
  const payloads: ImageInfo["hiddenPayloads"] = [];
  for (const chunk of chunks) {
    if (pngCriticalChunks.has(chunk.type) || !chunk.length) continue;
    const suspicious = chunk.risk.length || chunk.privateUse || !knownPngChunks.has(chunk.type) || chunk.length > 4096 || chunk.entropy > 7.35;
    if (!suspicious) continue;
    const payloadBytes = bytes.subarray(chunk.dataOffset, chunk.dataOffset + chunk.length);
    const inferred = inferPayloadLabel(payloadBytes);
    const label = inferred === "Binary" ? `PNG chunk ${chunk.type}` : `PNG chunk ${chunk.type} / ${inferred}`;
    const carvedBytes = carvePayloadBytes(inferred, payloadBytes);
    const meta = payloadMetaForSignature(inferred);
    payloads.push({
      label,
      source: `PNG ancillary chunk ${chunk.type}`,
      offset: chunk.dataOffset,
      size: carvedBytes.length,
      sha256: sha256Bytes(carvedBytes),
      extension: meta.extension,
      mime: meta.mime,
      preview: previewText(carvedBytes, 4096),
      bytes: carvedBytes
    });
  }
  return payloads.slice(0, 16);
}

function buildLsbByteStream(source: ImageData, channelIndexes: number[], bitPlane: number, bitOrder: "msb" | "lsb", maxBytes = 262_144) {
  const bitLimit = Math.min(source.width * source.height * channelIndexes.length, maxBytes * 8);
  const bytes: number[] = [];
  let value = 0;
  let bitCount = 0;
  for (let pixel = 0; pixel < source.width * source.height && bitCount < bitLimit; pixel += 1) {
    const base = pixel * 4;
    for (const channel of channelIndexes) {
      const bit = (source.data[base + channel] >> bitPlane) & 1;
      if (bitOrder === "msb") value = (value << 1) | bit;
      else value |= bit << (bitCount % 8);
      bitCount += 1;
      if (bitCount % 8 === 0) {
        bytes.push(value);
        value = 0;
        if (bytes.length >= maxBytes) return new Uint8Array(bytes);
      }
    }
  }
  return new Uint8Array(bytes);
}

function collectLsbPayloadsFromImageData(source: ImageData) {
  const payloads: ImageInfo["hiddenPayloads"] = [];
  const modes = [
    { label: "RGB", indexes: [0, 1, 2] },
    { label: "R", indexes: [0] },
    { label: "G", indexes: [1] },
    { label: "B", indexes: [2] },
    { label: "A", indexes: [3] }
  ];
  for (const mode of modes) {
    for (const bitPlane of [0, 1] as const) {
      for (const bitOrder of ["msb", "lsb"] as const) {
        const stream = buildLsbByteStream(source, mode.indexes, bitPlane, bitOrder);
        const hits = findEmbeddedFileSignatures(stream, 0);
        for (const hit of hits.slice(0, 3)) {
          if (hit.offset > 4096) continue;
        const label = `LSB ${mode.label} bit ${bitPlane} ${bitOrder.toUpperCase()} ${hit.label}`;
        const payloadOffset = normalizedEmbeddedOffset(hit.label, hit.offset);
        const payloadBytes = carvePayloadBytes(hit.label, stream.slice(payloadOffset));
        if (payloads.some((item) => item.label === label && item.offset === payloadOffset)) continue;
        const meta = payloadMetaForSignature(hit.label);
        payloads.push({
          label,
          source: `LSB byte stream (${mode.label} bit ${bitPlane} ${bitOrder.toUpperCase()})`,
          offset: payloadOffset,
          size: payloadBytes.length,
            sha256: sha256Bytes(payloadBytes),
            extension: meta.extension,
            mime: meta.mime,
            preview: previewText(payloadBytes, 4096),
            bytes: payloadBytes
          });
        }
      }
    }
  }
  return payloads.slice(0, 12);
}

async function buildHiddenPayloadPreviews(payloads: ImageInfo["hiddenPayloads"]) {
  const previews: ImageInfo["hiddenPayloadPreviews"] = [];
  for (const payload of payloads.slice(0, 8)) {
    if (!/^image\//i.test(payload.mime)) continue;
    const format = detectImageFormat(payload.bytes, payload.mime);
    const candidates: Array<{ label: string; bytes: Uint8Array; mime: string; note: string }> = [
      {
        label: "Original payload candidate",
        bytes: payload.bytes,
        mime: payload.mime,
        note: "Payload candidate decoded without repair."
      },
      ...buildImageRepairCandidates(payload.bytes, format)
    ];
    const rebuiltPng = tryRebuildPngContainer(payload.bytes);
    if (rebuiltPng) {
      candidates.push({
        label: "Rebuilt hidden PNG critical chunks",
        bytes: rebuiltPng.bytes,
        mime: "image/png",
        note: rebuiltPng.notes.join(" ")
      });
    }
    for (const candidate of candidates) {
      try {
        const src = await bytesToDataUrl(candidate.bytes, candidate.mime);
        await loadBrowserImage(src);
        const repaired = candidate.label !== "Original payload candidate";
        const sha256 = sha256Bytes(candidate.bytes);
        previews.push({
          label: repaired ? `${payload.label} / repaired` : payload.label,
          offset: payload.offset,
          src,
          detail: `${payload.label} at offset ${payload.offset}, ${formatBytes(payload.size)}, SHA256 ${payload.sha256.slice(0, 16)}...${repaired ? ` Preview recovered by: ${candidate.label}. Repaired SHA256 ${sha256.slice(0, 16)}...` : ""} ${candidate.note}`
        });
        break;
      } catch {
        // Try the next candidate. Extraction still remains available in the payload table.
      }
    }
    if (previews.some((preview) => preview.offset === payload.offset && preview.label.includes(payload.label))) continue;
    try {
      previews.push({
        label: payload.label,
        offset: payload.offset,
        src: await bytesToDataUrl(payload.bytes, payload.mime),
        detail: `${payload.label} at offset ${payload.offset}, ${formatBytes(payload.size)}, SHA256 ${payload.sha256.slice(0, 16)}... Browser decode was not confirmed; download and inspect separately.`
      });
    } catch {
      // Keep extraction available even if the browser cannot preview this payload.
    }
  }
  return previews;
}

function loadBrowserImage(src: string) {
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = src;
  });
}

function addImageSignal(signals: ImageDecodedSignal[], signal: ImageDecodedSignal) {
  const key = `${signal.type}|${signal.value.slice(0, 240)}`;
  if (signals.some((item) => `${item.type}|${item.value.slice(0, 240)}` === key)) return;
  signals.push(signal);
}

function classifyImageTextSignal(source: string, text: string) {
  const value = text.trim();
  const signals: ImageDecodedSignal[] = [];
  if (!value || value.length < 4) return signals;
  const preview = value.slice(0, 4000);
  const iocAnalysis = analyzeIocs(preview, source);
  const riskyIocs = iocAnalysis.records.filter((record) => record.risk.length);
  const urls = Array.from(new Set(preview.match(/https?:\/\/[^\s"'<>]+|www\.[^\s"'<>]+/gi) ?? [])).slice(0, 6);
  const emails = Array.from(new Set(preview.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) ?? [])).slice(0, 6);
  const secretMatches = Array.from(new Set(preview.match(/(?:AKIA|ASIA)[A-Z0-9]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,}|sk-[A-Za-z0-9_-]{24,}|(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*["']?[^"'\s,;]{6,}/gi) ?? [])).slice(0, 8);
  if (secretMatches.length) {
    addImageSignal(signals, {
      source,
      type: "Key / token pattern",
      level: "warn",
      value: secretMatches.join("\n"),
      detail: "文本片段包含 key/token/password 等字段样式，请结合上下文复核。",
      rows: secretMatches.map((item, index) => [`Hit ${index + 1}`, item])
    });
  }
  if (urls.length) {
    const urlRows = urls.flatMap((url, index) => {
      const findings = analyzeUrl(url).findings.filter((finding) => finding.level !== "info").slice(0, 3);
      return [
        [`URL ${index + 1}`, url],
        [`URL ${index + 1} checks`, findings.map((finding) => finding.title).join(" / ") || "--"]
      ] as Array<[string, string]>;
    });
    addImageSignal(signals, {
      source,
      type: "URL / Link",
      level: urlRows.some(([, risk]) => risk !== "--" && /review|redirect|credential|private|suspicious|danger/i.test(risk)) ? "warn" : "info",
      value: urls.join("\n"),
      detail: "文本片段中提取到 URL，可继续用 URL 分析器核验跳转、参数和主机信息。",
      rows: urlRows
    });
  }
  if (emails.length) {
    addImageSignal(signals, {
      source,
      type: "Email address",
      level: "info",
      value: emails.join("\n"),
      detail: "文本片段中提取到邮箱地址，请结合邮件、页面或案件上下文复核。",
      rows: emails.map((item, index) => [`Email ${index + 1}`, item] as [string, string])
    });
  }
  if (riskyIocs.length) {
    addImageSignal(signals, {
      source,
      type: "IOC review marker",
      level: "warn",
      value: riskyIocs.slice(0, 12).map((record) => `${record.type}: ${record.value}`).join("\n"),
      detail: "文本片段命中 IOC 样式规则，建议单独登记并交叉验证来源。",
      rows: riskyIocs.slice(0, 12).map((record) => [record.type, `${record.value} (${record.risk.join(", ")})`] as [string, string])
    });
  }
  if (/^[A-Za-z0-9+/=_-]{80,}$/.test(value.replace(/\s+/g, ""))) {
    const codec = analyzeCodecCandidates(value);
    addImageSignal(signals, {
      source,
      type: "Encoded blob",
      level: "info",
      value: value.slice(0, 1000),
      detail: "隐藏文本像 Base64/Base64URL/十六进制等编码内容，已列出自动检测候选。",
      rows: codec.candidates.slice(0, 6).map((candidate) => [candidate.label, `score ${candidate.score}; ${candidate.note ?? "--"}`] as [string, string])
    });
  }
  return signals;
}

async function decodeQrSignalFromDataUrl(src: string, source: string) {
  try {
    const jsQrModule = await import("jsqr");
    const jsQR = jsQrModule.default;
    const image = await loadBrowserImage(src);
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) return null;
    const dimensions = imageAnalysisDimensions(image.naturalWidth, image.naturalHeight, 1_000_000);
    canvas.width = dimensions.width;
    canvas.height = dimensions.height;
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);
    if (!code?.data) return null;
    const payloadType = classifyQrPayload(code.data);
    const payloadRows = parseQrPayloadDetails(code.data, payloadType);
    const iocAnalysis = analyzeIocs(code.data, `${source} QR`);
    const urlFindings = payloadType === "URL" ? analyzeUrl(code.data).findings.filter((finding) => finding.level !== "info") : [];
    const geometryRows: Array<[string, string]> = code.location ? qrGeometryRows(code.location as unknown as Record<string, unknown>, canvas.width, canvas.height) : [["Geometry", "--"]];
    const findings = buildQrFindings(code.data, payloadType, payloadRows, iocAnalysis.records, urlFindings, true, geometryRows, 0);
    const level = findings.some((finding) => finding.level === "danger") ? "danger" : findings.some((finding) => finding.level === "warn") ? "warn" : "info";
    return {
      source,
      type: `QR: ${payloadType}`,
      level,
      value: code.data,
      detail: findings.slice(0, 4).map((finding) => finding.title).join(" / ") || "二维码已在浏览器本地解码。",
      rows: [...payloadRows, ...geometryRows].slice(0, 28)
    } satisfies ImageDecodedSignal;
  } catch {
    return null;
  }
}

async function buildImageDecodedSignals(info: {
  displayDataUrl: string;
  repairedDataUrl: string;
  autoRevealPreviews: ImageInfo["autoRevealPreviews"];
  hiddenPayloadPreviews: ImageInfo["hiddenPayloadPreviews"];
  hiddenPayloads: ImageInfo["hiddenPayloads"];
  lsbCandidates: ImageInfo["lsbCandidates"];
  trailerText: string;
  pngTextEntries: PngTextEntry[];
}) {
  const signals: ImageDecodedSignal[] = [];
  const qrTargets = [
    { source: "Displayed image", src: info.displayDataUrl },
    { source: "Normalized PNG", src: info.repairedDataUrl },
    ...info.autoRevealPreviews
      .filter((preview) => /LSB|Low-bit|Alpha|Noise/i.test(preview.label))
      .slice(0, 5)
      .map((preview) => ({ source: preview.label, src: preview.src })),
    ...info.hiddenPayloadPreviews.slice(0, 4).map((preview) => ({ source: `Payload candidate ${preview.label}`, src: preview.src }))
  ].filter((target, index, rows) => target.src && rows.findIndex((item) => item.src === target.src) === index).slice(0, 6);
  for (const target of qrTargets) {
    const signal = await decodeQrSignalFromDataUrl(target.src, target.source);
    if (signal) addImageSignal(signals, signal);
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  for (const candidate of info.lsbCandidates) {
    classifyImageTextSignal(`LSB ${candidate.mode}`, candidate.text).forEach((signal) => addImageSignal(signals, signal));
  }
  if (info.trailerText) classifyImageTextSignal("Container trailer text", info.trailerText).forEach((signal) => addImageSignal(signals, signal));
  for (const entry of info.pngTextEntries) {
    classifyImageTextSignal(`PNG ${entry.chunk} ${entry.keyword}@${entry.offset}`, entry.text).forEach((signal) => addImageSignal(signals, signal));
  }
  for (const payload of info.hiddenPayloads.slice(0, 8)) {
    if (/^text\//i.test(payload.mime) || payload.preview.match(/[\t\n\r -~]{32,}/)) {
      classifyImageTextSignal(`${payload.source} ${payload.label}@${payload.offset}`, payload.preview).forEach((signal) => addImageSignal(signals, signal));
    }
  }
  return signals.slice(0, 24);
}

function inspectJpegStructure(bytes: Uint8Array) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (!(bytes[0] === 0xff && bytes[1] === 0xd8)) return { rows, findings };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 2;
  const markers: string[] = [];
  let appSegments = 0;
  let comments = 0;
  let sawSos = false;
  let brokenSegment = "";
  while (offset + 4 <= bytes.length && markers.length < 256) {
    while (offset < bytes.length && bytes[offset] !== 0xff) offset += 1;
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    if (offset >= bytes.length) break;
    const marker = bytes[offset];
    const markerOffset = offset - 1;
    markers.push(`0xFF${marker.toString(16).padStart(2, "0").toUpperCase()}@${markerOffset}`);
    if (marker >= 0xe0 && marker <= 0xef) appSegments += 1;
    if (marker === 0xfe) comments += 1;
    if (marker === 0xd9) break;
    if (marker === 0xda) {
      sawSos = true;
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      offset += 1;
      continue;
    }
    if (offset + 2 >= bytes.length) {
      brokenSegment = `marker 0xFF${marker.toString(16).padStart(2, "0").toUpperCase()} has no segment length`;
      break;
    }
    const length = view.getUint16(offset + 1);
    if (length < 2 || offset + 1 + length > bytes.length) {
      brokenSegment = `marker 0xFF${marker.toString(16).padStart(2, "0").toUpperCase()} length ${length} exceeds file boundary`;
      break;
    }
    offset += 1 + length;
  }
  rows.push(["JPEG markers before image data", String(markers.length)]);
  rows.push(["JPEG APP segments", String(appSegments)]);
  rows.push(["JPEG comments", String(comments)]);
  rows.push(["JPEG SOS found", sawSos ? "yes" : "no"]);
  if (brokenSegment) findings.push({ level: "warn", title: "Broken JPEG segment", detail: brokenSegment });
  if (!sawSos) findings.push({ level: "warn", title: "JPEG scan data not reached", detail: "The parser did not reach the Start Of Scan marker; the file may be truncated before pixel data." });
  return { rows, findings };
}

function inspectWebpStructure(bytes: Uint8Array) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (!(readAscii(bytes, 0, 4) === "RIFF" && readAscii(bytes, 8, 4) === "WEBP") || bytes.length < 12) return { rows, findings };
  const declaredSize = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(4, true) + 8;
  rows.push(["WEBP declared size", formatBytes(declaredSize)]);
  if (declaredSize > bytes.length) findings.push({ level: "warn", title: "WEBP appears truncated", detail: `RIFF declares ${formatBytes(declaredSize)}, but the file has ${formatBytes(bytes.length)}.` });
  if (declaredSize < bytes.length) findings.push({ level: "warn", title: "WEBP trailing bytes", detail: `${formatBytes(bytes.length - declaredSize)} exist after the declared RIFF payload.` });
  return { rows, findings };
}

function inspectBmpStructure(bytes: Uint8Array) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (bytes.length < 14 || bytes[0] !== 0x42 || bytes[1] !== 0x4d) return { rows, findings };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const declaredSize = view.getUint32(2, true);
  const pixelOffset = view.getUint32(10, true);
  rows.push(["BMP declared size", formatBytes(declaredSize)]);
  rows.push(["BMP pixel offset", String(pixelOffset)]);
  if (declaredSize > bytes.length) findings.push({ level: "warn", title: "BMP appears truncated", detail: `Header declares ${formatBytes(declaredSize)}, but the file has ${formatBytes(bytes.length)}.` });
  if (declaredSize > 0 && declaredSize < bytes.length) findings.push({ level: "warn", title: "BMP trailing bytes", detail: `${formatBytes(bytes.length - declaredSize)} exist after the declared BMP payload.` });
  if (pixelOffset >= bytes.length) findings.push({ level: "warn", title: "BMP pixel offset out of range", detail: `Pixel array offset ${pixelOffset} is outside the file.` });
  return { rows, findings };
}

function inspectHeifStructure(bytes: Uint8Array) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (bytes.length < 12 || readAscii(bytes, 4, 4) !== "ftyp") return { rows, findings };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  const boxes: string[] = [];
  while (offset + 8 <= bytes.length && boxes.length < 80) {
    let size = view.getUint32(offset);
    const type = readAscii(bytes, offset + 4, 4);
    let header = 8;
    if (size === 1 && offset + 16 <= bytes.length) {
      const high = view.getUint32(offset + 8);
      const low = view.getUint32(offset + 12);
      size = high * 0x100000000 + low;
      header = 16;
    }
    if (!size) size = bytes.length - offset;
    boxes.push(`${type}@${offset}:${formatBytes(size)}`);
    if (size < header || offset + size > bytes.length) {
      findings.push({ level: "warn", title: "HEIF/AVIF box exceeds file boundary", detail: `${type}@${offset} declares ${formatBytes(size)}, file has ${formatBytes(bytes.length - offset)} remaining.` });
      break;
    }
    offset += size;
  }
  rows.push(["HEIF/AVIF boxes", boxes.join(", ") || "--"]);
  if (offset < bytes.length) findings.push({ level: "warn", title: "HEIF/AVIF trailing bytes", detail: `${formatBytes(bytes.length - offset)} remain after parsed boxes.` });
  return { rows, findings };
}

function inspectTiffStructure(bytes: Uint8Array) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (bytes.length < 8) return { rows, findings };
  const little = readAscii(bytes, 0, 2) === "II";
  const big = readAscii(bytes, 0, 2) === "MM";
  if (!little && !big) return { rows, findings };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = view.getUint16(2, little);
  const ifdOffset = view.getUint32(4, little);
  rows.push(["TIFF endian", little ? "little" : "big"]);
  rows.push(["TIFF magic", String(magic)]);
  rows.push(["First IFD offset", String(ifdOffset)]);
  if (magic !== 42) findings.push({ level: "warn", title: "TIFF magic mismatch", detail: `Expected 42, got ${magic}.` });
  if (ifdOffset >= bytes.length) findings.push({ level: "warn", title: "TIFF IFD offset out of range", detail: `First IFD offset ${ifdOffset} is outside the file.` });
  return { rows, findings };
}

function imageEvidenceReportText(info: ImageInfo) {
  return [
    "# Image Analysis",
    "",
    `File: ${info.name}`,
    `Size: ${formatBytes(info.size)}`,
    `Type: ${info.type}`,
    `Decoded pixels: ${info.decoded ? "yes" : "no"}`,
    `Dimensions: ${info.width} x ${info.height}`,
    `SHA256: ${info.sha256}`,
    "",
    "## Diagnosis",
    `${info.diagnosis.title}: ${info.diagnosis.detail}`,
    "",
    "## Assessment",
    `[${info.autoAssessment.level}] ${info.autoAssessment.title}`,
    info.autoAssessment.subtitle,
    `Action: ${info.autoAssessment.primaryAction}`,
    ...info.autoAssessment.items.map((item) => `- [${item.level}] ${item.label}: ${item.value} - ${item.detail}`),
    "",
    "## Scan Steps",
    ...info.scanSteps.map((step) => `- [${step.level}] ${step.stage}: ${step.status}\n  Evidence: ${limitReportText(step.evidence, 700)}\n  Display: ${step.display}\n  Next: ${step.next}`),
    "",
    "## Display Queue",
    ...info.autoDisplayItems.map((item, index) => `${index + 1}. [${item.level}] ${item.label} (${item.role})\n   Reason: ${limitReportText(item.reason, 700)}\n   Action: ${item.action}`),
    "",
    "## Details",
    ...info.triageRows.map((row) => `- [${row.level}] ${row.area}: ${row.verdict}\n  Evidence: ${limitReportText(row.evidence, 700)}\n  Display: ${row.display}\n  Action: ${row.action}`),
    "",
    "## Priority Reveals",
    ...info.priorityReveals.map((item, index) => `${index + 1}. [${item.level}] ${item.title}\n   Result: ${limitReportText(item.result, 700)}\n   Reason: ${limitReportText(item.reason, 700)}`),
    "",
    "## Notes",
    ...info.autoInsights.map((item, index) => `${index + 1}. [${item.level}] ${item.title}\n   ${item.detail}\n   Action: ${item.action}`),
    "",
    "## Notes Board",
    ...info.evidenceBoard.map((item, index) => `${index + 1}. [${item.level}] ${item.title}\n   ${item.detail}\n   Action: ${item.action}`),
    "",
    "## Decoded Signals",
    ...(info.decodedSignals.length
      ? info.decodedSignals.map((signal) => `- [${signal.level}] ${signal.source} / ${signal.type}\n  ${limitReportText(signal.detail, 500)}\n  ${limitReportText(signal.value, 1000)}`)
      : ["- Not detected"]),
    "",
    "## Repair",
    info.repairStatus,
    ...info.repairNotes.map((note) => `- ${note}`),
    ...(info.repairDownloads.length
      ? ["", "## Downloadable Repair Candidates", ...info.repairDownloads.map((candidate) => `- ${candidate.label} / ${formatBytes(candidate.size)} / SHA256 ${candidate.sha256}\n  ${candidate.note}`)]
      : []),
    "",
    "## Findings",
    ...info.findings.map((finding) => `- [${finding.level}] ${finding.title}: ${finding.detail}`),
    "",
    "## Hidden Payloads",
    ...(info.hiddenPayloads.length
      ? info.hiddenPayloads.map((payload) => `- ${payload.label} / ${payload.source} / offset ${payload.offset} / ${formatBytes(payload.size)} / SHA256 ${payload.sha256}`)
      : ["- Not detected"]),
    "",
    "## PNG Text Metadata",
    ...(info.pngTextEntries.length
      ? info.pngTextEntries.map((entry) => `- ${entry.chunk} ${entry.keyword}@${entry.offset}: ${entry.text.slice(0, 300)}`)
      : ["- Not detected"]),
    "",
    "## LSB Candidates",
    ...(info.lsbCandidates.length
      ? info.lsbCandidates.map((candidate) => `- ${candidate.mode}: ${candidate.text.slice(0, 500)}`)
      : ["- Not detected"])
  ].join("\n");
}

function scoreImageNoise(source: ImageData) {
  if (source.width < 3 || source.height < 3) {
    return { rows: [["Local noise anomaly", "not available; image too small"]] as Array<[string, string]>, findings: [] as Array<{ level: string; title: string; detail: string }> };
  }
  let total = 0;
  let strong = 0;
  let checked = 0;
  const luminanceAt = (pixel: number) => {
    const base = pixel * 4;
    return source.data[base] * 0.299 + source.data[base + 1] * 0.587 + source.data[base + 2] * 0.114;
  };
  for (let y = 1; y < source.height - 1; y += 1) {
    for (let x = 1; x < source.width - 1; x += 1) {
      const pixel = y * source.width + x;
      const center = luminanceAt(pixel);
      const neighborAverage = (
        luminanceAt(pixel - 1) +
        luminanceAt(pixel + 1) +
        luminanceAt(pixel - source.width) +
        luminanceAt(pixel + source.width)
      ) / 4;
      const delta = Math.abs(center - neighborAverage);
      total += delta;
      if (delta > 52) strong += 1;
      checked += 1;
    }
  }
  const mean = checked ? total / checked : 0;
  const strongRatio = checked ? strong / checked : 0;
  const rows: Array<[string, string]> = [
    ["Local noise mean", mean.toFixed(2)],
    ["Strong local noise pixels", `${(strongRatio * 100).toFixed(2)}%`]
  ];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (strongRatio > 0.18 && mean > 26) {
    findings.push({
      level: "warn",
      title: "High local noise anomaly",
      detail: `${(strongRatio * 100).toFixed(2)}% of interior pixels differ strongly from their immediate neighborhood; inspect the noise map for pasted blocks, hidden masks, or generated noise.`
    });
  }
  return { rows, findings };
}

function createChannelPreviews(image: HTMLImageElement) {
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Canvas is not available");

  const dimensions = imageAnalysisDimensions(image.naturalWidth, image.naturalHeight, 220_000);
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  const source = context.getImageData(0, 0, canvas.width, canvas.height);

  const makeChannel = (channel: "red" | "green" | "blue" | "alpha" | "lsb" | "lsbRed" | "lsbGreen" | "lsbBlue" | "lowBitHeatmap" | "noiseMap") => {
    const output = context.createImageData(source.width, source.height);
    const luminanceAt = (pixel: number) => {
      const base = pixel * 4;
      return source.data[base] * 0.299 + source.data[base + 1] * 0.587 + source.data[base + 2] * 0.114;
    };
    for (let index = 0; index < source.data.length; index += 4) {
      const red = source.data[index];
      const green = source.data[index + 1];
      const blue = source.data[index + 2];
      const alpha = source.data[index + 3];
      const pixel = index / 4;
      const x = pixel % source.width;
      const y = Math.floor(pixel / source.width);
      let value = 0;
      if (channel === "red") value = red;
      if (channel === "green") value = green;
      if (channel === "blue") value = blue;
      if (channel === "alpha") value = alpha;
      if (channel === "lsb") value = ((red & 1) | ((green & 1) << 1) | ((blue & 1) << 2)) * 36;
      if (channel === "lsbRed") value = (red & 1) ? 255 : 0;
      if (channel === "lsbGreen") value = (green & 1) ? 255 : 0;
      if (channel === "lsbBlue") value = (blue & 1) ? 255 : 0;
      if (channel === "lowBitHeatmap") {
        output.data[index] = (red & 3) * 85;
        output.data[index + 1] = (green & 3) * 85;
        output.data[index + 2] = (blue & 3) * 85;
      } else if (channel === "noiseMap") {
        const hasNeighbors = x > 0 && x < source.width - 1 && y > 0 && y < source.height - 1;
        const neighborAverage = hasNeighbors
          ? (luminanceAt(pixel - 1) + luminanceAt(pixel + 1) + luminanceAt(pixel - source.width) + luminanceAt(pixel + source.width)) / 4
          : luminanceAt(pixel);
        const delta = Math.min(255, Math.abs(luminanceAt(pixel) - neighborAverage) * 4);
        output.data[index] = delta;
        output.data[index + 1] = delta > 96 ? Math.min(255, delta + 50) : delta;
        output.data[index + 2] = delta > 96 ? 30 : delta;
      } else {
        output.data[index] = value;
        output.data[index + 1] = value;
        output.data[index + 2] = value;
      }
      output.data[index + 3] = 255;
    }
    context.putImageData(output, 0, 0);
    return canvas.toDataURL("image/png");
  };

  const makeBitPlane = (channelIndex: 0 | 1 | 2 | 3, bit: number) => {
    const output = context.createImageData(source.width, source.height);
    for (let index = 0; index < source.data.length; index += 4) {
      const value = ((source.data[index + channelIndex] >> bit) & 1) ? 255 : 0;
      output.data[index] = value;
      output.data[index + 1] = value;
      output.data[index + 2] = value;
      output.data[index + 3] = 255;
    }
    context.putImageData(output, 0, 0);
    return canvas.toDataURL("image/png");
  };

  return {
    red: makeChannel("red"),
    green: makeChannel("green"),
    blue: makeChannel("blue"),
    alpha: makeChannel("alpha"),
    lsb: makeChannel("lsb"),
    lsbRed: makeChannel("lsbRed"),
    lsbGreen: makeChannel("lsbGreen"),
    lsbBlue: makeChannel("lsbBlue"),
    lowBitHeatmap: makeChannel("lowBitHeatmap"),
    noiseMap: makeChannel("noiseMap"),
    bitPlanes: [
      { label: "R bit 0", src: makeBitPlane(0, 0) },
      { label: "G bit 0", src: makeBitPlane(1, 0) },
      { label: "B bit 0", src: makeBitPlane(2, 0) },
      { label: "A bit 0", src: makeBitPlane(3, 0) },
      { label: "R bit 1", src: makeBitPlane(0, 1) },
      { label: "G bit 1", src: makeBitPlane(1, 1) },
      { label: "B bit 1", src: makeBitPlane(2, 1) },
      { label: "A bit 1", src: makeBitPlane(3, 1) }
    ]
  };
}

function buildAutoRevealPreviews(channels: ImageInfo["channelDataUrls"], hasAlphaSignal: boolean) {
  const previews = [
    {
      label: "Noise anomaly map",
      src: channels.noiseMap,
      detail: "局部噪声异常图。亮色块、规则边界或文字轮廓可能对应拼接、擦写、局部隐写或异常压缩区域。"
    },
    {
      label: "Low-bit heatmap",
      src: channels.lowBitHeatmap,
      detail: "RGB 低 2 位热力图。规则色块、文字轮廓或明显块状图案通常需要进一步检查。"
    },
    {
      label: "RGB LSB",
      src: channels.lsb,
      detail: "RGB 最低有效位组合图。出现清晰文字、形状或大块规律纹理时，优先怀疑 LSB 隐写。"
    },
    {
      label: "Red LSB",
      src: channels.lsbRed,
      detail: "红色通道最低位。单通道隐藏内容常会在这里形成高对比黑白图。"
    },
    {
      label: "Green LSB",
      src: channels.lsbGreen,
      detail: "绿色通道最低位。用于和 R/B 通道交叉比对，排除自然噪声。"
    },
    {
      label: "Blue LSB",
      src: channels.lsbBlue,
      detail: "蓝色通道最低位。很多简单隐写工具会优先使用 B 通道。"
    }
  ];
  if (hasAlphaSignal) {
    previews.unshift({
      label: "Alpha",
      src: channels.alpha,
      detail: "透明通道可视化。非透明区域异常、文字轮廓或规则图案可能表示隐藏信息。"
    });
  }
  channels.bitPlanes.forEach((plane) => {
    previews.push({
      label: plane.label,
      src: plane.src,
      detail: "自动位平面可视化。若能看到文字、二维码轮廓、规则图案或边界，优先按隐写线索处理。"
    });
  });
  return previews;
}

function scoreImageBitPlanes(source: ImageData) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  const channels = [
    { label: "R", index: 0 },
    { label: "G", index: 1 },
    { label: "B", index: 2 },
    { label: "A", index: 3 }
  ];
  const pixels = source.width * source.height;
  for (const channel of channels) {
    for (const bitPlane of [0, 1, 2, 3]) {
      let ones = 0;
      let horizontalTransitions = 0;
      let compared = 0;
      for (let y = 0; y < source.height; y += 1) {
        let previous = -1;
        for (let x = 0; x < source.width; x += 1) {
          const pixel = y * source.width + x;
          const bit = (source.data[pixel * 4 + channel.index] >> bitPlane) & 1;
          ones += bit;
          if (previous >= 0) {
            horizontalTransitions += previous === bit ? 0 : 1;
            compared += 1;
          }
          previous = bit;
        }
      }
      const oneRatio = pixels ? ones / pixels : 0;
      const transitionRatio = compared ? horizontalTransitions / compared : 0;
      const label = `${channel.label} bit ${bitPlane}`;
      rows.push([label, `ones ${(oneRatio * 100).toFixed(2)}% / transitions ${(transitionRatio * 100).toFixed(2)}%`]);
      const normalOpaqueAlpha = channel.label === "A" && oneRatio === 1 && transitionRatio === 0;
      if (!normalOpaqueAlpha && bitPlane <= 1 && (oneRatio < 0.30 || oneRatio > 0.70 || transitionRatio < 0.18 || transitionRatio > 0.82)) {
        findings.push({
          level: "info",
          title: `${label} distribution note`,
          detail: `ones ${(oneRatio * 100).toFixed(2)}%, horizontal transitions ${(transitionRatio * 100).toFixed(2)}%. Inspect the bit-plane preview only when it shows readable text, QR outlines, or regular shapes.`
        });
      }
    }
  }
  return { rows, findings };
}

function inspectImageContainerBytes(bytes: Uint8Array, fileType: string, exif: Record<string, unknown>) {
  const format = detectImageFormat(bytes, fileType);
  const logicalEnd = getImageLogicalEnd(bytes, format);
  const trailer = logicalEnd >= 0 && logicalEnd < bytes.length ? bytes.slice(logicalEnd) : new Uint8Array();
  const rows: Array<[string, string]> = [
    ["Detected format", format],
    ["Header", hexPreview(bytes, 16)],
    ["File entropy", `${shannonEntropy(bytes).toFixed(4)} / 8`],
    ["Logical end", logicalEnd >= 0 ? String(logicalEnd) : "--"],
    ["Trailing bytes", trailer.length ? formatBytes(trailer.length) : "0 B"]
  ];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (["PNG", "JPEG", "GIF", "WEBP"].includes(format) && logicalEnd < 0) {
    findings.push({
      level: "warn",
      title: "Image end marker not found",
      detail: `${format} logical end marker could not be located. The file may be truncated or structurally damaged.`
    });
  }
  const embeddedHits = format === "UNKNOWN" || logicalEnd < 0 ? findEmbeddedFileSignatures(bytes) : [];
  if (embeddedHits.length) {
    rows.push(["Embedded signatures", embeddedHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ")]);
    findings.push({ level: "warn", title: "Embedded file signature", detail: embeddedHits.map((hit) => `${hit.label} at offset ${hit.offset}`).join(", ") });
  }
  let pngChunks: ImageInfo["pngChunks"] = [];
  let pngTextEntries: PngTextEntry[] = [];
  if (format === "PNG") {
    try {
      const parsed = parsePngFile(bytes);
      pngChunks = parsed.chunks;
      pngTextEntries = parsed.chunks.map((chunk) => decodePngTextChunk(bytes, chunk)).filter(Boolean) as PngTextEntry[];
      const badChunks = parsed.chunks.filter((chunk) => !chunk.ok);
      const critical = parsed.chunks.filter((chunk) => pngCriticalChunks.has(chunk.type));
      rows.push(["PNG chunks", String(parsed.chunks.length)]);
      rows.push(["PNG critical chunks", critical.map((chunk) => chunk.type).join(", ") || "--"]);
      rows.push(["PNG CRC errors", String(badChunks.length)]);
      rows.push(["PNG text chunks", String(pngTextEntries.length)]);
      if (parsed.chunks[0]?.type !== "IHDR") findings.push({ level: "warn", title: "PNG IHDR is not first", detail: "Critical PNG chunk order is invalid; viewers may reject or recover differently." });
      if (!parsed.chunks.some((chunk) => chunk.type === "IEND")) findings.push({ level: "warn", title: "PNG IEND missing", detail: "The PNG logical end chunk was not parsed; the file may be truncated." });
      if (badChunks.length) findings.push({ level: "warn", title: "PNG CRC mismatch", detail: badChunks.map((chunk) => `${chunk.type}@${chunk.offset}`).join(", ") });
      if (pngTextEntries.length) findings.push({ level: "warn", title: "PNG text metadata", detail: pngTextEntries.map((entry) => `${entry.keyword}: ${entry.text.slice(0, 80)}`).join(" / ") });
      const unknownChunks = parsed.chunks.filter((chunk) => !knownPngChunks.has(chunk.type));
      if (unknownChunks.length) findings.push({ level: "warn", title: "Unusual PNG chunks", detail: unknownChunks.map((chunk) => `${chunk.type}@${chunk.offset}`).join(", ") });
    } catch (error) {
      findings.push({ level: "warn", title: "PNG structure parse failed", detail: error instanceof Error ? error.message : String(error) });
    }
  }
  if (format === "JPEG") {
    const jpeg = inspectJpegStructure(bytes);
    rows.push(...jpeg.rows);
    findings.push(...jpeg.findings);
  }
  if (format === "WEBP") {
    const webp = inspectWebpStructure(bytes);
    rows.push(...webp.rows);
    findings.push(...webp.findings);
  }
  if (format === "BMP") {
    const bmp = inspectBmpStructure(bytes);
    rows.push(...bmp.rows);
    findings.push(...bmp.findings);
  }
  if (format === "TIFF") {
    const tiff = inspectTiffStructure(bytes);
    rows.push(...tiff.rows);
    findings.push(...tiff.findings);
  }
  if (format === "HEIF/AVIF") {
    const heif = inspectHeifStructure(bytes);
    rows.push(...heif.rows);
    findings.push(...heif.findings);
  }
  if (format === "GIF") {
    rows.push(["GIF trailer found", logicalEnd >= 0 ? "yes" : "no"]);
  }
  if (trailer.length) {
    const trailerHits = findEmbeddedFileSignatures(trailer, 0);
    rows.push(["Trailer entropy", `${shannonEntropy(trailer).toFixed(4)} / 8`]);
    rows.push(["Trailer signatures", trailerHits.length ? trailerHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ") : "--"]);
    findings.push({
      level: "warn",
      title: "Trailing data after image end",
      detail: `${formatBytes(trailer.length)} after ${format} logical end; this is a common place for appended payload candidates.${trailerHits.length ? ` Signature: ${trailerHits.map((hit) => hit.label).join(", ")}` : ""}`
    });
  }
  if (Object.keys(exif).length > 20) findings.push({ level: "warn", title: "Large metadata surface", detail: `${Object.keys(exif).length} metadata fields were parsed.` });
  return { format, logicalEnd, trailer, rows, findings, embeddedHits, pngChunks, pngTextEntries };
}

function analyzeUndecodedImageBytes(bytes: Uint8Array, fileType: string, exif: Record<string, unknown>, recoveryRows: Array<[string, string]>) {
  const container = inspectImageContainerBytes(bytes, fileType, exif);
  const hiddenPayloads = [
    ...collectHiddenPayloads(bytes, container.logicalEnd, container.trailer, container.embeddedHits),
    ...collectPngChunkPayloads(bytes, container.pngChunks)
  ];
  const findings = [
    {
      level: "warn",
      title: "Pixel decode failed",
      detail: `The browser could not decode the image pixels after ${recoveryRows.length} attempt(s). Container-level evidence is still available; original pixels cannot be reliably reconstructed in-browser.`
    },
    ...container.findings
  ];
  if (hiddenPayloads.length) {
    findings.push({
      level: "warn",
      title: "Extractable payload candidate",
      detail: hiddenPayloads.map((payload) => `${payload.label}@${payload.offset} (${formatBytes(payload.size)})`).join(", ")
    });
  }
  const hiddenRows: Array<[string, string]> = [
    ["Trailing payload", container.trailer.length ? `${formatBytes(container.trailer.length)} after logical end` : "not detected"],
    ["Extractable payloads", hiddenPayloads.length ? hiddenPayloads.map((payload) => `${payload.label}@${payload.offset}`).join(", ") : "not detected"],
    ["LSB binary payloads", "not available; pixel decode failed"],
    ["PNG extra chunks", container.pngChunks.filter((chunk) => !pngCriticalChunks.has(chunk.type) && chunk.risk.length).map((chunk) => `${chunk.type}@${chunk.offset}`).join(", ") || "not detected"],
    ["Embedded file signatures", container.embeddedHits.length ? container.embeddedHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ") : "not detected"],
    ["Readable LSB candidates", "not available; pixel decode failed"],
    ["PNG text metadata", container.pngTextEntries.length ? container.pngTextEntries.map((entry) => `${entry.keyword}@${entry.offset}`).join(", ") : "not detected"],
    ["Alpha anomaly", "not available; pixel decode failed"],
    ["Metadata fields", String(Object.keys(exif).length)]
  ];
  return {
    rows: container.rows,
    findings,
    hiddenRows,
    stegoRows: [["Pixel-level LSB analysis", "not available; image pixels could not be decoded"]] as Array<[string, string]>,
    trailerBytes: container.trailer,
    trailerPreview: container.trailer.length ? hexPreview(container.trailer, 256) : "",
    trailerText: container.trailer.length ? previewText(container.trailer, 4096) : "",
    lsbText: "",
    lsbCandidates: [],
    hiddenPayloads,
    pngTextEntries: container.pngTextEntries,
    pngChunks: container.pngChunks
  };
}

function analyzeImageBytes(bytes: Uint8Array, fileType: string, image: HTMLImageElement, exif: Record<string, unknown>) {
  const container = inspectImageContainerBytes(bytes, fileType, exif);
  const { rows, findings, pngTextEntries, pngChunks, embeddedHits, logicalEnd, trailer } = container;

  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Canvas is not available");
  const dimensions = imageAnalysisDimensions(image.naturalWidth, image.naturalHeight, 1_000_000);
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
  let alphaTransparent = 0;
  let alphaNon255 = 0;
  let redOnes = 0;
  let greenOnes = 0;
  let blueOnes = 0;
  const pixels = imageData.width * imageData.height;
  for (let index = 0; index < imageData.data.length; index += 4) {
    if (imageData.data[index + 3] === 0) alphaTransparent += 1;
    if (imageData.data[index + 3] !== 255) alphaNon255 += 1;
    redOnes += imageData.data[index] & 1;
    greenOnes += imageData.data[index + 1] & 1;
    blueOnes += imageData.data[index + 2] & 1;
  }
  rows.push(["Alpha pixels != 255", String(alphaNon255)]);
  rows.push(["Red LSB one ratio", `${(redOnes / pixels * 100).toFixed(2)}%`]);
  rows.push(["Green LSB one ratio", `${(greenOnes / pixels * 100).toFixed(2)}%`]);
  rows.push(["Blue LSB one ratio", `${(blueOnes / pixels * 100).toFixed(2)}%`]);
  const lsbRatios = [
    ["Red", redOnes / pixels],
    ["Green", greenOnes / pixels],
    ["Blue", blueOnes / pixels]
  ] as Array<[string, number]>;
  const unusualRatios = lsbRatios.filter(([, ratio]) => ratio < 0.38 || ratio > 0.62);
  if (unusualRatios.length) {
    findings.push({
      level: "info",
      title: "Low-bit distribution note",
      detail: `${unusualRatios.map(([channel, ratio]) => `${channel} ${(ratio * 100).toFixed(2)}% ones`).join(", ")}. This is a local distribution note, not a standalone hidden-data finding.`
    });
  }
  if (alphaTransparent > 0 || alphaNon255 > pixels * 0.02) findings.push({ level: "warn", title: "Alpha channel carries data", detail: `${alphaNon255} pixels have non-opaque alpha; inspect alpha preview.` });
  const lsbCandidates = extractLsbCandidatesFromImageData(imageData);
  const lsbText = lsbCandidates[0]?.text ?? "";
  rows.push(["Readable LSB candidates", String(lsbCandidates.length)]);
  const bitPlaneScore = scoreImageBitPlanes(imageData);
  findings.push(...bitPlaneScore.findings.slice(0, 6));
  const noiseScore = scoreImageNoise(imageData);
  findings.push(...noiseScore.findings);
  if (lsbCandidates.some((candidate) => /https?:\/\/|flag\{|ctf|password|secret|key=|PK\x03\x04|MZ|%PDF/i.test(candidate.text))) {
    findings.push({ level: "warn", title: "Readable LSB candidate", detail: `${lsbCandidates[0].mode}: ${lsbCandidates[0].text.slice(0, 160)}` });
  } else if (lsbCandidates.length) {
    findings.push({ level: "warn", title: "Printable LSB text candidate", detail: `${lsbCandidates[0].mode}: ${lsbCandidates[0].text.slice(0, 160)}` });
  }
  if (!findings.length) findings.push({ level: "info", title: "No obvious hidden-data marker", detail: "No trailer, CRC error, readable LSB text, or major alpha anomaly was detected by quick checks." });
  const lsbPayloads = collectLsbPayloadsFromImageData(imageData);
  const hiddenPayloads = [
    ...collectHiddenPayloads(bytes, logicalEnd, trailer, embeddedHits),
    ...collectPngChunkPayloads(bytes, pngChunks),
    ...lsbPayloads
  ];
  if (hiddenPayloads.length) {
    const cleanIndex = findings.findIndex((finding) => finding.title === "No obvious hidden-data marker");
    if (cleanIndex >= 0) findings.splice(cleanIndex, 1);
    findings.push({
      level: "warn",
      title: "Extractable payload candidate",
      detail: hiddenPayloads.map((payload) => `${payload.label}@${payload.offset} (${formatBytes(payload.size)})`).join(", ")
    });
  }
  const hiddenRows: Array<[string, string]> = [
    ["Trailing payload", trailer.length ? `${formatBytes(trailer.length)} after logical end` : "not detected"],
    ["Extractable payloads", hiddenPayloads.length ? hiddenPayloads.map((payload) => `${payload.label}@${payload.offset}`).join(", ") : "not detected"],
    ["LSB binary payloads", lsbPayloads.length ? lsbPayloads.map((payload) => `${payload.label}@${payload.offset}`).join(", ") : "not detected"],
    ["PNG extra chunks", pngChunks.filter((chunk) => !pngCriticalChunks.has(chunk.type) && chunk.risk.length).map((chunk) => `${chunk.type}@${chunk.offset}`).join(", ") || "not detected"],
    ["Embedded file signatures", embeddedHits.length ? embeddedHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ") : "not detected"],
    ["Readable LSB candidates", lsbCandidates.length ? lsbCandidates.map((candidate) => candidate.mode).join(", ") : "not detected"],
    ["PNG text metadata", pngTextEntries.length ? pngTextEntries.map((entry) => `${entry.keyword}@${entry.offset}`).join(", ") : "not detected"],
    ["Alpha anomaly", alphaNon255 ? `${alphaNon255} non-opaque pixels` : "not detected"],
    ["Metadata fields", String(Object.keys(exif).length)]
  ];

  return {
    rows,
    findings,
    hiddenRows,
    stegoRows: [...bitPlaneScore.rows, ...noiseScore.rows],
    trailerBytes: trailer,
    trailerPreview: trailer.length ? hexPreview(trailer, 256) : "",
    trailerText: trailer.length ? previewText(trailer, 4096) : "",
    lsbText,
    lsbCandidates,
    hiddenPayloads,
    pngTextEntries,
    pngChunks
  };
}

function decodePngTextChunk(bytes: Uint8Array, chunk: PngChunkInfo): PngTextEntry | null {
  const data = bytes.slice(chunk.dataOffset, chunk.dataOffset + chunk.length);
  const nul = data.indexOf(0);
  if (nul < 0) return null;
  const keyword = strFromU8(data.slice(0, nul)) || "--";
  try {
    if (chunk.type === "tEXt") {
      return { chunk: chunk.type, offset: chunk.offset, keyword, text: strFromU8(data.slice(nul + 1)), compressed: false };
    }
    if (chunk.type === "zTXt") {
      const method = data[nul + 1];
      const payload = data.slice(nul + 2);
      const text = method === 0 ? strFromU8(decompressSync(payload)) : `Unsupported compression method ${method}`;
      return { chunk: chunk.type, offset: chunk.offset, keyword, text, compressed: true };
    }
    if (chunk.type === "iTXt") {
      const compressionFlag = data[nul + 1];
      let cursor = nul + 3;
      const langEnd = data.indexOf(0, cursor);
      cursor = langEnd >= 0 ? langEnd + 1 : cursor;
      const translatedEnd = data.indexOf(0, cursor);
      cursor = translatedEnd >= 0 ? translatedEnd + 1 : cursor;
      const payload = data.slice(cursor);
      const text = compressionFlag ? strFromU8(decompressSync(payload)) : strFromU8(payload);
      return { chunk: chunk.type, offset: chunk.offset, keyword, text, compressed: Boolean(compressionFlag) };
    }
  } catch (error) {
    return { chunk: chunk.type, offset: chunk.offset, keyword, text: error instanceof Error ? error.message : String(error), compressed: chunk.type !== "tEXt" };
  }
  return null;
}

function buildQrFindings(payload: string, payloadType: string, payloadRows: Array<[string, string]>, iocs: IocRecord[], urlFindings: QrAnalysis["urlFindings"], hasCode: boolean, geometryRows: Array<[string, string]>, imageEntropy: number) {
  const findings: QrAnalysis["findings"] = [];
  if (!hasCode) {
    findings.push({ level: "warn", title: "No QR code decoded", detail: "The image loaded, but jsQR did not find a decodable QR symbol." });
    return findings;
  }
  findings.push({ level: "info", title: "QR decoded locally", detail: `${payloadType} payload, ${new Blob([payload]).size} byte(s).` });
  if (payload.length > 2048) findings.push({ level: "warn", title: "Long QR payload", detail: `${payload.length} characters may hide nested or encoded data.` });
  if (payloadType === "OTP Secret") findings.push({ level: "warn", title: "OTP secret QR", detail: "The QR appears to contain a TOTP/HOTP enrollment secret. Treat it like a credential and redact before sharing." });
  if (payloadType === "Crypto Payment") findings.push({ level: "warn", title: "Cryptocurrency payment URI", detail: "The QR contains a cryptocurrency address or payment request. Verify address ownership and amount out-of-band." });
  if (payloadType === "Payment / App Link") findings.push({ level: "warn", title: "Payment or app action link", detail: "The QR can launch a payment/app workflow. Check scheme, host, amount, callback, and redirect parameters." });
  if (payloadType === "App Deep Link") findings.push({ level: "warn", title: "App deep link", detail: "The payload uses a non-web URI scheme and may trigger app-specific actions." });
  if (/WIFI:/i.test(payload) && /(?:^|;)P:[^;]+/i.test(payload)) findings.push({ level: "warn", title: "WiFi password in QR", detail: "The payload appears to contain a WiFi password field." });
  if (payloadType === "WiFi Config" && payloadRows.some(([key, value]) => key === "Auth" && /^nopass$/i.test(value))) findings.push({ level: "warn", title: "Open WiFi QR", detail: "The QR config appears to describe a network without authentication." });
  if (payloadType === "vCard") findings.push({ level: "info", title: "Contact data payload", detail: "The QR contains personal/contact fields; preserve only when relevant to the case scope." });
  if (payloadType === "Geo") findings.push({ level: "info", title: "Location payload", detail: "The QR contains geographic coordinates or a map query." });
  if (payloadType === "Email") findings.push({ level: "warn", title: "Email action payload", detail: "The QR can prefill an email recipient, subject, or body. Check the surrounding social-engineering context." });
  if (payloadType === "SMS") findings.push({ level: "warn", title: "SMS action payload", detail: "The QR can prefill a phone number and message body." });
  if (/(token|secret|password|passwd|pwd|session|auth|apikey|api_key)=/i.test(payload)) findings.push({ level: "warn", title: "Sensitive-looking parameter", detail: "Payload contains a credential/session keyword." });
  if (/[\u200b-\u200f\u202a-\u202e]/.test(payload)) findings.push({ level: "warn", title: "Invisible Unicode marker", detail: "Payload contains zero-width or bidi control characters." });
  if (/^[A-Za-z0-9+/=_-]{80,}$/.test(payload.trim().replace(/\s+/g, ""))) findings.push({ level: "info", title: "Encoded-looking payload", detail: "Payload resembles Base64/Base64URL or another compact encoding." });
  if (payloadRows.some(([key, value]) => /Address|URL|Host|To|Phone|Number/i.test(key) && /(xn--|\.top|\.xyz|\.zip|\.mov|bit\.ly|tinyurl|t\.co)/i.test(value))) {
    findings.push({ level: "warn", title: "Destination needs review", detail: "Structured QR fields contain punycode, special TLD, or URL-shortener-like destination." });
  }
  const geometryMap = new Map(geometryRows);
  const coverage = Number((geometryMap.get("Coverage") ?? "0").replace("%", ""));
  const rotation = Math.abs(Number((geometryMap.get("Rotation") ?? "0").replace(" deg", "")));
  if (coverage > 0 && coverage < 2) findings.push({ level: "warn", title: "Small QR in image", detail: `QR bounding box covers ${coverage.toFixed(2)}% of the image; resampling may affect repeatability.` });
  if (rotation > 12) findings.push({ level: "info", title: "Rotated QR symbol", detail: `Estimated top-edge rotation is ${rotation.toFixed(2)} degrees.` });
  if (imageEntropy > 7.4) findings.push({ level: "info", title: "High image entropy", detail: `${imageEntropy.toFixed(4)} / 8; compression/noise may affect decode repeatability.` });
  findings.push(...urlFindings);
  const riskyIocs = iocs.filter((record) => record.risk.length);
  if (riskyIocs.length) findings.push({ level: "warn", title: "IOC worth review", detail: riskyIocs.slice(0, 8).map((record) => `${record.type} ${record.value}: ${record.risk.join(", ")}`).join("\n") });
  return findings;
}

export { analyzeImageBytes, analyzeUndecodedImageBytes, buildAutoRevealPreviews, buildHiddenPayloadPreviews, buildImageDecodedSignals, buildImageRepairCandidates, bytesToDataUrl, carvePayloadBytes, createChannelPreviews, createNormalizedImageDataUrl, detectImageFormat, emptyImageChannels, getImageLogicalEnd, guessImageDimensions, imageEvidenceReportText, imageExtensionForMime, imageMimeForFormat, imagePlaceholderDataUrl, loadBrowserImage, payloadMetaForSignature, revokeImageObjectUrls, tryRebuildPngContainer, decodePngTextChunk };

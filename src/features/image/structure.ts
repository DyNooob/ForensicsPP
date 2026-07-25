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

import { decompressSync, strFromU8 } from "fflate";
import type { ImageInfo, PngChunkInfo, PngTextEntry } from "../../models";
import { hexPreview, readAscii, shannonEntropy, findEmbeddedFileSignatures } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { knownPngChunks, parsePngFile, pngCriticalChunks } from "../png/parser";
import { detectImageFormat, getImageLogicalEnd, imageMetadataFieldCount } from "./format";

type ImageMetadata = Record<string, unknown> | number;

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

function inspectImageContainerBytes(bytes: Uint8Array, fileType: string, exif: ImageMetadata) {
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
  const metadataFields = imageMetadataFieldCount(exif);
  if (metadataFields > 20) findings.push({ level: "warn", title: "Large metadata surface", detail: `${metadataFields} metadata fields were parsed.` });
  return { format, logicalEnd, trailer, rows, findings, embeddedHits, pngChunks, pngTextEntries };
}

export {
  decodePngTextChunk,
  inspectImageContainerBytes
};

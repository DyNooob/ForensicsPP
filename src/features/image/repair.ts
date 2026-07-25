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

import { crc32, hexPreview, readAscii } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { parsePngFile } from "../png/parser";
import { getImageLogicalEnd, imageMimeForFormat, findImageSignatureOffset } from "./format";

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

export {
  tryRebuildPngContainer,
  buildImageRepairCandidates
};

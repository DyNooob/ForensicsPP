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

import { findEmbeddedFileSignatures, previewText } from "../../utils/binary";
import type { ImageInfo, PngChunkInfo } from "../../models";
import { knownPngChunks, pngCriticalChunks } from "../png/parser";
import { findPngEnd, findJpegEnd, findGifEnd, findBmpEnd, findZipEnd, findPdfEnd, findRiffEnd } from "./format";

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
      extension: meta.extension,
      mime: meta.mime,
      preview: previewText(carvedBytes, 4096),
      bytes: carvedBytes
    });
  }
  return payloads.slice(0, 16);
}

export {
  payloadMetaForSignature,
  carvePayloadBytes,
  collectHiddenPayloads,
  collectPngChunkPayloads,
  normalizedEmbeddedOffset
};

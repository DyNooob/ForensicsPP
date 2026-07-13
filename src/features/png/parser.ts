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

import type { PngChunkInfo } from "../../models";
import { crc32, hexPreview, previewText, readAscii, shannonEntropy } from "../../utils/binary";

export const knownPngChunks = new Set(["IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "gAMA", "cHRM", "sRGB", "pHYs", "bKGD", "tIME", "iCCP", "sBIT", "tRNS", "hIST", "eXIf", "oFFs", "pCAL", "sCAL", "sPLT", "acTL", "fcTL", "fdAT"]);
export const pngCriticalChunks = new Set(["IHDR", "PLTE", "IDAT", "IEND"]);

export function pngChunkRisks(type: string, data: Uint8Array, ok: boolean, ancillary: boolean, privateUse: boolean, entropy: number) {
  const risk: string[] = [];
  if (!ok) risk.push("CRC mismatch");
  if (!knownPngChunks.has(type)) risk.push(ancillary ? "unknown ancillary chunk" : "unknown critical chunk");
  if (privateUse) risk.push("private-use chunk");
  if (pngCriticalChunks.has(type) && type !== "IDAT") {
    if (type === "IHDR" && data.length !== 13) risk.push("invalid IHDR length");
    if (type === "IEND" && data.length !== 0) risk.push("invalid IEND length");
  }
  if (!pngCriticalChunks.has(type) && data.length > 1024 * 1024) risk.push("large non-image chunk");
  if (!pngCriticalChunks.has(type) && entropy > 7.35 && data.length > 2048) risk.push("high-entropy metadata");
  if (["tEXt", "zTXt", "iTXt"].includes(type) && /https?:\/\/|www\.|token|password|secret|key=|apikey|bearer|flag\{/i.test(previewText(data, 4096))) risk.push("metadata contains IOC/secret-like text");
  return risk;
}

export function parsePngFile(bytes: Uint8Array) {
  const signature = "89 50 4E 47 0D 0A 1A 0A";
  if (hexPreview(bytes, 8) !== signature) throw new Error("Not a PNG file");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunks: PngChunkInfo[] = [];
  let offset = 8;
  let iendEnd = -1;
  while (offset + 12 <= bytes.length && chunks.length < 2000) {
    const length = view.getUint32(offset);
    const type = readAscii(bytes, offset + 4, 4);
    if (offset + 12 + length > bytes.length) break;
    const crc = view.getUint32(offset + 8 + length);
    const computed = crc32(bytes.slice(offset + 4, offset + 8 + length));
    const data = bytes.slice(offset + 8, offset + 8 + length);
    const entropy = shannonEntropy(data);
    const ancillary = (type.charCodeAt(0) & 0x20) !== 0;
    const privateUse = (type.charCodeAt(1) & 0x20) !== 0;
    const ok = crc === computed;
    chunks.push({
      offset,
      dataOffset: offset + 8,
      endOffset: offset + 12 + length,
      type,
      length,
      crc: `0x${crc.toString(16).padStart(8, "0").toUpperCase()}`,
      computed: `0x${computed.toString(16).padStart(8, "0").toUpperCase()}`,
      ok,
      ancillary,
      privateUse,
      safeToCopy: (type.charCodeAt(3) & 0x20) !== 0,
      entropy,
      hexPreview: hexPreview(data, 256),
      preview: previewText(data, 600),
      risk: pngChunkRisks(type, data, ok, ancillary, privateUse, entropy)
    });
    offset += 12 + length;
    if (type === "IEND") {
      iendEnd = offset;
      break;
    }
  }
  const ihdr = chunks.find((chunk) => chunk.type === "IHDR");
  const rows: Array<[string, string]> = [["Chunks", String(chunks.length)]];
  if (ihdr) {
    const ihdrOffset = ihdr.offset + 8;
    rows.unshift(
      ["Width", String(view.getUint32(ihdrOffset))],
      ["Height", String(view.getUint32(ihdrOffset + 4))],
      ["Bit depth", String(bytes[ihdrOffset + 8])],
      ["Color type", String(bytes[ihdrOffset + 9])],
      ["Interlace", String(bytes[ihdrOffset + 12])]
    );
  }
  const trailer = iendEnd >= 0 ? bytes.slice(iendEnd) : new Uint8Array();
  return { rows, chunks, trailer };
}

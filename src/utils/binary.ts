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

import { strFromU8 } from "fflate";
import type { FileSignatureDef } from "../models";

export const fileSignatures: FileSignatureDef[] = [
  { bytes: "89 50 4E 47 0D 0A 1A 0A", label: "PNG image", extensions: ["png"] },
  { bytes: "FF D8 FF", label: "JPEG image", extensions: ["jpg", "jpeg"] },
  { bytes: "47 49 46 38", label: "GIF image", extensions: ["gif"] },
  { bytes: "52 49 46 46", label: "RIFF container", extensions: ["webp", "wav", "avi"] },
  { bytes: "57 45 42 50", label: "WEBP image", extensions: ["webp"], offset: 8 },
  { bytes: "57 41 56 45", label: "WAV audio", extensions: ["wav"], offset: 8 },
  { bytes: "41 56 49 20", label: "AVI video", extensions: ["avi"], offset: 8 },
  { bytes: "66 74 79 70", label: "ISO BMFF / MP4 family", extensions: ["mp4", "mov", "heic", "heif", "m4a"], offset: 4 },
  { bytes: "42 4D", label: "BMP image", extensions: ["bmp"] },
  { bytes: "49 49 2A 00", label: "TIFF image little-endian", extensions: ["tif", "tiff"] },
  { bytes: "4D 4D 00 2A", label: "TIFF image big-endian", extensions: ["tif", "tiff"] },
  { bytes: "25 50 44 46", label: "PDF document", extensions: ["pdf"] },
  { bytes: "50 4B 03 04", label: "ZIP / OOXML / APK / JAR", extensions: ["zip", "docx", "xlsx", "pptx", "apk", "jar"] },
  { bytes: "50 4B 05 06", label: "Empty ZIP archive", extensions: ["zip"] },
  { bytes: "50 4B 07 08", label: "Spanned ZIP archive", extensions: ["zip"] },
  { bytes: "52 61 72 21 1A 07", label: "RAR archive", extensions: ["rar"] },
  { bytes: "37 7A BC AF 27 1C", label: "7-Zip archive", extensions: ["7z"] },
  { bytes: "1F 8B", label: "Gzip archive", extensions: ["gz", "tgz"] },
  { bytes: "42 5A 68", label: "Bzip2 archive", extensions: ["bz2"] },
  { bytes: "FD 37 7A 58 5A 00", label: "XZ archive", extensions: ["xz"] },
  { bytes: "4D 5A", label: "Windows PE executable", extensions: ["exe", "dll", "sys", "scr"] },
  { bytes: "7F 45 4C 46", label: "ELF executable", extensions: ["elf", "so"] },
  { bytes: "FE ED FA CE", label: "Mach-O 32-bit", extensions: ["macho"] },
  { bytes: "FE ED FA CF", label: "Mach-O 64-bit", extensions: ["macho"] },
  { bytes: "CA FE BA BE", label: "Mach-O Universal / Java class", extensions: ["class", "macho"] },
  { bytes: "D0 CF 11 E0 A1 B1 1A E1", label: "OLE Compound File", extensions: ["doc", "xls", "ppt", "msi"] },
  { bytes: "53 51 4C 69 74 65 20 66", label: "SQLite database", extensions: ["sqlite", "sqlite3", "db"] },
  { bytes: "0A 0D 0D 0A", label: "PCAPNG capture", extensions: ["pcapng"] },
  { bytes: "D4 C3 B2 A1", label: "PCAP capture little-endian", extensions: ["pcap"] },
  { bytes: "A1 B2 C3 D4", label: "PCAP capture big-endian", extensions: ["pcap"] },
  { bytes: "49 44 33", label: "MP3 ID3 audio", extensions: ["mp3"] },
  { bytes: "FF FB", label: "MP3 audio frame", extensions: ["mp3"] },
  { bytes: "4F 67 67 53", label: "Ogg media", extensions: ["ogg", "oga", "ogv"] },
  { bytes: "66 4C 61 43", label: "FLAC audio", extensions: ["flac"] },
  { bytes: "7B 5C 72 74 66", label: "RTF document", extensions: ["rtf"] },
  { bytes: "25 21 50 53", label: "PostScript", extensions: ["ps", "eps"] }
];

export function hexPreview(bytes: Uint8Array, count = 16) {
  return Array.from(bytes.slice(0, count))
    .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
    .join(" ");
}

export function previewText(bytes: Uint8Array, limit = 4096) {
  const sample = bytes.slice(0, limit);
  const text = strFromU8(sample).replace(/\u0000/g, "");
  const printableRatio = text ? (text.match(/[\t\n\r -~\u00a0-\uffff]/g)?.length ?? 0) / text.length : 0;
  return printableRatio > 0.82 ? text : hexPreview(sample, 256);
}

export function fileSignatureForBytes(bytes: Uint8Array) {
  return fileSignatures.find((signature) => {
    const offset = signature.offset ?? 0;
    const sample = hexPreview(bytes.slice(offset), 16);
    return sample.startsWith(signature.bytes);
  }) ?? null;
}

function looksLikePortableExecutable(bytes: Uint8Array, offset: number) {
  if (offset + 0x40 >= bytes.length) return false;
  if (bytes[offset] !== 0x4d || bytes[offset + 1] !== 0x5a) return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = view.getUint32(offset + 0x3c, true);
  if (peOffset < 0x40 || peOffset > 4096 || offset + peOffset + 4 > bytes.length) return false;
  return bytes[offset + peOffset] === 0x50
    && bytes[offset + peOffset + 1] === 0x45
    && bytes[offset + peOffset + 2] === 0
    && bytes[offset + peOffset + 3] === 0;
}

export function findEmbeddedFileSignatures(bytes: Uint8Array, startOffset = 32) {
  const signatures = [
    { label: "ZIP", bytes: [0x50, 0x4b, 0x03, 0x04] },
    { label: "ZIP empty", bytes: [0x50, 0x4b, 0x05, 0x06] },
    { label: "ZIP spanned", bytes: [0x50, 0x4b, 0x07, 0x08] },
    { label: "RAR", bytes: [0x52, 0x61, 0x72, 0x21] },
    { label: "7z", bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
    { label: "PDF", bytes: [0x25, 0x50, 0x44, 0x46] },
    { label: "EXE/DLL", bytes: [0x4d, 0x5a] },
    { label: "ELF", bytes: [0x7f, 0x45, 0x4c, 0x46] },
    { label: "SQLite", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66] },
    { label: "OLE", bytes: [0xd0, 0xcf, 0x11, 0xe0] },
    { label: "PNG", bytes: [0x89, 0x50, 0x4e, 0x47] },
    { label: "JPEG", bytes: [0xff, 0xd8, 0xff] },
    { label: "GIF", bytes: [0x47, 0x49, 0x46, 0x38] },
    { label: "WEBP", bytes: [0x52, 0x49, 0x46, 0x46] },
    { label: "BMP", bytes: [0x42, 0x4d] },
    { label: "TIFF", bytes: [0x49, 0x49, 0x2a, 0x00] },
    { label: "TIFF", bytes: [0x4d, 0x4d, 0x00, 0x2a] },
    { label: "ISO BMFF / MP4", bytes: [0x66, 0x74, 0x79, 0x70] }
  ];
  const hits: Array<{ label: string; offset: number }> = [];
  const found = new Set<string>();
  const byFirstByte = new Map<number, typeof signatures>();
  signatures.forEach((signature) => {
    const rows = byFirstByte.get(signature.bytes[0]) ?? [];
    rows.push(signature);
    byFirstByte.set(signature.bytes[0], rows);
  });
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let offset = Math.max(0, startOffset); offset < bytes.length; offset += 1) {
    const candidates = byFirstByte.get(bytes[offset]);
    if (!candidates) continue;
    for (const signature of candidates) {
      if (found.has(signature.label) || offset + signature.bytes.length > bytes.length) continue;
      if (!signature.bytes.every((byte, index) => bytes[offset + index] === byte)) continue;
      if (signature.label === "WEBP" && readAscii(bytes, offset + 8, 4) !== "WEBP") continue;
      if (signature.label === "EXE/DLL" && !looksLikePortableExecutable(bytes, offset)) continue;
      if (signature.label === "BMP") {
        if (offset + 6 > bytes.length) continue;
        const declaredSize = view.getUint32(offset + 2, true);
        if (declaredSize < 14 || offset + declaredSize > bytes.length) continue;
      }
      if (signature.label === "TIFF") {
        if (offset + 8 > bytes.length) continue;
        const little = bytes[offset] === 0x49;
        const ifdOffset = view.getUint32(offset + 4, little);
        if (ifdOffset < 8 || offset + ifdOffset >= bytes.length) continue;
      }
      if (signature.label === "ISO BMFF / MP4" && !/[a-z0-9]{4}/i.test(readAscii(bytes, offset + 4, 4))) continue;
      hits.push({ label: signature.label, offset });
      found.add(signature.label);
    }
  }
  return hits;
}

export function readAscii(bytes: Uint8Array, offset: number, length: number) {
  return Array.from(bytes.slice(offset, offset + length), (byte) => String.fromCharCode(byte)).join("");
}

export function crc32(bytes: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function shannonEntropy(bytes: Uint8Array) {
  if (!bytes.length) return 0;
  const counts = new Array(256).fill(0);
  bytes.forEach((byte) => {
    counts[byte] += 1;
  });
  return counts.reduce((sum, count) => {
    if (!count) return sum;
    const probability = count / bytes.length;
    return sum - probability * Math.log2(probability);
  }, 0);
}

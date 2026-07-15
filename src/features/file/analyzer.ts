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

import type { FileAnalysis, FileEmbeddedSignature } from "../../models";
import { fileSignatures, findEmbeddedFileSignatures, hexPreview, previewText, readAscii, shannonEntropy } from "../../utils/binary";
import { archiveExtension, formatBytes } from "../../utils/files";
import { sha256Bytes } from "../../utils/hash";
import { carvePayloadBytes, getImageLogicalEnd, payloadMetaForSignature } from "../image/analyzer";
import { extractPrintableStrings } from "../strings/analyzer";

function bytesFromHexSignature(signature: string) {
  return new Uint8Array(signature.split(/\s+/).filter(Boolean).map((part) => Number.parseInt(part, 16)));
}

function matchFileSignatures(bytes: Uint8Array) {
  return fileSignatures
    .filter((signature) => {
      const pattern = bytesFromHexSignature(signature.bytes);
      const offset = signature.offset ?? 0;
      return offset + pattern.length <= bytes.length && pattern.every((byte, index) => bytes[offset + index] === byte);
    })
    .map((signature) => ({
      label: signature.label,
      signature: signature.bytes,
      offset: signature.offset ?? 0,
      extensions: signature.extensions
    }))
    .sort((a, b) => {
      const genericPenalty = (label: string) => /RIFF container|ISO BMFF \/ MP4 family/i.test(label) ? -2 : 0;
      const score = (signature: { signature: string; offset: number; label: string }) =>
        signature.signature.split(/\s+/).filter(Boolean).length + (signature.offset ? 1 : 0) + genericPenalty(signature.label);
      return score(b) - score(a) || a.offset - b.offset;
    });
}

function fileEmbeddedMeta(label: string) {
  const normalized = label.replace(/^(?:Embedded|Trailer)\s+/i, "");
  const direct = payloadMetaForSignature(normalized);
  if (direct.extension !== "bin") return direct;
  if (/PE|executable/i.test(normalized)) return { extension: "bin", mime: "application/octet-stream" };
  if (/SQLite/i.test(normalized)) return { extension: "sqlite", mime: "application/vnd.sqlite3" };
  if (/WEBP/i.test(normalized)) return { extension: "webp", mime: "image/webp" };
  if (/BMP/i.test(normalized)) return { extension: "bmp", mime: "image/bmp" };
  if (/TIFF/i.test(normalized)) return { extension: "tiff", mime: "image/tiff" };
  if (/MP4|ISO BMFF/i.test(normalized)) return { extension: "mp4", mime: "video/mp4" };
  if (/WAV/i.test(normalized)) return { extension: "wav", mime: "audio/wav" };
  if (/MP3/i.test(normalized)) return { extension: "mp3", mime: "audio/mpeg" };
  return { extension: "bin", mime: "application/octet-stream" };
}

function canonicalPayloadLabel(label: string) {
  if (/zip|ooxml|apk|jar/i.test(label)) return "ZIP";
  if (/rar/i.test(label)) return "RAR";
  if (/7-?zip|7z/i.test(label)) return "7z";
  if (/pdf/i.test(label)) return "PDF";
  if (/png/i.test(label)) return "PNG";
  if (/jpeg|jpg/i.test(label)) return "JPEG";
  if (/gif/i.test(label)) return "GIF";
  if (/webp|riff/i.test(label)) return "WEBP";
  if (/bmp/i.test(label)) return "BMP";
  if (/tiff/i.test(label)) return "TIFF";
  if (/iso bmff|mp4|mov|heic/i.test(label)) return "ISO BMFF / MP4";
  if (/pe|exe|dll|mz/i.test(label)) return "EXE/DLL";
  if (/elf/i.test(label)) return "ELF";
  if (/sqlite/i.test(label)) return "SQLite";
  if (/ole/i.test(label)) return "OLE";
  return label;
}

function buildFileEmbeddedSignatures(bytes: Uint8Array, hits: Array<{ label: string; offset: number }>, includeHashes = true) {
  const seen = new Set<string>();
  return hits.slice(0, 80).flatMap((hit): FileEmbeddedSignature[] => {
    if (hit.offset <= 0 || hit.offset >= bytes.length) return [];
    const carvedBytes = carvePayloadBytes(canonicalPayloadLabel(hit.label), bytes.slice(hit.offset));
    const key = `${hit.label}-${hit.offset}-${carvedBytes.length}`;
    if (seen.has(key)) return [];
    seen.add(key);
    const meta = fileEmbeddedMeta(hit.label);
    const risk = [
      hit.offset < 64 ? "polyglot/header overlap" : "",
      hit.offset > Math.max(64, Math.floor(bytes.length * 0.1)) ? "late embedded payload" : "",
      carvedBytes.length < bytes.length - hit.offset ? "carved logical payload" : "",
      /PE|EXE|DLL|script|RTF|PDF|ZIP|RAR|7-Zip/i.test(hit.label) ? "active/container payload" : ""
    ].filter(Boolean);
    return [{
      label: hit.label,
      offset: hit.offset,
      size: carvedBytes.length,
      sha256: includeHashes ? sha256Bytes(carvedBytes) : "",
      extension: meta.extension,
      mime: meta.mime,
      preview: previewText(carvedBytes, 4096),
      risk,
      bytes: carvedBytes
    }];
  });
}

function asciiPreview(bytes: Uint8Array, count = 512) {
  return Array.from(bytes.slice(0, count), (byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".")).join("");
}

function fileContentProfile(bytes: Uint8Array) {
  const sample = bytes.slice(0, Math.min(bytes.length, 1024 * 1024));
  if (!sample.length) return { printableRatio: 0, nullRatio: 0, controlRatio: 0, lineBreaks: 0, profile: "empty" };
  let printable = 0;
  let nulls = 0;
  let controls = 0;
  let lineBreaks = 0;
  for (const byte of sample) {
    if (byte === 0) nulls += 1;
    if (byte === 0x0a || byte === 0x0d) lineBreaks += 1;
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e)) printable += 1;
    else if (byte < 0x20 || byte === 0x7f) controls += 1;
  }
  const printableRatio = printable / sample.length;
  const nullRatio = nulls / sample.length;
  const controlRatio = controls / sample.length;
  const profile = nullRatio > 0.08 ? "binary / structured" : printableRatio > 0.88 ? "text-like" : printableRatio > 0.45 ? "mixed" : "binary";
  return { printableRatio, nullRatio, controlRatio, lineBreaks, profile };
}

function filenameRisk(name: string, extension: string, primary: FileAnalysis["signatures"][number] | undefined) {
  const risks = [
    /\s+$/.test(name) ? "trailing whitespace" : "",
    /[\u202e\u202d\u2066-\u2069]/.test(name) ? "unicode direction override" : "",
    /\.(?:jpg|png|gif|pdf|docx?|xlsx?|txt)\.(?:exe|scr|js|vbs|ps1|bat|cmd|hta|lnk|jar)$/i.test(name) ? "double extension disguise" : "",
    /\.(?:exe|scr|js|vbs|ps1|bat|cmd|hta|lnk|jar)$/i.test(name) ? "executable/script extension" : "",
    primary && extension && !primary.extensions.includes(extension) ? "extension/header mismatch" : ""
  ].filter(Boolean);
  return Array.from(new Set(risks));
}

function parseByteOffset(value: string, max: number, fallback = 0) {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const parsed = /^0x[0-9a-f]+$/i.test(trimmed) ? Number.parseInt(trimmed.slice(2), 16) : Number.parseInt(trimmed, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(0, parsed), Math.max(0, max));
}

function binaryHexDumpRows(bytes: Uint8Array, start: number, length: number, width = 16) {
  const safeStart = Math.min(Math.max(0, start), bytes.length);
  const safeEnd = Math.min(bytes.length, safeStart + Math.max(width, length));
  const rows: Array<{ offset: number; hex: string; ascii: string }> = [];
  for (let offset = safeStart; offset < safeEnd; offset += width) {
    const chunk = bytes.slice(offset, Math.min(offset + width, safeEnd));
    rows.push({
      offset,
      hex: Array.from(chunk, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(" "),
      ascii: Array.from(chunk, (byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".")).join("")
    });
  }
  return rows;
}

function machineName(machine: number) {
  return ({
    0x014c: "Intel 386",
    0x8664: "AMD64",
    0x01c0: "ARM",
    0x01c4: "ARMv7",
    0xaa64: "ARM64"
  } as Record<number, string>)[machine] ?? `0x${machine.toString(16).toUpperCase()}`;
}

function peCharacteristics(value: number) {
  return [
    value & 0x0002 ? "EXECUTABLE_IMAGE" : "",
    value & 0x0020 ? "LARGE_ADDRESS_AWARE" : "",
    value & 0x2000 ? "DLL" : "",
    value & 0x0100 ? "32BIT_MACHINE" : ""
  ].filter(Boolean).join(", ") || `0x${value.toString(16).toUpperCase()}`;
}

function parsePeDetails(bytes: Uint8Array, view: DataView) {
  const rows: Array<[string, string]> = [];
  const sections: Array<Record<string, string>> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (bytes.length <= 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return { rows, sections, findings };
  const peOffset = view.getUint32(0x3c, true);
  rows.push(["Format", "PE / COFF"], ["PE offset", `0x${peOffset.toString(16).toUpperCase()}`]);
  if (peOffset + 24 > bytes.length || readAscii(bytes, peOffset, 4) !== "PE\u0000\u0000") {
    findings.push({ level: "danger", title: "Invalid PE header", detail: "MZ header exists, but PE signature is missing or outside the file." });
    return { rows, sections, findings };
  }
  const machine = view.getUint16(peOffset + 4, true);
  const sectionCount = view.getUint16(peOffset + 6, true);
  const timestamp = view.getUint32(peOffset + 8, true);
  const optionalSize = view.getUint16(peOffset + 20, true);
  const characteristics = view.getUint16(peOffset + 22, true);
  const optionalOffset = peOffset + 24;
  const magic = optionalOffset + 2 <= bytes.length ? view.getUint16(optionalOffset, true) : 0;
  const isPe32Plus = magic === 0x20b;
  const subsystem = optionalOffset + (isPe32Plus ? 0x5c : 0x44) + 2 <= bytes.length ? view.getUint16(optionalOffset + (isPe32Plus ? 0x5c : 0x44), true) : 0;
  const entryPoint = optionalOffset + 0x10 + 4 <= bytes.length ? view.getUint32(optionalOffset + 0x10, true) : 0;
  rows.push(
    ["Machine", machineName(machine)],
    ["Sections", String(sectionCount)],
    ["Compile Time", timestamp ? new Date(timestamp * 1000).toISOString() : "--"],
    ["Optional Header", magic === 0x20b ? "PE32+" : magic === 0x10b ? "PE32" : `0x${magic.toString(16)}`],
    ["Entry Point RVA", `0x${entryPoint.toString(16).toUpperCase()}`],
    ["Subsystem", String(subsystem)],
    ["Characteristics", peCharacteristics(characteristics)]
  );
  const sectionOffset = optionalOffset + optionalSize;
  for (let index = 0; index < sectionCount && sectionOffset + index * 40 + 40 <= bytes.length; index += 1) {
    const offset = sectionOffset + index * 40;
    const name = readAscii(bytes, offset, 8).replace(/\0/g, "");
    const virtualSize = view.getUint32(offset + 8, true);
    const virtualAddress = view.getUint32(offset + 12, true);
    const rawSize = view.getUint32(offset + 16, true);
    const rawPointer = view.getUint32(offset + 20, true);
    const chars = view.getUint32(offset + 36, true);
    const sectionBytes = rawPointer + rawSize <= bytes.length ? bytes.slice(rawPointer, rawPointer + rawSize) : new Uint8Array();
    const entropy = sectionBytes.length ? shannonEntropy(sectionBytes).toFixed(3) : "--";
    sections.push({
      Name: name || `section_${index}`,
      RVA: `0x${virtualAddress.toString(16).toUpperCase()}`,
      "Virtual Size": formatBytes(virtualSize),
      "Raw Size": formatBytes(rawSize),
      "Raw Offset": `0x${rawPointer.toString(16).toUpperCase()}`,
      Entropy: entropy,
      Flags: `0x${chars.toString(16).toUpperCase()}`
    });
    if (sectionBytes.length && Number(entropy) > 7.2) findings.push({ level: "warn", title: "High entropy PE section", detail: `${name || index}: ${entropy}/8` });
  }
  if (characteristics & 0x2000) findings.push({ level: "info", title: "DLL file", detail: "PE characteristics include DLL." });
  return { rows, sections, findings };
}

function parseElfDetails(bytes: Uint8Array, view: DataView) {
  const rows: Array<[string, string]> = [];
  const sections: Array<Record<string, string>> = [];
  if (!(bytes[0] === 0x7f && readAscii(bytes, 1, 3) === "ELF")) return { rows, sections, findings: [] as Array<{ level: string; title: string; detail: string }> };
  const is64 = bytes[4] === 2;
  const little = bytes[5] === 1;
  const type = view.getUint16(16, little);
  const machine = view.getUint16(18, little);
  const entry = is64 ? view.getBigUint64(24, little) : BigInt(view.getUint32(24, little));
  const phoff = is64 ? Number(view.getBigUint64(32, little)) : view.getUint32(28, little);
  const shoff = is64 ? Number(view.getBigUint64(40, little)) : view.getUint32(32, little);
  const phnum = view.getUint16(is64 ? 56 : 44, little);
  const shnum = view.getUint16(is64 ? 60 : 48, little);
  rows.push(
    ["Format", "ELF"],
    ["Class", is64 ? "64-bit" : "32-bit"],
    ["Endian", little ? "little-endian" : "big-endian"],
    ["Type", String(type)],
    ["Machine", `0x${machine.toString(16).toUpperCase()}`],
    ["Entry", `0x${entry.toString(16).toUpperCase()}`],
    ["Program Headers", `${phnum} @ 0x${phoff.toString(16).toUpperCase()}`],
    ["Section Headers", `${shnum} @ 0x${shoff.toString(16).toUpperCase()}`]
  );
  return { rows, sections, findings: [] as Array<{ level: string; title: string; detail: string }> };
}

function parseMachODetails(bytes: Uint8Array, view: DataView) {
  if (bytes.length < 4) return { rows: [] as Array<[string, string]>, sections: [] as Array<Record<string, string>>, findings: [] as Array<{ level: string; title: string; detail: string }> };
  const magic = view.getUint32(0, false);
  const littleMagic = view.getUint32(0, true);
  const machO = {
    0xfeedface: "Mach-O 32-bit",
    0xfeedfacf: "Mach-O 64-bit",
    0xcefaedfe: "Mach-O 32-bit little-endian",
    0xcffaedfe: "Mach-O 64-bit little-endian",
    0xcafebabe: "Mach-O Universal",
    0xbebafeca: "Mach-O Universal"
  }[magic] ?? ({ 0xfeedface: "Mach-O 32-bit", 0xfeedfacf: "Mach-O 64-bit" } as Record<number, string>)[littleMagic];
  if (!machO) return { rows: [] as Array<[string, string]>, sections: [] as Array<Record<string, string>>, findings: [] as Array<{ level: string; title: string; detail: string }> };
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const cpu = bytes.length >= 8 ? view.getUint32(4, little) : 0;
  const fileType = bytes.length >= 16 ? view.getUint32(12, little) : 0;
  const commands = bytes.length >= 20 ? view.getUint32(16, little) : 0;
  const commandSize = bytes.length >= 24 ? view.getUint32(20, little) : 0;
  return {
    rows: [
      ["Format", machO],
      ["CPU Type", `0x${cpu.toString(16).toUpperCase()}`],
      ["File Type", String(fileType)],
      ["Load Commands", String(commands)],
      ["Commands Size", formatBytes(commandSize)]
    ] as Array<[string, string]>,
    sections: [],
    findings: [] as Array<{ level: string; title: string; detail: string }>
  };
}

function analyzeFileBytes(bytes: Uint8Array, name: string, size: number, options: { includeHash?: boolean; includeSideEvidence?: boolean; includeEmbeddedHashes?: boolean } = {}): FileAnalysis {
  const includeHash = options.includeHash !== false;
  const includeSideEvidence = options.includeSideEvidence !== false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const extension = archiveExtension(name);
  const signatures = matchFileSignatures(bytes);
  const sha256 = includeHash ? sha256Bytes(bytes) : "";
  const sideEvidenceLimit = 16 * 1024 * 1024;
  const sideEvidenceBytes = includeSideEvidence ? (bytes.length > sideEvidenceLimit ? bytes.slice(0, sideEvidenceLimit) : bytes) : new Uint8Array();
  const stringAnalysis = extractPrintableStrings(sideEvidenceBytes, 5);
  const sideEvidenceScope = includeSideEvidence
    ? bytes.length > sideEvidenceLimit ? `first ${formatBytes(sideEvidenceLimit)} of ${formatBytes(bytes.length)}` : `full file (${formatBytes(bytes.length)})`
    : "not analyzed";
  const pe = parsePeDetails(bytes, view);
  const elf = parseElfDetails(bytes, view);
  const mach = parseMachODetails(bytes, view);
  const binaryRows: Array<[string, string]> = [...pe.rows, ...elf.rows, ...mach.rows];
  const sections = [...pe.sections, ...elf.sections, ...mach.sections];
  const findings: FileAnalysis["findings"] = [...pe.findings, ...elf.findings, ...mach.findings];
  const primary = signatures[0];
  const profile = fileContentProfile(bytes);
  const nameRisks = filenameRisk(name, extension, primary);
  if (!primary) findings.push({ level: "warn", title: "Unknown file signature", detail: hexPreview(bytes, 16) });
  if (primary && extension && !primary.extensions.includes(extension)) findings.push({ level: "warn", title: "Extension mismatch", detail: `.${extension} does not match ${primary.label} (${primary.extensions.join(", ")})` });
  if (nameRisks.length) findings.push({ level: "warn", title: "Filename review marker", detail: nameRisks.join(", ") });
  const embedded = buildFileEmbeddedSignatures(bytes, findEmbeddedFileSignatures(bytes).filter((hit) => hit.offset > 0), options.includeEmbeddedHashes !== false);
  if (embedded.length) findings.push({ level: "warn", title: "Embedded signature", detail: embedded.map((hit) => `${hit.label}@0x${hit.offset.toString(16).toUpperCase()} ${formatBytes(hit.size)}`).join(", ") });
  const logicalEnd = primary ? getImageLogicalEnd(bytes, primary.label.includes("PNG") ? "PNG" : primary.label.includes("JPEG") ? "JPEG" : primary.label.includes("GIF") ? "GIF" : primary.label.includes("WEBP") ? "WEBP" : "") : -1;
  const trailerBytes = logicalEnd > 0 && logicalEnd < bytes.length ? bytes.slice(logicalEnd) : new Uint8Array();
  const trailerHits = trailerBytes.length ? findEmbeddedFileSignatures(trailerBytes, 0) : [];
  if (trailerBytes.length) {
    findings.push({
      level: "warn",
      title: "Trailing data after logical end",
      detail: `${formatBytes(trailerBytes.length)} after offset 0x${logicalEnd.toString(16).toUpperCase()}${trailerHits.length ? `; signatures: ${trailerHits.map((hit) => hit.label).join(", ")}` : ""}`
    });
  }
  if (embedded.some((hit) => hit.offset > Math.max(64, Math.floor(bytes.length * 0.1)))) {
    findings.push({ level: "warn", title: "Late embedded file signature", detail: "A secondary file signature appears after the header region; check for appended or polyglot content." });
  }
  const entropy = shannonEntropy(bytes);
  if (entropy > 7.5) findings.push({ level: "warn", title: "High file entropy", detail: `${entropy.toFixed(4)} / 8` });
  if (includeSideEvidence && bytes.length > sideEvidenceLimit) findings.push({ level: "info", title: "Side evidence sampled", detail: `String/IOC/timestamp side evidence scanned ${sideEvidenceScope}. Use Strings Workbench for deeper full-file extraction if needed.` });
  if (includeSideEvidence && stringAnalysis.iocs.length) findings.push({ level: stringAnalysis.iocs.some((record) => record.risk.length) ? "warn" : "info", title: "IOC-like side evidence", detail: stringAnalysis.iocs.slice(0, 12).map((record) => `${record.type} ${record.normalized}${record.risk.length ? ` (${record.risk.join(", ")})` : ""}`).join("\n") });
  if (includeSideEvidence && stringAnalysis.timeline.length) findings.push({ level: "info", title: "Timestamp-like side evidence", detail: stringAnalysis.timeline.slice(0, 12).map((event) => `${event.iso} ${event.raw} (${event.format})`).join("\n") });
  if (includeSideEvidence && stringAnalysis.items.some((item) => item.risk.length)) findings.push({ level: "warn", title: "Strings worth review", detail: stringAnalysis.items.filter((item) => item.risk.length).slice(0, 12).map((item) => `0x${item.offset.toString(16).toUpperCase()} ${item.detectedType}: ${item.risk.join(", ")}`).join("\n") });
  const trailerRows: Array<[string, string]> = [
    ["Logical end", logicalEnd > 0 ? `0x${logicalEnd.toString(16).toUpperCase()} / ${logicalEnd}` : "--"],
    ["Trailing bytes", trailerBytes.length ? formatBytes(trailerBytes.length) : "0 B"],
    ["Trailer entropy", trailerBytes.length ? `${shannonEntropy(trailerBytes).toFixed(4)} / 8` : "--"],
    ["Trailer signatures", trailerHits.length ? trailerHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ") : "--"]
  ];
  return {
    size,
    rows: [
      ["Name", name],
      ["Size", formatBytes(size)],
      ["Extension", extension || "--"],
      ["Detected Type", primary?.label ?? "Unknown"],
      ["Signature confidence", primary ? (primary.offset === 0 ? "header match" : `offset ${primary.offset} match`) : "unknown"],
      ["Expected extensions", primary?.extensions.join(", ") ?? "--"],
      ["Extension match", primary && extension ? (primary.extensions.includes(extension) ? "yes" : "no") : "--"],
      ["Filename risk", nameRisks.join(", ") || "--"],
      ["Signature", hexPreview(bytes, 32)],
      ["Entropy", `${entropy.toFixed(4)} / 8`],
      ["Content profile", profile.profile],
      ["Printable ratio", `${(profile.printableRatio * 100).toFixed(2)}%`],
      ["Null byte ratio", `${(profile.nullRatio * 100).toFixed(2)}%`],
      ["Control byte ratio", `${(profile.controlRatio * 100).toFixed(2)}%`],
      ["Line breaks in sample", String(profile.lineBreaks)],
      ["Embedded payloads", String(embedded.length)],
      ...(includeSideEvidence ? [
        ["Side evidence scope", sideEvidenceScope],
        ["Extracted strings", String(stringAnalysis.items.length)],
        ["IOC-like strings", String(stringAnalysis.iocs.length)],
        ["Timestamp-like strings", String(stringAnalysis.timeline.length)]
      ] as Array<[string, string]> : []),
      ...(includeHash ? [["SHA256", sha256] as [string, string]] : [])
    ],
    binaryRows: binaryRows.length ? binaryRows : [["Format", primary?.label ?? "Unknown"]],
    signatures,
    embeddedSignatures: embedded,
    stringAnalysis,
    sideEvidenceScope,
    findings,
    hexPreview: hexPreview(bytes, 512),
    asciiPreview: asciiPreview(bytes, 512),
    trailerRows,
    trailerPreview: trailerBytes.length ? `${hexPreview(trailerBytes, 512)}\n\n${previewText(trailerBytes, 4096)}` : "",
    trailerBytes,
    sections
  };
}

export { analyzeFileBytes, binaryHexDumpRows, parseByteOffset };

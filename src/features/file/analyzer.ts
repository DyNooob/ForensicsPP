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
import { fileSignatures, hexPreview, previewText, readAscii, shannonEntropy } from "../../utils/binary";
import { archiveExtension, formatBytes } from "../../utils/files";
import { hashBytes, sha256Bytes } from "../../utils/hash";
import { getImageLogicalEnd, payloadMetaForSignature } from "../image/analyzer";
import { scanCarvableObjects } from "./carver";
import { scanRecursiveCarvableObjects } from "./recursiveCarver";
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

function buildFileEmbeddedSignatures(bytes: Uint8Array, includeHashes = true) {
  const recursive = scanRecursiveCarvableObjects(bytes, { maxDepth: 4, maxObjects: 256, maxExpandedBytes: 128 * 1024 * 1024, maxObjectBytes: 16 * 1024 * 1024 });
  const hits = recursive.filter((hit) => hit.offset > 0 || hit.origin !== "signature");
  const maxDownloadBytes = 16 * 1024 * 1024;
  const maxTotalDownloadBytes = 48 * 1024 * 1024;
  let retainedBytes = 0;
  return hits.slice(0, 192).map((hit): FileEmbeddedSignature => {
    const sourceBytes = hit.bytes;
    const canRetain = sourceBytes.length > 0 && sourceBytes.length <= maxDownloadBytes && retainedBytes + sourceBytes.length <= maxTotalDownloadBytes;
    const carvedBytes = canRetain ? sourceBytes.slice() : new Uint8Array();
    if (canRetain) retainedBytes += carvedBytes.byteLength;
    const previewBytes = sourceBytes.length ? sourceBytes.subarray(0, Math.min(sourceBytes.length, 4096)) : bytes.subarray(hit.offset, Math.min(bytes.length, hit.offset + Math.min(hit.size || 4096, 4096)));
    const risk = [
      hit.offset < 64 && hit.origin === "signature" ? "polyglot/header overlap" : "",
      hit.offset > Math.max(64, Math.floor(bytes.length * 0.1)) && hit.origin === "signature" ? "late embedded payload" : "",
      hit.extent === "heuristic" || hit.extent === "unknown" ? "unresolved/heuristic boundary" : "",
      /PE|EXE|DLL|script|RTF|PDF|ZIP|RAR|7z/i.test(hit.label) ? "active/container payload" : "",
      !canRetain && hit.size > 0 ? "download omitted by memory guard" : ""
    ].filter(Boolean);
    return {
      label: hit.label,
      offset: hit.offset,
      size: hit.size,
      sha256: includeHashes && carvedBytes.length ? sha256Bytes(carvedBytes) : "",
      extension: hit.extension,
      mime: hit.mime,
      preview: previewText(previewBytes, 4096),
      risk,
      confidence: hit.confidence,
      extent: hit.extent,
      detail: hit.detail,
      parentOffset: hit.parentOffset,
      depth: hit.depth,
      virtualPath: hit.virtualPath,
      origin: hit.origin,
      bytes: carvedBytes
    };
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
  const sectionCount = Math.min(96, view.getUint16(peOffset + 6, true));
  const timestamp = view.getUint32(peOffset + 8, true);
  const optionalSize = view.getUint16(peOffset + 20, true);
  const characteristics = view.getUint16(peOffset + 22, true);
  const optionalOffset = peOffset + 24;
  const magic = optionalOffset + 2 <= bytes.length ? view.getUint16(optionalOffset, true) : 0;
  const isPe32Plus = magic === 0x20b;
  const subsystem = optionalOffset + (isPe32Plus ? 0x5c : 0x44) + 2 <= bytes.length ? view.getUint16(optionalOffset + (isPe32Plus ? 0x5c : 0x44), true) : 0;
  const entryPoint = optionalOffset + 0x14 <= bytes.length ? view.getUint32(optionalOffset + 0x10, true) : 0;
  const imageBase = isPe32Plus && optionalOffset + 32 <= bytes.length ? view.getBigUint64(optionalOffset + 24, true) : optionalOffset + 32 <= bytes.length ? BigInt(view.getUint32(optionalOffset + 28, true)) : 0n;
  const sectionAlignment = optionalOffset + 36 <= bytes.length ? view.getUint32(optionalOffset + 32, true) : 0;
  const fileAlignment = optionalOffset + 40 <= bytes.length ? view.getUint32(optionalOffset + 36, true) : 0;
  const dllCharacteristics = optionalOffset + (isPe32Plus ? 0x46 : 0x46) + 2 <= bytes.length ? view.getUint16(optionalOffset + 0x46, true) : 0;
  rows.push(
    ["Machine", machineName(machine)], ["Sections", String(sectionCount)],
    ["Compile Time", timestamp ? new Date(timestamp * 1000).toISOString() : "--"],
    ["Optional Header", magic === 0x20b ? "PE32+" : magic === 0x10b ? "PE32" : `0x${magic.toString(16)}`],
    ["Entry Point RVA", `0x${entryPoint.toString(16).toUpperCase()}`], ["Image Base", `0x${imageBase.toString(16).toUpperCase()}`],
    ["Section alignment", `0x${sectionAlignment.toString(16).toUpperCase()}`], ["File alignment", `0x${fileAlignment.toString(16).toUpperCase()}`],
    ["Subsystem", String(subsystem)], ["Characteristics", peCharacteristics(characteristics)]
  );
  const sectionOffset = optionalOffset + optionalSize;
  const sectionMeta: Array<{ name: string; virtualSize: number; virtualAddress: number; rawSize: number; rawPointer: number; chars: number }> = [];
  let maximumRawEnd = 0;
  for (let index = 0; index < sectionCount && sectionOffset + index * 40 + 40 <= bytes.length; index += 1) {
    const offset = sectionOffset + index * 40;
    const name = readAscii(bytes, offset, 8).replace(/\0/g, "");
    const virtualSize = view.getUint32(offset + 8, true), virtualAddress = view.getUint32(offset + 12, true);
    const rawSize = view.getUint32(offset + 16, true), rawPointer = view.getUint32(offset + 20, true), chars = view.getUint32(offset + 36, true);
    sectionMeta.push({ name, virtualSize, virtualAddress, rawSize, rawPointer, chars });
    maximumRawEnd = Math.max(maximumRawEnd, rawPointer + rawSize);
    const sectionBytes = rawPointer + rawSize <= bytes.length ? bytes.slice(rawPointer, rawPointer + rawSize) : new Uint8Array();
    const entropy = sectionBytes.length ? shannonEntropy(sectionBytes).toFixed(3) : "--";
    sections.push({ Name: name || `section_${index}`, RVA: `0x${virtualAddress.toString(16).toUpperCase()}`, "Virtual Size": formatBytes(virtualSize), "Raw Size": formatBytes(rawSize), "Raw Offset": `0x${rawPointer.toString(16).toUpperCase()}`, Entropy: entropy, Flags: `0x${chars.toString(16).toUpperCase()}` });
    if (sectionBytes.length && Number(entropy) > 7.2) findings.push({ level: "warn", title: "High entropy PE section", detail: `${name || index}: ${entropy}/8` });
  }
  const rvaToOffset = (rva: number) => {
    for (const section of sectionMeta) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
        const result = section.rawPointer + (rva - section.virtualAddress);
        return result >= 0 && result < bytes.length ? result : -1;
      }
    }
    return rva < bytes.length ? rva : -1;
  };
  const cstring = (offset: number, max = 1024) => {
    if (offset < 0 || offset >= bytes.length) return "";
    let end = offset; while (end < bytes.length && end - offset < max && bytes[end]) end += 1;
    return new TextDecoder("windows-1252").decode(bytes.subarray(offset, end)).trim();
  };
  const dataDirectoryOffset = optionalOffset + (isPe32Plus ? 112 : 96);
  const directories: Array<{ rva: number; size: number }> = [];
  for (let index = 0; index < 16 && dataDirectoryOffset + index * 8 + 8 <= optionalOffset + optionalSize && dataDirectoryOffset + index * 8 + 8 <= bytes.length; index += 1) {
    directories.push({ rva: view.getUint32(dataDirectoryOffset + index * 8, true), size: view.getUint32(dataDirectoryOffset + index * 8 + 4, true) });
  }
  const imports: string[] = [];
  const importedLibraries: string[] = [];
  const importDirectory = directories[1];
  if (importDirectory?.rva) {
    const importOffset = rvaToOffset(importDirectory.rva);
    if (importOffset >= 0) for (let index = 0; index < 512 && importOffset + index * 20 + 20 <= bytes.length; index += 1) {
      const base = importOffset + index * 20;
      const originalThunk = view.getUint32(base, true), nameRva = view.getUint32(base + 12, true), firstThunk = view.getUint32(base + 16, true);
      if (!(originalThunk || nameRva || firstThunk)) break;
      const library = cstring(rvaToOffset(nameRva), 260);
      if (!library) continue;
      importedLibraries.push(library);
      const thunkOffset = rvaToOffset(originalThunk || firstThunk);
      const stride = isPe32Plus ? 8 : 4;
      if (thunkOffset < 0) continue;
      for (let item = 0; item < 4096 && thunkOffset + item * stride + stride <= bytes.length; item += 1) {
        const thunk = isPe32Plus ? view.getBigUint64(thunkOffset + item * stride, true) : BigInt(view.getUint32(thunkOffset + item * stride, true));
        if (!thunk) break;
        const ordinalMask = isPe32Plus ? (1n << 63n) : (1n << 31n);
        if (thunk & ordinalMask) imports.push(`${library}.#${Number(thunk & 0xffffn)}`);
        else {
          const nameOffset = rvaToOffset(Number(thunk));
          if (nameOffset >= 0 && nameOffset + 2 < bytes.length) imports.push(`${library}.${cstring(nameOffset + 2, 512) || "?"}`);
        }
        if (imports.length >= 10000) break;
      }
    }
  }
  if (importedLibraries.length) rows.push(["Imported libraries", Array.from(new Set(importedLibraries)).join(", ")], ["Imports", String(imports.length)]);
  if (imports.length) {
    const canonicalImports = imports.flatMap((item) => {
      const match = item.match(/^(.*)\.([^.]*)$/);
      if (!match) return [];
      const libraryName = match[1].toLowerCase().replace(/\.(dll|sys|ocx)$/i, "");
      const rawFunction = match[2].toLowerCase();
      if (!libraryName || !rawFunction) return [];
      const functionName = rawFunction.startsWith("#") ? `ord${rawFunction.slice(1)}` : rawFunction;
      return [`${libraryName}.${functionName}`];
    });
    if (canonicalImports.length) {
      rows.push(["Imphash", hashBytes(new TextEncoder().encode(canonicalImports.join(","))).md5]);
      if (imports.some((item) => /\.#\d+$/.test(item))) {
        rows.push(["Imphash compatibility", "Best-effort for ordinal-only imports; named imports follow the conventional DLL-extension stripping and ordered lower-case import list."]);
      }
    }
  }
  const exportDirectory = directories[0];
  if (exportDirectory?.rva) {
    const exportOffset = rvaToOffset(exportDirectory.rva);
    if (exportOffset >= 0 && exportOffset + 40 <= bytes.length) {
      const nameCount = view.getUint32(exportOffset + 24, true), namesRva = view.getUint32(exportOffset + 32, true);
      const namesOffset = rvaToOffset(namesRva); const exported: string[] = [];
      if (namesOffset >= 0) for (let index = 0; index < Math.min(nameCount, 4096) && namesOffset + index * 4 + 4 <= bytes.length; index += 1) {
        const value = cstring(rvaToOffset(view.getUint32(namesOffset + index * 4, true)), 512); if (value) exported.push(value);
      }
      rows.push(["Exports", String(nameCount)], ["Export names", exported.slice(0, 40).join(", ") || "--"]);
    }
  }
  const resourceDirectory = directories[2]; if (resourceDirectory?.rva) rows.push(["Resources", `${formatBytes(resourceDirectory.size)} @ RVA 0x${resourceDirectory.rva.toString(16).toUpperCase()}`]);
  const securityDirectory = directories[4];
  if (securityDirectory?.rva && securityDirectory.rva + securityDirectory.size <= bytes.length) rows.push(["Authenticode certificate table", `${formatBytes(securityDirectory.size)} @ file offset 0x${securityDirectory.rva.toString(16).toUpperCase()}`]);
  else rows.push(["Authenticode certificate table", "--"]);
  const debugDirectory = directories[6];
  if (debugDirectory?.rva) {
    const debugOffset = rvaToOffset(debugDirectory.rva);
    for (let index = 0; debugOffset >= 0 && index < Math.min(64, Math.floor(debugDirectory.size / 28)) && debugOffset + index * 28 + 28 <= bytes.length; index += 1) {
      const base = debugOffset + index * 28, type = view.getUint32(base + 12, true), rawSize = view.getUint32(base + 16, true), rawPointer = view.getUint32(base + 24, true);
      if (type === 2 && rawPointer + rawSize <= bytes.length && readAscii(bytes, rawPointer, 4) === "RSDS") {
        const pdb = cstring(rawPointer + 24, Math.min(4096, rawSize - 24)); if (pdb) rows.push(["PDB path", pdb]);
      }
    }
  }
  const richOffset = (() => { for (let i = 0x40; i + 8 <= Math.min(peOffset, bytes.length); i += 1) if (readAscii(bytes, i, 4) === "Rich") return i; return -1; })();
  if (richOffset >= 0) rows.push(["Rich Header", `present @ 0x${richOffset.toString(16).toUpperCase()} · XOR key 0x${view.getUint32(richOffset + 4, true).toString(16).toUpperCase()}`]);
  const text = extractPrintableStrings(bytes.subarray(0, Math.min(bytes.length, 16 * 1024 * 1024)), 6).items.map((item) => item.value);
  const manifest = text.find((value) => /<assembly\b/i.test(value)); if (manifest) rows.push(["Manifest", manifest.slice(0, 500)]);
  const versionKeys = ["FileDescription", "CompanyName", "ProductName", "OriginalFilename", "FileVersion", "ProductVersion"];
  const versionHits = text.filter((value) => versionKeys.some((key) => value.includes(key))).slice(0, 24); if (versionHits.length) rows.push(["Version-resource strings", versionHits.join(" | ")]);
  const overlayStart = Math.max(maximumRawEnd, securityDirectory?.rva && securityDirectory.rva + securityDirectory.size <= bytes.length ? securityDirectory.rva + securityDirectory.size : 0);
  if (overlayStart > 0 && overlayStart < bytes.length) { rows.push(["Overlay", `${formatBytes(bytes.length - overlayStart)} @ 0x${overlayStart.toString(16).toUpperCase()}`]); findings.push({ level: "warn", title: "PE overlay present", detail: `${formatBytes(bytes.length - overlayStart)} follows the mapped image/certificate area.` }); }
  if (!(dllCharacteristics & 0x40)) findings.push({ level: "info", title: "ASLR flag absent", detail: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set." });
  if (!(dllCharacteristics & 0x100)) findings.push({ level: "info", title: "NX compatibility flag absent", detail: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is not set." });
  const suspicious = imports.filter((item) => /(VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|WinExec|ShellExecute|URLDownloadToFile|InternetOpen|HttpSendRequest|RegSetValue|SetWindowsHookEx|LoadLibrary|GetProcAddress)/i.test(item));
  if (suspicious.length) findings.push({ level: "warn", title: "Imports worth review", detail: suspicious.slice(0, 30).join("\n") });
  if (characteristics & 0x2000) findings.push({ level: "info", title: "DLL file", detail: "PE characteristics include DLL." });
  return { rows, sections, findings };
}

function parseElfDetails(bytes: Uint8Array, view: DataView) {
  const rows: Array<[string, string]> = [];
  const sections: Array<Record<string, string>> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (!(bytes[0] === 0x7f && readAscii(bytes, 1, 3) === "ELF") || bytes.length < 52) return { rows, sections, findings };
  const is64 = bytes[4] === 2, little = bytes[5] === 1;
  const u16=(o:number)=>view.getUint16(o,little), u32=(o:number)=>view.getUint32(o,little), word=(o:number)=>is64?Number(view.getBigUint64(o,little)):u32(o);
  const type=u16(16), machine=u16(18), entry=is64?view.getBigUint64(24,little):BigInt(u32(24));
  const phoff=word(is64?32:28), shoff=word(is64?40:32), phentsize=u16(is64?54:42), phnum=Math.min(512,u16(is64?56:44)), shentsize=u16(is64?58:46), shnum=Math.min(4096,u16(is64?60:48)), shstrndx=u16(is64?62:50);
  rows.push(["Format","ELF"],["Class",is64?"64-bit":"32-bit"],["Endian",little?"little-endian":"big-endian"],["Type",String(type)],["Machine",`0x${machine.toString(16).toUpperCase()}`],["Entry",`0x${entry.toString(16).toUpperCase()}`],["Program Headers",`${phnum} @ 0x${phoff.toString(16).toUpperCase()}`],["Section Headers",`${shnum} @ 0x${shoff.toString(16).toUpperCase()}`]);
  const programs:Array<{type:number,offset:number,vaddr:number,filesz:number,memsz:number,flags:number}>=[];
  for(let i=0;i<phnum && phentsize && phoff+i*phentsize+phentsize<=bytes.length;i++){
    const o=phoff+i*phentsize; const ptype=u32(o); const flags=is64?u32(o+4):u32(o+24); const offset=word(o+(is64?8:4)); const vaddr=word(o+(is64?16:8)); const filesz=word(o+(is64?32:16)); const memsz=word(o+(is64?40:20)); programs.push({type:ptype,offset,vaddr,filesz,memsz,flags});
    if(ptype===3 && offset+filesz<=bytes.length){ let end=offset; while(end<offset+filesz&&bytes[end])end++; rows.push(["Interpreter",new TextDecoder().decode(bytes.subarray(offset,end))]); }
  }
  const rawSections:Array<{nameOff:number,type:number,flags:number,addr:number,offset:number,size:number,link:number,entsize:number}>=[];
  for(let i=0;i<shnum && shentsize && shoff+i*shentsize+shentsize<=bytes.length;i++){
    const o=shoff+i*shentsize; rawSections.push({nameOff:u32(o),type:u32(o+4),flags:word(o+8),addr:word(o+(is64?16:12)),offset:word(o+(is64?24:16)),size:word(o+(is64?32:20)),link:u32(o+(is64?40:24)),entsize:word(o+(is64?56:36))});
  }
  const shstr=rawSections[shstrndx]; const sectionName=(off:number)=>{ if(!shstr||shstr.offset+off>=bytes.length)return ""; let e=shstr.offset+off; while(e<Math.min(bytes.length,shstr.offset+shstr.size)&&bytes[e])e++; return new TextDecoder().decode(bytes.subarray(shstr.offset+off,e)); };
  const names=rawSections.map((section)=>sectionName(section.nameOff));
  for(let i=0;i<rawSections.length;i++){ const sec=rawSections[i], name=names[i]||`section_${i}`; const secBytes=sec.offset+sec.size<=bytes.length&&sec.size<=64*1024*1024?bytes.subarray(sec.offset,sec.offset+sec.size):new Uint8Array(); const entropy=secBytes.length?shannonEntropy(secBytes).toFixed(3):"--"; sections.push({Name:name,Type:`0x${sec.type.toString(16).toUpperCase()}`,Address:`0x${sec.addr.toString(16).toUpperCase()}`,Offset:`0x${sec.offset.toString(16).toUpperCase()}`,Size:formatBytes(sec.size),Entropy:entropy,Flags:`0x${sec.flags.toString(16).toUpperCase()}`}); if(secBytes.length&&Number(entropy)>7.2)findings.push({level:"warn",title:"High entropy ELF section",detail:`${name}: ${entropy}/8`}); }
  const cstrFrom=(data:Uint8Array,off:number)=>{ if(off<0||off>=data.length)return"";let e=off;while(e<data.length&&data[e])e++;return new TextDecoder().decode(data.subarray(off,e));};
  const dynamic=rawSections.findIndex((sec)=>sec.type===6); const needed:string[]=[]; let rpath="", runpath="";
  if(dynamic>=0){ const dyn=rawSections[dynamic], str=rawSections[dyn.link]; if(str&&str.offset+str.size<=bytes.length&&dyn.offset+dyn.size<=bytes.length){ const strBytes=bytes.subarray(str.offset,str.offset+str.size), stride=dyn.entsize||(is64?16:8); for(let o=dyn.offset,count=0;o+stride<=dyn.offset+dyn.size&&count<4096;o+=stride,count++){ const tag=is64?Number(view.getBigInt64(o,little)):view.getInt32(o,little); const val=word(o+(is64?8:4)); if(tag===0)break; if(tag===1){const v=cstrFrom(strBytes,val);if(v)needed.push(v);} if(tag===15)rpath=cstrFrom(strBytes,val); if(tag===29)runpath=cstrFrom(strBytes,val); } } }
  if(needed.length)rows.push(["NEEDED libraries",needed.join(", ")]); if(rpath)rows.push(["RPATH",rpath]); if(runpath)rows.push(["RUNPATH",runpath]);
  let symbolCount=0; for(const sec of rawSections)if((sec.type===2||sec.type===11)&&sec.entsize)symbolCount+=Math.floor(sec.size/sec.entsize); if(symbolCount)rows.push(["Symbols",String(symbolCount)]);
  const notes=rawSections.filter((sec)=>sec.type===7); for(const sec of notes){ if(sec.offset+sec.size>bytes.length)continue; let o=sec.offset; const limit=sec.offset+sec.size; while(o+12<=limit){ const namesz=u32(o),descsz=u32(o+4),ntype=u32(o+8); const nstart=o+12,nend=nstart+namesz,dstart=(nend+3)&~3,dend=dstart+descsz; if(dend>limit)break; const owner=new TextDecoder().decode(bytes.subarray(nstart,Math.max(nstart,nend-1))); if(owner==="GNU"&&ntype===3){rows.push(["Build ID",Array.from(bytes.subarray(dstart,dend),b=>b.toString(16).padStart(2,"0")).join("")]);break;} o=(dend+3)&~3; } }
  if(rpath && !rpath.startsWith("/"))findings.push({level:"warn",title:"Relative ELF RPATH",detail:rpath});
  if(type===3)rows.push(["PIE/shared object","ET_DYN (shared object or PIE executable)"]);
  const stack=programs.find((p)=>p.type===0x6474e551); if(stack && (stack.flags&1))findings.push({level:"warn",title:"Executable GNU stack",detail:"PT_GNU_STACK includes execute permission."});
  return { rows, sections, findings };
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
  const embedded = buildFileEmbeddedSignatures(bytes, options.includeEmbeddedHashes !== false);
  if (embedded.length) findings.push({ level: "warn", title: "Embedded signature", detail: embedded.map((hit) => `${hit.label}@0x${hit.offset.toString(16).toUpperCase()} ${formatBytes(hit.size)}`).join(", ") });
  const logicalEnd = primary ? getImageLogicalEnd(bytes, primary.label.includes("PNG") ? "PNG" : primary.label.includes("JPEG") ? "JPEG" : primary.label.includes("GIF") ? "GIF" : primary.label.includes("WEBP") ? "WEBP" : "") : -1;
  const trailerBytes = logicalEnd > 0 && logicalEnd < bytes.length ? bytes.slice(logicalEnd) : new Uint8Array();
  const trailerHits = trailerBytes.length ? scanCarvableObjects(trailerBytes, { startOffset: 0, maxHits: 32 }) : [];
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

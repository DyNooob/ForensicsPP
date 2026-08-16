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

import type { TimelineEvent, WindowsArtifactAnalysis, WindowsArtifactRecord } from "../../models";
import { hexPreview, previewText, readAscii } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { isPrivateHost } from "../../utils/forensics";
import { extractPrintableStrings } from "../strings/analyzer";

type WindowsFinding = { level: string; title: string; detail: string };

function readUint32Le(bytes: Uint8Array, offset: number) {
  if (offset + 4 > bytes.length) return null;
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

function readUint16Le(bytes: Uint8Array, offset: number) {
  if (offset + 2 > bytes.length) return null;
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

function decodeUtf16Le(bytes: Uint8Array) {
  return new TextDecoder("utf-16le").decode(bytes).replace(/\u0000+$/g, "").trim();
}

function windowsFiletimeToIso(bytes: Uint8Array, offset: number) {
  if (offset + 8 > bytes.length) return "--";
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const value = (BigInt(view.getUint32(offset + 4, true)) << 32n) | BigInt(view.getUint32(offset, true));
  if (value === 0n) return "--";
  const unixMs = Number(value / 10000n - 11644473600000n);
  if (!Number.isFinite(unixMs)) return "--";
  const date = new Date(unixMs);
  return Number.isNaN(date.getTime()) ? "--" : date.toISOString();
}

function makeArtifactEvent(id: string, iso: string, raw: string, format: string, source: string, context: string): TimelineEvent | null {
  if (!iso || iso === "--") return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return { id, iso, local: date.toLocaleString(), raw, format, line: 0, source, context };
}

function readNullTerminatedAnsi(bytes: Uint8Array, offset: number, max = 4096) {
  if (offset < 0 || offset >= bytes.length) return "";
  let end = offset;
  const limit = Math.min(bytes.length, offset + max);
  while (end < limit && bytes[end] !== 0) end += 1;
  return new TextDecoder("windows-1252").decode(bytes.slice(offset, end)).replace(/\u0000+$/g, "").trim();
}

function readNullTerminatedUtf16Le(bytes: Uint8Array, offset: number, max = 8192) {
  if (offset < 0 || offset >= bytes.length) return "";
  let end = offset;
  const limit = Math.min(bytes.length - 1, offset + max);
  while (end + 1 < limit && !(bytes[end] === 0 && bytes[end + 1] === 0)) end += 2;
  return decodeUtf16Le(bytes.slice(offset, end)).trim();
}

function describeLnkShowCommand(value: number | undefined) {
  if (value === 1) return "SW_SHOWNORMAL";
  if (value === 3) return "SW_SHOWMAXIMIZED";
  if (value === 7) return "SW_SHOWMINNOACTIVE";
  return value == null ? "--" : String(value);
}

function describeLnkFileAttributes(value: number) {
  const labels = [
    [0x00000001, "READONLY"],
    [0x00000002, "HIDDEN"],
    [0x00000004, "SYSTEM"],
    [0x00000010, "DIRECTORY"],
    [0x00000020, "ARCHIVE"],
    [0x00000040, "DEVICE"],
    [0x00000080, "NORMAL"],
    [0x00000100, "TEMPORARY"],
    [0x00000400, "REPARSE_POINT"],
    [0x00000800, "COMPRESSED"],
    [0x00001000, "OFFLINE"],
    [0x00004000, "ENCRYPTED"]
  ].filter(([flag]) => value & Number(flag)).map(([, label]) => label);
  return labels.length ? `${labels.join(", ")} (0x${value.toString(16).toUpperCase()})` : `0x${value.toString(16).toUpperCase()}`;
}

function describeLnkHotkey(value: number | undefined) {
  if (!value) return "--";
  const keyCode = value & 0xff;
  const modifierValue = (value >> 8) & 0xff;
  const modifiers = [
    modifierValue & 0x01 ? "SHIFT" : "",
    modifierValue & 0x02 ? "CTRL" : "",
    modifierValue & 0x04 ? "ALT" : ""
  ].filter(Boolean);
  const key = keyCode >= 32 && keyCode <= 126 ? String.fromCharCode(keyCode) : `VK_${keyCode}`;
  return [...modifiers, key].join("+");
}

function parseLnkLinkInfo(bytes: Uint8Array, cursor: number) {
  const rows: Array<[string, string]> = [];
  const strings: string[] = [];
  const findings: WindowsFinding[] = [];
  const linkInfoSize = readUint32Le(bytes, cursor) ?? 0;
  rows.push(["LinkInfo size", linkInfoSize ? formatBytes(linkInfoSize) : "--"]);
  if (!linkInfoSize || cursor + linkInfoSize > bytes.length) {
    if (linkInfoSize) findings.push({ level: "warn", title: "LNK LinkInfo out of bounds", detail: `LinkInfo size ${linkInfoSize} exceeds file boundary.` });
    return { rows, strings, findings, nextCursor: cursor };
  }
  const headerSize = readUint32Le(bytes, cursor + 4) ?? 0;
  const flags = readUint32Le(bytes, cursor + 8) ?? 0;
  rows.push(["LinkInfo header size", headerSize ? `0x${headerSize.toString(16).toUpperCase()}` : "--"]);
  rows.push(["LinkInfo flags", [
    flags & 1 ? "VolumeIDAndLocalBasePath" : "",
    flags & 2 ? "CommonNetworkRelativeLinkAndPathSuffix" : ""
  ].filter(Boolean).join(", ") || "--"]);
  const offsets: Array<[string, number | undefined, "ansi" | "utf16"]> = [
    ["Local base path", readUint32Le(bytes, cursor + 16) ?? undefined, "ansi"],
    ["Common path suffix", readUint32Le(bytes, cursor + 24) ?? undefined, "ansi"]
  ];
  if (headerSize >= 0x24) {
    offsets.push(
      ["Local base path Unicode", readUint32Le(bytes, cursor + 28) ?? undefined, "utf16"],
      ["Common path suffix Unicode", readUint32Le(bytes, cursor + 32) ?? undefined, "utf16"]
    );
  }
  const commonNetworkOffset = readUint32Le(bytes, cursor + 20) ?? 0;
  if (commonNetworkOffset > 0 && commonNetworkOffset + 20 < linkInfoSize) {
    const networkBase = cursor + commonNetworkOffset;
    const networkFlags = readUint32Le(bytes, networkBase + 4) ?? 0;
    const shareOffset = readUint32Le(bytes, networkBase + 8) ?? 0;
    const deviceOffset = readUint32Le(bytes, networkBase + 12) ?? 0;
    rows.push(["Network provider flags", networkFlags ? `0x${networkFlags.toString(16).toUpperCase()}` : "--"]);
    if (shareOffset) offsets.push(["Network share", commonNetworkOffset + shareOffset, "ansi"]);
    if (deviceOffset) offsets.push(["Network device", commonNetworkOffset + deviceOffset, "ansi"]);
    if (headerSize >= 0x24) {
      const shareUnicodeOffset = readUint32Le(bytes, networkBase + 20) ?? 0;
      const deviceUnicodeOffset = readUint32Le(bytes, networkBase + 24) ?? 0;
      if (shareUnicodeOffset) offsets.push(["Network share Unicode", commonNetworkOffset + shareUnicodeOffset, "utf16"]);
      if (deviceUnicodeOffset) offsets.push(["Network device Unicode", commonNetworkOffset + deviceUnicodeOffset, "utf16"]);
    }
  }
  for (const [label, relativeOffset, encoding] of offsets) {
    if (!relativeOffset || relativeOffset >= linkInfoSize) continue;
    const value = encoding === "utf16"
      ? readNullTerminatedUtf16Le(bytes, cursor + relativeOffset)
      : readNullTerminatedAnsi(bytes, cursor + relativeOffset);
    if (!value) continue;
    rows.push([label, value]);
    strings.push(value);
  }
  if (strings.some((value) => /^\\\\/.test(value))) findings.push({ level: "warn", title: "LNK references network path", detail: strings.filter((value) => /^\\\\/.test(value)).join("\n") });
  if (strings.some((value) => /\\(?:temp|tmp|downloads|appdata\\roaming|startup|recent)\\/i.test(value))) findings.push({ level: "warn", title: "LNK references user-writable path", detail: strings.filter((value) => /\\(?:temp|tmp|downloads|appdata\\roaming|startup|recent)\\/i.test(value)).join("\n") });
  return { rows, strings, findings, nextCursor: cursor + linkInfoSize };
}

function parseLnkArtifact(bytes: Uint8Array, source: string) {
  const rows: Array<[string, string]> = [];
  const timeline: TimelineEvent[] = [];
  const findings: WindowsFinding[] = [];
  const strings: string[] = [];
  const headerSize = readUint32Le(bytes, 0);
  const clsid = hexPreview(bytes.slice(4, 20), 16);
  const expectedClsid = "01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46";
  rows.push(["Header size", headerSize === 0x4c ? "0x4C" : String(headerSize ?? "--")]);
  rows.push(["Shell Link CLSID", clsid]);
  if (clsid !== expectedClsid) findings.push({ level: "warn", title: "Unexpected LNK CLSID", detail: clsid });
  const flags = readUint32Le(bytes, 20) ?? 0;
  const attrs = readUint32Le(bytes, 24) ?? 0;
  const flagLabels = [
    [0, "HasLinkTargetIDList"],
    [1, "HasLinkInfo"],
    [2, "HasName"],
    [3, "HasRelativePath"],
    [4, "HasWorkingDir"],
    [5, "HasArguments"],
    [6, "HasIconLocation"],
    [7, "IsUnicode"],
    [9, "HasExpString"],
    [13, "RunAsUser"]
  ].filter(([bit]) => flags & (1 << Number(bit))).map(([, label]) => label);
  rows.push(["Link flags", flagLabels.join(", ") || "--"]);
  rows.push(["File attributes", describeLnkFileAttributes(attrs)]);
  const created = windowsFiletimeToIso(bytes, 28);
  const accessed = windowsFiletimeToIso(bytes, 36);
  const modified = windowsFiletimeToIso(bytes, 44);
  rows.push(["Target created", created], ["Target accessed", accessed], ["Target modified", modified]);
  [
    makeArtifactEvent("lnk-created", created, "LNK target created FILETIME", "Windows FILETIME", source, "Shell Link target created time"),
    makeArtifactEvent("lnk-accessed", accessed, "LNK target accessed FILETIME", "Windows FILETIME", source, "Shell Link target accessed time"),
    makeArtifactEvent("lnk-modified", modified, "LNK target modified FILETIME", "Windows FILETIME", source, "Shell Link target modified time")
  ].filter(Boolean).forEach((event) => timeline.push(event as TimelineEvent));
  rows.push(["Target file size", formatBytes(readUint32Le(bytes, 52) ?? 0)]);
  rows.push(["Show command", describeLnkShowCommand(readUint32Le(bytes, 60) ?? undefined)]);
  rows.push(["Hotkey", describeLnkHotkey(readUint16Le(bytes, 64) ?? undefined)]);
  let cursor = 76;
  if (flags & 1) {
    const idListSize = readUint16Le(bytes, cursor) ?? 0;
    rows.push(["LinkTargetIDList size", formatBytes(idListSize)]);
    cursor += 2 + idListSize;
  }
  if (flags & 2) {
    const parsedLinkInfo = parseLnkLinkInfo(bytes, cursor);
    rows.push(...parsedLinkInfo.rows);
    strings.push(...parsedLinkInfo.strings);
    findings.push(...parsedLinkInfo.findings);
    cursor = parsedLinkInfo.nextCursor;
  }
  const isUnicode = Boolean(flags & (1 << 7));
  const stringFields: Array<[number, string]> = [
    [2, "Name"],
    [3, "Relative path"],
    [4, "Working dir"],
    [5, "Arguments"],
    [6, "Icon location"]
  ];
  for (const [bit, label] of stringFields) {
    if (!(flags & (1 << bit)) || cursor + 2 > bytes.length) continue;
    const chars = readUint16Le(bytes, cursor) ?? 0;
    cursor += 2;
    const byteLength = isUnicode ? chars * 2 : chars;
    if (!chars || cursor + byteLength > bytes.length) continue;
    const value = isUnicode ? decodeUtf16Le(bytes.slice(cursor, cursor + byteLength)) : new TextDecoder("windows-1252").decode(bytes.slice(cursor, cursor + byteLength)).replace(/\u0000+$/g, "").trim();
    cursor += byteLength;
    rows.push([label, value || "--"]);
    if (value) strings.push(value);
  }
  if (flags & (1 << 13)) findings.push({ level: "warn", title: "RunAsUser flag", detail: "Shortcut requests Run as different user / elevated context." });
  if (strings.some((value) => /(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|http)/i.test(value))) {
    findings.push({ level: "warn", title: "Suspicious LNK string", detail: strings.filter((value) => /(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|http)/i.test(value)).join("\n") });
  }
  return { rows, timeline, findings };
}

function parsePrefetchArtifact(bytes: Uint8Array, source: string) {
  const rows: Array<[string, string]> = [];
  const timeline: TimelineEvent[] = [];
  const findings: WindowsFinding[] = [];
  const version = readUint32Le(bytes, 0) ?? 0;
  const declaredSize = readUint32Le(bytes, 12) ?? 0;
  const executable = decodeUtf16Le(bytes.slice(16, Math.min(bytes.length, 76)));
  const hash = readUint32Le(bytes, 76);
  const runCountOffset = version === 17 ? 0x90 : 0xd0;
  const lastRunOffset = version === 17 ? 0x78 : 0x80;
  rows.push(["Prefetch version", String(version)]);
  rows.push(["Signature", readAscii(bytes, 4, 4)]);
  rows.push(["Declared size", declaredSize ? formatBytes(declaredSize) : "--"]);
  rows.push(["Executable", executable || "--"]);
  rows.push(["Prefetch hash", hash == null ? "--" : `0x${hash.toString(16).toUpperCase().padStart(8, "0")}`]);
  const runCount = readUint32Le(bytes, runCountOffset);
  rows.push(["Run count", String(runCount ?? "--")]);
  for (let index = 0; index < (version === 17 ? 1 : 8); index += 1) {
    const iso = windowsFiletimeToIso(bytes, lastRunOffset + index * 8);
    if (iso === "--") continue;
    rows.push([index ? `Last run ${index + 1}` : "Last run", iso]);
    const event = makeArtifactEvent(`pf-last-run-${index}`, iso, "Prefetch last run FILETIME", "Windows FILETIME", source, `${executable || "Executable"} last run ${index + 1}`);
    if (event) timeline.push(event);
  }
  if (declaredSize && declaredSize !== bytes.length) findings.push({ level: "warn", title: "Prefetch size mismatch", detail: `Header declares ${formatBytes(declaredSize)}, file has ${formatBytes(bytes.length)}.` });
  if (executable && /\.(scr|ps1|vbs|js|hta|bat|cmd)$/i.test(executable)) findings.push({ level: "warn", title: "Script-like executable in Prefetch", detail: executable });
  if (executable && /^(?:POWERSHELL|PWSH|CMD|MSHTA|RUNDLL32|REGSVR32|WSCRIPT|CSCRIPT|CERTUTIL|BITSADMIN|WMIC|SCHTASKS|REG|NET|CURL|MSBUILD)\.EXE/i.test(executable)) {
    findings.push({ level: "warn", title: "LOLBAS-style executable in Prefetch", detail: `${executable} has Prefetch execution evidence. Review command context and related artifacts.` });
  }
  if (runCount != null && runCount > 25) findings.push({ level: "info", title: "High Prefetch run count", detail: `${executable || "Executable"} run count is ${runCount}.` });
  if (![17, 23, 26, 30, 31].includes(version)) findings.push({ level: "warn", title: "Unknown Prefetch version", detail: `Version ${version} is not one of the common Windows XP/7/8/10/11 values.` });
  return { rows, timeline, findings };
}

function parseZoneIdentifier(text: string) {
  const rows: Array<[string, string]> = [];
  const findings: WindowsFinding[] = [];
  const zoneMap: Record<string, string> = { "0": "My Computer", "1": "Local Intranet", "2": "Trusted Sites", "3": "Internet", "4": "Restricted Sites" };
  const values = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const item = line.match(/^([^=;\[][^=]*)=(.*)$/);
    if (item) {
      const key = item[1].trim();
      const value = item[2].trim();
      rows.push([key, value]);
      values.set(key.toLowerCase(), value);
    }
  }
  const zoneId = values.get("zoneid");
  if (zoneId) rows.push(["Zone", zoneMap[zoneId] ?? zoneId]);
  if (zoneId === "3" || zoneId === "4") findings.push({ level: "warn", title: "Downloaded from untrusted zone", detail: `ZoneId=${zoneId} (${zoneMap[zoneId]})` });
  const hostUrl = values.get("hosturl") ?? "";
  const referrerUrl = values.get("referrerurl") ?? "";
  const hostIp = values.get("hostipaddress") ?? "";
  if (hostUrl) findings.push({ level: "info", title: "HostUrl present", detail: hostUrl });
  if (hostUrl && /^http:\/\//i.test(hostUrl)) findings.push({ level: "warn", title: "Downloaded over HTTP", detail: hostUrl });
  if (hostUrl && /\.(exe|dll|scr|js|jse|vbs|vbe|ps1|hta|bat|cmd|msi|iso|img|lnk|url|zip|rar|7z)(?:$|[?#])/i.test(hostUrl)) findings.push({ level: "warn", title: "Downloaded file type worth review", detail: hostUrl });
  if (referrerUrl) findings.push({ level: "info", title: "ReferrerUrl present", detail: referrerUrl });
  if (hostUrl && referrerUrl) {
    try {
      const host = new URL(hostUrl).hostname.replace(/^www\./i, "");
      const referrer = new URL(referrerUrl).hostname.replace(/^www\./i, "");
      if (host && referrer && host !== referrer) findings.push({ level: "warn", title: "HostUrl/referrer domain mismatch", detail: `${hostUrl}\nReferrer: ${referrerUrl}` });
    } catch {
      // Keep raw values in the rows even if URL parsing fails.
    }
  }
  if (hostIp) findings.push({ level: isPrivateHost(hostIp) ? "warn" : "info", title: "Host IP recorded", detail: hostIp });
  return { rows, findings };
}

function parseRegistryExportArtifact(text: string) {
  const rows: Array<[string, string]> = [];
  const findings: WindowsFinding[] = [];
  const keys = Array.from(text.matchAll(/^\[([^\]]+)\]/gim)).map((match) => match[1]);
  const valueLines = text.split(/\r?\n/).filter((line) => /^"[^"]+"\s*=/.test(line));
  rows.push(["Registry keys", String(keys.length)]);
  rows.push(["Registry values", String(valueLines.length)]);
  const persistenceKeys = keys.filter((key) => /\\(?:run|runonce|runservices|winlogon|image file execution options|appinit_dlls|services|shellserviceobjectdelayload|explorer\\browser helper objects|schedule\\taskcache)\\?/i.test(`${key}\\`));
  if (persistenceKeys.length) findings.push({ level: "warn", title: "Persistence-related registry key", detail: persistenceKeys.slice(0, 12).join("\n") });
  const commandLines = valueLines.filter((line) => /(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|http|\\\\|appdata|temp)/i.test(line));
  if (commandLines.length) findings.push({ level: "warn", title: "Suspicious registry value data", detail: commandLines.slice(0, 12).join("\n") });
  const deletedKeys = keys.filter((key) => key.startsWith("-"));
  if (deletedKeys.length) findings.push({ level: "info", title: "Registry deletion entries", detail: deletedKeys.slice(0, 12).join("\n") });
  rows.push(["Persistence-like keys", String(persistenceKeys.length)]);
  rows.push(["Suspicious value lines", String(commandLines.length)]);
  return { rows, findings };
}


function readU64Le(bytes: Uint8Array, offset: number) {
  if (offset + 8 > bytes.length) return 0n;
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0, true);
}

function ntfsFileReference(value: bigint) {
  return Number(value & 0x0000ffffffffffffn);
}

function applyMftFixup(record: Uint8Array) {
  if (record.length < 48 || readAscii(record, 0, 4) !== "FILE") return null;
  const usaOffset = readUint16Le(record, 4) ?? 0, usaCount = readUint16Le(record, 6) ?? 0;
  if (!usaOffset || usaCount < 2 || usaOffset + usaCount * 2 > record.length) return null;
  const sectors = usaCount - 1, sectorSize = Math.floor(record.length / sectors);
  if (!sectorSize || sectorSize * sectors !== record.length) return null;
  const fixed = record.slice(); const usn = readUint16Le(record, usaOffset);
  for (let index = 0; index < sectors; index += 1) {
    const tail = (index + 1) * sectorSize - 2;
    if (readUint16Le(record, tail) !== usn) return null;
    fixed[tail] = record[usaOffset + 2 + index * 2]; fixed[tail + 1] = record[usaOffset + 3 + index * 2];
  }
  return fixed;
}

function parseMftArtifact(bytes: Uint8Array, source: string) {
  let recordSize = 1024;
  if (readAscii(bytes, 1024, 4) !== "FILE" && readAscii(bytes, 4096, 4) === "FILE") recordSize = 4096;
  const records: WindowsArtifactRecord[] = [], timeline: TimelineEvent[] = []; let valid = 0, deleted = 0, directories = 0, ads = 0;
  const maxRecords = Math.min(Math.floor(bytes.length / recordSize), 20000);
  for (let index = 0; index < maxRecords; index += 1) {
    const raw = bytes.subarray(index * recordSize, (index + 1) * recordSize); if (readAscii(raw, 0, 4) !== "FILE") continue;
    const record = applyMftFixup(raw); if (!record) continue; valid += 1;
    const flags = readUint16Le(record, 0x16) ?? 0, inUse = Boolean(flags & 1), directory = Boolean(flags & 2); if (!inUse) deleted += 1; if (directory) directories += 1;
    const recordNumber = readUint32Le(record, 0x2c) ?? index, sequence = readUint16Le(record, 0x10) ?? 0, firstAttribute = readUint16Le(record, 0x14) ?? 0;
    let cursor = firstAttribute; const names: Array<{name:string,parent:number,created:string,modified:string,mftModified:string,accessed:string,namespace:number}> = []; const dataNames:string[]=[]; let residentData="";
    for (let count = 0; count < 256 && cursor + 16 <= record.length; count += 1) {
      const type = readUint32Le(record, cursor) ?? 0; if (type === 0xffffffff || !type) break; const length = readUint32Le(record, cursor + 4) ?? 0; if (length < 24 || cursor + length > record.length) break;
      const nonResident = record[cursor + 8] === 1, nameLength = record[cursor + 9], nameOffset = readUint16Le(record, cursor + 10) ?? 0; const attrName = nameLength && nameOffset + nameLength * 2 <= length ? decodeUtf16Le(record.subarray(cursor + nameOffset, cursor + nameOffset + nameLength * 2)) : "";
      if (!nonResident) { const valueLength = readUint32Le(record, cursor + 16) ?? 0, valueOffset = readUint16Le(record, cursor + 20) ?? 0, valueStart = cursor + valueOffset, valueEnd = valueStart + valueLength;
        if (valueStart >= cursor && valueEnd <= cursor + length) {
          if (type === 0x30 && valueLength >= 66) { const parent = ntfsFileReference(readU64Le(record, valueStart)); const nameChars = record[valueStart + 64], namespace = record[valueStart + 65], fileName = decodeUtf16Le(record.subarray(valueStart + 66, Math.min(valueEnd, valueStart + 66 + nameChars * 2))); if (fileName) names.push({name:fileName,parent,created:windowsFiletimeToIso(record,valueStart+8),modified:windowsFiletimeToIso(record,valueStart+16),mftModified:windowsFiletimeToIso(record,valueStart+24),accessed:windowsFiletimeToIso(record,valueStart+32),namespace}); }
          if (type === 0x80) { dataNames.push(attrName || "$DATA"); if (attrName) ads += 1; if (!attrName && valueLength <= 4096) residentData = hexPreview(record.subarray(valueStart,valueEnd), 64); }
        }
      } else if (type === 0x80) { dataNames.push(attrName || "$DATA (non-resident)"); if (attrName) ads += 1; }
      cursor += length;
    }
    const preferred = names.find(n=>n.namespace===1||n.namespace===3) ?? names[0]; const fields:Record<string,string>={"Record":String(recordNumber),"Sequence":String(sequence),"State":inUse?"in-use":"deleted","Directory":directory?"yes":"no","Filename":preferred?.name??"--","Parent record":preferred?String(preferred.parent):"--","Data streams":dataNames.join(", ")||"--"}; if (residentData) fields["Resident data preview"] = residentData;
    records.push({id:`mft-${recordNumber}-${sequence}`,kind:"MFT",fields});
    if (preferred && timeline.length < 3000) for (const [suffix,iso,label] of [["created",preferred.created,"Created"],["modified",preferred.modified,"Modified"],["mft",preferred.mftModified,"MFT modified"],["accessed",preferred.accessed,"Accessed"]] as const) { const event=makeArtifactEvent(`mft-${recordNumber}-${suffix}`,iso,"NTFS FILETIME","Windows FILETIME",source,`${preferred.name} · ${label} · MFT #${recordNumber}`); if(event)timeline.push(event); }
  }
  return { records, timeline, rows:[["MFT record size",formatBytes(recordSize)],["Valid FILE records",String(valid)],["Deleted records",String(deleted)],["Directories",String(directories)],["Named data streams (ADS)",String(ads)],["Displayed records",String(records.length)]] as Array<[string,string]> };
}

const usnReasonNames: Array<[number,string]> = [[0x1,"DATA_OVERWRITE"],[0x2,"DATA_EXTEND"],[0x4,"DATA_TRUNCATION"],[0x100,"FILE_CREATE"],[0x200,"FILE_DELETE"],[0x1000,"RENAME_OLD_NAME"],[0x2000,"RENAME_NEW_NAME"],[0x8000,"BASIC_INFO_CHANGE"],[0x10000,"HARD_LINK_CHANGE"],[0x20000,"COMPRESSION_CHANGE"],[0x80000,"OBJECT_ID_CHANGE"],[0x100000,"REPARSE_POINT_CHANGE"],[0x80000000,"CLOSE"]];
function usnReasons(value:number){return usnReasonNames.filter(([flag])=>value&flag).map(([,name])=>name).join(", ")||`0x${value.toString(16).toUpperCase()}`;}
function parseUsnArtifact(bytes:Uint8Array,source:string){const records:WindowsArtifactRecord[]=[],timeline:TimelineEvent[]=[];let cursor=0,invalid=0;while(cursor+60<=bytes.length&&records.length<50000){const length=readUint32Le(bytes,cursor)??0,major=readUint16Le(bytes,cursor+4)??0;if(!length||length<60||cursor+length>bytes.length||![2,3].includes(major)){cursor+=8;invalid+=1;continue;}let fileRef=0,parentRef=0,usn="",timeOffset=0,reasonOffset=0,attrsOffset=0,nameLengthOffset=0,nameOffsetOffset=0;if(major===2){fileRef=ntfsFileReference(readU64Le(bytes,cursor+8));parentRef=ntfsFileReference(readU64Le(bytes,cursor+16));usn=readU64Le(bytes,cursor+24).toString();timeOffset=32;reasonOffset=40;attrsOffset=52;nameLengthOffset=56;nameOffsetOffset=58;}else{fileRef=Number(readU64Le(bytes,cursor+8)&0xffffffffffffffffn);parentRef=Number(readU64Le(bytes,cursor+24)&0xffffffffffffffffn);usn=readU64Le(bytes,cursor+40).toString();timeOffset=48;reasonOffset=56;attrsOffset=68;nameLengthOffset=72;nameOffsetOffset=74;}const reason=readUint32Le(bytes,cursor+reasonOffset)??0,attrs=readUint32Le(bytes,cursor+attrsOffset)??0,nameLength=readUint16Le(bytes,cursor+nameLengthOffset)??0,nameOffset=readUint16Le(bytes,cursor+nameOffsetOffset)??0;const name=nameOffset+nameLength<=length?decodeUtf16Le(bytes.subarray(cursor+nameOffset,cursor+nameOffset+nameLength)):"";const iso=windowsFiletimeToIso(bytes,cursor+timeOffset);records.push({id:`usn-${cursor}`,kind:`USN v${major}`,fields:{Offset:`0x${cursor.toString(16).toUpperCase()}`,Name:name||"--","File reference":String(fileRef),"Parent reference":String(parentRef),USN:usn,Timestamp:iso,Reason:usnReasons(reason),Attributes:`0x${attrs.toString(16).toUpperCase()}`}});const event=makeArtifactEvent(`usn-${cursor}`,iso,"NTFS USN FILETIME","Windows FILETIME",source,`${name||"USN record"} · ${usnReasons(reason)}`);if(event&&timeline.length<10000)timeline.push(event);cursor+=length;}return{records,timeline,rows:[["USN records",String(records.length)],["Skipped/invalid regions",String(invalid)],["Displayed records",String(records.length)]] as Array<[string,string]>};}

function analyzeWindowsArtifact(bytes: Uint8Array, name: string): WindowsArtifactAnalysis {
  const stringsAnalysis = extractPrintableStrings(bytes.subarray(0, Math.min(bytes.length, 8 * 1024 * 1024)), 5);
  const textPreviewValue = previewText(bytes, 10000);
  const rows: Array<[string, string]> = [
    ["Name", name],
    ["Size", formatBytes(bytes.length)],
    ["Header", hexPreview(bytes, 16)]
  ];
  const findings: WindowsFinding[] = [];
  let artifactType = "Generic Windows-related File";
  let timeline: TimelineEvent[] = [];
  let records: WindowsArtifactRecord[] = [];
  const lnkClsid = "01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46";
  const isLnk = bytes.length >= 76 && readUint32Le(bytes, 0) === 0x4c && hexPreview(bytes.slice(4, 20), 16) === lnkClsid;
  const isPrefetch = bytes.length >= 84 && readAscii(bytes, 4, 4) === "SCCA";
  const isZone = /\[ZoneTransfer\]/i.test(textPreviewValue) || /Zone\.Identifier$/i.test(name);
  const isMft = readAscii(bytes, 0, 4) === "FILE" && (/\$MFT$/i.test(name) || readAscii(bytes, 1024, 4) === "FILE" || readAscii(bytes, 4096, 4) === "FILE");
  const usnMajor = readUint16Le(bytes, 4) ?? 0;
  const isUsn = /UsnJrnl|\$J$/i.test(name) || ((usnMajor === 2 || usnMajor === 3) && (readUint32Le(bytes, 0) ?? 0) >= 60);
  if (isMft) {
    artifactType = "NTFS $MFT";
    const parsed = parseMftArtifact(bytes, name); rows.push(...parsed.rows); timeline = parsed.timeline; records = parsed.records;
  } else if (isUsn) {
    artifactType = "NTFS $UsnJrnl:$J";
    const parsed = parseUsnArtifact(bytes, name); rows.push(...parsed.rows); timeline = parsed.timeline; records = parsed.records;
  } else if (isLnk) {
    artifactType = "Windows Shell Link (.lnk)";
    const parsed = parseLnkArtifact(bytes, name);
    rows.push(...parsed.rows);
    findings.push(...parsed.findings);
    timeline = timeline.concat(parsed.timeline);
  } else if (isPrefetch) {
    artifactType = "Windows Prefetch (.pf)";
    const parsed = parsePrefetchArtifact(bytes, name);
    rows.push(...parsed.rows);
    findings.push(...parsed.findings);
    timeline = timeline.concat(parsed.timeline);
  } else if (isZone) {
    artifactType = "Zone.Identifier ADS";
    const parsed = parseZoneIdentifier(textPreviewValue);
    rows.push(...parsed.rows);
    findings.push(...parsed.findings);
  } else if (/Windows Registry Editor Version/i.test(textPreviewValue)) {
    artifactType = "Registry Export (.reg)";
    const parsed = parseRegistryExportArtifact(textPreviewValue);
    rows.push(...parsed.rows);
    findings.push(...parsed.findings);
    findings.push({ level: "info", title: "Registry export detected", detail: "Text appears to be a .reg export; persistence-related keys and risky values are highlighted." });
  }
  rows.splice(3, 0, ["Artifact type", artifactType]);
  const windowsPaths = stringsAnalysis.items.filter((item) => /(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)/.test(item.value));
  const executablePaths = windowsPaths.filter((item) => /\.(exe|dll|scr|ps1|vbs|js|hta|bat|cmd|msi|lnk)(?:\s|$|")/i.test(item.value));
  rows.push(["Windows paths", String(windowsPaths.length)]);
  rows.push(["Executable/script paths", String(executablePaths.length)]);
  return {
    name,
    size: bytes.length,
    artifactType,
    rows,
    timeline,
    strings: windowsPaths.slice(0, 100),
    textPreview: textPreviewValue,
    records
  };
}

export { analyzeWindowsArtifact };

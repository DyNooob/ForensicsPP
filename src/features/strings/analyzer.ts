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

import type { ExtractedStringRow, StringsAnalysis } from "../../models";

function classifyStringEvidence(value: string) {
  let detectedType = "Text";
  const trimmed = value.trim();
  if (/^https?:\/\/\S+$/i.test(trimmed)) detectedType = "URL";
  else if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(trimmed)) detectedType = "Email";
  else if (/^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(trimmed)) detectedType = "IPv4";
  else if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(trimmed)) detectedType = "Hash-like";
  else if (/^(?:[A-Za-z]:\\|\\\\|\/(?:etc|usr|var|tmp|home|opt|bin|sbin)\/)/.test(trimmed)) detectedType = "Path";
  return { detectedType, risk: [] };
}

function makeStringRow(offset: number, encoding: ExtractedStringRow["encoding"], value: string): ExtractedStringRow {
  const classification = classifyStringEvidence(value);
  return {
    id: `${encoding.toLowerCase()}-${offset}-${value.length}`,
    offset,
    encoding,
    length: value.length,
    value,
    detectedType: classification.detectedType,
    risk: classification.risk
  };
}

function stringsToCsv(items: ExtractedStringRow[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["offset_dec", "offset_hex", "encoding", "length", "detected_type", "value"].join(","),
    ...items.map((item) => [item.offset, `0x${item.offset.toString(16).toUpperCase()}`, item.encoding, item.length, item.detectedType, item.value].map(escape).join(","))
  ].join("\n");
}

function stringRowKey(item: ExtractedStringRow) {
  return `${item.encoding}:${item.offset}:${item.length}`;
}

function extractPrintableStrings(bytes: Uint8Array, minLength: number): StringsAnalysis {
  const items: ExtractedStringRow[] = [];
  const scanLimit = Math.min(bytes.length, 64 * 1024 * 1024);
  const valueLimit = 16 * 1024;
  const scanTruncated = scanLimit < bytes.length;
  let current = "";
  let start = 0;
  for (let index = 0; index < scanLimit && items.length < 5000; index += 1) {
    const byte = bytes[index];
    if (byte >= 32 && byte <= 126) current += String.fromCharCode(byte);
    else {
      if (current.length >= minLength) items.push(makeStringRow(start, "ASCII", current));
      current = "";
      start = index + 1;
    }
    if (current.length === valueLimit) {
      items.push(makeStringRow(start, "ASCII", current));
      current = "";
      start = index + 1;
    }
  }
  if (current.length >= minLength && items.length < 5000) items.push(makeStringRow(start, "ASCII", current));

  current = "";
  start = 0;
  for (let index = 0; index < scanLimit - 1 && items.length < 5000; index += 2) {
    const code = bytes[index] | (bytes[index + 1] << 8);
    if (code >= 32 && code <= 126) current += String.fromCharCode(code);
    else {
      if (current.length >= minLength) items.push(makeStringRow(start, "UTF-16LE", current));
      current = "";
      start = index + 2;
    }
    if (current.length === valueLimit) {
      items.push(makeStringRow(start, "UTF-16LE", current));
      current = "";
      start = index + 2;
    }
  }
  if (current.length >= minLength && items.length < 5000) items.push(makeStringRow(start, "UTF-16LE", current));
  const sorted = items
    .filter((item, index, array) => array.findIndex((other) => other.encoding === item.encoding && other.value === item.value && other.offset === item.offset) === index)
    .sort((a, b) => a.offset - b.offset || a.encoding.localeCompare(b.encoding))
    .slice(0, 5000);
  const asciiItems = sorted.filter((item) => item.encoding === "ASCII");
  const utf16Items = sorted.filter((item) => item.encoding === "UTF-16LE");
  const iocs: StringsAnalysis["iocs"] = [];
  const timeline: StringsAnalysis["timeline"] = [];
  const typeRows = Array.from(sorted.reduce((map, item) => {
    map.set(item.detectedType, (map.get(item.detectedType) ?? 0) + 1);
    return map;
  }, new Map<string, number>()).entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([type, count]) => [type, String(count)] as [string, string]);
  const findings: StringsAnalysis["findings"] = [
    sorted.length >= 5000 || scanTruncated ? { level: "warn", title: "String view truncated", detail: scanTruncated ? "The browser scan is limited to the first 64 MiB and 5000 extracted strings." : "Only the first 5000 extracted strings are kept in this browser view." } : null,
    null
  ].filter(Boolean) as StringsAnalysis["findings"];
  return {
    rows: [
      ["Total strings", String(sorted.length)],
      ["ASCII", String(asciiItems.length)],
      ["UTF-16LE", String(utf16Items.length)],
      ["Detected types", String(typeRows.length)]
    ],
    typeRows,
    items: sorted,
    iocs,
    timeline,
    findings,
    asciiText: asciiItems.map((item) => `0x${item.offset.toString(16).toUpperCase()}\t${item.value}`).join("\n"),
    utf16Text: utf16Items.map((item) => `0x${item.offset.toString(16).toUpperCase()}\t${item.value}`).join("\n")
  };
}

export { extractPrintableStrings, stringRowKey, stringsToCsv };

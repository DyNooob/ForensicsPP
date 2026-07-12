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
import { analyzeIocs, iocRisk } from "../ioc/analyzer";
import { parseTimestampCandidates } from "../timestamp/analyzer";
import { classifyRegexMatch } from "../../utils/regex";

function stringRisk(value: string) {
  const classification = classifyRegexMatch(value.trim(), iocRisk);
  const extra = [
    /(pass(word)?|token|secret|api[_-]?key|session|auth|jwt|bearer|private[_-]?key)/i.test(value) ? "credential marker" : "",
    /https?:\/\//i.test(value) ? "URL" : "",
    /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/i.test(value) ? "hash" : "",
    /(?:\.\.\/|cmd\.exe|powershell|\/bin\/sh|<script|select\s+.+from|union\s+select)/i.test(value) ? "attack/script marker" : "",
    /\b(?:cmd\.exe|powershell(?:\.exe)?|pwsh(?:\.exe)?|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget)\b/i.test(value) ? "execution marker" : "",
    /(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER)|\\Run(?:Once)?\\|\\Services\\|\\Winlogon\\)/i.test(value) ? "registry/persistence marker" : "",
    /(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\|\/(?:etc|usr|var|tmp|home|opt|bin|sbin)\/)/.test(value) ? "filesystem path" : "",
    /(?:BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY|ssh-rsa|ssh-ed25519)/i.test(value) ? "key material" : "",
    /^[A-Za-z0-9+/=_-]{40,}$/.test(value) ? "encoded-looking" : ""
  ].filter(Boolean);
  return Array.from(new Set([...classification.risk, ...extra]));
}

function classifyStringEvidence(value: string) {
  const trimmed = value.trim();
  const classification = classifyRegexMatch(trimmed, iocRisk);
  let detectedType = classification.detectedType;
  if (detectedType === "Text") {
    if (/https?:\/\//i.test(value)) detectedType = "URL-containing";
    else if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(value)) detectedType = "Email-containing";
    else if (/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/.test(value)) detectedType = "IPv4-containing";
    else if (/\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b/i.test(value)) detectedType = "Hash-containing";
    else if (/(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\|\/(?:etc|usr|var|tmp|home|opt|bin|sbin)\/)/.test(value)) detectedType = "Path";
    else if (/(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER)|\\Run(?:Once)?\\|\\Services\\|\\Winlogon\\)/i.test(value)) detectedType = "Registry";
    else if (/\b(?:cmd\.exe|powershell(?:\.exe)?|pwsh(?:\.exe)?|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget)\b/i.test(value)) detectedType = "Command";
    else if (/^[A-Za-z0-9+/=_-]{48,}$/.test(value)) detectedType = "Encoded blob";
  }
  return {
    detectedType,
    risk: stringRisk(value)
  };
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
    ["offset_dec", "offset_hex", "encoding", "length", "detected_type", "risk", "value"].join(","),
    ...items.map((item) => [item.offset, `0x${item.offset.toString(16).toUpperCase()}`, item.encoding, item.length, item.detectedType, item.risk.join("; "), item.value].map(escape).join(","))
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
  const risky = sorted.filter((item) => item.risk.length);
  const textCorpus = sorted.map((item) => item.value).join("\n");
  const iocs = analyzeIocs(textCorpus, "extracted strings").records;
  const timeline = parseTimestampCandidates(textCorpus, "extracted strings");
  const typeRows = Array.from(sorted.reduce((map, item) => {
    map.set(item.detectedType, (map.get(item.detectedType) ?? 0) + 1);
    return map;
  }, new Map<string, number>()).entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([type, count]) => [type, String(count)] as [string, string]);
  const findings: StringsAnalysis["findings"] = [
    sorted.length >= 5000 || scanTruncated ? { level: "warn", title: "String view truncated", detail: scanTruncated ? "The browser scan is limited to the first 64 MiB and 5000 extracted strings." : "Only the first 5000 extracted strings are kept in this browser view." } : null,
    risky.length ? { level: "warn", title: "Strings worth review", detail: risky.slice(0, 12).map((item) => `${item.detectedType} ${item.encoding}@0x${item.offset.toString(16).toUpperCase()}: ${item.risk.join(", ")}`).join("\n") } : { level: "info", title: "No obvious string review marker", detail: "No credential/script/hash/URL marker was detected by local string heuristics." },
    iocs.length ? { level: "info", title: "IOC-like strings", detail: iocs.slice(0, 12).map((ioc) => `${ioc.type} ${ioc.value}`).join("\n") } : { level: "info", title: "No IOC-like value", detail: "No URL/domain/IP/hash/CVE/email pattern was extracted from strings." },
    timeline.length ? { level: "info", title: "Timestamp-like strings", detail: timeline.slice(0, 12).map((event) => `${event.iso} ${event.raw}`).join("\n") } : { level: "info", title: "No timestamp-like value", detail: "No supported forensic timestamp format was extracted from strings." }
  ].filter(Boolean) as StringsAnalysis["findings"];
  return {
    rows: [
      ["Total strings", String(sorted.length)],
      ["ASCII", String(asciiItems.length)],
      ["UTF-16LE", String(utf16Items.length)],
      ["Review-marked", String(risky.length)],
      ["IOC-like", String(iocs.length)],
      ["Timestamp-like", String(timeline.length)],
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

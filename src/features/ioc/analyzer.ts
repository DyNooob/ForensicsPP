/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import type { IocAnalysis, IocEvidenceRow, IocRecord } from "../../models";
import { uniqueValues } from "../../utils/collections";
import { limitReportText } from "../../utils/files";
import { isPrivateHost } from "../../utils/forensics";

function parseIocUrl(raw: string) {
  const value = raw.trim();
  return new URL(/^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`);
}

export function matchesOf(text: string, regex: RegExp, limit = 200) {
  return uniqueValues(Array.from(text.matchAll(regex), (match) => match[0]), limit);
}

export function refangIocText(value: string) {
  return value
    .replace(/\bhxxps?:\/\//gi, (match) => match.toLowerCase().replace("hxxp", "http"))
    .replace(/\[\.\]|\(\.\)|\{\.}/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/")
    .replace(/\b(\d{1,3})\s+dot\s+(\d{1,3})\s+dot\s+(\d{1,3})\s+dot\s+(\d{1,3})\b/gi, "$1.$2.$3.$4");
}

export function defangIocValue(value: string) {
  return value
    .replace(/^http/gi, (match) => match.replace(/tt/i, "xx"))
    .replace(/\./g, "[.]")
    .replace(/:/g, "[:]")
    .replace(/\//g, "[/]");
}

export function extractIocs(text: string) {
  const refanged = refangIocText(text);
  return {
    URL: matchesOf(refanged, /\bhttps?:\/\/[^\s"'<>]+/gi),
    Domain: matchesOf(refanged, /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi),
    IPv4: matchesOf(refanged, /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g),
    CIDR: matchesOf(refanged, /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:[0-9]|[12]\d|3[0-2])\b/g),
    IPv6: matchesOf(refanged, /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi),
    Email: matchesOf(refanged, /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi),
    Hash: matchesOf(refanged, /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})\b/gi),
    CVE: matchesOf(refanged, /\bCVE-\d{4}-\d{4,7}\b/gi),
    "MITRE ATT&CK": matchesOf(refanged, /\bT\d{4}(?:\.\d{3})?\b/g),
    MAC: matchesOf(refanged, /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi),
    "Windows Path": matchesOf(refanged, /\b[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/gi),
    Registry: matchesOf(refanged, /\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\r\n]+/gi),
    "BTC / ETH": matchesOf(refanged, /\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g)
  };
}

export function normalizeIoc(type: string, value: string) {
  const trimmed = refangIocText(value).replace(/[),.;\]}]+$/g, "");
  if (["Domain", "Email", "URL", "Hash", "CVE", "CIDR", "MAC", "Registry", "Windows Path", "MITRE ATT&CK", "BTC / ETH"].includes(type)) return trimmed.toLowerCase();
  return trimmed;
}

export function iocRisk(type: string, value: string) {
  const risks: string[] = [];
  const normalized = normalizeIoc(type, value);
  const lower = normalized.toLowerCase();
  if (type === "URL") {
    try {
      const url = parseIocUrl(normalized);
      if (url.protocol !== "https:") risks.push("non-HTTPS");
      if (isPrivateHost(url.hostname)) risks.push("private host");
      if (url.username || url.password) risks.push("credential in URL");
      if (/%25[0-9a-f]{2}/i.test(value)) risks.push("double encoding");
      if (/(token|key|secret|session|auth|password|passwd|pwd)=/i.test(url.search)) risks.push("sensitive query");
      if (/xn--/i.test(url.hostname)) risks.push("punycode");
      if (/\/(?:login|signin|verify|invoice|payment|download|update|payload|gate|panel)\b/i.test(url.pathname)) risks.push("credential/download path keyword");
      if (/\.(exe|dll|scr|js|vbs|ps1|bat|cmd|hta|jar|apk|iso|img|docm|xlsm)(?:$|[?#])/i.test(url.pathname)) risks.push("risky download extension");
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)) risks.push("IP host");
      if (url.port && !["80", "443", "8080", "8443"].includes(url.port)) risks.push("unusual URL port");
      if (/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at)$/i.test(url.hostname)) risks.push("URL shortener");
      if ((url.search.match(/https?:/gi) ?? []).length) risks.push("nested URL in query");
    } catch {
      risks.push("invalid URL");
    }
  }
  if ((type === "IPv4" || type === "CIDR") && isPrivateHost(normalized.split("/")[0])) risks.push("private IP");
  if (type === "IPv4") {
    const first = Number(normalized.split(".")[0]);
    if (first === 0 || first >= 224) risks.push("reserved/multicast IP");
  }
  if (type === "Domain" && /(?:xn--|\.top$|\.xyz$|\.cc$|\.tk$|\.zip$|\.mov$|\.click$|\.work$|\.info$)/i.test(lower)) risks.push("suspicious TLD/punycode");
  if (type === "Domain" && /(?:duckdns\.org|no-ip\.|dynu\.|ddns\.|hopto\.org|servehttp\.com)$/i.test(lower)) risks.push("dynamic DNS");
  if (type === "Domain" && /(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at)$/i.test(lower)) risks.push("URL shortener domain");
  if (type === "Hash") {
    if (/^[a-f0-9]{32}$/i.test(value)) risks.push("MD5");
    if (/^[a-f0-9]{40}$/i.test(value)) risks.push("SHA1");
    if (/^[a-f0-9]{64}$/i.test(value)) risks.push("SHA256");
    if (/^[a-f0-9]{96}$/i.test(value)) risks.push("SHA384");
    if (/^[a-f0-9]{128}$/i.test(value)) risks.push("SHA512");
  }
  if (type === "Email" && /(admin|root|support|security|billing|invoice)/i.test(value)) risks.push("sensitive mailbox");
  if (type === "Email" && /(?:\.top|\.xyz|\.cc|\.tk|\.zip)$/i.test(normalized.split("@")[1] ?? "")) risks.push("suspicious mail domain");
  if (type === "Registry" && /\\(?:run|runonce|services|winlogon|image file execution options|appinit_dlls)\\/i.test(`${normalized}\\`)) risks.push("persistence-related key");
  if (type === "Windows Path" && /\\(?:temp|appdata|startup|downloads)\\/i.test(`${normalized}\\`)) risks.push("user-writable/suspicious path");
  if (type === "BTC / ETH") risks.push("cryptocurrency address");
  return risks;
}

export function isLikelyFilenameDomainFalsePositive(value: string) {
  const lower = value.toLowerCase();
  if (!/^[a-z0-9_. -]+\.[a-z0-9]{2,8}$/i.test(value)) return false;
  return /\.(exe|dll|sys|lnk|url|pf|reg|dat|db|sqlite|sqlite3|edb|evtx|log|txt|csv|json|xml|ini|cfg|conf|ps1|bat|cmd|vbs|js|jar|apk|ipa|msi|scr|hta|zip|rar|7z|tar|gz|jpg|jpeg|png|gif|bmp|webp|pdf|doc|docx|xls|xlsx|ppt|pptx|eml|msg)$/i.test(lower);
}

export function analyzeIocs(text: string, source = "pasted text"): IocAnalysis {
  const patterns: Array<[string, RegExp]> = [
    ["URL", /\bhttps?:\/\/[^\s"'<>]+/gi],
    ["Email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
    ["CIDR", /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:[0-9]|[12]\d|3[0-2])\b/g],
    ["IPv4", /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g],
    ["IPv6", /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi],
    ["Hash", /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})\b/gi],
    ["CVE", /\bCVE-\d{4}-\d{4,7}\b/gi],
    ["MITRE ATT&CK", /\bT\d{4}(?:\.\d{3})?\b/g],
    ["MAC", /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi],
    ["Windows Path", /\b[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/gi],
    ["Registry", /\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\r\n]+/gi],
    ["BTC / ETH", /\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g],
    ["Domain", /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi]
  ];
  const map = new Map<string, IocRecord>();
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  lines.forEach((line, lineIndex) => {
    const refangedLine = refangIocText(line);
    for (const [type, pattern] of patterns) {
      pattern.lastIndex = 0;
      for (const match of refangedLine.matchAll(pattern)) {
        const value = match[0].replace(/[),.;\]}]+$/g, "");
        if (type === "Domain" && (
          refangedLine.includes(`${value}/`) ||
          /@/.test(refangedLine.slice(Math.max(0, (match.index ?? 0) - 2), (match.index ?? 0) + value.length + 2)) ||
          isLikelyFilenameDomainFalsePositive(value)
        )) continue;
        if (type === "IPv4" && new RegExp(`${value.replace(/\./g, "\\.")}/\\d{1,2}`).test(refangedLine)) continue;
        const normalized = normalizeIoc(type, value);
        const id = `${type}:${normalized}`;
        const current = map.get(id);
        if (current) {
          current.count += 1;
          if (!current.lines.includes(lineIndex + 1)) current.lines.push(lineIndex + 1);
          const context = line.trim();
          if (context && !current.contexts.includes(context) && current.contexts.length < 5) {
            current.contexts.push(context);
            current.context = current.contexts.join("\n");
          }
          continue;
        }
        map.set(id, {
          id,
          type,
          value,
          normalized,
          line: lineIndex + 1,
          lines: [lineIndex + 1],
          count: 1,
          context: line.trim(),
          contexts: line.trim() ? [line.trim()] : [],
          defanged: defangIocValue(normalized),
          risk: iocRisk(type, value)
        });
      }
    }
  });
  const records = Array.from(map.values()).sort((a, b) => a.type.localeCompare(b.type) || a.normalized.localeCompare(b.normalized));
  const grouped = records.reduce<Record<string, number>>((acc, record) => {
    acc[record.type] = (acc[record.type] ?? 0) + 1;
    return acc;
  }, {});
  const risky = records.filter((record) => record.risk.length);
  const repeated = records.filter((record) => record.count >= 3);
  const riskGroups = risky.reduce<Record<string, number>>((acc, record) => {
    record.risk.forEach((risk) => {
      acc[risk] = (acc[risk] ?? 0) + 1;
    });
    return acc;
  }, {});
  const findings: IocAnalysis["findings"] = [
    risky.length ? { level: "warn", title: "Indicators worth review", detail: risky.slice(0, 12).map((record) => `${record.type} ${record.value}: ${record.risk.join(", ")}`).join("\n") } : { level: "info", title: "No review marker", detail: "Indicators were extracted, but no local heuristic review marker was assigned." }
  ];
  if (/\bhxxps?:\/\/|\[\.\]|\(\.\)|\{\.}/i.test(text)) findings.push({ level: "info", title: "Defanged indicators refanged", detail: "hxxp and [.] style indicators were normalized for extraction." });
  if (repeated.length) findings.push({ level: "info", title: "Repeated sightings", detail: repeated.slice(0, 10).map((record) => `${record.type} ${record.normalized} x${record.count}`).join("\n") });
  if (Object.keys(riskGroups).length) findings.push({ level: "info", title: "Notes summary", detail: Object.entries(riskGroups).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([risk, count]) => `${risk}: ${count}`).join(", ") });
  if (!records.length) findings.splice(0, findings.length, { level: "warn", title: "No IOC extracted", detail: "No supported indicator pattern was found in the current input." });
  return {
    rows: [
      ["Source", source],
      ["Total unique", String(records.length)],
      ["Total sightings", String(records.reduce((sum, record) => sum + record.count, 0))],
      ["Types", Object.entries(grouped).map(([type, count]) => `${type}: ${count}`).join(", ") || "--"],
      ["Review-marked", String(risky.length)]
    ],
    records,
    findings,
    grouped
  };
}

export function iocRecordsToCsv(records: IocRecord[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["type", "value", "normalized", "defanged", "first_line", "lines", "count", "severity", "risk", "context"].join(","),
    ...records.map((record) => [record.type, record.value, record.normalized, record.defanged, record.line, record.lines.join(";"), record.count, iocSeverity(record), record.risk.join("; "), record.context].map(escape).join(","))
  ].join("\n");
}

export function iocSeverity(record: IocRecord) {
  const riskText = record.risk.join(" ").toLowerCase();
  if (/(credential|sensitive|phishing|malware|risky download|persistence|cryptocurrency|double encoding|punycode|shortener|dynamic dns|cve|mitre)/i.test(`${record.type} ${riskText}`)) return "high";
  if (record.risk.length || record.count >= 3) return "medium";
  return "low";
}

export function iocSeverityCounts(records: IocRecord[]) {
  return records.reduce<Record<string, number>>((acc, record) => {
    const severity = iocSeverity(record);
    acc[severity] = (acc[severity] ?? 0) + 1;
    return acc;
  }, { high: 0, medium: 0, low: 0 });
}

export function iocRiskRows(records: IocRecord[]) {
  const map = new Map<string, { count: number; examples: Set<string> }>();
  records.forEach((record) => {
    record.risk.forEach((risk) => {
      const current = map.get(risk) ?? { count: 0, examples: new Set<string>() };
      current.count += 1;
      if (current.examples.size < 4) current.examples.add(`${record.type}: ${record.normalized}`);
      map.set(risk, current);
    });
  });
  return Array.from(map.entries())
    .map(([risk, item]) => ({ risk, count: item.count, examples: Array.from(item.examples).join("\n") }))
    .sort((a, b) => b.count - a.count || a.risk.localeCompare(b.risk));
}

export function escapeStixString(value: string) {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

export function iocStixPattern(record: IocRecord) {
  const value = escapeStixString(record.normalized);
  if (record.type === "URL") return `[url:value = '${value}']`;
  if (record.type === "Domain") return `[domain-name:value = '${value}']`;
  if (record.type === "IPv4") return `[ipv4-addr:value = '${value}']`;
  if (record.type === "IPv6") return `[ipv6-addr:value = '${value}']`;
  if (record.type === "Email") return `[email-addr:value = '${value}']`;
  if (record.type === "MAC") return `[mac-addr:value = '${value}']`;
  if (record.type === "CVE") return `[vulnerability:name = '${value.toUpperCase()}']`;
  if (record.type === "Hash") {
    const algorithm = record.normalized.length === 32 ? "MD5" :
      record.normalized.length === 40 ? "SHA-1" :
      record.normalized.length === 64 ? "SHA-256" :
      record.normalized.length === 96 ? "SHA-384" :
      record.normalized.length === 128 ? "SHA-512" : "";
    return algorithm ? `[file:hashes.${algorithm} = '${value}']` : "";
  }
  return "";
}

export function iocRecordsToStixBundle(records: IocRecord[], source: string) {
  const created = new Date().toISOString();
  const objects = records
    .map((record) => {
      const pattern = iocStixPattern(record);
      if (!pattern) return null;
      return {
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${crypto.randomUUID()}`,
        created,
        modified: created,
        name: `${record.type}: ${record.normalized}`,
        description: `Source: ${source}; lines: ${record.lines.join(", ")}; sightings: ${record.count}; risk: ${record.risk.join(", ") || "none"}`,
        pattern,
        pattern_type: "stix",
        valid_from: created,
        labels: ["forensicspp", iocSeverity(record), ...record.risk.map((risk) => risk.toLowerCase().replace(/[^a-z0-9]+/g, "-")).filter(Boolean)]
      };
    })
    .filter(Boolean);
  return JSON.stringify({
    type: "bundle",
    id: `bundle--${crypto.randomUUID()}`,
    objects
  }, null, 2);
}

export function iocReportText(source: string, analysis: IocAnalysis, records: IocRecord[]) {
  const severity = iocSeverityCounts(records);
  const riskRows = iocRiskRows(records);
  const matrixRows = iocEvidenceMatrixRows(source, analysis, records, null);
  return [
    "# IOC Extraction Report",
    "",
    `Source: ${source}`,
    "",
    "## Summary",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${value}`),
    "",
    "## Findings",
    ...(analysis.findings.length ? analysis.findings.map((finding) => `- [${finding.level}] ${finding.title}: ${limitReportText(finding.detail, 1000)}`) : ["- none"]),
    "",
    "## Details",
    ...matrixRows.map((row) => `- [${row.level.toUpperCase()}] ${row.area}: ${row.count}\n  Evidence: ${limitReportText(row.evidence, 700)}\n  Check: ${limitReportText(row.risk, 700)}\n  Action: ${row.action}`),
    "",
    "## Severity",
    `- high: ${severity.high}`,
    `- medium: ${severity.medium}`,
    `- low: ${severity.low}`,
    "",
    "## Notes Summary",
    ...(riskRows.length ? riskRows.map((row) => `- ${row.risk}: ${row.count} (${row.examples.replace(/\n/g, "; ")})`) : ["- none"]),
    "",
    "## Indicators",
    ...(records.length
      ? records.slice(0, 300).map((record) => `- ${record.type} ${record.normalized} severity=${iocSeverity(record)} count=${record.count} lines=${record.lines.join(",")}${record.risk.length ? ` review=${record.risk.join(", ")}` : ""}\n  defanged=${record.defanged}\n  context=${limitReportText(record.context, 500)}`)
      : ["- none"])
  ].join("\n");
}

export function iocRecordText(record: IocRecord) {
  return [
    `Type: ${record.type}`,
    `Value: ${record.value}`,
    `Normalized: ${record.normalized}`,
    `Defanged: ${record.defanged}`,
    `Severity: ${iocSeverity(record)}`,
    `Count: ${record.count}`,
    `Lines: ${record.lines.join(", ")}`,
    `Check: ${record.risk.join(", ") || "--"}`,
    "",
    "STIX pattern:",
    iocStixPattern(record) || "--",
    "",
    "Contexts:",
    record.contexts.length ? record.contexts.join("\n---\n") : record.context || "--"
  ].join("\n");
}

export function iocBriefing(source: string, analysis: IocAnalysis, records: IocRecord[], selected?: IocRecord | null) {
  const severity = iocSeverityCounts(records);
  const riskRows = iocRiskRows(records);
  const matrixRows = iocEvidenceMatrixRows(source, analysis, records, selected ?? null);
  return [
    "IOC extraction briefing",
    `Generated: ${new Date().toISOString()}`,
    `Source: ${source}`,
    "",
    "Summary:",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${value}`),
    `- Filtered records: ${records.length}`,
    `- Severity: high=${severity.high}, medium=${severity.medium}, low=${severity.low}`,
    "",
    "Priority risks:",
    ...(riskRows.length ? riskRows.slice(0, 12).map((row) => `- ${row.risk}: ${row.count} (${row.examples.replace(/\n/g, "; ")})`) : ["- none"]),
    "",
    "Findings:",
    ...(analysis.findings.length ? analysis.findings.map((finding) => `- [${finding.level}] ${finding.title}: ${limitReportText(finding.detail, 900)}`) : ["- none"]),
    "",
    "Review details:",
    ...matrixRows.map((row, index) => `${index + 1}. [${row.level}] ${row.area} - ${row.count}: ${limitReportText(row.risk, 500)}`),
    "",
    "Current indicator:",
    selected ? iocRecordText(selected) : "--",
    "",
    "Filtered indicator preview:",
    ...(records.length ? records.slice(0, 80).map((record) => `- [${iocSeverity(record)}] ${record.type} ${record.normalized} x${record.count}${record.risk.length ? ` review=${record.risk.join(", ")}` : ""}`) : ["- none"])
  ].join("\n");
}

export function iocEvidenceMatrixRows(source: string, analysis: IocAnalysis, records: IocRecord[], selected?: IocRecord | null) {
  const severity = iocSeverityCounts(records);
  const riskRows = iocRiskRows(records);
  const repeated = records.filter((record) => record.count >= 3);
  const network = records.filter((record) => ["URL", "Domain", "IPv4", "IPv6", "CIDR"].includes(record.type));
  const hashes = records.filter((record) => record.type === "Hash");
  const endpoint = records.filter((record) => ["Windows Path", "Registry", "MAC"].includes(record.type));
  const identity = records.filter((record) => ["Email", "BTC / ETH"].includes(record.type));
  const vuln = records.filter((record) => ["CVE", "MITRE ATT&CK"].includes(record.type));
  const stixCount = records.filter((record) => iocStixPattern(record)).length;
  const highRisk = records.filter((record) => iocSeverity(record) === "high");
  const endpointRisk = endpoint.some((record) => /persistence|user-writable/i.test(record.risk.join(" ")));
  const identityRisk = identity.some((record) => /cryptocurrency|sensitive mailbox|suspicious mail/i.test(record.risk.join(" ")));
  const row = (area: string, count: string, level: string, evidence: string, risk: string, action: string): IocEvidenceRow => ({ area, count, level, evidence, risk, action });
  return [
    row(
      "Extraction Coverage",
      `${records.length}/${analysis.records.length}`,
      records.length ? "info" : "warn",
      [`Source: ${source}`, ...analysis.rows.map(([key, value]) => `${key}=${value}`)].join("；"),
      analysis.records.length && !records.length ? "Current filters hide every indicator" : "Filtered view is the current evidence scope",
      "Record source name, filter state, and total unique/sighting counts when exporting IOC evidence."
    ),
    row(
      "Type Distribution",
      `${Object.keys(analysis.grouped).length} types`,
      Object.keys(analysis.grouped).length ? "info" : "warn",
      Object.entries(analysis.grouped).sort((a, b) => b[1] - a[1]).map(([type, count]) => `${type}: ${count}`).join(" / ") || "No supported IOC type extracted",
      network.length ? `${network.length} network indicator(s)` : "No URL/domain/IP indicator in current filter",
      "Use type filters to split network, hash, endpoint, identity, and vulnerability work queues."
    ),
    row(
      "Priority Queue",
      `priority=${severity.high} / review=${severity.medium} / routine=${severity.low}`,
      severity.high || severity.medium ? "warn" : records.length ? "info" : "warn",
      highRisk.slice(0, 8).map((record) => `${record.type} ${record.normalized}: ${record.risk.join(", ") || "priority marker"}`).join(" / ") || "No priority indicator in current filter",
      severity.high ? "Priority uses local markers such as credentials, review-marked downloads, punycode, shorteners, persistence, crypto, CVE, or ATT&CK" : "No priority marker found locally",
      "Start enrichment with priority records, then repeated review records."
    ),
    row(
      "Review Categories",
      `${riskRows.length} categories`,
      riskRows.length ? "warn" : records.length ? "info" : "warn",
      riskRows.slice(0, 10).map((risk) => `${risk.risk}: ${risk.count}`).join(" / ") || "No risk category assigned by local heuristics",
      riskRows[0] ? `${riskRows[0].risk}: ${riskRows[0].examples.replace(/\n/g, " / ")}` : "No review marker means only that no local heuristic matched",
      "Export Review CSV to keep the local triage rationale visible in the report."
    ),
    row(
      "Repeated Sightings",
      `${repeated.length} repeated`,
      repeated.length ? "warn" : "info",
      repeated.slice(0, 8).map((record) => `${record.type} ${record.normalized} x${record.count} lines ${record.lines.join(",")}`).join(" / ") || "No indicator appears three or more times",
      repeated.length ? "Repeated sightings may indicate infrastructure reuse, log noise, or campaign artifacts" : "No repetition-based priority boost",
      "Use line/context data to decide whether repeated indicators are meaningful or boilerplate."
    ),
    row(
      "Network Indicators",
      `${network.length} records`,
      network.some((record) => iocSeverity(record) === "high") || network.some((record) => record.risk.length) ? "warn" : network.length ? "info" : "info",
      network.slice(0, 10).map((record) => `${record.type} ${record.normalized}${record.risk.length ? ` (${record.risk.join(", ")})` : ""}`).join(" / ") || "No network indicator in current filter",
      network.some((record) => record.risk.length) ? "Network review markers include private hosts, shorteners, punycode, dynamic DNS, nested URL, sensitive query, or download extensions" : "No network marker in current filter",
      "Send URLs to URL Analyzer; keep domains/IPs normalized and defanged for sharing."
    ),
    row(
      "Hash / File Indicators",
      `${hashes.length} hashes`,
      hashes.length ? "info" : "info",
      hashes.slice(0, 10).map((record) => `${record.normalized} (${record.risk.join(", ") || "hash"})`).join(" / ") || "No hash indicator in current filter",
      hashes.length ? "Hash type is inferred from length only; no reputation lookup is performed locally" : "No hash work queue",
      "Pair hashes with file names, sizes, and source context before enrichment or report publication."
    ),
    row(
      "Endpoint / Persistence Clues",
      `${endpoint.length} records`,
      endpoint.some((record) => record.risk.length) ? "warn" : endpoint.length ? "info" : "info",
      endpoint.slice(0, 10).map((record) => `${record.type} ${record.normalized}${record.risk.length ? ` (${record.risk.join(", ")})` : ""}`).join(" / ") || "No endpoint/persistence clue in current filter",
      endpointRisk ? "persistence or user-writable path marker" : "No endpoint marker detected",
      "Send registry/path records to Windows Artifact or strings workflows for context."
    ),
    row(
      "Identity / Value Transfer",
      `${identity.length} records`,
      identity.some((record) => record.risk.length) ? "warn" : identity.length ? "info" : "info",
      identity.slice(0, 10).map((record) => `${record.type} ${record.normalized}${record.risk.length ? ` (${record.risk.join(", ")})` : ""}`).join(" / ") || "No email/crypto identity indicator in current filter",
      identityRisk ? "identity or crypto marker" : "No identity marker detected",
      "Treat email addresses, support/admin aliases, and crypto addresses as sensitive report data."
    ),
    row(
      "Vulnerability / Technique",
      `${vuln.length} records`,
      vuln.length ? "warn" : "info",
      vuln.slice(0, 10).map((record) => `${record.type} ${record.normalized}`).join(" / ") || "No CVE or MITRE ATT&CK technique in current filter",
      vuln.length ? "CVE/ATT&CK values are context clues, not proof that exploitation occurred" : "No vulnerability/technique marker",
      "Cross-check CVE/ATT&CK values against timeline, process, network, and exploit evidence."
    ),
    row(
      "STIX Coverage",
      `${stixCount}/${records.length}`,
      stixCount ? "info" : records.length ? "warn" : "info",
      records.filter((record) => iocStixPattern(record)).slice(0, 8).map((record) => `${record.type} ${record.normalized}`).join(" / ") || "No STIX-supported indicator in current filter",
      records.length - stixCount ? `${records.length - stixCount} record(s) need CSV/Markdown handling rather than STIX indicator objects` : "All filtered records are STIX-supported",
      "Use STIX for supported IOC sharing; keep unsupported records in CSV/report bundle."
    ),
    row(
      "Current Record",
      selected ? iocSeverity(selected) : "none",
      selected ? (iocSeverity(selected) === "high" || iocSeverity(selected) === "medium" ? "warn" : "info") : "info",
      selected ? `${selected.type} ${selected.normalized} / lines ${selected.lines.join(",")}` : "No selected IOC",
      selected ? selected.risk.join(", ") || "No local review marker" : "Select a row to anchor the evidence detail panel",
      selected ? "Copy normalized/defanged value, export TXT, or include this record in the report bundle." : "Select the highest-value row before writing notes."
    )
  ];
}

export function iocEvidenceMatrixToCsv(rows: IocEvidenceRow[]) {
  const escape = (value: unknown) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  return [
    ["area", "count", "level", "evidence", "risk_or_limit", "action"].join(","),
    ...rows.map((row) => [row.area, row.count, row.level, row.evidence, row.risk, row.action].map(escape).join(","))
  ].join("\n");
}

export function iocWorkbenchBundle(source: string, analysis: IocAnalysis, records: IocRecord[], selected?: IocRecord | null) {
  const matrix = iocEvidenceMatrixRows(source, analysis, records, selected ?? null);
  return {
    generatedAt: new Date().toISOString(),
    source,
    summary: analysis.rows,
    grouped: analysis.grouped,
    severity: iocSeverityCounts(records),
    riskSummary: iocRiskRows(records),
    matrix,
    findings: analysis.findings,
    selectedRecord: selected ? {
      ...selected,
      severity: iocSeverity(selected),
      stixPattern: iocStixPattern(selected) || ""
    } : null,
    records: records.map((record) => ({
      ...record,
      severity: iocSeverity(record),
      stixPattern: iocStixPattern(record) || ""
    })),
    exports: {
      csv: iocRecordsToCsv(records),
      normalized: records.map((record) => record.normalized).join("\n"),
      defanged: records.map((record) => record.defanged).join("\n")
    },
    briefing: iocBriefing(source, analysis, records, selected ?? null),
    reportMarkdown: iocReportText(source, analysis, records)
  };
}

export function iocTriageCards(analysis: IocAnalysis, records: IocRecord[]) {
  const severity = iocSeverityCounts(records);
  const riskRows = iocRiskRows(records);
  const repeated = records.filter((record) => record.count >= 3);
  const stixCount = records.filter((record) => iocStixPattern(record)).length;
  return [
    {
      label: "筛选结果",
      value: `${records.length}/${analysis.records.length}`,
      level: records.length ? "info" : "warn",
      detail: `${Object.keys(analysis.grouped).length} 类型，${stixCount} 条可导出 STIX。`
    },
    {
      label: "复核提示",
      value: `${severity.high + severity.medium} 条`,
      level: severity.high || severity.medium ? "warn" : "info",
      detail: severity.high || severity.medium ? "本地规则提示，仅作为筛选线索。" : `${severity.low} 条常规 IOC。`
    },
    {
      label: "提示类型",
      value: riskRows[0]?.risk ?? "--",
      level: riskRows.length ? "warn" : "info",
      detail: riskRows.slice(0, 3).map((row) => `${row.risk}: ${row.count}`).join(" / ") || "未命中本地复核规则。"
    },
    {
      label: "重复出现",
      value: `${repeated.length}`,
      level: repeated.length ? "warn" : "info",
      detail: repeated.slice(0, 3).map((record) => `${record.normalized} x${record.count}`).join(" / ") || "没有三次以上重复项。"
    }
  ];
}

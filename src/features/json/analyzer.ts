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

import type { IocAnalysis, JsonAnalysis, JsonDecodedRow, JsonPathRow, TimelineEvent } from "../../models";
import { formatBytes, limitReportText } from "../../utils/files";

export type JsonAnalysisServices = {
  analyzeIocs: (text: string, source?: string) => IocAnalysis;
  parseTimestampCandidates: (text: string, source?: string) => TimelineEvent[];
  decodeBase64Url: (input: string) => string;
  decodeBase64Loose: (input: string) => string;
};

function parseJsonEvidence(text: string): { mode: string; value: unknown; normalized: string; minified: string; jsonl: string } {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Empty input");
  try {
    const value = JSON.parse(trimmed);
    const normalized = JSON.stringify(value, null, 2);
    const minified = JSON.stringify(value);
    return {
      mode: Array.isArray(value) ? "JSON array" : "JSON",
      value,
      normalized,
      minified,
      jsonl: Array.isArray(value) ? value.map((item) => JSON.stringify(item)).join("\n") : JSON.stringify(value)
    };
  } catch (firstError) {
    const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (lines.length > 1) {
      try {
        const items = lines.map((line) => JSON.parse(line));
        return {
          mode: "JSON Lines",
          value: items,
          normalized: JSON.stringify(items, null, 2),
          minified: JSON.stringify(items),
          jsonl: items.map((item) => JSON.stringify(item)).join("\n")
        };
      } catch {
        // Fall through to the original JSON.parse error.
      }
    }
    throw firstError;
  }
}

function jsonValueType(value: unknown) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function formatJsonScalar(value: unknown) {
  if (typeof value === "string") return value;
  if (value == null || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `[${value.length}]`;
  if (typeof value === "object") return `{${Object.keys(value as Record<string, unknown>).length}}`;
  return String(value);
}

function riskForJsonPath(path: string, type: string, value: string, raw: unknown) {
  const risk = [
    /(pass(word)?|token|secret|api[_-]?key|session|cookie|auth|jwt|bearer|private[_-]?key|credential|passwd|pwd|access[_-]?key|refresh[_-]?token|client[_-]?secret)/i.test(path) ? "sensitive key" : "",
    typeof raw === "string" && /(pass(word)?|token|secret|api[_-]?key|session|cookie|bearer|private key)\s*[:=]/i.test(raw) ? "credential marker" : "",
    typeof raw === "string" && /(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_|sk-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/.test(raw) ? "known secret pattern" : "",
    typeof raw === "string" && /^https?:\/\//i.test(raw) ? "url value" : "",
    typeof raw === "string" && /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(raw) ? "email value" : "",
    typeof raw === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/.test(raw) ? "JWT-like" : "",
    typeof raw === "string" && /^[A-Za-z0-9+/=_-]{24,}$/.test(raw) && raw.length % 4 !== 1 ? "encoded-looking" : "",
    typeof raw === "string" && /^[\[{]/.test(raw.trim()) && /[\]}]$/.test(raw.trim()) ? "embedded JSON string" : "",
    /(isAdmin|admin|role|permission|scope|privilege|mfa|2fa|totp)/i.test(path) ? "authorization field" : "",
    /(lat|latitude|lon|lng|longitude|gps|location|address)/i.test(path) ? "location field" : "",
    type === "number" && /\b(?:ts|time|date|created|updated|expires|iat|exp|nbf)\b/i.test(path) ? "timestamp field" : "",
    type === "boolean" && /\b(?:admin|enabled|disabled|mfa|2fa|verified|active|locked|deleted)\b/i.test(path) ? "state flag" : "",
    value.length > 1000 ? "long value" : ""
  ].filter(Boolean);
  return Array.from(new Set(risk));
}

export function jsonTypeSummaryRows(paths: JsonPathRow[]) {
  const map = paths.reduce<Map<string, number>>((acc, row) => acc.set(row.type, (acc.get(row.type) ?? 0) + 1), new Map());
  return Array.from(map.entries()).sort((a, b) => b[1] - a[1]).map(([type, count]) => [type, String(count)] as [string, string]);
}

export function jsonRiskSummaryRows(paths: JsonPathRow[]) {
  const map = new Map<string, { count: number; examples: string[] }>();
  paths.forEach((row) => {
    row.risk.forEach((risk) => {
      const current = map.get(risk) ?? { count: 0, examples: [] };
      current.count += 1;
      if (current.examples.length < 4) current.examples.push(row.path);
      map.set(risk, current);
    });
  });
  return Array.from(map.entries())
    .map(([risk, item]) => [risk, `${item.count} (${item.examples.join(", ")})`] as [string, string])
    .sort((a, b) => Number(b[1].match(/^\d+/)?.[0] ?? 0) - Number(a[1].match(/^\d+/)?.[0] ?? 0));
}

function jsonTopLevelRows(value: unknown) {
  if (Array.isArray(value)) {
    return [
      ["Root array length", String(value.length)],
      ["First item type", value.length ? jsonValueType(value[0]) : "--"]
    ] as Array<[string, string]>;
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>);
    return [
      ["Top-level keys", keys.slice(0, 40).join(", ") || "--"],
      ["Top-level key count", String(keys.length)]
    ] as Array<[string, string]>;
  }
  return [["Top-level keys", "--"]] as Array<[string, string]>;
}

function jsonDecodedCandidates(paths: JsonPathRow[], services: JsonAnalysisServices) {
  const rows: JsonDecodedRow[] = [];
  const add = (path: string, method: string, value: string, risk: string[] = []) => {
    const preview = value.replace(/\u0000/g, "").slice(0, 3000);
    if (!preview.trim()) return;
    if (rows.some((row) => row.path === path && row.method === method && row.preview === preview)) return;
    rows.push({ path, method, risk, preview });
  };
  paths.filter((row) => typeof row.raw === "string").slice(0, 2000).forEach((row) => {
    const value = String(row.raw).trim();
    if (!value || value.length > 12000) return;
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/.test(value)) {
      const parts = value.split(".");
      try {
        const header = JSON.stringify(JSON.parse(services.decodeBase64Url(parts[0])), null, 2);
        const payload = parts[1] ? JSON.stringify(JSON.parse(services.decodeBase64Url(parts[1])), null, 2) : "";
        add(row.path, "JWT decode", `${header}\n${payload}`.trim(), ["token"]);
      } catch {
        add(row.path, "JWT-like token", value, ["token"]);
      }
    }
    if (/^[A-Za-z0-9+/=_-]{24,}$/.test(value) && value.length % 4 !== 1) {
      try {
        const decoded = /[-_]/.test(value) ? services.decodeBase64Url(value) : services.decodeBase64Loose(value);
        if (decoded && decoded !== value && /[\t\n\r -~\u00a0-\uffff]{8,}/.test(decoded)) add(row.path, /[-_]/.test(value) ? "Base64URL decode" : "Base64 decode", decoded, /(pass|token|secret|key|bearer|cookie)/i.test(decoded) ? ["decoded secret marker"] : []);
      } catch {
        // Keep other decoders best-effort.
      }
    }
    if (/^[\[{]/.test(value) && /[\]}]$/.test(value)) {
      try {
        add(row.path, "Embedded JSON parse", JSON.stringify(JSON.parse(value), null, 2), ["nested JSON"]);
      } catch {
        // Not JSON after all.
      }
    }
  });
  return rows.slice(0, 80);
}

export function jsonVerdict(analysis: JsonAnalysis) {
  const danger = analysis.findings.filter((finding) => finding.level === "danger");
  const warn = analysis.findings.filter((finding) => finding.level === "warn");
  if (analysis.empty) return { level: "info", title: "等待 JSON 输入", detail: "粘贴或上传 JSON / JSONL 后在浏览器本地解析。" };
  if (!analysis.ok) return { level: "warn", title: "JSON 解析失败", detail: analysis.error ?? "Invalid JSON input." };
  if (danger.length) return { level: "warn", title: "JSON 内含需要复核的字段", detail: danger.slice(0, 3).map((finding) => finding.title).join(" / ") };
  if (warn.length) return { level: "warn", title: "JSON 内含需要复核的字段", detail: warn.slice(0, 4).map((finding) => finding.title).join(" / ") };
  return { level: "info", title: "JSON 已结构化整理", detail: "未命中明显敏感键、IOC、编码载荷或时间戳关注项。" };
}

function flattenJsonPaths(value: unknown, basePath = "$", limit = 5000) {
  const rows: JsonPathRow[] = [];
  const visit = (current: unknown, path: string) => {
    if (rows.length >= limit) return;
    const type = jsonValueType(current);
    const scalarValue = formatJsonScalar(current);
    rows.push({
      path,
      type,
      value: scalarValue,
      length: scalarValue.length,
      risk: riskForJsonPath(path, type, scalarValue, current),
      raw: current
    });
    if (Array.isArray(current)) {
      current.slice(0, 1000).forEach((item, index) => visit(item, `${path}[${index}]`));
      return;
    }
    if (current && typeof current === "object") {
      Object.entries(current as Record<string, unknown>).slice(0, 1000).forEach(([key, item]) => {
        const safeKey = /^[A-Za-z_$][\w$]*$/.test(key) ? `.${key}` : `[${JSON.stringify(key)}]`;
        visit(item, `${path}${safeKey}`);
      });
    }
  };
  visit(value, basePath);
  return rows;
}

export function jsonPathsToCsv(rows: JsonPathRow[]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["path", "type", "length", "risk", "value"].join(","),
    ...rows.map((row) => [row.path, row.type, String(row.length), row.risk.join("; "), row.value].map(escape).join(","))
  ].join("\n");
}

export function analyzeJsonEvidence(text: string, services: JsonAnalysisServices): JsonAnalysis {
  if (!text.trim()) {
    return {
      ok: false,
      empty: true,
      mode: "Waiting",
      value: null,
      normalized: "",
      minified: "",
      jsonl: "",
      rows: [["Status", "Waiting for JSON input"]],
      paths: [],
      decodedRows: [],
      iocs: [],
      timestamps: [],
      findings: []
    };
  }
  try {
    const parsed = parseJsonEvidence(text);
    const paths = flattenJsonPaths(parsed.value);
    const scalarRows = paths.filter((row) => !["object", "array"].includes(row.type));
    const objectCount = paths.filter((row) => row.type === "object").length;
    const arrayCount = paths.filter((row) => row.type === "array").length;
    const decodedRows = jsonDecodedCandidates(paths, services);
    const findings: JsonAnalysis["findings"] = [];
    const sensitiveKeys = scalarRows.filter((row) => /(pass(word)?|token|secret|api[_-]?key|session|cookie|auth|jwt|bearer|private[_-]?key)/i.test(row.path));
    if (sensitiveKeys.length) findings.push({ level: "warn", title: "Sensitive-looking keys", detail: sensitiveKeys.slice(0, 12).map((row) => row.path).join("\n") });
    const iocAnalysis = services.analyzeIocs(scalarRows.map((row) => `${row.path}: ${row.value}`).join("\n"), "JSON scalar values");
    if (iocAnalysis.records.length) findings.push({ level: "warn", title: "IOC-like values", detail: iocAnalysis.records.slice(0, 12).map((record) => `${record.type} ${record.value}`).join("\n") });
    const timestamps = services.parseTimestampCandidates(scalarRows.map((row) => `${row.path}: ${row.value}`).join("\n"), "JSON scalar values");
    if (timestamps.length) findings.push({ level: "info", title: "Timestamp-like values", detail: timestamps.slice(0, 12).map((event) => `${event.raw} -> ${event.iso}`).join("\n") });
    const base64Rows = scalarRows.filter((row) => typeof row.raw === "string" && /^[A-Za-z0-9+/=_-]{24,}$/.test(row.raw) && row.value.length % 4 !== 1);
    if (base64Rows.length) findings.push({ level: "warn", title: "Encoded-looking strings", detail: base64Rows.slice(0, 12).map((row) => row.path).join("\n") });
    const knownSecrets = scalarRows.filter((row) => row.risk.includes("known secret pattern"));
    if (knownSecrets.length) findings.push({ level: "warn", title: "Known secret token pattern", detail: knownSecrets.slice(0, 12).map((row) => row.path).join("\n") });
    const stateFlags = scalarRows.filter((row) => row.risk.includes("state flag"));
    if (stateFlags.length) findings.push({ level: "info", title: "State/permission flags", detail: stateFlags.slice(0, 12).map((row) => `${row.path}=${row.value}`).join("\n") });
    if (decodedRows.length) findings.push({ level: "warn", title: "Decoded candidate values", detail: decodedRows.slice(0, 10).map((row) => `${row.path}: ${row.method}`).join("\n") });
    const longRows = scalarRows.filter((row) => row.value.length > 1000);
    if (longRows.length) findings.push({ level: "info", title: "Long scalar values", detail: longRows.slice(0, 8).map((row) => `${row.path} (${row.value.length} chars)`).join("\n") });
    if (!findings.length) findings.push({ level: "info", title: "No obvious review marker", detail: "No sensitive key, IOC, timestamp, or encoded long string was detected by local heuristics." });
    return {
      ok: true,
      ...parsed,
      rows: [
        ["Mode", parsed.mode],
        ["Root type", jsonValueType(parsed.value)],
        ["Total paths", String(paths.length)],
        ["Objects", String(objectCount)],
        ["Arrays", String(arrayCount)],
        ["Scalars", String(scalarRows.length)],
        ["Review paths", String(paths.filter((row) => row.risk.length).length)],
        ["Decoded candidates", String(decodedRows.length)],
        ["IOC-like values", String(iocAnalysis.records.length)],
        ["Timestamp-like values", String(timestamps.length)],
        ["Normalized bytes", formatBytes(new TextEncoder().encode(parsed.normalized).length)],
        ...jsonTopLevelRows(parsed.value)
      ],
      paths,
      decodedRows,
      iocs: iocAnalysis.records,
      timestamps,
      findings
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      mode: "Invalid",
      value: null,
      normalized: detail,
      minified: detail,
      jsonl: "",
      rows: [["Error", detail]],
      paths: [],
      decodedRows: [],
      iocs: [],
      timestamps: [],
      findings: [{ level: "warn", title: "JSON parse failed", detail }],
      error: detail
    };
  }
}

export function jsonEvidenceReportText(analysis: JsonAnalysis, paths: JsonPathRow[]) {
  const verdict = jsonVerdict(analysis);
  const lines = [
    "# JSON Review",
    "",
    `Summary: [${verdict.level}] ${verdict.title} - ${verdict.detail}`,
    "",
    "## Summary",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${limitReportText(value, 800)}`),
    "",
    "## Type Stats",
    ...jsonTypeSummaryRows(paths).map(([key, value]) => `- ${key}: ${value}`),
    "",
    "## Notes Summary",
    ...(jsonRiskSummaryRows(paths).length ? jsonRiskSummaryRows(paths).map(([key, value]) => `- ${key}: ${value}`) : ["- --"]),
    "",
    "## Findings",
    ...analysis.findings.map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 1200)}`),
    "",
    "## Review Paths",
    ...(paths.filter((row) => row.risk.length).length
      ? paths.filter((row) => row.risk.length).slice(0, 120).map((row) => `- ${row.path} (${row.type}, ${row.risk.join(", ")}): ${limitReportText(row.value, 800)}`)
      : ["- --"]),
    "",
    "## Decoded Candidates",
    ...(analysis.decodedRows.length
      ? analysis.decodedRows.slice(0, 60).map((row) => `- ${row.path} (${row.method}${row.risk.length ? `, ${row.risk.join(", ")}` : ""})\n  ${limitReportText(row.preview, 1000).replace(/\n/g, "\n  ")}`)
      : ["- --"]),
    "",
    "## IOC-like Values",
    ...(analysis.iocs.length ? analysis.iocs.slice(0, 120).map((ioc) => `- ${ioc.type}: ${ioc.value}${ioc.risk.length ? ` (${ioc.risk.join(", ")})` : ""}`) : ["- --"]),
    "",
    "## Timestamp-like Values",
    ...(analysis.timestamps.length ? analysis.timestamps.slice(0, 120).map((event) => `- ${event.iso} | ${event.raw} | ${event.context}`) : ["- --"])
  ];
  return limitReportText(lines.join("\n"), 30000);
}

export function jsonPathKey(row: JsonPathRow) {
  return `${row.path}|${row.type}|${row.length}`;
}

export function jsonTriageCards(analysis: JsonAnalysis) {
  const verdict = jsonVerdict(analysis);
  const riskPaths = analysis.paths.filter((row) => row.risk.length);
  const scalarCount = analysis.paths.filter((row) => !["object", "array"].includes(row.type)).length;
  return [
    {
      label: "状态",
      value: analysis.ok ? verdict.title : "解析失败",
      detail: analysis.ok ? verdict.detail : analysis.error ?? "输入不是有效 JSON / JSONL。",
      level: verdict.level
    },
    {
      label: "结构",
      value: `${analysis.paths.length} paths`,
      detail: `${scalarCount} scalar values, ${jsonTypeSummaryRows(analysis.paths).length} detected types.`,
      level: analysis.ok ? "info" : "warn"
    },
    {
      label: "关注项 / IOC",
      value: `${riskPaths.length} note paths`,
      detail: `${analysis.iocs.length} IOC-like values, ${analysis.findings.filter((finding) => finding.level === "danger" || finding.level === "warn").length} note(s).`,
      level: riskPaths.length || analysis.iocs.length ? "warn" : "info"
    },
    {
      label: "时间 / 编码",
      value: `${analysis.timestamps.length} timestamps`,
      detail: `${analysis.decodedRows.length} decoded payload candidates found locally.`,
      level: analysis.decodedRows.length ? "warn" : "info"
    }
  ];
}

export function jsonBriefing(analysis: JsonAnalysis, selected?: JsonPathRow | null) {
  const verdict = jsonVerdict(analysis);
  const riskPaths = analysis.paths.filter((row) => row.risk.length);
  const lines = [
    "# JSON Review Briefing",
    `Generated: ${new Date().toISOString()}`,
    "",
    `Summary: [${verdict.level}] ${verdict.title}`,
    verdict.detail,
    "",
    "## Summary",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${limitReportText(value, 500)}`),
    "",
    "## Current Path",
    selected
      ? `- Path: ${selected.path}\n- Type: ${selected.type}\n- Length: ${selected.length}\n- Check: ${selected.risk.join(", ") || "--"}\n- Value: ${limitReportText(selected.value, 1200)}`
      : "- --",
    "",
    "## Findings",
    ...analysis.findings.slice(0, 20).map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 900)}`),
    "",
    "## Review Paths",
    ...(riskPaths.length
      ? riskPaths.slice(0, 60).map((row) => `- ${row.path} (${row.type}, ${row.risk.join(", ")}): ${limitReportText(row.value, 500)}`)
      : ["- --"]),
    "",
    "## Decoded Candidates",
    ...(analysis.decodedRows.length
      ? analysis.decodedRows.slice(0, 30).map((row) => `- ${row.path} / ${row.method}: ${limitReportText(row.preview, 500).replace(/\n/g, " ")}`)
      : ["- --"]),
    "",
    "## IOC Preview",
    ...(analysis.iocs.length
      ? analysis.iocs.slice(0, 40).map((ioc) => `- ${ioc.type}: ${ioc.value}${ioc.risk.length ? ` (${ioc.risk.join(", ")})` : ""}`)
      : ["- --"]),
    "",
    "## Timestamp Preview",
    ...(analysis.timestamps.length
      ? analysis.timestamps.slice(0, 40).map((event) => `- ${event.iso} | ${event.raw} | ${event.context}`)
      : ["- --"])
  ];
  return limitReportText(lines.join("\n"), 24000);
}

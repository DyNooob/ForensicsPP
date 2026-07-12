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

import type { TimelineEvent } from "../../models";
import { FILETIME_EPOCH_OFFSET_MS, isUsableDate } from "../../utils/forensics";
import { limitReportText } from "../../utils/files";

export const DOTNET_EPOCH_OFFSET_MS = 62135596800000n;
export const COCOA_EPOCH_MS = 978307200000;
export const HFS_EPOCH_OFFSET_MS = 2082844800000;
export const GPS_EPOCH_MS = 315964800000;
const UUID_GREGORIAN_OFFSET_MS = 12219292800000n;
const KSUID_EPOCH_MS = 1400000000000;
const DISCORD_SNOWFLAKE_EPOCH_MS = 1420070400000n;
const TWITTER_SNOWFLAKE_EPOCH_MS = 1288834974657n;
export const DAY_MS = 86400000;
const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KSUID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function formatTimelineDuration(seconds: number) {
  const safe = Math.max(0, Math.floor(seconds));
  const days = Math.floor(safe / 86400);
  const hours = Math.floor((safe % 86400) / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  const rest = safe % 60;
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", minutes ? `${minutes}m` : "", `${rest}s`].filter(Boolean).join(" ");
}

export function generalizedTime(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
}

export function exifDateTime(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}:${pad(date.getMonth() + 1)}:${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function decodeBaseNBigInt(value: string, alphabet: string) {
  const lookup = new Map(Array.from(alphabet, (char, index) => [char, BigInt(index)]));
  let output = 0n;
  const base = BigInt(alphabet.length);
  for (const char of value) {
    const digit = lookup.get(char);
    if (digit == null) return null;
    output = output * base + digit;
  }
  return output;
}

export function parseUuidV1Timestamp(value: string) {
  const match = value.trim().match(/^([0-9a-f]{8})-([0-9a-f]{4})-([1][0-9a-f]{3})-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  if (!match) return null;
  const ticks = (BigInt(`0x${match[3]}`) & 0x0fffn) << 48n | BigInt(`0x${match[2]}`) << 32n | BigInt(`0x${match[1]}`);
  return Number(ticks / 10000n - UUID_GREGORIAN_OFFSET_MS);
}

export function parseUlidTimestamp(value: string) {
  const normalized = value.trim().toUpperCase();
  if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(normalized)) return null;
  const decoded = decodeBaseNBigInt(normalized.slice(0, 10), ULID_ALPHABET);
  if (decoded == null) return null;
  return Number(decoded);
}

export function parseKsuidTimestamp(value: string) {
  const normalized = value.trim();
  if (!/^[0-9A-Za-z]{27}$/.test(normalized)) return null;
  const decoded = decodeBaseNBigInt(normalized, KSUID_ALPHABET);
  if (decoded == null) return null;
  const seconds = Number(decoded >> 128n);
  return seconds * 1000 + KSUID_EPOCH_MS;
}

export function parseMongoObjectIdTimestamp(value: string) {
  const normalized = value.trim().replace(/^0x/i, "");
  if (!/^[0-9a-f]{24}$/i.test(normalized)) return null;
  return parseInt(normalized.slice(0, 8), 16) * 1000;
}

export function parseFatPackedDateTime(value: number) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) return null;
  const time = value & 0xffff;
  const date = Math.floor(value / 0x10000) & 0xffff;
  const year = 1980 + ((date >> 9) & 0x7f);
  const month = (date >> 5) & 0x0f;
  const day = date & 0x1f;
  const hour = (time >> 11) & 0x1f;
  const minute = (time >> 5) & 0x3f;
  const second = (time & 0x1f) * 2;
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return null;
  return Date.UTC(year, month - 1, day, hour, minute, second);
}

export function dateRows(date: Date): Array<[string, string]> {
  if (Number.isNaN(date.getTime())) return [["Invalid", "--"]];
  const ms = BigInt(date.getTime());
  return [
    ["Unix seconds", Math.floor(date.getTime() / 1000).toString()],
    ["Unix milliseconds", date.getTime().toString()],
    ["Unix microseconds", (ms * 1000n).toString()],
    ["Unix / APFS nanoseconds", (ms * 1000000n).toString()],
    ["ISO", date.toISOString()],
    ["Local", date.toLocaleString()],
    ["UTC", date.toUTCString()],
    ["EXIF local", exifDateTime(date)],
    ["LDAP / AD GeneralizedTime", generalizedTime(date)],
    ["Windows FILETIME", ((ms + FILETIME_EPOCH_OFFSET_MS) * 10000n).toString()],
    ["Chrome/WebKit", ((ms + FILETIME_EPOCH_OFFSET_MS) * 1000n).toString()],
    [".NET ticks", ((ms + DOTNET_EPOCH_OFFSET_MS) * 10000n).toString()],
    ["UUID v1 timestamp field", ((ms + UUID_GREGORIAN_OFFSET_MS) * 10000n).toString()],
    ["Cocoa / CoreData seconds", ((date.getTime() - COCOA_EPOCH_MS) / 1000).toFixed(3).replace(/\.000$/, "")],
    ["Mac HFS+ seconds", Math.floor((date.getTime() + HFS_EPOCH_OFFSET_MS) / 1000).toString()],
    ["OLE Automation days", (date.getTime() / DAY_MS + 25569).toFixed(8).replace(/0+$/, "").replace(/\.$/, "")],
    ["GPS seconds", Math.floor((date.getTime() - GPS_EPOCH_MS) / 1000).toString()]
  ];
}

export function parseTimestampRows(raw: string): Array<[string, string]> {
  const text = raw.trim();
  const now = new Date();
  if (!text) return dateRows(now);
  const candidates: Array<{ label: string; date: Date }> = [];
  const numeric = /^-?\d+$/.test(text) ? BigInt(text) : /^0x[0-9a-f]+$/i.test(text) ? BigInt(text) : null;
  const numericFloat = /^-?\d+(?:\.\d+)?$/.test(text) ? Number(text) : null;

  const add = (label: string, ms: number) => {
    const date = new Date(ms);
    if (!isUsableDate(date)) return;
    const iso = date.toISOString();
    if (candidates.some((candidate) => candidate.label === label && candidate.date.toISOString() === iso)) return;
    candidates.push({ label, date });
  };
  const addBigInt = (label: string, ms: bigint) => {
    const value = Number(ms);
    if (Number.isFinite(value)) add(label, value);
  };
  const uuidV1Ms = parseUuidV1Timestamp(text);
  if (uuidV1Ms != null) add("UUID v1 timestamp", uuidV1Ms);
  const mongoObjectIdMs = parseMongoObjectIdTimestamp(text);
  if (mongoObjectIdMs != null) add("MongoDB ObjectId", mongoObjectIdMs);
  const ulidMs = parseUlidTimestamp(text);
  if (ulidMs != null) add("ULID timestamp", ulidMs);
  const ksuidMs = parseKsuidTimestamp(text);
  if (ksuidMs != null) add("KSUID timestamp", ksuidMs);

  if (numeric != null || numericFloat != null) {
    if (numeric != null) {
      const numberValue = Number(numeric);
      if (Number.isFinite(numberValue)) {
        if (text.length <= 11) add("Unix seconds", numberValue * 1000);
        if (text.length >= 11 && text.length <= 13) add("Unix milliseconds", numberValue);
        if (text.length >= 14 && text.length <= 16) add("Unix microseconds", Math.floor(numberValue / 1000));
        if (text.length >= 17 && text.length <= 19) add("Unix / APFS nanoseconds", Math.floor(numberValue / 1_000_000));
        if (text.length <= 11) {
          add("Cocoa / CoreData seconds", numberValue * 1000 + COCOA_EPOCH_MS);
          add("Mac HFS+ seconds", numberValue * 1000 - HFS_EPOCH_OFFSET_MS);
          add("GPS seconds", numberValue * 1000 + GPS_EPOCH_MS);
        }
        const fatMs = parseFatPackedDateTime(numberValue);
        if (fatMs != null) add("FAT packed date/time", fatMs);
      }
      if (text.length >= 16) {
        addBigInt("Windows FILETIME", numeric / 10000n - FILETIME_EPOCH_OFFSET_MS);
        addBigInt("Chrome/WebKit", numeric / 1000n - FILETIME_EPOCH_OFFSET_MS);
        addBigInt(".NET ticks", numeric / 10000n - DOTNET_EPOCH_OFFSET_MS);
        addBigInt("UUID v1 100ns timestamp", numeric / 10000n - UUID_GREGORIAN_OFFSET_MS);
        addBigInt("Discord snowflake", (numeric >> 22n) + DISCORD_SNOWFLAKE_EPOCH_MS);
        addBigInt("Twitter snowflake", (numeric >> 22n) + TWITTER_SNOWFLAKE_EPOCH_MS);
      }
    }
    if (numericFloat != null && Number.isFinite(numericFloat)) {
      if (numeric == null || text.includes(".")) add("Unix seconds with fraction", numericFloat * 1000);
      if (numericFloat > 20000 && numericFloat < 1000000) add("OLE Automation days", (numericFloat - 25569) * DAY_MS);
    }
    const sortedCandidates = [...candidates].sort((a, b) => Math.abs(Date.now() - a.date.getTime()) - Math.abs(Date.now() - b.date.getTime()));
    const best = sortedCandidates[0]?.date;
    return [
      ["Input", text],
      ...sortedCandidates.map((candidate) => [candidate.label, candidate.date.toISOString()] as [string, string]),
      ["Current", best ? best.toISOString() : "--"],
      ...dateRows(best ?? new Date(Number.NaN))
    ] as Array<[string, string]>;
  }

  const generalized = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?(Z|[+-]\d{4})?$/);
  if (generalized) {
    const [, year, month, day, hour, minute, second, zone = "Z"] = generalized;
    const isoZone = zone === "Z" ? "Z" : `${zone.slice(0, 3)}:${zone.slice(3)}`;
    add("LDAP / AD GeneralizedTime", Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${isoZone}`));
  }
  const exif = text.match(/^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (exif) add("EXIF local", new Date(Number(exif[1]), Number(exif[2]) - 1, Number(exif[3]), Number(exif[4]), Number(exif[5]), Number(exif[6])).getTime());
  const normalized = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(text) ? text.replace(" ", "T") : text;
  add(/T/.test(normalized) ? "ISO / RFC3339" : "Date string", Date.parse(normalized));
  const sortedCandidates = [...candidates].sort((a, b) => Math.abs(Date.now() - a.date.getTime()) - Math.abs(Date.now() - b.date.getTime()));
  const best = sortedCandidates[0]?.date;
  return [
    ["Input", text],
    ...sortedCandidates.map((candidate) => [candidate.label, candidate.date.toISOString()] as [string, string]),
    ["Current", best ? best.toISOString() : "--"],
    ...dateRows(best ?? new Date(Number.NaN))
  ] as Array<[string, string]>;
}

const timestampOutputLabels = new Set([
  "Input",
  "Current",
  "Unix seconds",
  "Unix milliseconds",
  "Unix microseconds",
  "Unix / APFS nanoseconds",
  "ISO",
  "Local",
  "UTC",
  "EXIF local",
  "LDAP / AD GeneralizedTime",
  "Windows FILETIME",
  "Chrome/WebKit",
  ".NET ticks",
  "UUID v1 timestamp field",
  "Cocoa / CoreData seconds",
  "Mac HFS+ seconds",
  "OLE Automation days",
  "GPS seconds",
  "Invalid"
]);

export function timestampCandidateRows(rows: Array<[string, string]>) {
  const currentIndex = rows.findIndex(([label]) => label === "Current");
  const candidateSlice = currentIndex >= 0 ? rows.slice(0, currentIndex) : rows;
  return candidateSlice.filter(([label, value]) => label !== "Input" && value !== "--");
}

export function timestampRowsToCsv(rows: Array<[string, string]>, candidates: Array<[string, string]>) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["section", "name", "value"].join(","),
    ...candidates.map(([name, value]) => ["candidate", name, value].map(escape).join(",")),
    ...rows.map(([name, value]) => ["output", name, value].map(escape).join(","))
  ].join("\n");
}

export function timestampReportText(input: string, rows: Array<[string, string]>, candidates: Array<[string, string]>) {
  return [
    "# Timestamp Evidence Conversion",
    "",
    `Input: ${input.trim() || "current time"}`,
    "",
    "## Candidate Interpretations",
    ...(candidates.length ? candidates.map(([label, iso]) => `- ${label}: ${iso}`) : ["- none"]),
    "",
    "## Current Conversion",
    ...rows.map(([label, value]) => `- ${label}: ${value}`)
  ].join("\n");
}

export function timestampCandidateKey(candidate: [string, string], index: number) {
  return `${index}::${candidate[0]}::${candidate[1]}`;
}

export function timestampSelectedIso(rows: Array<[string, string]>) {
  return rows.find(([label]) => label === "Current")?.[1] ?? "--";
}

export function timestampTriageCards(input: string, rows: Array<[string, string]>, candidates: Array<[string, string]>) {
  const selected = timestampSelectedIso(rows);
  const invalid = selected === "--" || rows.some(([label]) => label === "Invalid");
  const uniqueIso = new Set(candidates.map(([, iso]) => iso));
  return [
    {
      label: "识别结果",
      value: invalid ? "未识别" : selected,
      level: invalid ? "danger" : "info",
      detail: input.trim() ? "已识别当前输入。" : "当前时间。"
    },
    {
      label: "候选数量",
      value: `${candidates.length}`,
      level: candidates.length > 1 ? "warn" : candidates.length ? "info" : "danger",
      detail: candidates.length > 1 ? `${uniqueIso.size} 个不同时间值，需结合上下文判定。` : "单一候选或未命中。"
    },
    {
      label: "格式家族",
      value: candidates.slice(0, 3).map(([label]) => label.replace(/ timestamp| seconds| milliseconds| microseconds| nanoseconds/gi, "")).join(" / ") || "--",
      level: candidates.some(([label]) => /FILETIME|Chrome|UUID|Snowflake|ObjectId|ULID|KSUID/i.test(label)) ? "info" : "warn",
      detail: candidates.slice(0, 3).map(([label, iso]) => `${label}: ${iso}`).join(" | ") || "没有可用候选。"
    },
    {
      label: "报告时间",
      value: rows.find(([label]) => label === "UTC")?.[1] ?? "--",
      level: invalid ? "danger" : "info",
      detail: rows.find(([label]) => label === "Local")?.[1] ?? "--"
    }
  ];
}

export function timestampBriefing(input: string, rows: Array<[string, string]>, candidates: Array<[string, string]>, selectedCandidate?: [string, string] | null) {
  return [
    "Timestamp evidence conversion",
    `Generated: ${new Date().toISOString()}`,
    `Input: ${input.trim() || "current time"}`,
    "",
    "Candidate interpretations:",
    ...(candidates.length ? candidates.map(([label, iso], index) => `${index + 1}. ${label}: ${iso}`) : ["1. none"]),
    "",
    "Current candidate:",
    selectedCandidate ? `${selectedCandidate[0]}: ${selectedCandidate[1]}` : "--",
    "",
    "Conversion rows:",
    ...rows.map(([label, value]) => `- ${label}: ${value}`)
  ].join("\n");
}

export function timestampBatchBriefing(events: TimelineEvent[], filteredEvents: TimelineEvent[], selectedEvent?: TimelineEvent | null) {
  const analysis = analyzeTimelineEvents(events, filteredEvents, "timestamp batch");
  return [
    "Timestamp batch extraction",
    `Generated: ${new Date().toISOString()}`,
    `Total events: ${events.length}`,
    `Filtered events: ${filteredEvents.length}`,
    "",
    "Summary:",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${value}`),
    "",
    "Findings:",
    ...(analysis.findings.length ? analysis.findings.map((finding) => `- [${finding.level}] ${finding.title}: ${finding.detail}`) : ["- none"]),
    "",
    "Current event:",
    selectedEvent
      ? [
          `- ISO: ${selectedEvent.iso}`,
          `- Local: ${selectedEvent.local}`,
          `- Format: ${selectedEvent.format}`,
          `- Raw: ${selectedEvent.raw}`,
          `- Line: ${selectedEvent.line}`,
          `- Category: ${selectedEvent.category ?? classifyTimelineContext(selectedEvent.context, selectedEvent.source)}`,
          `- Check: ${selectedEvent.risk?.join(", ") || "--"}`,
          `- Context: ${selectedEvent.context}`
        ].join("\n")
      : "- none",
    "",
    "Preview:",
    ...(filteredEvents.length ? filteredEvents.slice(0, 40).map((event, index) => `${index + 1}. ${event.iso} | ${event.format} | ${event.raw} | line ${event.line} | ${event.context}`) : ["- none"])
  ].join("\n");
}

export function timestampBatchTriageCards(events: TimelineEvent[], filteredEvents: TimelineEvent[]) {
  const analysis = analyzeTimelineEvents(events, filteredEvents, "timestamp batch");
  const first = events[0]?.iso ?? "--";
  const last = events[events.length - 1]?.iso ?? "--";
  const risky = events.filter((event) => event.risk?.length);
  const formats = new Set(events.map((event) => event.format));
  return [
    {
      label: "批量提取",
      value: `${filteredEvents.length}/${events.length}`,
      level: events.length ? "info" : "warn",
      detail: events.length ? `${formats.size} 种格式；范围 ${first} -> ${last}` : "粘贴日志或文本后自动抽取多格式时间。"
    },
    {
      label: "风险上下文",
      value: `${risky.length}`,
      level: risky.length ? "warn" : "info",
      detail: risky.slice(0, 3).map((event) => `${event.raw}: ${event.risk?.join("/")}`).join(" | ") || "未命中失败登录、删除、命令执行等上下文提示。"
    },
    {
      label: "格式分布",
      value: analysis.formatRows.slice(0, 3).map(([format, count]) => `${format}:${count}`).join(" / ") || "--",
      level: formats.size > 1 ? "warn" : events.length ? "info" : "warn",
      detail: formats.size > 1 ? "多格式混合时要结合字段来源确认解释。" : "单一格式或暂无数据。"
    },
    {
      label: "时间密度",
      value: analysis.denseRows[0]?.[1] ? `${analysis.denseRows[0][1]} / min` : "--",
      level: analysis.denseRows.length ? "warn" : "info",
      detail: analysis.denseRows[0] ? `${analysis.denseRows[0][0]} 为最高密度分钟。` : "未发现分钟级高密度聚集。"
    }
  ];
}

export function parseTimelineTimestamp(raw: string) {
  const value = raw.trim();
  const numeric = /^-?\d+$/.test(value) ? BigInt(value) : /^0x[0-9a-f]+$/i.test(value) ? BigInt(value) : null;
  const numericFloat = /^-?\d+(?:\.\d+)?$/.test(value) ? Number(value) : null;
  const candidates: Array<{ format: string; date: Date }> = [];
  const add = (format: string, ms: number) => {
    const date = new Date(ms);
    if (!Number.isNaN(date.getTime()) && date.getUTCFullYear() >= 1970 && date.getUTCFullYear() <= 3000) candidates.push({ format, date });
  };
  const uuidV1Ms = parseUuidV1Timestamp(value);
  if (uuidV1Ms != null) add("UUID v1 timestamp", uuidV1Ms);
  const mongoObjectIdMs = parseMongoObjectIdTimestamp(value);
  if (mongoObjectIdMs != null) add("MongoDB ObjectId", mongoObjectIdMs);
  const ulidMs = parseUlidTimestamp(value);
  if (ulidMs != null) add("ULID timestamp", ulidMs);
  const ksuidMs = parseKsuidTimestamp(value);
  if (ksuidMs != null) add("KSUID timestamp", ksuidMs);
  if (numeric != null) {
    const numberValue = Number(numeric);
    if (value.length === 10) add("Unix seconds", numberValue * 1000);
    if (value.length <= 11) {
      add("Cocoa / CoreData seconds", numberValue * 1000 + COCOA_EPOCH_MS);
      add("Mac HFS+ seconds", numberValue * 1000 - HFS_EPOCH_OFFSET_MS);
      add("GPS seconds", numberValue * 1000 + GPS_EPOCH_MS);
    }
    if (value.length === 13) add("Unix milliseconds", numberValue);
    if (value.length === 16) add("Unix microseconds", Math.floor(numberValue / 1000));
    if (value.length === 17 || value.length === 18 || value.length === 19) {
      add("Unix / APFS nanoseconds", Math.floor(numberValue / 1_000_000));
      add("Windows FILETIME", Number(numeric / 10000n - 11644473600000n));
      add("Chrome/WebKit", Number(numeric / 1000n - 11644473600000n));
      add(".NET ticks", Number(numeric / 10000n - DOTNET_EPOCH_OFFSET_MS));
      add("UUID v1 100ns timestamp", Number(numeric / 10000n - UUID_GREGORIAN_OFFSET_MS));
      add("Discord snowflake", Number((numeric >> 22n) + DISCORD_SNOWFLAKE_EPOCH_MS));
      add("Twitter snowflake", Number((numeric >> 22n) + TWITTER_SNOWFLAKE_EPOCH_MS));
    }
    const fatMs = parseFatPackedDateTime(numberValue);
    if (fatMs != null) add("FAT packed date/time", fatMs);
    if (/^0x/i.test(value)) {
      add("Hex Unix seconds", numberValue * 1000);
      add("Hex Unix milliseconds", numberValue);
    }
  } else if (numericFloat != null && Number.isFinite(numericFloat)) {
    if (numericFloat > 20000 && numericFloat < 1000000) add("OLE Automation days", (numericFloat - 25569) * DAY_MS);
    if (numericFloat > 0 && numericFloat < 4102444800) add("Unix seconds with fraction", numericFloat * 1000);
  } else {
    const generalized = value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?(Z|[+-]\d{4})?$/);
    if (generalized) {
      const [, year, month, day, hour, minute, second, zone = "Z"] = generalized;
      const isoZone = zone === "Z" ? "Z" : `${zone.slice(0, 3)}:${zone.slice(3)}`;
      add("LDAP / AD GeneralizedTime", Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${isoZone}`));
    }
    const exif = value.match(/^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$/);
    if (exif) add("EXIF local", new Date(Number(exif[1]), Number(exif[2]) - 1, Number(exif[3]), Number(exif[4]), Number(exif[5]), Number(exif[6])).getTime());
    const slashDate = value.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?/);
    if (slashDate) add("Slash date string", new Date(Number(slashDate[1]), Number(slashDate[2]) - 1, Number(slashDate[3]), Number(slashDate[4]), Number(slashDate[5]), Number(slashDate[6] ?? 0)).getTime());
    const normalized = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(value) ? value.replace(" ", "T") : value;
    const parsed = new Date(normalized);
    if (!Number.isNaN(parsed.getTime())) candidates.push({ format: /T/.test(normalized) ? "ISO / RFC3339" : "Date string", date: parsed });
  }
  return candidates.sort((a, b) => Math.abs(Date.now() - a.date.getTime()) - Math.abs(Date.now() - b.date.getTime()))[0] ?? null;
}

export function classifyTimelineContext(context: string, source: string) {
  const text = `${source} ${context}`.toLowerCase();
  if (/(logon|login|logout|signin|sign-in|authentication|auth|password|mfa|2fa|account)/i.test(text)) return "Authentication";
  if (/(process|proc|pid=|cmd\.exe|powershell|pwsh|bash|sh\s+-c|exec|spawn|service|task scheduler|prefetch)/i.test(text)) return "Process";
  if (/(file|path|created|modified|deleted|rename|download|upload|write|read|hash|sha256|md5|document|attachment)/i.test(text)) return "File";
  if (/(http|https|dns|tcp|udp|ip=|src=|dst=|url|domain|host|connection|socket|beacon|network)/i.test(text)) return "Network";
  if (/(email|mail|smtp|imap|pop3|from:|to:|subject:|message-id|received:)/i.test(text)) return "Email";
  if (/(chrome|edge|firefox|safari|browser|history|cookie|cache|webcache|download)/i.test(text)) return "Browser";
  if (/(registry|reg_|hkey_|hkcu|hklm|runonce|winlogon|services\\|autorun)/i.test(text)) return "Registry";
  if (/(security|alert|blocked|malware|trojan|ransom|payload|exploit|cve|yara|ioc|edr|av|defender)/i.test(text)) return "Security";
  if (/(boot|shutdown|restart|kernel|system|event id|eventid|windows event)/i.test(text)) return "System";
  return "Other";
}

export function timelineContextRisks(context: string) {
  const risks = [
    /(failed|failure|denied|invalid password|bad password|authentication failed|logon failure)/i.test(context) ? "failed auth" : "",
    /(admin|administrator|root|sudo|privilege|elevat|uac|sebackupprivilege|debug privilege)/i.test(context) ? "privilege marker" : "",
    /(delete|deleted|remove|removed|wipe|cleared|truncate|shred)/i.test(context) ? "destructive action" : "",
    /(powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|mshta|bitsadmin|certutil|wmic)/i.test(context) ? "living-off-the-land command" : "",
    /(malware|trojan|ransom|payload|exploit|c2|beacon|ioc|yara|defender|quarantine)/i.test(context) ? "security marker" : "",
    /(external|public ip|tor|proxy|vpn|pastebin|telegram|discord webhook|ngrok|cloudflare tunnel)/i.test(context) ? "external service marker" : ""
  ].filter(Boolean);
  return risks;
}

export function parseTimestampCandidates(raw: string, source = "pasted text"): TimelineEvent[] {
  const patterns = [
    /\b[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    /\b[0-9a-f]{24}\b/gi,
    /\b[0-9A-HJKMNP-TV-Z]{26}\b/g,
    /\b[0-9A-Za-z]{27}\b/g,
    /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g,
    /\b\d{4}:\d{2}:\d{2}\s+\d{2}:\d{2}:\d{2}\b/g,
    /\b\d{4}\/\d{1,2}\/\d{1,2}[ T]\d{1,2}:\d{2}(?::\d{2})?\b/g,
    /\b\d{14}(?:\.\d+)?(?:Z|[+-]\d{4})?\b/g,
    /\b\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:GMT|UTC|[+-]\d{4})\b/g,
    /\b\d{10}\b|\b\d{13}\b|\b\d{16}\b|\b\d{17,19}\b/g,
    /\b0x[0-9a-fA-F]{8,16}\b/g,
    /\b\d{5,6}\.\d{1,8}\b/g
  ];
  const events: TimelineEvent[] = [];
  const seen = new Set<string>();
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  lines.forEach((line, lineIndex) => {
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      for (const match of line.matchAll(pattern)) {
        const parsed = parseTimelineTimestamp(match[0]);
        if (!parsed) continue;
        const iso = parsed.date.toISOString();
        const epochMs = parsed.date.getTime();
        const context = line.trim();
        const category = classifyTimelineContext(context, source);
        const risk = [
          epochMs > Date.now() + DAY_MS ? "future timestamp" : "",
          epochMs < Date.parse("1980-01-01T00:00:00Z") ? "very old timestamp" : "",
          ...timelineContextRisks(context)
        ].filter(Boolean);
        const key = `${iso}|${lineIndex + 1}|${match[0]}|${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        events.push({
          id: `${lineIndex + 1}-${match.index ?? 0}-${match[0]}`,
          iso,
          local: parsed.date.toLocaleString(),
          raw: match[0],
          format: parsed.format,
          category,
          line: lineIndex + 1,
          source,
          context,
          epochMs,
          risk: Array.from(new Set(risk))
        });
      }
    }
  });
  return events.sort((a, b) => a.iso.localeCompare(b.iso)).slice(0, 5000);
}

export function analyzeTimelineEvents(events: TimelineEvent[], filteredEvents: TimelineEvent[], source: string) {
  const formats = new Map<string, number>();
  const lines = new Map<number, number>();
  const duplicateIso = new Map<string, number>();
  const sources = new Map<string, number>();
  const days = new Map<string, number>();
  const minuteBuckets = new Map<string, number>();
  const categories = new Map<string, number>();
  events.forEach((event) => {
    formats.set(event.format, (formats.get(event.format) ?? 0) + 1);
    lines.set(event.line, (lines.get(event.line) ?? 0) + 1);
    duplicateIso.set(event.iso, (duplicateIso.get(event.iso) ?? 0) + 1);
    sources.set(event.source, (sources.get(event.source) ?? 0) + 1);
    days.set(event.iso.slice(0, 10), (days.get(event.iso.slice(0, 10)) ?? 0) + 1);
    minuteBuckets.set(event.iso.slice(0, 16), (minuteBuckets.get(event.iso.slice(0, 16)) ?? 0) + 1);
    categories.set(event.category ?? classifyTimelineContext(event.context, event.source), (categories.get(event.category ?? classifyTimelineContext(event.context, event.source)) ?? 0) + 1);
  });
  const first = events[0];
  const last = events[events.length - 1];
  const sortedEvents = [...events].sort((a, b) => (a.epochMs ?? 0) - (b.epochMs ?? 0));
  const gapRows = sortedEvents.slice(1).map((event, index) => {
    const previous = sortedEvents[index];
    const seconds = Math.max(0, Math.floor(((event.epochMs ?? 0) - (previous.epochMs ?? 0)) / 1000));
    return {
      from: previous.iso,
      to: event.iso,
      seconds,
      duration: formatTimelineDuration(seconds),
      fromContext: previous.context,
      toContext: event.context
    };
  }).filter((gap) => gap.seconds > 0).sort((a, b) => b.seconds - a.seconds).slice(0, 40);
  const denseBuckets = Array.from(minuteBuckets.entries()).filter(([, count]) => count >= 5).sort((a, b) => b[1] - a[1]);
  const duplicateRows = Array.from(duplicateIso.entries())
    .filter(([, count]) => count > 1)
    .map(([iso, count]) => {
      const grouped = events.filter((event) => event.iso === iso);
      return {
        iso,
        count,
        formats: Array.from(new Set(grouped.map((event) => event.format))).join(", "),
        lines: grouped.slice(0, 12).map((event) => String(event.line)).join(", "),
        contexts: grouped.slice(0, 3).map((event) => event.context).join("\n")
      };
    })
    .sort((a, b) => b.count - a.count || a.iso.localeCompare(b.iso))
    .slice(0, 60);
  const sessionRows: Array<{ start: string; end: string; events: number; duration: string; sources: string; categories: string; risks: string; firstContext: string; lastContext: string }> = [];
  let currentSession: TimelineEvent[] = [];
  const flushSession = () => {
    if (!currentSession.length) return;
    const start = currentSession[0];
    const end = currentSession[currentSession.length - 1];
    const durationSeconds = Math.max(0, Math.floor(((end.epochMs ?? 0) - (start.epochMs ?? 0)) / 1000));
    const sourceCounts = new Map<string, number>();
    const categoryCounts = new Map<string, number>();
    const risks = new Set<string>();
    currentSession.forEach((event) => {
      sourceCounts.set(event.source, (sourceCounts.get(event.source) ?? 0) + 1);
      const category = event.category ?? classifyTimelineContext(event.context, event.source);
      categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + 1);
      event.risk?.forEach((risk) => risks.add(risk));
    });
    sessionRows.push({
      start: start.iso,
      end: end.iso,
      events: currentSession.length,
      duration: formatTimelineDuration(durationSeconds),
      sources: Array.from(sourceCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([item, count]) => `${item} (${count})`).join(", "),
      categories: Array.from(categoryCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([item, count]) => `${item} (${count})`).join(", "),
      risks: Array.from(risks).join(", ") || "--",
      firstContext: start.context,
      lastContext: end.context
    });
    currentSession = [];
  };
  sortedEvents.forEach((event) => {
    const previous = currentSession[currentSession.length - 1];
    if (previous && (event.epochMs ?? 0) - (previous.epochMs ?? 0) > 30 * 60 * 1000) flushSession();
    currentSession.push(event);
  });
  flushSession();
  const spanMs = first?.epochMs != null && last?.epochMs != null ? last.epochMs - first.epochMs : 0;
  const rows: Array<[string, string]> = [
    ["Events", String(events.length)],
    ["Filtered", String(filteredEvents.length)],
    ["First", first?.iso ?? "--"],
    ["Last", last?.iso ?? "--"],
    ["Span", events.length > 1 ? formatTimelineDuration(Math.floor(spanMs / 1000)) : "--"],
    ["Largest gap", gapRows[0] ? `${gapRows[0].duration} (${gapRows[0].from} -> ${gapRows[0].to})` : "--"],
    ["Sources", String(sources.size)],
    ["Days", String(days.size)],
    ["Sessions", String(sessionRows.length)],
    ["Formats", Array.from(formats.entries()).map(([format, count]) => `${format}: ${count}`).join(", ") || "--"],
    ["Categories", Array.from(categories.entries()).map(([category, count]) => `${category}: ${count}`).join(", ") || "--"],
    ["Source", source]
  ];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  const future = events.filter((event) => event.risk?.includes("future timestamp"));
  const old = events.filter((event) => event.risk?.includes("very old timestamp"));
  const denseLines = Array.from(lines.entries()).filter(([, count]) => count > 3);
  const duplicates = Array.from(duplicateIso.entries()).filter(([, count]) => count > 1);
  if (!events.length) findings.push({ level: "warn", title: "No timestamp extracted", detail: "No supported timestamp pattern was found in the current input." });
  if (events.length >= 5000) findings.push({ level: "warn", title: "Timeline truncated", detail: "Only the first 5000 normalized events are kept in this browser view." });
  if (future.length) findings.push({ level: "warn", title: "Future timestamps", detail: future.slice(0, 8).map((event) => `${event.iso} line ${event.line}`).join("\n") });
  if (old.length) findings.push({ level: "info", title: "Very old timestamps", detail: old.slice(0, 8).map((event) => `${event.iso} line ${event.line}`).join("\n") });
  if (denseLines.length) findings.push({ level: "info", title: "Multiple timestamps on same line", detail: denseLines.slice(0, 8).map(([line, count]) => `line ${line}: ${count}`).join(", ") });
  if (duplicates.length) findings.push({ level: "info", title: "Repeated normalized times", detail: duplicates.slice(0, 8).map(([iso, count]) => `${iso} x${count}`).join("\n") });
  if (Array.from(categories.keys()).filter((category) => category !== "Other").length >= 4) findings.push({ level: "info", title: "Multi-domain activity", detail: Array.from(categories.entries()).sort((a, b) => b[1] - a[1]).map(([category, count]) => `${category}: ${count}`).join(", ") });
  const riskySessions = sessionRows.filter((session) => session.risks !== "--");
  if (riskySessions.length) findings.push({ level: "warn", title: "Activity sessions worth review", detail: riskySessions.slice(0, 6).map((session) => `${session.start} -> ${session.end}: ${session.risks}`).join("\n") });
  if (formats.size > 3) findings.push({ level: "info", title: "Mixed timestamp formats", detail: Array.from(formats.keys()).join(", ") });
  if (gapRows[0]?.seconds > 3600) findings.push({ level: "info", title: "Large timeline gap", detail: `${gapRows[0].duration} between ${gapRows[0].from} and ${gapRows[0].to}` });
  if (denseBuckets.length) findings.push({ level: "info", title: "Dense minute bucket", detail: denseBuckets.slice(0, 8).map(([bucket, count]) => `${bucket}: ${count}`).join("\n") });
  if (!findings.length) findings.push({ level: "info", title: "Timeline normalized", detail: `${events.length} event(s) sorted by UTC time.` });
  return {
    rows,
    findings,
    formatRows: Array.from(formats.entries()).sort((a, b) => b[1] - a[1]).map(([format, count]) => [format, String(count)] as [string, string]),
    categoryRows: Array.from(categories.entries()).sort((a, b) => b[1] - a[1]).map(([category, count]) => [category, String(count)] as [string, string]),
    sourceRows: Array.from(sources.entries()).sort((a, b) => b[1] - a[1]).map(([item, count]) => [item, String(count)] as [string, string]),
    dayRows: Array.from(days.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([item, count]) => [item, String(count)] as [string, string]),
    gapRows,
    denseRows: denseBuckets.map(([bucket, count]) => [bucket, String(count)] as [string, string]),
    duplicateRows,
    sessionRows
  };
}

export function timelineToCsv(events: TimelineEvent[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["iso", "local", "epoch_ms", "format", "category", "raw", "line", "source", "risk", "context"].join(","),
    ...events.map((event) => [event.iso, event.local, event.epochMs ?? "", event.format, event.category ?? classifyTimelineContext(event.context, event.source), event.raw, event.line, event.source, event.risk?.join("; ") ?? "", event.context].map(escape).join(","))
  ].join("\n");
}

export function timelineEventPriorityScore(event: TimelineEvent) {
  const context = `${event.format} ${event.category ?? ""} ${event.context}`.toLowerCase();
  return (
    (event.risk?.length ?? 0) * 220
    + (/login|auth|password|token|session|admin|remote|download|execute|deleted?|failed?|error|attachment|email|ip|url/.test(context) ? 80 : 0)
    + (/filetime|chrome|webkit|uuid|objectid|ulid|ksuid|snowflake|ldap|exif|hfs|ole|cocoa/i.test(event.format) ? 45 : 0)
  );
}

export function timelineGapsToCsv(gaps: Array<{ from: string; to: string; seconds: number; duration: string; fromContext: string; toContext: string }>) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["from", "to", "seconds", "duration", "from_context", "to_context"].join(","),
    ...gaps.map((gap) => [gap.from, gap.to, gap.seconds, gap.duration, gap.fromContext, gap.toContext].map(escape).join(","))
  ].join("\n");
}

export function timelineSessionsToCsv(sessions: Array<{ start: string; end: string; events: number; duration: string; sources: string; categories: string; risks: string; firstContext: string; lastContext: string }>) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["start", "end", "events", "duration", "sources", "categories", "risks", "first_context", "last_context"].join(","),
    ...sessions.map((session) => [session.start, session.end, session.events, session.duration, session.sources, session.categories, session.risks, session.firstContext, session.lastContext].map(escape).join(","))
  ].join("\n");
}

export function timelineEventSummary(event: TimelineEvent) {
  return [
    `ISO: ${event.iso}`,
    `Local: ${event.local}`,
    `Epoch ms: ${event.epochMs ?? "--"}`,
    `Format: ${event.format}`,
    `Category: ${event.category ?? classifyTimelineContext(event.context, event.source)}`,
    `Raw: ${event.raw}`,
    `Line: ${event.line}`,
    `Source: ${event.source}`,
    `Check: ${event.risk?.join(", ") || "--"}`,
    "",
    event.context
  ].join("\n");
}

export function timelineReportText(events: TimelineEvent[], findings: Array<{ level: string; title: string; detail: string }>, rows: Array<[string, string]>, sessions: Array<{ start: string; end: string; events: number; duration: string; sources: string; categories: string; risks: string; firstContext: string; lastContext: string }> = []) {
  const lines = [
    "# Timeline Analysis",
    "",
    "## Summary",
    ...rows.map(([key, value]) => `- ${key}: ${limitReportText(value, 800)}`),
    "",
    "## Findings",
    ...findings.map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 1200)}`),
    "",
    "## Activity Sessions",
    ...(sessions.length
      ? sessions.slice(0, 80).map((session) => `- ${session.start} -> ${session.end} | ${session.events} event(s) | ${session.duration} | ${session.categories}${session.risks !== "--" ? ` | review=${session.risks}` : ""}`)
      : ["- --"]),
    "",
    "## Events",
    ...(events.length
      ? events.slice(0, 200).map((event) => `- ${event.iso} | ${event.format} | ${event.category ?? classifyTimelineContext(event.context, event.source)} | line ${event.line} | ${limitReportText(event.context, 1200)}`)
      : ["- --"])
  ];
  return limitReportText(lines.join("\n"), 30000);
}

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

export type EvtxEvent = {
  id: string;
  source: string;
  recordId: string;
  timestamp: string;
  provider: string;
  providerGuid: string;
  eventId: number | null;
  level: number | null;
  levelName: string;
  channel: string;
  computer: string;
  processId: string;
  threadId: string;
  userId: string;
  task: string;
  opcode: string;
  keywords: string;
  data: Record<string, string>;
  message: string;
  xml: string;
};

export type EvtxFileAnalysis = {
  source: string;
  size: number;
  chunkCount: number;
  nextRecordNumber: string;
  dirty: boolean;
  full: boolean;
  version: string;
  parsedRecords: number;
  skippedRecords: number;
  truncated: boolean;
  events: EvtxEvent[];
};

const MAX_PERSISTED_EVTX_SNAPSHOT_BYTES = 8 * 1024 * 1024;

export function persistableEvtxResults(results: Array<EvtxFileAnalysis | { source: string; size: number; error: string }>) {
  const estimatedBytes = results.reduce((total, file) => {
    if (!("events" in file)) return total + file.source.length + file.error.length + 64;
    return total + file.source.length + file.events.reduce((eventTotal, event) => eventTotal
      + event.xml.length + event.message.length + event.provider.length + event.channel.length
      + Object.entries(event.data).reduce((dataTotal, [key, value]) => dataTotal + key.length + value.length, 0), 0);
  }, 0);
  if (estimatedBytes <= MAX_PERSISTED_EVTX_SNAPSHOT_BYTES) return results;
  return results.map((file) => "events" in file
    ? { ...file, events: file.events.map((event) => ({ ...event, xml: "" })) }
    : file);
}

const LEVEL_NAMES: Record<number, string> = {
  0: "LogAlways",
  1: "Critical",
  2: "Error",
  3: "Warning",
  4: "Information",
  5: "Verbose"
};

function decodeXml(value: string) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, raw: string) => String.fromCodePoint(Number.parseInt(raw, 16)))
    .replace(/&#(\d+);/g, (_, raw: string) => String.fromCodePoint(Number.parseInt(raw, 10)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function tagText(xml: string, tag: string) {
  const match = xml.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match ? decodeXml(match[1].replace(/<[^>]+>/g, "").trim()) : "";
}

function attribute(xml: string, element: string, name: string) {
  const match = xml.match(new RegExp(`<${element}\\b[^>]*\\b${name}=(?:"([^"]*)"|'([^']*)')`, "i"));
  return decodeXml(match?.[1] ?? match?.[2] ?? "");
}

function parseData(xml: string) {
  const result: Record<string, string> = {};
  const eventData = xml.match(/<EventData\b[^>]*>([\s\S]*?)<\/EventData>/i)?.[1] ?? "";
  let index = 0;
  for (const match of eventData.matchAll(/<Data\b([^>]*)>([\s\S]*?)<\/Data>|<Data\b([^>]*)\/>/gi)) {
    const attrs = match[1] ?? match[3] ?? "";
    const name = attrs.match(/\bName=(?:"([^"]*)"|'([^']*)')/i)?.slice(1).find(Boolean);
    const key = decodeXml(name ?? `Data_${index + 1}`);
    result[key] = decodeXml((match[2] ?? "").replace(/<[^>]+>/g, "").trim());
    index += 1;
  }
  if (Object.keys(result).length) return result;

  const userData = xml.match(/<UserData\b[^>]*>([\s\S]*?)<\/UserData>/i)?.[1] ?? "";
  for (const match of userData.matchAll(/<([A-Za-z_][\w:.-]*)\b[^>]*>([^<>]*)<\/\1>/g)) {
    const key = match[1].split(":").pop() ?? match[1];
    result[key] = decodeXml(match[2].trim());
  }
  return result;
}

export function eventFromXml(xml: string, source: string, fallbackRecordId = "", fallbackTimestamp = ""): EvtxEvent {
  const eventIdText = tagText(xml, "EventID");
  const levelText = tagText(xml, "Level");
  const eventId = /^\d+$/.test(eventIdText) ? Number(eventIdText) : null;
  const level = /^\d+$/.test(levelText) ? Number(levelText) : null;
  const data = parseData(xml);
  const message = Object.entries(data).slice(0, 8).map(([key, value]) => `${key}=${value}`).join(" | ");
  const recordId = tagText(xml, "EventRecordID") || fallbackRecordId;
  return {
    id: `${source}:${recordId || fallbackTimestamp}`,
    source,
    recordId,
    timestamp: attribute(xml, "TimeCreated", "SystemTime") || fallbackTimestamp,
    provider: attribute(xml, "Provider", "Name"),
    providerGuid: attribute(xml, "Provider", "Guid"),
    eventId,
    level,
    levelName: level == null ? "Unknown" : LEVEL_NAMES[level] ?? `Unknown(${level})`,
    channel: tagText(xml, "Channel"),
    computer: tagText(xml, "Computer"),
    processId: attribute(xml, "Execution", "ProcessID"),
    threadId: attribute(xml, "Execution", "ThreadID"),
    userId: attribute(xml, "Security", "UserID"),
    task: tagText(xml, "Task"),
    opcode: tagText(xml, "Opcode"),
    keywords: tagText(xml, "Keywords"),
    data,
    message,
    xml
  };
}

export function evtxEventsToCsv(events: EvtxEvent[]) {
  const escape = (value: unknown) => {
    const text = String(value ?? "");
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const rows: unknown[][] = [
    ["timestamp", "source", "record_id", "provider", "event_id", "level", "channel", "computer", "user_id", "process_id", "message", "event_data"],
    ...events.map((event) => [event.timestamp, event.source, event.recordId, event.provider, event.eventId ?? "", event.levelName, event.channel, event.computer, event.userId, event.processId, event.message, JSON.stringify(event.data)])
  ];
  return rows.map((row) => row.map(escape).join(",")).join("\n");
}

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

import type {
  IocRecord,
  PcapConversation,
  PcapDnsItem,
  PcapExtractedFile,
  PcapHttpItem,
  PcapPacket,
  PcapTimelineBucket,
  PcapTimelineEvent
} from "../../models";
import { formatBytes } from "../../utils/files";

export function pcapShortTime(timestamp: string) {
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) return timestamp;
  return new Date(parsed).toISOString().split("T")[1]?.replace("Z", "") ?? timestamp;
}

export function buildPcapTimeline(packets: PcapPacket[]): PcapTimelineBucket[] {
  const parsed = packets
    .map((packet) => ({ packet, ms: Date.parse(packet.timestamp) }))
    .filter((item) => Number.isFinite(item.ms));
  if (!parsed.length) return [];
  const first = parsed[0].ms;
  const last = parsed[parsed.length - 1].ms;
  const duration = Math.max(1, last - first);
  const targetBuckets = Math.min(48, Math.max(8, Math.ceil(Math.sqrt(parsed.length))));
  const bucketSize = Math.max(1, Math.ceil(duration / targetBuckets));
  const buckets = new Map<number, { packets: number; bytes: number; protocols: Map<string, number>; start: number; end: number }>();
  for (const { packet, ms } of parsed) {
    const index = Math.min(targetBuckets - 1, Math.max(0, Math.floor((ms - first) / bucketSize)));
    const current = buckets.get(index) ?? { packets: 0, bytes: 0, protocols: new Map<string, number>(), start: first + index * bucketSize, end: Math.min(last, first + (index + 1) * bucketSize) };
    current.packets += 1;
    current.bytes += packet.captured;
    current.protocols.set(packet.protocol, (current.protocols.get(packet.protocol) ?? 0) + 1);
    buckets.set(index, current);
  }
  return Array.from({ length: targetBuckets }, (_, index) => {
    const current = buckets.get(index) ?? { packets: 0, bytes: 0, protocols: new Map<string, number>(), start: first + index * bucketSize, end: Math.min(last, first + (index + 1) * bucketSize) };
    const protocols = Array.from(current.protocols.entries()).sort((a, b) => b[1] - a[1]);
    return {
      index,
      label: pcapShortTime(new Date(current.start).toISOString()),
      startTimestamp: new Date(current.start).toISOString(),
      endTimestamp: new Date(current.end).toISOString(),
      packets: current.packets,
      bytes: current.bytes,
      protocols,
      topProtocol: protocols[0]?.[0] ?? "--"
    };
  });
}

export function buildPcapTimelineEvents(
  packets: PcapPacket[],
  conversations: PcapConversation[],
  httpItems: PcapHttpItem[],
  dnsItems: PcapDnsItem[],
  extractedFiles: PcapExtractedFile[],
  iocs: IocRecord[],
  findings: Array<{ level: string; title: string; detail: string }>,
  timeline: PcapTimelineBucket[]
) {
  const events: PcapTimelineEvent[] = [];
  const firstTimestamp = packets[0]?.timestamp ?? "--";
  const packetMap = new Map(packets.map((packet) => [packet.no, packet]));
  const add = (event: PcapTimelineEvent) => {
    const key = `${event.timestamp}|${event.title}|${event.packetNo ?? ""}|${event.detail.slice(0, 160)}`;
    if (events.some((item) => `${item.timestamp}|${item.title}|${item.packetNo ?? ""}|${item.detail.slice(0, 160)}` === key)) return;
    events.push(event);
  };

  const nonEmpty = timeline.filter((bucket) => bucket.packets);
  const averageBytes = nonEmpty.length ? nonEmpty.reduce((sum, bucket) => sum + bucket.bytes, 0) / nonEmpty.length : 0;
  for (const bucket of nonEmpty.filter((item) => item.bytes > Math.max(64 * 1024, averageBytes * 2.5)).slice(0, 8)) {
    add({
      level: "warn",
      timestamp: bucket.startTimestamp,
      title: "Traffic burst",
      detail: `${formatBytes(bucket.bytes)} across ${bucket.packets} packet(s); top protocol ${bucket.topProtocol}.`
    });
  }

  for (const item of httpItems.filter((entry) => entry.risk.length).slice(0, 24)) {
    const packet = packetMap.get(item.packetNo);
    add({
      level: "warn",
      timestamp: item.timestamp,
      title: "HTTP worth review",
      detail: `${item.method} ${item.host}${item.path !== "--" ? item.path : ""}: ${item.risk.join(", ")}`,
      packetNo: item.packetNo,
      flow: packet?.flow
    });
  }

  for (const item of extractedFiles.slice(0, 20)) {
    add({
      level: "warn",
      timestamp: item.timestamp,
      title: "HTTP file candidate",
      detail: `${item.filename} / ${item.signature} / ${formatBytes(item.size)} / ${item.host}${item.path !== "--" ? item.path : ""}`,
      packetNo: item.packetNo,
      flow: `${item.source} -> ${item.destination}`
    });
  }

  for (const item of dnsItems.filter((entry) => /(?:xn--|\.top$|\.xyz$|\.cc$|\.tk$|\.zip$)/i.test(entry.name)).slice(0, 16)) {
    add({
      level: "warn",
      timestamp: item.timestamp,
      title: "Suspicious DNS name",
      detail: `${item.type} ${item.name}`,
      packetNo: item.packetNo,
      flow: `${item.source} -> ${item.destination}`
    });
  }

  for (const conversation of conversations.filter((item) => item.risk.length).slice(0, 20)) {
    add({
      level: conversation.risk.some((risk) => /sensitive|large|cleartext/i.test(risk)) ? "warn" : "info",
      timestamp: conversation.firstTimestamp,
      title: "Conversation worth review",
      detail: `${conversation.protocol} ${conversation.endpointA} <-> ${conversation.endpointB}; ${formatBytes(conversation.bytes)}; ${conversation.risk.join(", ")}`,
      flow: `${conversation.endpointA} <-> ${conversation.endpointB}`
    });
  }

  for (const item of iocs.filter((entry) => entry.risk.length).slice(0, 20)) {
    add({
      level: "warn",
      timestamp: firstTimestamp,
      title: "IOC worth review",
      detail: `${item.type} ${item.value}: ${item.risk.join(", ")}`
    });
  }

  for (const finding of findings.filter((item) => item.level === "danger").slice(0, 8)) {
    add({
      level: "warn",
      timestamp: firstTimestamp,
      title: finding.title,
      detail: finding.detail
    });
  }

  return events
    .sort((a, b) => {
      const left = Date.parse(a.timestamp);
      const right = Date.parse(b.timestamp);
      return (Number.isFinite(left) ? left : 0) - (Number.isFinite(right) ? right : 0);
    })
    .slice(0, 120);
}

export function pcapTimelineToCsv(items: PcapTimelineBucket[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["index", "start", "end", "packets", "bytes", "top_protocol", "protocols"].join(","),
    ...items.map((item) => [item.index, item.startTimestamp, item.endTimestamp, item.packets, item.bytes, item.topProtocol, item.protocols.map(([name, count]) => `${name}:${count}`).join("; ")].map(escape).join(","))
  ].join("\n");
}

export function pcapEventsToCsv(items: PcapTimelineEvent[]) {
  const escape = (value: string | number | undefined) => {
    const text = String(value ?? "");
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["level", "timestamp", "title", "detail", "packet_no", "flow"].join(","),
    ...items.map((item) => [item.level, item.timestamp, item.title, item.detail, item.packetNo, item.flow].map(escape).join(","))
  ].join("\n");
}

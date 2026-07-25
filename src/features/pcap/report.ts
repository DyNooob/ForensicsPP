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
  PcapEndpointStat,
  PcapEvidenceMatrixRow,
  PcapExtractedFile,
  PcapHttpItem,
  PcapInfo,
  PcapPacket,
  PcapPortStat,
  PcapSummary,
  PcapTimelineBucket,
  PcapTimelineEvent
} from "../../models";
import { formatBytes, limitReportText } from "../../utils/files";
import { isPrivateHost } from "../../utils/forensics";
import {
  pcapConversationHostSet,
  pcapConversationPacketMatch,
  pcapHostOnly,
  pcapTrafficShare
} from "./conversations";

export function buildPcapFindings(packets: PcapPacket[], conversations: PcapConversation[], httpItems: PcapHttpItem[], dnsItems: PcapDnsItem[], extractedFiles: PcapExtractedFile[], iocs: IocRecord[], format: string, endpoints: PcapEndpointStat[] = [], portStats: PcapPortStat[] = []) {
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (!packets.length) findings.push({ level: "warn", title: "No packets parsed", detail: `${format} header was recognized, but no packet records were decoded.` });
  const cleartextHttp = httpItems.filter((item) => item.host !== "--");
  if (cleartextHttp.length) findings.push({ level: "warn", title: "Cleartext HTTP traffic", detail: `${cleartextHttp.length} HTTP request/response candidates found.` });
  const riskyHttp = httpItems.filter((item) => item.risk.some((risk) => /auth|cookie|sensitive|traversal|double|punycode|IP host|HTTP [45]/i.test(risk)));
  if (riskyHttp.length) findings.push({ level: "warn", title: "HTTP payloads worth review", detail: riskyHttp.slice(0, 8).map((item) => `#${item.packetNo} ${item.host}${item.path !== "--" ? item.path : ""}: ${item.risk.join(", ")}`).join(" / ") });
  const suspiciousDns = dnsItems.filter((item) => /(?:xn--|\.top$|\.xyz$|\.cc$|\.tk$|\.zip$)/i.test(item.name));
  if (suspiciousDns.length) findings.push({ level: "warn", title: "DNS naming needs review", detail: suspiciousDns.slice(0, 6).map((item) => item.name).join(", ") });
  if (extractedFiles.length) findings.push({ level: "warn", title: "HTTP file candidates extracted", detail: extractedFiles.slice(0, 8).map((item) => `#${item.packetNo} ${item.filename} ${item.signature} ${formatBytes(item.size)}`).join(" / ") });
  const riskyFiles = extractedFiles.filter((item) => item.risk.length);
  if (riskyFiles.length) findings.push({ level: "warn", title: "HTTP downloads worth review", detail: riskyFiles.slice(0, 8).map((item) => `${item.filename}: ${item.risk.join(", ")}`).join(" / ") });
  if (iocs.length) findings.push({ level: "info", title: "Network IOC summary", detail: `${iocs.length} IOC-like value(s) extracted from HTTP, DNS, and endpoints.` });
  const resets = packets.filter((packet) => /\bRST\b/.test(packet.info)).length;
  if (resets > 10) findings.push({ level: "warn", title: "Many TCP resets", detail: `${resets} packets include RST.` });
  const sensitiveConversations = conversations.filter((conversation) => conversation.risk.some((risk) => /sensitive service|cleartext web|large byte/i.test(risk)));
  if (sensitiveConversations.length) findings.push({ level: "warn", title: "Conversations worth review", detail: sensitiveConversations.slice(0, 8).map((item) => `${item.endpointA} <-> ${item.endpointB}: ${item.risk.join(", ")}`).join(" / ") });
  const topConversation = conversations[0];
  if (topConversation && topConversation.bytes > Math.max(1024 * 1024, packets.reduce((sum, packet) => sum + packet.captured, 0) * 0.4)) {
    findings.push({ level: "info", title: "Dominant traffic flow", detail: `${topConversation.endpointA} <-> ${topConversation.endpointB}, ${formatBytes(topConversation.bytes)}.` });
  }
  const topEndpoint = endpoints[0];
  if (topEndpoint) findings.push({ level: "info", title: "Top traffic endpoint", detail: `${topEndpoint.endpoint}: sent ${formatBytes(topEndpoint.bytesSent)}, received ${formatBytes(topEndpoint.bytesReceived)}, packets ${topEndpoint.packetsSent + topEndpoint.packetsReceived}.` });
  const riskyEndpoints = endpoints.filter((endpoint) => endpoint.risk.length);
  if (riskyEndpoints.length) findings.push({ level: "warn", title: "Endpoints worth review", detail: riskyEndpoints.slice(0, 8).map((endpoint) => `${endpoint.endpoint}: ${endpoint.risk.join(", ")}`).join(" / ") });
  const riskyPorts = portStats.filter((item) => item.risk.length);
  if (riskyPorts.length) findings.push({ level: "warn", title: "Services worth review", detail: riskyPorts.slice(0, 8).map((item) => `${item.protocol}/${item.port}: ${item.risk.join(", ")}`).join(" / ") });
  return findings;
}

export function pcapBriefing(info: {
  name: string;
  size: number;
  format: string;
  sha256: string;
  summary: PcapSummary;
  conversations: PcapConversation[];
  endpoints: PcapEndpointStat[];
  portStats: PcapPortStat[];
  httpItems: PcapHttpItem[];
  dnsItems: PcapDnsItem[];
  extractedFiles: PcapExtractedFile[];
  iocs: IocRecord[];
  findings: Array<{ level: string; title: string; detail: string }>;
  timeline: PcapTimelineBucket[];
  events: PcapTimelineEvent[];
}) {
  const topBucket = info.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0];
  const topFlow = info.conversations[0];
  const topEndpoint = info.endpoints[0];
  return [
    "# PCAP Traffic Summary",
    "",
    `File: ${info.name} (${formatBytes(info.size)})`,
    `Format: ${info.format}`,
    ...(info.sha256 ? [`SHA256: ${info.sha256}`] : []),
    `Packets: ${info.summary.packetCount}`,
    `Captured bytes: ${formatBytes(info.summary.totalCaptured)}`,
    `Time range: ${info.summary.firstTimestamp} -> ${info.summary.lastTimestamp}`,
    "",
    "## First Look",
    `Notes: ${info.findings.filter((item) => item.level === "danger" || item.level === "warn").length}`,
    `Top flow: ${topFlow ? `${topFlow.protocol} ${topFlow.endpointA} <-> ${topFlow.endpointB}, ${formatBytes(topFlow.bytes)}` : "--"}`,
    `Top endpoint: ${topEndpoint ? `${topEndpoint.endpoint}, ${formatBytes(topEndpoint.bytesSent + topEndpoint.bytesReceived)}` : "--"}`,
    `Peak bucket: ${topBucket ? `${topBucket.label}, ${formatBytes(topBucket.bytes)}, ${topBucket.packets} packet(s), ${topBucket.topProtocol}` : "--"}`,
    `HTTP / DNS / files / IOC: ${info.httpItems.length} / ${info.dnsItems.length} / ${info.extractedFiles.length} / ${info.iocs.length}`,
    "",
    "## Priority events",
    ...(info.events.length ? info.events.slice(0, 20).map((event, index) => `${index + 1}. [${event.level}] ${event.timestamp} ${event.title}${event.packetNo ? ` #${event.packetNo}` : ""}\n   ${limitReportText(event.detail, 700)}`) : ["- none"]),
    "",
    "## Findings",
    ...(info.findings.length ? info.findings.map((finding) => `- [${finding.level}] ${finding.title}: ${limitReportText(finding.detail, 700)}`) : ["- none"])
  ].join("\n");
}

export function pcapReportText(pcap: PcapInfo) {
  return [
    "# PCAP Traffic Summary",
    "",
    `Name: ${pcap.name}`,
    `Size: ${formatBytes(pcap.size)}`,
    `Format: ${pcap.format}`,
    ...(pcap.sha256 ? [`SHA256: ${pcap.sha256}`] : []),
    "",
    "## Summary",
    `- Packets: ${pcap.summary?.packetCount ?? 0}`,
    `- Captured bytes: ${pcap.summary ? formatBytes(pcap.summary.totalCaptured) : "--"}`,
    `- First: ${pcap.summary?.firstTimestamp ?? "--"}`,
    `- Last: ${pcap.summary?.lastTimestamp ?? "--"}`,
    `- Protocols: ${pcap.summary?.protocols.map(([name, count]) => `${name}: ${count}`).join(", ") || "--"}`,
    "",
    "## Findings",
    ...(pcap.findings.length ? pcap.findings.map((finding) => `- [${finding.level}] ${finding.title}: ${limitReportText(finding.detail, 1000)}`) : ["- none"]),
    "",
    "## Traffic Details",
    ...(pcap.evidenceMatrix.length ? pcap.evidenceMatrix.map((row) => `- [${row.level}] ${row.area}: ${row.verdict}; ${row.metric}\n  Evidence: ${limitReportText(row.evidence, 900)}\n  Action: ${row.action}`) : ["- none"]),
    "",
    "## Timeline Peaks",
    ...(pcap.timeline.length ? pcap.timeline.slice().sort((a, b) => b.bytes - a.bytes).slice(0, 12).map((item) => `- ${item.startTimestamp} -> ${item.endTimestamp}: ${formatBytes(item.bytes)}, packets=${item.packets}, top=${item.topProtocol}`) : ["- none"]),
    "",
    "## Priority Events",
    ...(pcap.events.length ? pcap.events.slice(0, 40).map((item) => `- [${item.level}] ${item.timestamp}${item.packetNo ? ` #${item.packetNo}` : ""} ${item.title}: ${limitReportText(item.detail, 800)}`) : ["- none"]),
    "",
    "## Top Conversations",
    ...(pcap.conversations.length ? pcap.conversations.slice(0, 50).map((item) => `- ${item.protocol} ${item.endpointA} <-> ${item.endpointB} packets=${item.packets} bytes=${formatBytes(item.bytes)}${item.risk.length ? ` notes=${item.risk.join(", ")}` : ""}`) : ["- none"]),
    "",
    "## Top Endpoints",
    ...(pcap.endpoints.length ? pcap.endpoints.slice(0, 40).map((item) => `- ${item.endpoint} sent=${formatBytes(item.bytesSent)} received=${formatBytes(item.bytesReceived)} packets=${item.packetsSent + item.packetsReceived}${item.risk.length ? ` notes=${item.risk.join(", ")}` : ""}`) : ["- none"]),
    "",
    "## Top Services",
    ...(pcap.portStats.length ? pcap.portStats.slice(0, 40).map((item) => `- ${item.protocol}/${item.port} packets=${item.packets} bytes=${formatBytes(item.bytes)} endpoints=${item.endpoints.slice(0, 8).join(", ")}${item.risk.length ? ` notes=${item.risk.join(", ")}` : ""}`) : ["- none"]),
    "",
    "## HTTP Extracted Files",
    ...(pcap.extractedFiles.length ? pcap.extractedFiles.map((item) => `- #${item.packetNo} ${item.filename} ${item.signature} ${formatBytes(item.size)}${item.sha256 ? ` sha256=${item.sha256}` : ""}${item.risk.length ? ` notes=${item.risk.join(", ")}` : ""}`) : ["- none"]),
    "",
    "## IOC Preview",
    ...(pcap.iocs.length ? pcap.iocs.slice(0, 100).map((item) => `- ${item.type}: ${item.value}${item.risk.length ? ` (${item.risk.join(", ")})` : ""}`) : ["- none"])
  ].join("\n");
}

export function pcapPacketsToCsv(packets: PcapPacket[]) {
  const escape = (value: string | number | null) => {
    const text = String(value ?? "");
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["no", "timestamp", "delta_ms", "captured", "original", "protocol", "source", "source_port", "destination", "destination_port", "flow", "info"].join(","),
    ...packets.map((packet) => [
      packet.no,
      packet.timestamp,
      packet.deltaMs,
      packet.captured,
      packet.original,
      packet.protocol,
      packet.source,
      packet.sourcePort,
      packet.destination,
      packet.destinationPort,
      packet.flow,
      packet.info
    ].map(escape).join(","))
  ].join("\n");
}

export function pcapExtractedFilesToCsv(items: PcapExtractedFile[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  const includeHashes = items.some((item) => Boolean(item.sha256 && item.sha256 !== "--"));
  return [
    ["packet_no", "timestamp", "source", "destination", "host", "path", "filename", "content_type", "size", ...(includeHashes ? ["sha256"] : []), "signature", "risk", "preview"].join(","),
    ...items.map((item) => [item.packetNo, item.timestamp, item.source, item.destination, item.host, item.path, item.filename, item.contentType, item.size, ...(includeHashes ? [item.sha256] : []), item.signature, item.risk.join("; "), item.preview.slice(0, 1000)].map(escape).join(","))
  ].join("\n");
}

export function pcapConversationsToCsv(conversations: PcapConversation[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["protocol", "endpoint_a", "endpoint_b", "packets", "bytes", "first_timestamp", "last_timestamp", "risk"].join(","),
    ...conversations.map((item) => [item.protocol, item.endpointA, item.endpointB, item.packets, item.bytes, item.firstTimestamp, item.lastTimestamp, item.risk.join("; ")].map(escape).join(","))
  ].join("\n");
}

export function pcapEndpointsToCsv(endpoints: PcapEndpointStat[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["endpoint", "packets_sent", "packets_received", "bytes_sent", "bytes_received", "total_bytes", "protocols", "ports", "first_timestamp", "last_timestamp", "risk"].join(","),
    ...endpoints.map((item) => [
      item.endpoint,
      item.packetsSent,
      item.packetsReceived,
      item.bytesSent,
      item.bytesReceived,
      item.bytesSent + item.bytesReceived,
      item.protocols.join("; "),
      item.ports.join("; "),
      item.firstTimestamp,
      item.lastTimestamp,
      item.risk.join("; ")
    ].map(escape).join(","))
  ].join("\n");
}

export function pcapPortsToCsv(ports: PcapPortStat[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["protocol", "port", "packets", "bytes", "endpoints", "risk"].join(","),
    ...ports.map((item) => [item.protocol, item.port, item.packets, item.bytes, item.endpoints.join("; "), item.risk.join("; ")].map(escape).join(","))
  ].join("\n");
}

export function pcapHttpToCsv(items: PcapHttpItem[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  const includeHashes = items.some((item) => Boolean(item.bodySha256 && item.bodySha256 !== "--"));
  return [
    ["packet_no", "timestamp", "source", "destination", "method", "host", "path", "line", "user_agent", "content_type", "body_size", ...(includeHashes ? ["body_sha256"] : []), "risk"].join(","),
    ...items.map((item) => [item.packetNo, item.timestamp, item.source, item.destination, item.method, item.host, item.path, item.line, item.userAgent, item.contentType, item.bodySize, ...(includeHashes ? [item.bodySha256] : []), item.risk.join("; ")].map(escape).join(","))
  ].join("\n");
}

export function pcapDnsToCsv(items: PcapDnsItem[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["packet_no", "timestamp", "source", "destination", "name", "type"].join(","),
    ...items.map((item) => [item.packetNo, item.timestamp, item.source, item.destination, item.name, item.type].map(escape).join(","))
  ].join("\n");
}

export function pcapEvidenceMatrixRows(info: {
  summary: PcapSummary | null;
  packets: PcapPacket[];
  conversations: PcapConversation[];
  endpoints: PcapEndpointStat[];
  portStats: PcapPortStat[];
  httpItems: PcapHttpItem[];
  dnsItems: PcapDnsItem[];
  extractedFiles: PcapExtractedFile[];
  iocs: IocRecord[];
  timeline: PcapTimelineBucket[];
  events: PcapTimelineEvent[];
  findings: Array<{ level: string; title: string; detail: string }>;
}) {
  const totalBytes = info.summary?.totalCaptured ?? info.packets.reduce((sum, packet) => sum + packet.captured, 0);
  const dangerFindings = info.findings.filter((finding) => finding.level === "danger").length;
  const topConversation = info.conversations[0];
  const topEndpoint = info.endpoints[0];
  const topService = info.portStats[0];
  const riskyServices = info.portStats.filter((service) => service.risk.length);
  const cleartextServices = info.portStats.filter((service) => [21, 23, 25, 80, 110, 143].includes(service.port));
  const riskyHttp = info.httpItems.filter((item) => item.risk.length);
  const uniqueDns = new Set(info.dnsItems.map((item) => item.name.toLowerCase())).size;
  const suspiciousDns = info.dnsItems.filter((item) => /xn--|\.top$|\.xyz$|\.cc$|\.tk$|\.zip$|\.mov$|\.click$|\.work$/i.test(item.name));
  const riskyFiles = info.extractedFiles.filter((item) => item.risk.length);
  const totalFileBytes = info.extractedFiles.reduce((sum, item) => sum + item.size, 0);
  const riskyIocs = info.iocs.filter((item) => item.risk.length);
  const peak = info.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0];
  const dangerEvents = info.events.filter((event) => event.level === "danger").length;
  const warnEvents = info.events.filter((event) => event.level === "warn").length;
  const rows: PcapEvidenceMatrixRow[] = [];

  rows.push({
    area: "Capture Scope",
    verdict: info.packets.length ? "可分析" : "无可解析包",
    level: info.packets.length ? dangerFindings ? "warn" : "info" : "danger",
    metric: `${info.packets.length} packets / ${formatBytes(totalBytes)}`,
    evidence: info.summary ? `${info.summary.firstTimestamp} -> ${info.summary.lastTimestamp}; ${info.summary.protocols.map(([name, count]) => `${name}:${count}`).join(" / ") || "no protocol summary"}` : "No packet summary was produced.",
    action: info.packets.length ? "先记录文件名、大小和格式，再从高流量、异常项和明文服务开始检查。" : "确认文件格式、链路类型和截获完整性。"
  });

  rows.push({
    area: "Top Conversation",
    verdict: topConversation ? `${pcapTrafficShare(topConversation.bytes, totalBytes)} of bytes` : "无会话",
    level: topConversation?.risk.length || (topConversation && totalBytes && topConversation.bytes / totalBytes > 0.55) ? "warn" : "info",
    metric: topConversation ? `${formatBytes(topConversation.bytes)} / ${topConversation.packets} packets` : "--",
    evidence: topConversation ? `${topConversation.protocol} ${topConversation.endpointA} <-> ${topConversation.endpointB}${topConversation.risk.length ? `; ${topConversation.risk.join(" / ")}` : ""}` : "No bidirectional conversation decoded.",
    action: topConversation ? "点击 Top Conversation 相关包，交叉查看 HTTP/DNS/文件和 IOC。" : "检查链路类型是否已支持。"
  });

  rows.push({
    area: "Top Endpoint",
    verdict: topEndpoint ? `${pcapTrafficShare(topEndpoint.bytesSent + topEndpoint.bytesReceived, totalBytes)} of bytes` : "无端点",
    level: topEndpoint?.risk.length || (topEndpoint && !isPrivateHost(pcapHostOnly(topEndpoint.endpoint)) && topEndpoint.bytesSent > topEndpoint.bytesReceived * 2) ? "warn" : "info",
    metric: topEndpoint ? `${formatBytes(topEndpoint.bytesSent)} sent / ${formatBytes(topEndpoint.bytesReceived)} received` : "--",
    evidence: topEndpoint ? `${topEndpoint.endpoint}; protocols=${topEndpoint.protocols.join(", ") || "--"}; ports=${topEndpoint.ports.slice(0, 8).join(", ") || "--"}${topEndpoint.risk.length ? `; ${topEndpoint.risk.join(" / ")}` : ""}` : "No endpoint stats.",
    action: topEndpoint ? "优先判断该端点是内网主机、外部服务器还是异常高上传目标。" : "检查解析范围。"
  });

  rows.push({
    area: "Services",
    verdict: riskyServices.length || cleartextServices.length ? "存在需检查服务" : "未见明显服务提示",
    level: riskyServices.length || cleartextServices.length ? "warn" : "info",
    metric: topService ? `${topService.protocol}/${topService.port} ${formatBytes(topService.bytes)}` : "--",
    evidence: [
      topService ? `Top ${topService.protocol}/${topService.port}, endpoints=${topService.endpoints.slice(0, 6).join(", ")}` : "No service stats",
      riskyServices.length ? `${riskyServices.length} service note(s)` : "",
      cleartextServices.length ? `${cleartextServices.length} cleartext service marker(s)` : ""
    ].filter(Boolean).join("; "),
    action: "优先检查明文、管理端口、文件传输和异常高流量服务。"
  });

  rows.push({
    area: "HTTP",
    verdict: info.httpItems.length ? `${info.httpItems.length} item(s)` : "未解析到 HTTP",
    level: riskyHttp.length ? "warn" : info.httpItems.length ? "info" : "info",
    metric: `${formatBytes(info.httpItems.reduce((sum, item) => sum + item.bodySize, 0))} body bytes`,
    evidence: info.httpItems.length ? `${riskyHttp.length} note(s); ${info.httpItems.slice(0, 4).map((item) => `${item.method} ${item.host}${item.path}`).join(" / ")}` : "No HTTP request/response candidates decoded from payloads.",
    action: info.httpItems.length ? "查看 Host、Path、User-Agent、Cookie/凭据、下载体和 HTTP 明文内容。" : "若预期有 Web 流量，检查非标准端口或 TLS 加密。"
  });

  rows.push({
    area: "DNS",
    verdict: info.dnsItems.length ? `${uniqueDns} unique name(s)` : "未解析到 DNS",
    level: suspiciousDns.length ? "warn" : "info",
    metric: `${info.dnsItems.length} DNS record(s)`,
    evidence: info.dnsItems.length ? `${suspiciousDns.length} special TLD/punycode marker(s); ${info.dnsItems.slice(0, 5).map((item) => item.name).join(" / ")}` : "No DNS messages decoded.",
    action: "把相关域名与 HTTP Host、IOC 表和时间线峰值互相印证。"
  });

  rows.push({
    area: "Extracted Files",
    verdict: info.extractedFiles.length ? `${info.extractedFiles.length} candidate(s)` : "未提取到文件候选",
    level: riskyFiles.length || info.extractedFiles.length ? "warn" : "info",
    metric: `${formatBytes(totalFileBytes)} total`,
    evidence: info.extractedFiles.length ? `${riskyFiles.length} note(s); ${info.extractedFiles.slice(0, 4).map((item) => `${item.filename} ${item.signature} ${formatBytes(item.size)}`).join(" / ")}` : "HTTP payload/file signature carving did not produce candidates.",
    action: info.extractedFiles.length ? "下载候选文件，单独计算哈希，并送 File ID / Archive / YARA / Image 工具继续检查。" : "继续从 HTTP body、流量峰值和包预览寻找载荷。"
  });

  rows.push({
    area: "IOC",
    verdict: info.iocs.length ? `${info.iocs.length} indicator(s)` : "未提取到 IOC",
    level: riskyIocs.length ? "warn" : info.iocs.length ? "info" : "info",
    metric: `${riskyIocs.length} note(s)`,
    evidence: info.iocs.length ? info.iocs.slice(0, 6).map((item) => `${item.type}:${item.normalized}`).join(" / ") : "No URL/domain/IP/email indicator emitted by quick extraction.",
    action: info.iocs.length ? "导出 IOC CSV，去重、defang，并把上下文回链到包号/会话/HTTP/DNS。" : "未提取到 IOC 只代表快速规则未命中，仍需结合会话、端点、HTTP/DNS 和时间线检查。"
  });

  rows.push({
    area: "Timeline",
    verdict: peak ? "已生成峰值窗口" : "无时间线",
    level: dangerEvents || warnEvents || (peak && totalBytes && peak.bytes / totalBytes > 0.45) ? "warn" : "info",
    metric: peak ? `${peak.label}: ${formatBytes(peak.bytes)} / ${peak.packets} packets` : "--",
    evidence: peak ? `${dangerEvents + warnEvents} event note(s); peak protocol=${peak.topProtocol}; ${peak.startTimestamp} -> ${peak.endTimestamp}` : "No timeline bucket generated.",
    action: "从峰值 bucket 和 priority events 定位相关包号，再回看会话、文件和 IOC。"
  });

  return rows;
}

export function pcapEvidenceMatrixToCsv(rows: PcapEvidenceMatrixRow[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["area", "verdict", "level", "metric", "evidence", "action"].join(","),
    ...rows.map((row) => [row.area, row.verdict, row.level, row.metric, row.evidence, row.action].map(escape).join(","))
  ].join("\n");
}

export function pcapWorkItemRows(pcap: PcapInfo) {
  const riskCount = (items: Array<{ risk?: string[] }>) => items.filter((item) => item.risk?.length).length;
  const dangerEvents = pcap.events.filter((event) => event.level === "danger").length;
  const warnEvents = pcap.events.filter((event) => event.level === "warn").length;
  return [
    {
      section: "Conversations",
      count: pcap.conversations.length,
      primary: pcap.conversations[0] ? `${pcap.conversations[0].protocol} ${pcap.conversations[0].endpointA} <-> ${pcap.conversations[0].endpointB}` : "--",
      volume: pcap.conversations[0] ? formatBytes(pcap.conversations[0].bytes) : "--",
      risk: riskCount(pcap.conversations),
      action: "Check top flows by bytes and local notes; pivot into related HTTP/DNS/files."
    },
    {
      section: "Endpoints",
      count: pcap.endpoints.length,
      primary: pcap.endpoints[0]?.endpoint ?? "--",
      volume: pcap.endpoints[0] ? formatBytes(pcap.endpoints[0].bytesSent + pcap.endpoints[0].bytesReceived) : "--",
      risk: riskCount(pcap.endpoints),
      action: "Identify highest traffic hosts and cleartext/private/public boundary markers."
    },
    {
      section: "Services",
      count: pcap.portStats.length,
      primary: pcap.portStats[0] ? `${pcap.portStats[0].protocol}/${pcap.portStats[0].port}` : "--",
      volume: pcap.portStats[0] ? formatBytes(pcap.portStats[0].bytes) : "--",
      risk: riskCount(pcap.portStats),
      action: "Prioritize cleartext, admin, file-transfer, and unusual high-volume service ports."
    },
    {
      section: "HTTP",
      count: pcap.httpItems.length,
      primary: pcap.httpItems[0] ? `${pcap.httpItems[0].method} ${pcap.httpItems[0].host}${pcap.httpItems[0].path}` : "--",
      volume: formatBytes(pcap.httpItems.reduce((sum, item) => sum + item.bodySize, 0)),
      risk: riskCount(pcap.httpItems),
      action: "Check hosts, paths, credentials/cookies, cleartext downloads, and HTTP errors."
    },
    {
      section: "DNS",
      count: pcap.dnsItems.length,
      primary: pcap.dnsItems[0]?.name ?? "--",
      volume: `${new Set(pcap.dnsItems.map((item) => item.name)).size} unique name(s)`,
      risk: pcap.dnsItems.filter((item) => /xn--|\.top$|\.xyz$|\.cc$|\.tk$|\.zip$/i.test(item.name)).length,
      action: "Pivot special TLD, punycode, rare names, and domains also seen in HTTP/IOC tables."
    },
    {
      section: "Files",
      count: pcap.extractedFiles.length,
      primary: pcap.extractedFiles[0]?.filename ?? "--",
      volume: formatBytes(pcap.extractedFiles.reduce((sum, item) => sum + item.size, 0)),
      risk: riskCount(pcap.extractedFiles),
      action: "Download candidates, hash-register, and send noted files to File ID/YARA/Image/Archive tools."
    },
    {
      section: "IOC",
      count: pcap.iocs.length,
      primary: pcap.iocs[0]?.normalized ?? "--",
      volume: `${pcap.iocs.filter((item) => item.risk.length).length} note(s)`,
      risk: pcap.iocs.filter((item) => item.risk.length).length,
      action: "Export IOC CSV and normalize/defang before adding to case notes."
    },
    {
      section: "Timeline",
      count: pcap.events.length,
      primary: pcap.timeline.slice().sort((a, b) => b.bytes - a.bytes)[0]?.label ?? "--",
      volume: `${dangerEvents + warnEvents} event note(s)`,
      risk: dangerEvents + warnEvents,
      action: "Use peak buckets and priority events to locate burst windows and relevant packet numbers."
    }
  ];
}

export function pcapWorkItemsToCsv(pcap: PcapInfo) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["section", "count", "primary", "volume", "risk_count", "action"].join(","),
    ...pcapWorkItemRows(pcap).map((row) => [row.section, row.count, row.primary, row.volume, row.risk, row.action].map(escape).join(","))
  ].join("\n");
}

export function pcapExtractionManifestText(pcap: PcapInfo) {
  const rows = pcapWorkItemRows(pcap);
  return [
    "# PCAP Extraction Items",
    "",
    `Generated: ${new Date().toISOString()}`,
    `File: ${pcap.name}`,
    ...(pcap.sha256 ? [`SHA256: ${pcap.sha256}`] : []),
    "",
    "## Work Items",
    ...rows.map((row) => `- ${row.section}: count=${row.count}; primary=${row.primary}; volume=${row.volume}; notes=${row.risk}\n  Action: ${row.action}`),
    "",
    "## Top Conversations",
    ...(pcap.conversations.length ? pcap.conversations.slice(0, 20).map((item) => `- ${item.protocol} ${item.endpointA} <-> ${item.endpointB}; ${formatBytes(item.bytes)}; packets=${item.packets}; notes=${item.risk.join(", ") || "--"}`) : ["- --"]),
    "",
    "## Extracted File Candidates",
    ...(pcap.extractedFiles.length ? pcap.extractedFiles.map((item) => `- #${item.packetNo} ${item.filename}; ${item.signature}; ${formatBytes(item.size)}${item.sha256 ? `; sha256=${item.sha256}` : ""}; notes=${item.risk.join(", ") || "--"}`) : ["- --"]),
    "",
    "## Priority Events",
    ...(pcap.events.length ? pcap.events.slice(0, 40).map((event) => `- [${event.level}] ${event.timestamp}${event.packetNo ? ` #${event.packetNo}` : ""} ${event.title}: ${limitReportText(event.detail, 700)}`) : ["- --"])
  ].join("\n");
}

export function pcapWorkbenchBundle(pcap: PcapInfo) {
  return {
    generatedAt: new Date().toISOString(),
    evidence: {
      name: pcap.name,
      size: pcap.size,
      format: pcap.format,
      ...(pcap.sha256 ? { sha256: pcap.sha256 } : {}),
      signature: pcap.signature
    },
    summary: pcap.summary,
    trafficDetails: pcap.evidenceMatrix,
    extractionItems: pcapWorkItemRows(pcap),
    findings: pcap.findings,
    priorityEvents: pcap.events,
    topConversations: pcap.conversations.slice(0, 200),
    topEndpoints: pcap.endpoints.slice(0, 200),
    services: pcap.portStats.slice(0, 200),
    http: pcap.httpItems,
    dns: pcap.dnsItems,
    extractedFiles: pcap.extractedFiles.map(({ bytes, ...item }) => ({
      ...item,
      bytes: { size: bytes.length, ...(item.sha256 ? { sha256: item.sha256 } : {}) }
    })),
    iocs: pcap.iocs,
    summaryText: pcap.briefing,
    extractionManifest: pcapExtractionManifestText(pcap)
  };
}

export function pcapRelatedForConversation(pcap: PcapInfo, conversation: PcapConversation | null) {
  if (!conversation) return { packets: [] as PcapPacket[], http: [] as PcapHttpItem[], dns: [] as PcapDnsItem[], files: [] as PcapExtractedFile[], iocs: [] as IocRecord[] };
  const hosts = pcapConversationHostSet(conversation);
  const packets = pcap.packets.filter((packet) => pcapConversationPacketMatch(conversation, packet));
  const packetNos = new Set(packets.map((packet) => packet.no));
  const hostMatch = (value: string) => Array.from(hosts).some((host) => host && value.includes(host));
  return {
    packets,
    http: pcap.httpItems.filter((item) => packetNos.has(item.packetNo) || hostMatch(`${item.source} ${item.destination} ${item.host}`)).slice(0, 120),
    dns: pcap.dnsItems.filter((item) => packetNos.has(item.packetNo) || hostMatch(`${item.source} ${item.destination} ${item.name}`)).slice(0, 120),
    files: pcap.extractedFiles.filter((item) => packetNos.has(item.packetNo) || hostMatch(`${item.source} ${item.destination} ${item.host}`)).slice(0, 60),
    iocs: pcap.iocs.filter((item) => hostMatch(`${item.value} ${item.normalized} ${item.context}`)).slice(0, 80)
  };
}

export function pcapTriageCards(pcap: PcapInfo) {
  const danger = pcap.findings.filter((finding) => finding.level === "danger").length;
  const warn = pcap.findings.filter((finding) => finding.level === "warn").length;
  const topFlow = pcap.conversations[0];
  const topEndpoint = pcap.endpoints[0];
  const cleartext = pcap.httpItems.length + pcap.portStats.filter((item) => [21, 23, 25, 80, 110, 143].includes(item.port)).length;
  return [
    {
      label: "Notes",
      value: `${danger + warn} item(s)`,
      level: danger ? "danger" : warn ? "warn" : "info",
      detail: pcap.findings.slice(0, 2).map((finding) => finding.title).join(" / ") || "No local note in parsed traffic."
    },
    {
      label: "Top flow",
      value: topFlow ? formatBytes(topFlow.bytes) : "--",
      level: topFlow?.risk.length ? "warn" : "info",
      detail: topFlow ? `${topFlow.protocol} ${topFlow.endpointA} <-> ${topFlow.endpointB}` : "No conversation decoded."
    },
    {
      label: "Top endpoint",
      value: topEndpoint ? formatBytes(topEndpoint.bytesSent + topEndpoint.bytesReceived) : "--",
      level: topEndpoint?.risk.length ? "warn" : "info",
      detail: topEndpoint ? `${topEndpoint.endpoint}; sent ${formatBytes(topEndpoint.bytesSent)}, received ${formatBytes(topEndpoint.bytesReceived)}` : "--"
    },
    {
      label: "Extracted",
      value: `${pcap.extractedFiles.length} files / ${pcap.iocs.length} IOC`,
      level: pcap.extractedFiles.some((item) => item.risk.length) || pcap.iocs.some((item) => item.risk.length) ? "warn" : pcap.extractedFiles.length || pcap.iocs.length ? "warn" : "info",
      detail: `${pcap.httpItems.length} HTTP item(s), ${pcap.dnsItems.length} DNS item(s), ${cleartext} cleartext/service signal(s).`
    }
  ];
}

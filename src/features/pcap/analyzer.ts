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

import { analyzeIocs } from "../ioc/analyzer";
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
  PcapTcpStream,
  PcapTcpStreamSegment,
  PcapTimelineBucket,
  PcapTimelineEvent
} from "../../models";
import { fileSignatureForBytes, hexPreview, previewText } from "../../utils/binary";
import { formatBytes, limitReportText } from "../../utils/files";
import { isPrivateHost } from "../../utils/forensics";
import { parseTlsFromTcpStreams } from "./tls";

export function parsePcap(bytes: Uint8Array, name: string, size: number, sha256: string): PcapInfo {
  const signature = hexPreview(bytes, 8);
  const first4 = hexPreview(bytes, 4);
  const pcapMagic = {
    "D4 C3 B2 A1": { format: "PCAP", littleEndian: true },
    "A1 B2 C3 D4": { format: "PCAP", littleEndian: false },
    "4D 3C B2 A1": { format: "PCAP nanosecond", littleEndian: true },
    "A1 B2 3C 4D": { format: "PCAP nanosecond", littleEndian: false },
    "0A 0D 0D 0A": { format: "PCAPNG", littleEndian: true }
  }[first4];

  if (!pcapMagic || bytes.length < 24) {
    return {
      name,
      size,
      signature,
      format: "Unknown",
      endian: "--",
      version: "--",
      snaplen: null,
      linkType: null,
      sha256,
      summary: null,
      packets: [],
      conversations: [],
      tcpStreams: [],
      endpoints: [],
      portStats: [],
      httpItems: [],
      dnsItems: [],
      tlsItems: [],
      extractedFiles: [],
      iocs: [],
      timeline: [],
      events: [],
      evidenceMatrix: [],
      briefing: "Unsupported or unrecognized packet capture.",
      findings: [{ level: "danger", title: "Unknown capture format", detail: signature }]
    };
  }

  const parsed = pcapMagic.format === "PCAPNG"
    ? parsePcapngPackets(bytes)
    : parseClassicPcapPackets(bytes, pcapMagic.littleEndian, pcapMagic.format.includes("nanosecond"));
  const summary = summarizeParsedPackets(parsed.packets);
  const tcpStreams = buildPcapTcpStreams(parsed.packets);
  const tlsItems = parseTlsFromTcpStreams(tcpStreams);
  const conversations = buildPcapConversations(parsed.packets);
  const streamHttp = parseHttpFromTcpStreams(tcpStreams);
  const streamPacketNumbers = new Set(streamHttp.items.map((item) => item.packetNo));
  const httpItems = [...streamHttp.items, ...parsed.httpItems.filter((item) => !streamPacketNumbers.has(item.packetNo))]
    .sort((left, right) => left.packetNo - right.packetNo);
  const endpoints = buildPcapEndpointStats(parsed.packets);
  const portStats = buildPcapPortStats(parsed.packets);
  const packetsByNumber = new Map(parsed.packets.map((packet) => [packet.no, packet]));
  const packetFiles = parsed.httpItems
    .map((item) => {
      const packet = packetsByNumber.get(item.packetNo);
      return packet ? buildPcapExtractedFile(item, packet.payloadBytes) : null;
    })
    .filter(Boolean) as PcapExtractedFile[];
  const streamFilePackets = new Set(streamHttp.files.map((item) => item.packetNo));
  const extractedFiles = [...streamHttp.files, ...packetFiles.filter((item) => !streamFilePackets.has(item.packetNo))];
  parsed.packets.forEach((packet) => {
    if (packet.payloadBytes.length > 2048) packet.payloadBytes = packet.payloadBytes.slice(0, 2048);
  });
  const iocs: PcapInfo["iocs"] = [];
  const findings: PcapInfo["findings"] = [];
  const evidenceMatrix: PcapInfo["evidenceMatrix"] = [];
  const briefing = "";
  const timeline = buildPcapTimeline(parsed.packets);
  const events = buildPcapTimelineEvents(parsed.packets, conversations, httpItems, parsed.dnsItems, extractedFiles, iocs, findings, timeline);

  if (pcapMagic.format === "PCAPNG") {
    return {
      name,
      size,
      signature,
      format: pcapMagic.format,
      endian: "section-defined",
      version: "--",
      snaplen: parsed.snaplen,
      linkType: parsed.linkType,
      sha256,
      summary,
      packets: parsed.packets,
      conversations,
      tcpStreams,
      endpoints,
      portStats,
      httpItems,
      dnsItems: parsed.dnsItems,
      tlsItems,
      extractedFiles,
      iocs,
      timeline,
      events,
      evidenceMatrix,
      briefing,
      findings
    };
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const little = pcapMagic.littleEndian;
  return {
    name,
    size,
    signature,
    format: pcapMagic.format,
    endian: little ? "little-endian" : "big-endian",
    version: `${view.getUint16(4, little)}.${view.getUint16(6, little)}`,
    snaplen: view.getUint32(16, little),
    linkType: view.getUint32(20, little),
    sha256,
    summary,
    packets: parsed.packets,
    conversations,
    tcpStreams,
    endpoints,
    portStats,
    httpItems,
    dnsItems: parsed.dnsItems,
    tlsItems,
    extractedFiles,
    iocs,
    timeline,
    events,
    evidenceMatrix,
    briefing,
    findings
  };
}

export function ipFromBytes(bytes: Uint8Array, offset: number) {
  if (offset + 4 > bytes.length) return "";
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

export function ipv6FromBytes(bytes: Uint8Array, offset: number) {
  if (offset + 16 > bytes.length) return "";
  const parts = Array.from({ length: 8 }, (_, index) => ((bytes[offset + index * 2] << 8) | bytes[offset + index * 2 + 1]).toString(16));
  return parts.join(":").replace(/(?:^|:)0(?::0)+(?::|$)/, "::");
}

export function tcpFlags(byte: number) {
  return [
    byte & 0x01 ? "FIN" : "",
    byte & 0x02 ? "SYN" : "",
    byte & 0x04 ? "RST" : "",
    byte & 0x08 ? "PSH" : "",
    byte & 0x10 ? "ACK" : "",
    byte & 0x20 ? "URG" : "",
    byte & 0x40 ? "ECE" : "",
    byte & 0x80 ? "CWR" : ""
  ].filter(Boolean).join(",");
}

export function parseDnsNameFromPayload(payload: Uint8Array, offset: number, depth = 0): { name: string; next: number } {
  if (depth > 8) return { name: "", next: offset };
  const labels: string[] = [];
  let cursor = offset;
  let next = offset;
  while (cursor < payload.length) {
    const length = payload[cursor];
    if (length === 0) {
      next = cursor + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | payload[cursor + 1];
      const pointed = parseDnsNameFromPayload(payload, pointer, depth + 1);
      if (pointed.name) labels.push(pointed.name);
      next = cursor + 2;
      break;
    }
    const start = cursor + 1;
    const end = start + length;
    if (end > payload.length) break;
    labels.push(new TextDecoder().decode(payload.slice(start, end)));
    cursor = end;
  }
  return { name: labels.join("."), next };
}

export function networkEndpoint(host: string, port: number | null) {
  if (port == null) return host;
  return host.includes(":") && !host.startsWith("[") ? `[${host}]:${port}` : `${host}:${port}`;
}

export function dnsTypeName(value: number) {
  return ({ 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS" } as Record<number, string>)[value] ?? String(value);
}

export function parseHttpPayload(payloadText: string) {
  const firstLine = payloadText.split(/\r?\n/)[0] ?? "";
  const request = firstLine.match(/^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP\/\d(?:\.\d)?/i);
  const response = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i);
  const header = (name: string) => payloadText.match(new RegExp(`\\n${name}:\\s*([^\\r\\n]+)`, "i"))?.[1]?.trim() ?? "--";
  const headerEnd = payloadText.search(/\r?\n\r?\n/);
  const bodyText = headerEnd >= 0 ? payloadText.slice(headerEnd).replace(/^\r?\n\r?\n/, "") : "";
  const host = header("Host");
  const method = request?.[1]?.toUpperCase() ?? (response ? "RESPONSE" : "--");
  const path = request?.[2] ?? "--";
  const userAgent = header("User-Agent");
  const contentType = header("Content-Type");
  const risk = [
    host !== "--" ? "cleartext HTTP" : "",
    /Authorization:\s*Basic\s+/i.test(payloadText) ? "Basic auth in cleartext" : "",
    /Cookie:\s*[^;\r\n]*(session|token|auth|sid|jwt)/i.test(payloadText) ? "session cookie in cleartext" : "",
    /password|passwd|pwd|token|secret|api[_-]?key/i.test(path) ? "sensitive parameter path" : "",
    /(?:\.\.\/|%2e%2e%2f|%252e%252e)/i.test(path) ? "path traversal marker" : "",
    /%25[0-9a-f]{2}/i.test(path) ? "double-encoded URL" : "",
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) ? "IP host" : "",
    /xn--/i.test(host) ? "punycode host" : "",
    /application\/(?:octet-stream|x-msdownload|zip|pdf)|image\/|audio\/|video\//i.test(contentType) ? "download-like content" : "",
    response && Number(response[1]) >= 400 ? `HTTP ${response[1]}` : ""
  ].filter(Boolean);
  return { firstLine, host, method, path, userAgent, contentType, bodyText, risk };
}

export function httpFilenameFromHeaders(payloadText: string, path: string, packetNo: number) {
  const disposition = payloadText.match(/\nContent-Disposition:\s*[^\r\n]*filename\*?=(?:"([^"]+)"|([^;\r\n]+))/i);
  const fromDisposition = disposition?.[1] ?? disposition?.[2];
  if (fromDisposition) return decodeURIComponent(fromDisposition.trim().replace(/^UTF-8''/i, ""));
  const cleanPath = path.split("?")[0].split("/").filter(Boolean).pop();
  return cleanPath && /\.[a-z0-9]{1,8}$/i.test(cleanPath) ? cleanPath : `http-packet-${packetNo}.bin`;
}

export function buildPcapExtractedFile(item: PcapHttpItem, payloadBytes: Uint8Array): PcapExtractedFile | null {
  const payloadText = new TextDecoder().decode(payloadBytes);
  const headerEndMatch = payloadText.match(/\r?\n\r?\n/);
  if (!headerEndMatch || headerEndMatch.index == null) return null;
  const bodyStart = new TextEncoder().encode(payloadText.slice(0, headerEndMatch.index + headerEndMatch[0].length)).length;
  const bodyBytes = payloadBytes.slice(bodyStart);
  return buildPcapExtractedFileFromBody(item, bodyBytes, payloadText);
}

export function buildPcapExtractedFileFromBody(item: PcapHttpItem, bodyBytes: Uint8Array, headerText: string): PcapExtractedFile | null {
  if (!bodyBytes.length || bodyBytes.length < 16) return null;
  const signature = fileSignatureForBytes(bodyBytes)?.label ?? "Binary";
  const looksLikeFile = signature !== "Binary" || /\nContent-Disposition:\s*attachment\b/i.test(headerText) || /application\/(?:octet-stream|x-msdownload|zip|pdf|json)|image\/|audio\/|video\//i.test(item.contentType) || /\.(?:zip|rar|7z|pdf|png|jpg|jpeg|gif|exe|dll|apk|jar|docx|xlsx|sqlite|db)$/i.test(item.path);
  if (!looksLikeFile) return null;
  return {
    packetNo: item.packetNo,
    timestamp: item.timestamp,
    source: item.source,
    destination: item.destination,
    host: item.host,
    path: item.path,
    contentType: item.contentType,
    filename: httpFilenameFromHeaders(headerText, item.path, item.packetNo),
    size: bodyBytes.length,
    sha256: "",
    signature,
    preview: previewText(bodyBytes, 2048),
    risk: [
      /executable|PE|EXE|DLL/i.test(signature) ? "executable payload" : "",
      /application\/octet-stream|x-msdownload/i.test(item.contentType) ? "binary download" : "",
      /\.(?:exe|dll|scr|ps1|vbs|js|hta|bat|cmd)$/i.test(item.path) ? "risky extension path" : ""
    ].filter(Boolean),
    bytes: bodyBytes
  };
}

export function inspectFrame(frame: Uint8Array, packetNo: number, timestamp: string, deltaMs: number, captured: number, original: number, linkType: number | null) {
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  let networkOffset = 0;
  let etherType = 0;
  let protocol = "Frame";
  let source = "--";
  let destination = "--";
  let sourcePort: number | null = null;
  let destinationPort: number | null = null;
  let info = `${captured} bytes`;
  let payload = new Uint8Array();
  let http: PcapHttpItem | null = null;
  let dns: PcapDnsItem | null = null;
  let tcpMetadata: Pick<PcapPacket, "transportProtocol" | "tcpSequence" | "tcpAcknowledgment" | "tcpFlags" | "tcpPayloadSequence" | "tcpPayloadLength"> | undefined;

  if (linkType === 1 && frame.length >= 14) {
    etherType = view.getUint16(12, false);
    networkOffset = 14;
    if ((etherType === 0x8100 || etherType === 0x88a8) && frame.length >= 18) {
      etherType = view.getUint16(16, false);
      networkOffset = 18;
    }
  } else if (linkType === 101 || linkType == null) {
    etherType = (frame[0] >> 4) === 4 ? 0x0800 : (frame[0] >> 4) === 6 ? 0x86dd : 0;
    networkOffset = 0;
  } else {
    return { packet: makePcapPacket(packetNo, timestamp, deltaMs, captured, original, "LinkType-" + linkType, source, destination, sourcePort, destinationPort, "", info, frame), http, dns };
  }

  if (etherType === 0x0800 && networkOffset + 20 <= frame.length) {
    const ihl = (frame[networkOffset] & 0x0f) * 4;
    const ipProtocol = frame[networkOffset + 9];
    source = ipFromBytes(frame, networkOffset + 12);
    destination = ipFromBytes(frame, networkOffset + 16);
    const totalLength = view.getUint16(networkOffset + 2, false);
    const transportOffset = networkOffset + ihl;
    const packetEnd = Math.min(frame.length, networkOffset + totalLength);
    if (ipProtocol === 6 && transportOffset + 20 <= packetEnd) {
      protocol = "TCP";
      sourcePort = view.getUint16(transportOffset, false);
      destinationPort = view.getUint16(transportOffset + 2, false);
      const dataOffset = ((frame[transportOffset + 12] >> 4) & 0x0f) * 4;
      payload = frame.slice(transportOffset + dataOffset, packetEnd);
      const flags = tcpFlags(frame[transportOffset + 13]);
      const sequence = view.getUint32(transportOffset + 4, false);
      tcpMetadata = {
        transportProtocol: "TCP",
        tcpSequence: sequence,
        tcpAcknowledgment: view.getUint32(transportOffset + 8, false),
        tcpFlags: flags,
        tcpPayloadSequence: (sequence + ((frame[transportOffset + 13] & 0x02) ? 1 : 0)) >>> 0,
        tcpPayloadLength: payload.length
      };
      const payloadText = previewText(payload, 2048);
      const firstLine = payloadText.split(/\r?\n/)[0] ?? "";
      if (sourcePort === 80 || destinationPort === 80 || sourcePort === 8080 || destinationPort === 8080 || /^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|HTTP)\s/i.test(firstLine)) {
        protocol = "HTTP";
        const parsedHttp = parseHttpPayload(payloadText);
        const bodyBytes = new TextEncoder().encode(parsedHttp.bodyText);
        http = {
          packetNo,
          timestamp,
          source: `${source}:${sourcePort}`,
          destination: `${destination}:${destinationPort}`,
          host: parsedHttp.host,
          line: parsedHttp.firstLine || "--",
          method: parsedHttp.method,
          path: parsedHttp.path,
          userAgent: parsedHttp.userAgent,
          contentType: parsedHttp.contentType,
          bodySize: bodyBytes.length,
          bodyPreview: parsedHttp.bodyText.slice(0, 1000),
          bodySha256: "--",
          risk: parsedHttp.risk
        };
        info = parsedHttp.host === "--" ? parsedHttp.firstLine || flags : `${parsedHttp.firstLine || "HTTP"} Host=${parsedHttp.host}`;
      } else {
        info = `${sourcePort} -> ${destinationPort} ${flags}${payload.length ? ` Len=${payload.length}` : ""}`;
      }
    } else if (ipProtocol === 17 && transportOffset + 8 <= packetEnd) {
      protocol = "UDP";
      sourcePort = view.getUint16(transportOffset, false);
      destinationPort = view.getUint16(transportOffset + 2, false);
      payload = frame.slice(transportOffset + 8, packetEnd);
      if ((sourcePort === 53 || destinationPort === 53) && payload.length >= 16) {
        protocol = "DNS";
        const question = parseDnsNameFromPayload(payload, 12);
        const typeOffset = question.next;
        const type = typeOffset + 2 <= payload.length ? dnsTypeName(new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint16(typeOffset, false)) : "--";
        if (question.name) dns = { packetNo, timestamp, source: `${source}:${sourcePort}`, destination: `${destination}:${destinationPort}`, name: question.name, type };
        info = question.name ? `${type} ${question.name}` : `${sourcePort} -> ${destinationPort}`;
      } else {
        info = `${sourcePort} -> ${destinationPort} Len=${payload.length}`;
      }
    } else if (ipProtocol === 1) {
      protocol = "ICMP";
      payload = frame.slice(transportOffset, packetEnd);
      info = `Type=${payload[0] ?? "--"} Code=${payload[1] ?? "--"}`;
    } else {
      protocol = `IPv4-${ipProtocol}`;
      payload = frame.slice(transportOffset, packetEnd);
    }
  } else if (etherType === 0x86dd && networkOffset + 40 <= frame.length) {
    const nextHeader = frame[networkOffset + 6];
    source = ipv6FromBytes(frame, networkOffset + 8);
    destination = ipv6FromBytes(frame, networkOffset + 24);
    const payloadLength = view.getUint16(networkOffset + 4, false);
    const transportOffset = networkOffset + 40;
    const packetEnd = Math.min(frame.length, transportOffset + payloadLength);
    if (nextHeader === 6 && transportOffset + 20 <= packetEnd) {
      protocol = "TCPv6";
      sourcePort = view.getUint16(transportOffset, false);
      destinationPort = view.getUint16(transportOffset + 2, false);
      const dataOffset = ((frame[transportOffset + 12] >> 4) & 0x0f) * 4;
      payload = frame.slice(transportOffset + dataOffset, packetEnd);
      const flags = tcpFlags(frame[transportOffset + 13]);
      const sequence = view.getUint32(transportOffset + 4, false);
      tcpMetadata = {
        transportProtocol: "TCP",
        tcpSequence: sequence,
        tcpAcknowledgment: view.getUint32(transportOffset + 8, false),
        tcpFlags: flags,
        tcpPayloadSequence: (sequence + ((frame[transportOffset + 13] & 0x02) ? 1 : 0)) >>> 0,
        tcpPayloadLength: payload.length
      };
      const payloadText = previewText(payload, 2048);
      const firstLine = payloadText.split(/\r?\n/)[0] ?? "";
      if (sourcePort === 80 || destinationPort === 80 || sourcePort === 8080 || destinationPort === 8080 || /^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|HTTP)\s/i.test(firstLine)) {
        protocol = "HTTP";
        const parsedHttp = parseHttpPayload(payloadText);
        const bodyBytes = new TextEncoder().encode(parsedHttp.bodyText);
        http = {
          packetNo,
          timestamp,
          source: networkEndpoint(source, sourcePort),
          destination: networkEndpoint(destination, destinationPort),
          host: parsedHttp.host,
          line: parsedHttp.firstLine || "--",
          method: parsedHttp.method,
          path: parsedHttp.path,
          userAgent: parsedHttp.userAgent,
          contentType: parsedHttp.contentType,
          bodySize: bodyBytes.length,
          bodyPreview: parsedHttp.bodyText.slice(0, 1000),
          bodySha256: "--",
          risk: parsedHttp.risk
        };
        info = parsedHttp.host === "--" ? parsedHttp.firstLine || flags : `${parsedHttp.firstLine || "HTTP"} Host=${parsedHttp.host}`;
      } else {
        info = `${sourcePort} -> ${destinationPort} ${flags}${payload.length ? ` Len=${payload.length}` : ""}`;
      }
    } else if (nextHeader === 17 && transportOffset + 8 <= packetEnd) {
      protocol = "UDPv6";
      sourcePort = view.getUint16(transportOffset, false);
      destinationPort = view.getUint16(transportOffset + 2, false);
      payload = frame.slice(transportOffset + 8, packetEnd);
      if ((sourcePort === 53 || destinationPort === 53) && payload.length >= 16) {
        protocol = "DNS";
        const question = parseDnsNameFromPayload(payload, 12);
        const typeOffset = question.next;
        const type = typeOffset + 2 <= payload.length ? dnsTypeName(new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint16(typeOffset, false)) : "--";
        if (question.name) dns = { packetNo, timestamp, source: networkEndpoint(source, sourcePort), destination: networkEndpoint(destination, destinationPort), name: question.name, type };
        info = question.name ? `${type} ${question.name}` : `${sourcePort} -> ${destinationPort}`;
      } else {
        info = `${sourcePort} -> ${destinationPort} Len=${payload.length}`;
      }
    } else if (nextHeader === 58) {
      protocol = "ICMPv6";
      payload = frame.slice(transportOffset, packetEnd);
      info = `Type=${payload[0] ?? "--"} Code=${payload[1] ?? "--"}`;
    } else {
      protocol = `IPv6-${nextHeader}`;
      payload = frame.slice(transportOffset, packetEnd);
      info = `${source} -> ${destination}`;
    }
  } else if (etherType === 0x0806) {
    protocol = "ARP";
    info = "ARP";
  } else if (etherType) {
    protocol = `EtherType-0x${etherType.toString(16)}`;
  }

  const flow = sourcePort != null && destinationPort != null ? `${networkEndpoint(source, sourcePort)} -> ${networkEndpoint(destination, destinationPort)}` : `${source} -> ${destination}`;
  return { packet: makePcapPacket(packetNo, timestamp, deltaMs, captured, original, protocol, source, destination, sourcePort, destinationPort, flow, info, payload.length ? payload : frame, tcpMetadata), http, dns };
}

export function makePcapPacket(no: number, timestamp: string, deltaMs: number, captured: number, original: number, protocol: string, source: string, destination: string, sourcePort: number | null, destinationPort: number | null, flow: string, info: string, previewBytes: Uint8Array, tcpMetadata?: Pick<PcapPacket, "transportProtocol" | "tcpSequence" | "tcpAcknowledgment" | "tcpFlags" | "tcpPayloadSequence" | "tcpPayloadLength">): PcapPacket {
  return {
    no,
    timestamp,
    deltaMs,
    captured,
    original,
    protocol,
    source,
    destination,
    sourcePort,
    destinationPort,
    flow,
    info,
    payloadPreview: previewText(previewBytes, 2048),
    hexPreview: hexPreview(previewBytes, 256),
    payloadBytes: previewBytes,
    ...tcpMetadata
  };
}

export function parseClassicPcapPackets(bytes: Uint8Array, little: boolean, nano: boolean) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const linkType = view.getUint32(20, little);
  const packets: PcapPacket[] = [];
  const httpItems: PcapHttpItem[] = [];
  const dnsItems: PcapDnsItem[] = [];
  let offset = 24;
  let firstMs = 0;

  while (offset + 16 <= bytes.length && packets.length < 20000) {
    const seconds = view.getUint32(offset, little);
    const fraction = view.getUint32(offset + 4, little);
    const captured = view.getUint32(offset + 8, little);
    const original = view.getUint32(offset + 12, little);
    const packetOffset = offset + 16;
    if (captured <= 0 || packetOffset + captured > bytes.length) break;
    const timestampMs = seconds * 1000 + Math.floor(fraction / (nano ? 1_000_000 : 1000));
    if (!firstMs) firstMs = timestampMs;
    const inspected = inspectFrame(bytes.slice(packetOffset, packetOffset + captured), packets.length + 1, new Date(timestampMs).toISOString(), timestampMs - firstMs, captured, original, linkType);
    packets.push(inspected.packet);
    if (inspected.http) httpItems.push(inspected.http);
    if (inspected.dns) dnsItems.push(inspected.dns);
    offset = packetOffset + captured;
  }
  return { packets, httpItems, dnsItems, linkType, snaplen: view.getUint32(16, little) };
}

export function pcapngTimestampResolution(options: Map<number, Uint8Array>) {
  const raw = options.get(9);
  if (!raw?.length) return 1_000_000;
  const value = raw[0];
  if (value & 0x80) return Math.pow(2, value & 0x7f);
  return Math.pow(10, value);
}

export function pcapngReadOptions(view: DataView, start: number, end: number, little: boolean) {
  const options = new Map<number, Uint8Array>();
  let cursor = start;
  while (cursor + 4 <= end) {
    const code = view.getUint16(cursor, little);
    const length = view.getUint16(cursor + 2, little);
    cursor += 4;
    if (code === 0) break;
    if (cursor + length > end) break;
    options.set(code, new Uint8Array(view.buffer, view.byteOffset + cursor, length));
    cursor += length + ((4 - (length % 4)) % 4);
  }
  return options;
}

export function parsePcapngPackets(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const packets: PcapPacket[] = [];
  const httpItems: PcapHttpItem[] = [];
  const dnsItems: PcapDnsItem[] = [];
  const interfaces: Array<{ linkType: number; snaplen: number; tsresol: number; name?: string }> = [];
  let little = true;
  let offset = 0;
  let firstMs = 0;

  while (offset + 12 <= bytes.length && packets.length < 20000) {
    const blockType = view.getUint32(offset, little);
    let blockLength = view.getUint32(offset + 4, little);
    if (blockType === 0x0a0d0d0a) {
      const littleLength = view.getUint32(offset + 4, true);
      const bigLength = view.getUint32(offset + 4, false);
      blockLength = littleLength >= 12 && offset + littleLength <= bytes.length ? littleLength : bigLength;
    }
    if (blockLength < 12 || offset + blockLength > bytes.length) break;
    if (blockType === 0x0a0d0d0a) {
      const bom = view.getUint32(offset + 8, true);
      little = bom === 0x1a2b3c4d;
    } else if (blockType === 0x00000001) {
      const options = pcapngReadOptions(view, offset + 16, offset + blockLength - 4, little);
      const nameBytes = options.get(2);
      interfaces.push({
        linkType: view.getUint16(offset + 8, little),
        snaplen: view.getUint32(offset + 12, little),
        tsresol: pcapngTimestampResolution(options),
        name: nameBytes?.length ? new TextDecoder().decode(nameBytes) : undefined
      });
    } else if (blockType === 0x00000006 && offset + 32 <= bytes.length) {
      const interfaceId = view.getUint32(offset + 8, little);
      const high = view.getUint32(offset + 12, little);
      const low = view.getUint32(offset + 16, little);
      const captured = view.getUint32(offset + 20, little);
      const original = view.getUint32(offset + 24, little);
      const packetOffset = offset + 28;
      const iface = interfaces[interfaceId] ?? interfaces[0] ?? { linkType: 1, snaplen: 0, tsresol: 1_000_000 };
      if (packetOffset + captured <= offset + blockLength - 4) {
        const timestampMs = Number((BigInt(high) << 32n) | BigInt(low)) / (iface.tsresol / 1000);
        if (!firstMs) firstMs = timestampMs;
        const inspected = inspectFrame(bytes.slice(packetOffset, packetOffset + captured), packets.length + 1, new Date(timestampMs).toISOString(), timestampMs - firstMs, captured, original, iface.linkType);
        packets.push(inspected.packet);
        if (inspected.http) httpItems.push(inspected.http);
        if (inspected.dns) dnsItems.push(inspected.dns);
      }
    }
    offset += blockLength;
  }
  return {
    packets,
    httpItems,
    dnsItems,
    linkType: interfaces[0]?.linkType ?? null,
    snaplen: interfaces[0]?.snaplen ?? null
  };
}

export function summarizeParsedPackets(packets: PcapPacket[]): PcapSummary {
  const protocols = new Map<string, number>();
  const talkers = new Map<string, number>();
  const services = new Map<string, number>();
  const dnsNames = new Set<string>();
  const httpHosts = new Set<string>();
  let totalCaptured = 0;
  for (const packet of packets) {
    protocols.set(packet.protocol, (protocols.get(packet.protocol) ?? 0) + 1);
    if (packet.source && packet.source !== "--") talkers.set(packet.source, (talkers.get(packet.source) ?? 0) + packet.captured);
    if (packet.destination && packet.destination !== "--") talkers.set(packet.destination, (talkers.get(packet.destination) ?? 0) + packet.captured);
    const servicePort = packet.destinationPort ?? packet.sourcePort;
    if (servicePort != null) {
      const service = `${packet.protocol}/${servicePort}`;
      services.set(service, (services.get(service) ?? 0) + packet.captured);
    }
    if (packet.protocol === "DNS") {
      const name = packet.info.replace(/^\S+\s+/, "");
      if (name) dnsNames.add(name);
    }
    if (packet.protocol === "HTTP") {
      const host = packet.info.match(/Host=([^\s]+)/)?.[1];
      if (host) httpHosts.add(host);
    }
    totalCaptured += packet.captured;
  }

  return {
    packetCount: packets.length,
    totalCaptured,
    firstTimestamp: packets[0]?.timestamp ?? "--",
    lastTimestamp: packets[packets.length - 1]?.timestamp ?? "--",
    topTalkers: Array.from(talkers.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10),
    topServices: Array.from(services.entries()).sort((a, b) => b[1] - a[1]).slice(0, 12),
    protocols: Array.from(protocols.entries()).sort((a, b) => b[1] - a[1]),
    dnsNames: Array.from(dnsNames).slice(0, 30),
    httpHosts: Array.from(httpHosts).slice(0, 30)
  };
}

type TcpStreamPacket = {
  packetNo: number;
  timestamp: string;
  direction: "a-to-b" | "b-to-a";
  sequence: number;
  bytes: Uint8Array;
};

function signedSequenceDistance(sequence: number, reference: number) {
  const unsigned = (sequence - reference) >>> 0;
  return unsigned >= 0x80000000 ? unsigned - 0x100000000 : unsigned;
}

function reassembleTcpDirection(packets: TcpStreamPacket[]) {
  if (!packets.length) return { segments: [] as PcapTcpStreamSegment[], bytes: 0, gapBytes: 0, retransmittedBytes: 0 };
  const reference = packets[0].sequence;
  const positions = packets.map((packet) => ({ packet, position: signedSequenceDistance(packet.sequence, reference) }));
  const minimum = Math.min(...positions.map((item) => item.position));
  positions.forEach((item) => { item.position -= minimum; });
  positions.sort((left, right) => left.position - right.position || left.packet.packetNo - right.packet.packetNo);

  const segments: PcapTcpStreamSegment[] = [];
  let cursor = 0;
  let gapBytes = 0;
  let retransmittedBytes = 0;
  let bytes = 0;
  for (const item of positions) {
    const end = item.position + item.packet.bytes.length;
    const overlap = Math.max(0, cursor - item.position);
    retransmittedBytes += Math.min(overlap, item.packet.bytes.length);
    if (end <= cursor) continue;
    const gapBefore = Math.max(0, item.position - cursor);
    gapBytes += gapBefore;
    const unique = item.packet.bytes.slice(overlap);
    const streamOffset = item.position + overlap;
    segments.push({
      packetNo: item.packet.packetNo,
      timestamp: item.packet.timestamp,
      direction: item.packet.direction,
      sequence: (item.packet.sequence + overlap) >>> 0,
      streamOffset,
      gapBefore,
      bytes: unique
    });
    bytes += unique.length;
    cursor = end;
  }
  return { segments, bytes, gapBytes, retransmittedBytes };
}

export function buildPcapTcpStreams(packets: PcapPacket[]): PcapTcpStream[] {
  type StreamBuilder = {
    key: string;
    endpointA: string;
    endpointB: string;
    firstTimestamp: string;
    lastTimestamp: string;
    packetCount: number;
    aToB: TcpStreamPacket[];
    bToA: TcpStreamPacket[];
    initialSynSequence?: number;
    closed: boolean;
  };
  const streams: StreamBuilder[] = [];
  const currentByBase = new Map<string, StreamBuilder>();
  const countByBase = new Map<string, number>();

  for (const packet of packets) {
    if (packet.transportProtocol !== "TCP" || packet.sourcePort == null || packet.destinationPort == null) continue;
    const source = networkEndpoint(packet.source, packet.sourcePort);
    const destination = networkEndpoint(packet.destination, packet.destinationPort);
    const [endpointA, endpointB] = [source, destination].sort();
    const baseKey = `TCP|${endpointA}|${endpointB}`;
    const openingSyn = Boolean(packet.tcpFlags?.includes("SYN") && !packet.tcpFlags.includes("ACK"));
    let current = currentByBase.get(baseKey);
    const startsNewConnection = openingSyn && current && (current.closed || (current.initialSynSequence != null && current.initialSynSequence !== packet.tcpSequence) || (current.initialSynSequence == null && current.packetCount > 0));
    if (!current || startsNewConnection) {
      const index = countByBase.get(baseKey) ?? 0;
      current = {
        key: `${baseKey}|${index}`,
        endpointA,
        endpointB,
        firstTimestamp: packet.timestamp,
        lastTimestamp: packet.timestamp,
        packetCount: 0,
        aToB: [],
        bToA: [],
        initialSynSequence: openingSyn ? packet.tcpSequence : undefined,
        closed: false
      };
      countByBase.set(baseKey, index + 1);
      currentByBase.set(baseKey, current);
      streams.push(current);
    } else if (openingSyn && current.initialSynSequence == null) current.initialSynSequence = packet.tcpSequence;
    packet.tcpStreamKey = current.key;
    current.packetCount += 1;
    current.lastTimestamp = packet.timestamp;
    if ((packet.tcpPayloadLength ?? 0) > 0 && packet.tcpPayloadSequence != null) {
      const direction = source === endpointA ? "a-to-b" : "b-to-a";
      const item: TcpStreamPacket = {
        packetNo: packet.no,
        timestamp: packet.timestamp,
        direction,
        sequence: packet.tcpPayloadSequence,
        bytes: packet.payloadBytes
      };
      (direction === "a-to-b" ? current.aToB : current.bToA).push(item);
    }
    if (packet.tcpFlags?.includes("FIN") || packet.tcpFlags?.includes("RST")) current.closed = true;
  }

  return streams.map((stream): PcapTcpStream => {
    const aToB = reassembleTcpDirection(stream.aToB);
    const bToA = reassembleTcpDirection(stream.bToA);
    return {
      key: stream.key,
      endpointA: stream.endpointA,
      endpointB: stream.endpointB,
      firstTimestamp: stream.firstTimestamp,
      lastTimestamp: stream.lastTimestamp,
      packetCount: stream.packetCount,
      payloadPacketCount: stream.aToB.length + stream.bToA.length,
      bytesAtoB: aToB.bytes,
      bytesBtoA: bToA.bytes,
      retransmittedBytes: aToB.retransmittedBytes + bToA.retransmittedBytes,
      gapBytesAtoB: aToB.gapBytes,
      gapBytesBtoA: bToA.gapBytes,
      segments: [...aToB.segments, ...bToA.segments].sort((left, right) => left.packetNo - right.packetNo)
    };
  }).sort((left, right) => (right.bytesAtoB + right.bytesBtoA) - (left.bytesAtoB + left.bytesBtoA));
}

function concatTcpSegments(segments: PcapTcpStreamSegment[]) {
  const sorted = segments.slice().sort((left, right) => left.streamOffset - right.streamOffset || left.packetNo - right.packetNo);
  const total = sorted.reduce((sum, segment) => sum + segment.bytes.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const segment of sorted) {
    bytes.set(segment.bytes, offset);
    offset += segment.bytes.length;
  }
  return { bytes, segments: sorted };
}

function findLineEnd(bytes: Uint8Array, start: number) {
  for (let index = start; index < bytes.length; index += 1) {
    if (bytes[index] === 0x0a) return { contentEnd: index > start && bytes[index - 1] === 0x0d ? index - 1 : index, next: index + 1 };
  }
  return null;
}

function findHttpHeaderEnd(bytes: Uint8Array, start: number) {
  for (let index = start; index + 1 < bytes.length; index += 1) {
    if (bytes[index] === 0x0a && bytes[index + 1] === 0x0a) return index + 2;
    if (index + 3 < bytes.length && bytes[index] === 0x0d && bytes[index + 1] === 0x0a && bytes[index + 2] === 0x0d && bytes[index + 3] === 0x0a) return index + 4;
  }
  return -1;
}

function isHttpStartLine(value: string) {
  return /^(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP\/\d(?:\.\d)?$/i.test(value) || /^HTTP\/\d(?:\.\d)?\s+\d{3}\b/i.test(value);
}

function findHttpMessageStart(bytes: Uint8Array, start: number) {
  let cursor = start;
  while (cursor < bytes.length) {
    const line = findLineEnd(bytes, cursor);
    if (!line) return -1;
    const value = new TextDecoder("latin1").decode(bytes.slice(cursor, line.contentEnd));
    if (isHttpStartLine(value)) return cursor;
    cursor = line.next;
  }
  return -1;
}

function decodeChunkedBody(bytes: Uint8Array, start: number) {
  const chunks: Uint8Array[] = [];
  let total = 0;
  let cursor = start;
  while (cursor < bytes.length) {
    const sizeLine = findLineEnd(bytes, cursor);
    if (!sizeLine) return null;
    const sizeText = new TextDecoder("latin1").decode(bytes.slice(cursor, sizeLine.contentEnd)).split(";", 1)[0].trim();
    if (!/^[0-9a-f]+$/i.test(sizeText)) return null;
    const size = Number.parseInt(sizeText, 16);
    cursor = sizeLine.next;
    if (size === 0) {
      const trailerEnd = findHttpHeaderEnd(bytes, cursor);
      const end = trailerEnd >= 0 ? trailerEnd : Math.min(bytes.length, cursor + 2);
      const body = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
      return { body, end };
    }
    if (cursor + size > bytes.length) return null;
    const chunk = bytes.slice(cursor, cursor + size);
    chunks.push(chunk);
    total += chunk.length;
    cursor += size;
    if (bytes[cursor] === 0x0d && bytes[cursor + 1] === 0x0a) cursor += 2;
    else if (bytes[cursor] === 0x0a) cursor += 1;
    else return null;
  }
  return null;
}

function parseHttpDirection(stream: PcapTcpStream, direction: "a-to-b" | "b-to-a") {
  const source = direction === "a-to-b" ? stream.endpointA : stream.endpointB;
  const destination = direction === "a-to-b" ? stream.endpointB : stream.endpointA;
  const joined = concatTcpSegments(stream.segments.filter((segment) => segment.direction === direction));
  const items: PcapHttpItem[] = [];
  const files: PcapExtractedFile[] = [];
  let cursor = 0;
  while (cursor < joined.bytes.length && items.length < 5000) {
    const messageStart = findHttpMessageStart(joined.bytes, cursor);
    if (messageStart < 0) break;
    const firstLineEnd = findLineEnd(joined.bytes, messageStart);
    const headerEnd = findHttpHeaderEnd(joined.bytes, messageStart);
    if (!firstLineEnd || headerEnd < 0) break;
    const headerText = new TextDecoder("latin1").decode(joined.bytes.slice(messageStart, headerEnd));
    const firstLine = new TextDecoder("latin1").decode(joined.bytes.slice(messageStart, firstLineEnd.contentEnd));
    const contentLengthMatch = headerText.match(/\nContent-Length:\s*(\d+)/i);
    const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : null;
    const chunked = /\nTransfer-Encoding:\s*[^\r\n]*\bchunked\b/i.test(headerText);
    let body = new Uint8Array();
    let messageEnd = headerEnd;
    let completeBody = true;
    if (chunked) {
      const decoded = decodeChunkedBody(joined.bytes, headerEnd);
      if (decoded) { body = decoded.body; messageEnd = decoded.end; }
      else { completeBody = false; body = joined.bytes.slice(headerEnd); messageEnd = joined.bytes.length; }
    } else if (contentLength != null) {
      messageEnd = Math.min(joined.bytes.length, headerEnd + contentLength);
      body = joined.bytes.slice(headerEnd, messageEnd);
      completeBody = body.length === contentLength;
    } else if (/^HTTP\//i.test(firstLine) && /\nConnection:\s*close\b/i.test(headerText)) {
      body = joined.bytes.slice(headerEnd);
      messageEnd = joined.bytes.length;
    }

    const parsed = parseHttpPayload(`${headerText}\r\n${readableHttpBody(body)}`);
    const sourceSegment = joined.segments.find((segment) => segment.streamOffset <= messageStart && segment.streamOffset + segment.bytes.length > messageStart) ?? joined.segments[0];
    const item: PcapHttpItem = {
      packetNo: sourceSegment?.packetNo ?? 0,
      timestamp: sourceSegment?.timestamp ?? stream.firstTimestamp,
      source,
      destination,
      host: parsed.host,
      line: firstLine,
      method: parsed.method,
      path: parsed.path,
      userAgent: parsed.userAgent,
      contentType: parsed.contentType,
      bodySize: body.length,
      bodyPreview: readableHttpBody(body).slice(0, 1000),
      bodySha256: "--",
      risk: parsed.risk
    };
    items.push(item);
    if (completeBody) {
      const extracted = buildPcapExtractedFileFromBody(item, body, headerText);
      if (extracted) files.push(extracted);
    }
    cursor = Math.max(messageEnd, firstLineEnd.next);
  }
  return { items, files };
}

function readableHttpBody(bytes: Uint8Array) {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function parseHttpFromTcpStreams(streams: PcapTcpStream[]) {
  const items: PcapHttpItem[] = [];
  const files: PcapExtractedFile[] = [];
  for (const stream of streams) {
    if (!stream.segments.length) continue;
    if (!stream.gapBytesAtoB) {
      const parsed = parseHttpDirection(stream, "a-to-b");
      items.push(...parsed.items);
      files.push(...parsed.files);
    }
    if (!stream.gapBytesBtoA) {
      const parsed = parseHttpDirection(stream, "b-to-a");
      items.push(...parsed.items);
      files.push(...parsed.files);
    }
  }
  return { items, files };
}

export function buildPcapConversations(packets: PcapPacket[]): PcapConversation[] {
  const map = new Map<string, PcapConversation>();
  for (const packet of packets) {
    if (!packet.flow || packet.source === "--" || packet.destination === "--") continue;
    const left = networkEndpoint(packet.source, packet.sourcePort);
    const right = networkEndpoint(packet.destination, packet.destinationPort);
    const [endpointA, endpointB] = [left, right].sort();
    const protocol = packet.transportProtocol ?? packet.protocol;
    const key = packet.tcpStreamKey ?? `${protocol}|${endpointA}|${endpointB}`;
    const current = map.get(key) ?? {
      key,
      protocol,
      endpointA,
      endpointB,
      packets: 0,
      bytes: 0,
      firstTimestamp: packet.timestamp,
      lastTimestamp: packet.timestamp,
      risk: []
    };
    current.packets += 1;
    current.bytes += packet.captured;
    current.lastTimestamp = packet.timestamp;
    map.set(key, current);
  }
  return updatePcapConversationRisk(Array.from(map.values()).sort((a, b) => b.bytes - a.bytes));
}

export function buildPcapEndpointStats(packets: PcapPacket[]): PcapEndpointStat[] {
  const map = new Map<string, {
    endpoint: string;
    packetsSent: number;
    packetsReceived: number;
    bytesSent: number;
    bytesReceived: number;
    protocols: Set<string>;
    ports: Set<string>;
    firstTimestamp: string;
    lastTimestamp: string;
  }>();
  const ensure = (endpoint: string, timestamp: string) => {
    const current = map.get(endpoint) ?? {
      endpoint,
      packetsSent: 0,
      packetsReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      protocols: new Set<string>(),
      ports: new Set<string>(),
      firstTimestamp: timestamp,
      lastTimestamp: timestamp
    };
    if (timestamp.localeCompare(current.firstTimestamp) < 0) current.firstTimestamp = timestamp;
    if (timestamp.localeCompare(current.lastTimestamp) > 0) current.lastTimestamp = timestamp;
    map.set(endpoint, current);
    return current;
  };
  for (const packet of packets) {
    if (packet.source && packet.source !== "--") {
      const source = ensure(packet.source, packet.timestamp);
      source.packetsSent += 1;
      source.bytesSent += packet.captured;
      source.protocols.add(packet.protocol);
      if (packet.sourcePort != null) source.ports.add(String(packet.sourcePort));
    }
    if (packet.destination && packet.destination !== "--") {
      const destination = ensure(packet.destination, packet.timestamp);
      destination.packetsReceived += 1;
      destination.bytesReceived += packet.captured;
      destination.protocols.add(packet.protocol);
      if (packet.destinationPort != null) destination.ports.add(String(packet.destinationPort));
    }
  }
  return Array.from(map.values())
    .map((item) => {
      const totalBytes = item.bytesSent + item.bytesReceived;
      const risk = [
        !isPrivateHost(item.endpoint) ? "public endpoint" : "",
        totalBytes > 10 * 1024 * 1024 ? "large byte volume" : "",
        item.ports.has("23") || item.ports.has("21") || item.ports.has("110") || item.ports.has("143") ? "cleartext service" : "",
        item.ports.has("445") || item.ports.has("3389") ? "sensitive internal service" : "",
        item.packetsSent > item.packetsReceived * 10 && item.packetsSent > 50 ? "send-heavy endpoint" : "",
        item.packetsReceived > item.packetsSent * 10 && item.packetsReceived > 50 ? "receive-heavy endpoint" : ""
      ].filter(Boolean);
      return {
        endpoint: item.endpoint,
        packetsSent: item.packetsSent,
        packetsReceived: item.packetsReceived,
        bytesSent: item.bytesSent,
        bytesReceived: item.bytesReceived,
        protocols: Array.from(item.protocols).sort(),
        ports: Array.from(item.ports).sort((a, b) => Number(a) - Number(b)),
        firstTimestamp: item.firstTimestamp,
        lastTimestamp: item.lastTimestamp,
        risk: Array.from(new Set(risk))
      };
    })
    .sort((a, b) => (b.bytesSent + b.bytesReceived) - (a.bytesSent + a.bytesReceived))
    .slice(0, 300);
}

export function buildPcapPortStats(packets: PcapPacket[]): PcapPortStat[] {
  const map = new Map<string, { protocol: string; port: number; packets: number; bytes: number; endpoints: Set<string> }>();
  for (const packet of packets) {
    const candidates = [
      packet.sourcePort == null ? null : { port: packet.sourcePort, endpoint: packet.source },
      packet.destinationPort == null ? null : { port: packet.destinationPort, endpoint: packet.destination }
    ].filter(Boolean) as Array<{ port: number; endpoint: string }>;
    for (const candidate of candidates) {
      const protocol = packet.transportProtocol ?? packet.protocol;
      const key = `${protocol}/${candidate.port}`;
      const current = map.get(key) ?? { protocol, port: candidate.port, packets: 0, bytes: 0, endpoints: new Set<string>() };
      current.packets += 1;
      current.bytes += packet.captured;
      if (candidate.endpoint && candidate.endpoint !== "--") current.endpoints.add(candidate.endpoint);
      map.set(key, current);
    }
  }
  return Array.from(map.values())
    .map((item) => {
      const risk = [
        [21, 23, 25, 80, 110, 143].includes(item.port) ? "cleartext service" : "",
        [139, 445, 3389, 5900].includes(item.port) ? "sensitive service" : "",
        item.bytes > 10 * 1024 * 1024 ? "large byte volume" : "",
        item.endpoints.size > 20 ? "many endpoints" : ""
      ].filter(Boolean);
      return {
        protocol: item.protocol,
        port: item.port,
        packets: item.packets,
        bytes: item.bytes,
        endpoints: Array.from(item.endpoints).sort().slice(0, 30),
        risk: Array.from(new Set(risk))
      };
    })
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 200);
}

export function pcapEndpointHost(endpoint: string) {
  if (/^\[[^\]]+\]/.test(endpoint)) return endpoint.replace(/^\[([^\]]+)\].*$/, "$1");
  return endpoint.replace(/:\d+$/, "");
}

export function pcapEndpointRisk(endpoint: string) {
  const host = pcapEndpointHost(endpoint);
  return [
    isPrivateHost(host) ? "" : "public endpoint",
    /:23$|:21$|:25$|:110$|:143$|:3389$|:445$|:139$/.test(endpoint) ? "sensitive service port" : "",
    /:80$/.test(endpoint) ? "cleartext web" : ""
  ].filter(Boolean);
}

export function updatePcapConversationRisk(conversations: PcapConversation[]) {
  conversations.forEach((conversation) => {
    conversation.risk = [
      ...pcapEndpointRisk(conversation.endpointA),
      ...pcapEndpointRisk(conversation.endpointB),
      conversation.packets === 1 ? "single-packet conversation" : "",
      conversation.bytes > 10 * 1024 * 1024 ? "large byte volume" : ""
    ].filter((item, index, items) => item && items.indexOf(item) === index);
  });
  return conversations;
}

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

export function buildPcapBriefing(info: {
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
    "## TLS Handshakes",
    ...(pcap.tlsItems.length ? pcap.tlsItems.slice(0, 100).map((item) => `- ${item.timestamp} ${item.type} ${item.source} -> ${item.destination}${item.sni ? ` sni=${item.sni}` : ""}${item.negotiatedVersion ? ` version=${item.negotiatedVersion}` : ""}${item.alpn.length ? ` alpn=${item.alpn.join("|")}` : ""}${item.ja3Hash ? ` ja3=${item.ja3Hash}` : ""}${item.ja3sHash ? ` ja3s=${item.ja3sHash}` : ""}${item.certificates.length ? ` certs=${item.certificates.map((cert) => cert.sha256).join(",")}` : ""}`) : ["- none"]),
    "",
    "## IOC Preview",
    ...(pcap.iocs.length ? pcap.iocs.slice(0, 100).map((item) => `- ${item.type}: ${item.value}${item.risk.length ? ` (${item.risk.join(", ")})` : ""}`) : ["- none"])
  ].join("\n");
}

export function serializablePcapInfo(pcap: PcapInfo) {
  return {
    ...pcap,
    packets: pcap.packets.map(({ payloadBytes, ...packet }) => ({
      ...packet,
      payloadBytes: {
        size: payloadBytes.length
      }
    })),
    extractedFiles: pcap.extractedFiles.map(({ bytes, ...item }) => ({
      ...item,
      bytes: {
        size: bytes.length,
        sha256: item.sha256
      }
    }))
  };
}

// Packet payload previews are already represented by payloadPreview/hexPreview.
// Workspace snapshots keep a bounded amount of raw data so a large capture does
// not turn IndexedDB into a second copy of the evidence file.
const MAX_PERSISTED_STREAM_BYTES = 8 * 1024 * 1024;
const MAX_PERSISTED_EXTRACTED_BYTES = 8 * 1024 * 1024;

export function persistablePcapInfo(pcap: PcapInfo): PcapInfo {
  let retainedStreamBytes = 0;
  let streamBytesLimited = false;
  const tcpStreams = pcap.tcpStreams.map((stream) => ({
    ...stream,
    segments: stream.segments.map((segment) => {
      const remaining = MAX_PERSISTED_STREAM_BYTES - retainedStreamBytes;
      if (segment.bytes.byteLength <= remaining) {
        retainedStreamBytes += segment.bytes.byteLength;
        return { ...segment, bytes: segment.bytes.slice() };
      }
      streamBytesLimited = true;
      return { ...segment, bytes: new Uint8Array() };
    })
  }));
  let retainedExtractedBytes = 0;
  let extractedBytesLimited = false;
  const extractedFiles = pcap.extractedFiles.map((file) => {
    const remaining = MAX_PERSISTED_EXTRACTED_BYTES - retainedExtractedBytes;
    if (file.bytes.byteLength <= remaining) {
      retainedExtractedBytes += file.bytes.byteLength;
      return { ...file, bytes: file.bytes.slice() };
    }
    extractedBytesLimited = true;
    return { ...file, bytes: new Uint8Array() };
  });
  return {
    ...pcap,
    packets: pcap.packets.map((packet) => ({ ...packet, payloadBytes: new Uint8Array() })),
    tcpStreams,
    extractedFiles,
    streamBytesLimited,
    extractedBytesLimited
  };
}

export function pcapEndpointForPacket(packet: PcapPacket, side: "source" | "destination") {
  const host = side === "source" ? packet.source : packet.destination;
  const port = side === "source" ? packet.sourcePort : packet.destinationPort;
  return networkEndpoint(host, port);
}

export function pcapConversationPacketMatch(conversation: PcapConversation, packet: PcapPacket) {
  const source = pcapEndpointForPacket(packet, "source");
  const destination = pcapEndpointForPacket(packet, "destination");
  return (packet.tcpStreamKey ? packet.tcpStreamKey === conversation.key : (packet.transportProtocol ?? packet.protocol) === conversation.protocol) &&
    ((source === conversation.endpointA && destination === conversation.endpointB) || (source === conversation.endpointB && destination === conversation.endpointA));
}

export function pcapConversationHostSet(conversation: PcapConversation) {
  const stripPort = (value: string) => value.replace(/:\d+$/, "");
  return new Set([stripPort(conversation.endpointA), stripPort(conversation.endpointB), conversation.endpointA, conversation.endpointB]);
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

export function pcapHostOnly(endpoint: string) {
  return pcapEndpointHost(endpoint);
}

export function pcapTrafficShare(bytes: number, total: number) {
  if (!total) return "--";
  return `${((bytes / total) * 100).toFixed(bytes / total >= 0.1 ? 1 : 2)}%`;
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
  const warnFindings = info.findings.filter((finding) => finding.level === "warn").length;
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

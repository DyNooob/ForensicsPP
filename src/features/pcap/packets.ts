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
  PcapDnsItem,
  PcapExtractedFile,
  PcapHttpItem,
  PcapInfo,
  PcapPacket,
  PcapSummary
} from "../../models";
import { hexPreview, previewText } from "../../utils/binary";
import {
  dnsTypeName,
  ipFromBytes,
  ipv6FromBytes,
  networkEndpoint,
  parseDnsNameFromPayload,
  parseHttpPayload,
  tcpFlags
} from "./protocols";
import { buildPcapExtractedFile, buildPcapTcpStreams, parseHttpFromTcpStreams } from "./streams";
import { buildPcapConversations, buildPcapEndpointStats, buildPcapPortStats } from "./conversations";
import { buildPcapTimeline, buildPcapTimelineEvents } from "./timeline";

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
    extractedFiles,
    iocs,
    timeline,
    events,
    evidenceMatrix,
    briefing,
    findings
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

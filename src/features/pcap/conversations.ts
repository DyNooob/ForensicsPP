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
  PcapConversation,
  PcapEndpointStat,
  PcapPacket,
  PcapPortStat
} from "../../models";
import { isPrivateHost } from "../../utils/forensics";
import { networkEndpoint } from "./protocols";

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

export function pcapHostOnly(endpoint: string) {
  return pcapEndpointHost(endpoint);
}

export function pcapTrafficShare(bytes: number, total: number) {
  if (!total) return "--";
  return `${((bytes / total) * 100).toFixed(bytes / total >= 0.1 ? 1 : 2)}%`;
}

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
  PcapExtractedFile,
  PcapHttpItem,
  PcapPacket,
  PcapTcpStream,
  PcapTcpStreamSegment
} from "../../models";
import { fileSignatureForBytes, previewText } from "../../utils/binary";
import { httpFilenameFromHeaders, networkEndpoint, parseHttpPayload } from "./protocols";

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

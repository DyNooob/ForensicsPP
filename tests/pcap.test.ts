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

import { describe, expect, it } from "vitest";
import {
  parsePcap,
  pcapExtractedFilesToCsv,
  pcapHttpToCsv,
  pcapReportText,
  persistablePcapInfo,
  serializablePcapInfo
} from "../src/features/pcap/analyzer";

function dnsPcapFixture() {
  const qname = new Uint8Array([7, ...new TextEncoder().encode("example"), 3, ...new TextEncoder().encode("com"), 0]);
  const dns = new Uint8Array(12 + qname.length + 4);
  const dnsView = new DataView(dns.buffer);
  dnsView.setUint16(0, 0x1234, false);
  dnsView.setUint16(4, 1, false);
  dns.set(qname, 12);
  dnsView.setUint16(12 + qname.length, 1, false);
  dnsView.setUint16(14 + qname.length, 1, false);

  const frame = new Uint8Array(14 + 20 + 8 + dns.length);
  frame.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00]);
  const ip = 14;
  frame[ip] = 0x45;
  new DataView(frame.buffer).setUint16(ip + 2, 20 + 8 + dns.length, false);
  frame[ip + 8] = 64;
  frame[ip + 9] = 17;
  frame.set([10, 0, 0, 1], ip + 12);
  frame.set([8, 8, 8, 8], ip + 16);
  const udp = ip + 20;
  new DataView(frame.buffer).setUint16(udp, 53000, false);
  new DataView(frame.buffer).setUint16(udp + 2, 53, false);
  new DataView(frame.buffer).setUint16(udp + 4, 8 + dns.length, false);
  frame.set(dns, udp + 8);

  const bytes = new Uint8Array(24 + 16 + frame.length);
  const view = new DataView(bytes.buffer);
  bytes.set([0xd4, 0xc3, 0xb2, 0xa1]);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, 1, true);
  view.setUint32(24, 1, true);
  view.setUint32(32, frame.length, true);
  view.setUint32(36, frame.length, true);
  bytes.set(frame, 40);
  return bytes;
}

function tcpFrame(source: number[], destination: number[], sourcePort: number, destinationPort: number, sequence: number, payload: string | Uint8Array, flags = 0x18) {
  const data = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
  const frame = new Uint8Array(14 + 20 + 20 + data.length);
  frame.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00]);
  const view = new DataView(frame.buffer);
  const ip = 14;
  frame[ip] = 0x45;
  view.setUint16(ip + 2, 20 + 20 + data.length, false);
  frame[ip + 8] = 64;
  frame[ip + 9] = 6;
  frame.set(source, ip + 12);
  frame.set(destination, ip + 16);
  const tcp = ip + 20;
  view.setUint16(tcp, sourcePort, false);
  view.setUint16(tcp + 2, destinationPort, false);
  view.setUint32(tcp + 4, sequence, false);
  view.setUint32(tcp + 8, 1, false);
  frame[tcp + 12] = 0x50;
  frame[tcp + 13] = flags;
  frame.set(data, tcp + 20);
  return frame;
}

function classicPcap(frames: Uint8Array[]) {
  const length = 24 + frames.reduce((sum, frame) => sum + 16 + frame.length, 0);
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  bytes.set([0xd4, 0xc3, 0xb2, 0xa1]);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, 1, true);
  let offset = 24;
  frames.forEach((frame, index) => {
    view.setUint32(offset, index + 1, true);
    view.setUint32(offset + 8, frame.length, true);
    view.setUint32(offset + 12, frame.length, true);
    bytes.set(frame, offset + 16);
    offset += 16 + frame.length;
  });
  return bytes;
}

function streamText(result: ReturnType<typeof parsePcap>, direction: "a-to-b" | "b-to-a") {
  return new TextDecoder().decode(Uint8Array.from(result.tcpStreams[0].segments
    .filter((segment) => segment.direction === direction)
    .sort((left, right) => left.streamOffset - right.streamOffset)
    .flatMap((segment) => Array.from(segment.bytes))));
}

describe("PCAP parser", () => {
  it("decodes a classic Ethernet IPv4 UDP DNS capture", () => {
    const bytes = dnsPcapFixture();
    const result = parsePcap(bytes, "dns.pcap", bytes.length, "");

    expect(result.format).toBe("PCAP");
    expect(result.version).toBe("2.4");
    expect(result.packets).toHaveLength(1);
    expect(result.packets[0].protocol).toBe("DNS");
    expect(result.dnsItems[0]).toMatchObject({ name: "example.com", type: "A" });
    expect(result.conversations).toHaveLength(1);
    expect(result.endpoints.map((item) => item.endpoint)).toEqual(expect.arrayContaining(["10.0.0.1", "8.8.8.8"]));
  });

  it("marks an unrelated file as unknown", () => {
    const result = parsePcap(new TextEncoder().encode("not a capture"), "sample.bin", 13, "");
    expect(result.format).toBe("Unknown");
    expect(result.packets).toEqual([]);
  });

  it("reassembles bidirectional TCP payloads and removes retransmitted overlap", () => {
    const client = [10, 0, 0, 2];
    const server = [93, 184, 216, 34];
    const first = "GET / HTTP/1.1\r\nHost: ex";
    const second = "ample.com\r\n\r\n";
    const bytes = classicPcap([
      tcpFrame(client, server, 51000, 80, 1000 + first.length, second),
      tcpFrame(client, server, 51000, 80, 1000, first),
      tcpFrame(client, server, 51000, 80, 1000 + first.length, second),
      tcpFrame(server, client, 80, 51000, 9000, "HTTP/1.1 200 OK\r\n\r\n")
    ]);
    const result = parsePcap(bytes, "http.pcap", bytes.length, "");

    expect(result.tcpStreams).toHaveLength(1);
    expect(result.conversations).toHaveLength(1);
    expect(result.conversations[0].protocol).toBe("TCP");
    expect(result.httpItems.some((item) => item.host === "example.com")).toBe(true);
    expect(streamText(result, "a-to-b")).toBe(first + second);
    expect(streamText(result, "b-to-a")).toBe("HTTP/1.1 200 OK\r\n\r\n");
    expect(result.tcpStreams[0].retransmittedBytes).toBe(second.length);
    expect(result.tcpStreams[0].gapBytesAtoB).toBe(0);
  });

  it("marks missing TCP sequence ranges without inserting fabricated bytes", () => {
    const bytes = classicPcap([
      tcpFrame([10, 0, 0, 3], [10, 0, 0, 4], 40000, 9000, 100, "abc"),
      tcpFrame([10, 0, 0, 3], [10, 0, 0, 4], 40000, 9000, 106, "def")
    ]);
    const result = parsePcap(bytes, "gap.pcap", bytes.length, "");

    expect(streamText(result, "a-to-b")).toBe("abcdef");
    expect(result.tcpStreams[0].gapBytesAtoB).toBe(3);
    expect(result.tcpStreams[0].segments[1].gapBefore).toBe(3);
  });

  it("does not calculate payload hashes during display serialization", () => {
    const result = parsePcap(dnsPcapFixture(), "dns.pcap", 1, "");
    const serializable = serializablePcapInfo(result) as { packets: Array<{ payloadBytes: { size: number; sha256?: string } }> };
    expect(serializable.packets[0].payloadBytes).toEqual(expect.objectContaining({ size: expect.any(Number) }));
    expect(serializable.packets[0].payloadBytes).not.toHaveProperty("sha256");
  });

  it("does not duplicate packet payload bytes in a persisted workspace", () => {
    const result = parsePcap(dnsPcapFixture(), "dns.pcap", 1, "");
    const persisted = persistablePcapInfo(result);
    expect(persisted.packets[0].payloadBytes).toHaveLength(0);
    expect(persisted.packets[0].payloadPreview).toBe(result.packets[0].payloadPreview);
  });

  it("bounds raw stream and extracted-file bytes in a persisted workspace", () => {
    const source = parsePcap(classicPcap([
      tcpFrame([10, 0, 0, 5], [10, 0, 0, 6], 41000, 9000, 100, "payload")
    ]), "large.pcap", 1, "");
    const largeBytes = new Uint8Array(9 * 1024 * 1024);
    const result = {
      ...source,
      extractedFiles: [{
        packetNo: 1,
        timestamp: "2026-07-15T00:00:00.000Z",
        source: "10.0.0.5:41000",
        destination: "10.0.0.6:9000",
        host: "example.test",
        path: "/large.bin",
        contentType: "application/octet-stream",
        filename: "large.bin",
        size: largeBytes.byteLength,
        sha256: "",
        signature: "Binary",
        preview: "",
        risk: [],
        bytes: largeBytes
      }],
      tcpStreams: source.tcpStreams.map((stream) => ({
        ...stream,
        segments: stream.segments.map((segment) => ({ ...segment, bytes: largeBytes }))
      }))
    };
    const persisted = persistablePcapInfo(result);

    expect(persisted.streamBytesLimited).toBe(true);
    expect(persisted.extractedBytesLimited).toBe(true);
    expect(persisted.tcpStreams[0].segments[0].bytes).toHaveLength(0);
    expect(persisted.extractedFiles[0].bytes).toHaveLength(0);
  });

  it("handles TCP sequence wraparound", () => {
    const bytes = classicPcap([
      tcpFrame([192, 168, 1, 2], [192, 168, 1, 3], 4444, 5555, 0xfffffffc, "ABCD"),
      tcpFrame([192, 168, 1, 2], [192, 168, 1, 3], 4444, 5555, 0, "EFG")
    ]);
    const result = parsePcap(bytes, "wrap.pcap", bytes.length, "");

    expect(streamText(result, "a-to-b")).toBe("ABCDEFG");
    expect(result.tcpStreams[0].gapBytesAtoB).toBe(0);
  });

  it("extracts a file body whose HTTP response spans TCP packets", () => {
    const client = [10, 0, 0, 8];
    const server = [10, 0, 0, 9];
    const body = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const header = new TextEncoder().encode(`HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ${body.length}\r\nContent-Disposition: attachment; filename="capture.png"\r\n\r\n`);
    const response = new Uint8Array(header.length + body.length);
    response.set(header);
    response.set(body, header.length);
    const split = header.length + 4;
    const bytes = classicPcap([
      tcpFrame(client, server, 52000, 8080, 200, "GET /capture.png HTTP/1.1\r\nHost: local.test\r\n\r\n"),
      tcpFrame(server, client, 8080, 52000, 800, response.slice(0, split)),
      tcpFrame(server, client, 8080, 52000, 800 + split, response.slice(split))
    ]);
    const result = parsePcap(bytes, "download.pcap", bytes.length, "");

    expect(result.httpItems.some((item) => item.bodySize === body.length)).toBe(true);
    expect(result.extractedFiles).toHaveLength(1);
    expect(result.extractedFiles[0]).toMatchObject({ filename: "capture.png", signature: "PNG image", size: body.length });
    expect(Array.from(result.extractedFiles[0].bytes)).toEqual(Array.from(body));
  });

  it("keeps reused TCP four-tuples as separate connection instances", () => {
    const source = [10, 10, 0, 1];
    const destination = [10, 10, 0, 2];
    const bytes = classicPcap([
      tcpFrame(source, destination, 53000, 443, 100, "", 0x02),
      tcpFrame(source, destination, 53000, 443, 101, "first"),
      tcpFrame(source, destination, 53000, 443, 106, "", 0x11),
      tcpFrame(source, destination, 53000, 443, 500, "", 0x02),
      tcpFrame(source, destination, 53000, 443, 501, "second")
    ]);
    const result = parsePcap(bytes, "port-reuse.pcap", bytes.length, "");
    const texts = result.tcpStreams.map((stream) => new TextDecoder().decode(Uint8Array.from(stream.segments.flatMap((segment) => Array.from(segment.bytes)))));

    expect(result.tcpStreams).toHaveLength(2);
    expect(result.conversations).toHaveLength(2);
    expect(new Set(result.tcpStreams.map((stream) => stream.key)).size).toBe(2);
    expect(texts.sort()).toEqual(["first", "second"]);
  });

  it("does not claim hashes that were not calculated", () => {
    const bytes = classicPcap([]);
    const result = parsePcap(bytes, "empty.pcap", bytes.length, "");

    expect(pcapReportText(result)).not.toContain("SHA256:");
    expect(pcapExtractedFilesToCsv([])).toBe("packet_no,timestamp,source,destination,host,path,filename,content_type,size,signature,risk,preview");
    expect(pcapHttpToCsv([])).toBe("packet_no,timestamp,source,destination,method,host,path,line,user_agent,content_type,body_size,risk");

    const extracted = pcapExtractedFilesToCsv([{
      packetNo: 1,
      timestamp: "2026-07-08T00:00:00.000Z",
      source: "10.0.0.1:1",
      destination: "10.0.0.2:2",
      host: "example.org",
      path: "/sample.bin",
      contentType: "application/octet-stream",
      filename: "sample.bin",
      size: 4,
      sha256: "abc123",
      signature: "Binary",
      preview: "",
      risk: [],
      bytes: new Uint8Array([1, 2, 3, 4])
    }]);
    expect(extracted.split("\n", 1)[0]).toContain("sha256");
  });
});

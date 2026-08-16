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

import { describe, expect, it } from "vitest";
import type { PcapTcpStream } from "../src/models";
import { parseTlsFromTcpStreams } from "../src/features/pcap/tls";

function uint16(value: number) {
  return [value >>> 8, value & 0xff];
}

function extension(type: number, body: number[]) {
  return [...uint16(type), ...uint16(body.length), ...body];
}

function clientHelloRecord() {
  const host = Array.from(new TextEncoder().encode("example.com"));
  const sniName = [0, ...uint16(host.length), ...host];
  const sni = [...uint16(sniName.length), ...sniName];
  const alpn = [0, 3, 2, 0x68, 0x32];
  const supportedVersions = [4, 0x03, 0x04, 0x03, 0x03];
  const groups = [0, 4, 0, 29, 0, 23];
  const pointFormats = [1, 0];
  const extensions = [
    ...extension(0, sni),
    ...extension(16, alpn),
    ...extension(43, supportedVersions),
    ...extension(10, groups),
    ...extension(11, pointFormats)
  ];
  const body = [
    0x03, 0x03,
    ...new Array(32).fill(0x11),
    0,
    0, 4, 0x13, 0x01, 0x13, 0x02,
    1, 0,
    ...uint16(extensions.length),
    ...extensions
  ];
  const handshake = [1, (body.length >>> 16) & 0xff, (body.length >>> 8) & 0xff, body.length & 0xff, ...body];
  return Uint8Array.from([22, 0x03, 0x01, ...uint16(handshake.length), ...handshake]);
}

function stream(bytes: Uint8Array): PcapTcpStream {
  return {
    key: "10.0.0.1:50000<->93.184.216.34:443",
    endpointA: "10.0.0.1:50000",
    endpointB: "93.184.216.34:443",
    firstTimestamp: "2026-08-16T06:00:00.000Z",
    lastTimestamp: "2026-08-16T06:00:00.000Z",
    packetCount: 1,
    payloadPacketCount: 1,
    bytesAtoB: bytes.length,
    bytesBtoA: 0,
    retransmittedBytes: 0,
    gapBytesAtoB: 0,
    gapBytesBtoA: 0,
    segments: [{
      packetNo: 1,
      timestamp: "2026-08-16T06:00:00.000Z",
      direction: "a-to-b",
      sequence: 1,
      streamOffset: 0,
      gapBefore: 0,
      bytes
    }]
  };
}

describe("PCAP TLS metadata parser", () => {
  it("extracts ClientHello SNI, ALPN, versions, cipher suites, and JA3", () => {
    const items = parseTlsFromTcpStreams([stream(clientHelloRecord())]);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      type: "ClientHello",
      sni: "example.com",
      alpn: ["h2"]
    });
    expect(items[0].negotiatedVersion).toContain("TLS 1.3");
    expect(items[0].cipherSuites).toEqual(["0x1301", "0x1302"]);
    expect(items[0].ja3).toContain("771,4865-4866");
    expect(items[0].ja3Hash).toMatch(/^[a-f0-9]{32}$/);
  });
});

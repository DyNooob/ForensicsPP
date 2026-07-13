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

import { describe, expect, it } from "vitest";
import { parsePcap } from "../src/features/pcap/analyzer";

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
});

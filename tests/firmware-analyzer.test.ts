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
import { MemoryEvidenceReader, type EvidenceReadOptions, type EvidenceReader } from "../src/core/evidence/reader";
import { analyzeFirmware, buildFirmwareManifest } from "../src/features/firmware/analyzer";


class CountingReader implements EvidenceReader {
  readonly size: number;
  readBytes = 0;
  readCalls = 0;
  private readonly source: MemoryEvidenceReader;

  constructor(bytes: Uint8Array) {
    this.source = new MemoryEvidenceReader(bytes);
    this.size = bytes.length;
  }

  async read(offset: number, length: number, options?: EvidenceReadOptions) {
    this.readCalls += 1;
    const bytes = await this.source.read(offset, length, options);
    this.readBytes += bytes.length;
    return bytes;
  }

  slice(offset: number, length?: number) { return this.source.slice(offset, length); }
  stream(offset?: number, length?: number) { return this.source.stream(offset, length); }
}

function setU32Be(bytes: Uint8Array, offset: number, value: number) {
  new DataView(bytes.buffer).setUint32(offset, value, false);
}

describe("firmware analyzer", () => {
  it("streams signatures across chunk boundaries and resolves structural extents", async () => {
    const bytes = new Uint8Array(800 * 1024);
    const ubootOffset = 32 * 1024;
    bytes.set([0x27, 0x05, 0x19, 0x56], ubootOffset);
    setU32Be(bytes, ubootOffset + 12, 4096);
    bytes[ubootOffset + 29] = 2;
    bytes[ubootOffset + 31] = 1;
    bytes.set(new TextEncoder().encode("test-image\0"), ubootOffset + 32);

    const pngOffset = 256 * 1024 - 4;
    bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], pngOffset);
    bytes.set([0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0], pngOffset + 8);

    const { analysis } = await analyzeFirmware(new MemoryEvidenceReader(bytes), "firmware.bin", { chunkSize: 256 * 1024, maxRecursiveBytes: 64 * 1024 });
    const uboot = analysis.objects.find((item) => item.label === "U-Boot uImage");
    const png = analysis.objects.find((item) => item.label === "PNG");
    expect(uboot).toMatchObject({ offset: ubootOffset, size: 4160, extent: "structural", architecture: "ARM" });
    expect(uboot?.metadata?.Compression).toBe("gzip");
    expect(png?.offset).toBe(pngOffset);
    expect(analysis.entropy.length).toBeGreaterThan(0);
    expect(analysis.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(buildFirmwareManifest(analysis).schema).toBe("forensicspp.firmware-manifest/v1");
    expect(analysis.timings.totalMs).toBeGreaterThanOrEqual(0);
  });

  it("does not re-read multi-megabyte probes for every signature candidate", async () => {
    const bytes = new Uint8Array(16 * 1024 * 1024);
    for (let index = 0; index < 12; index += 1) {
      const offset = 128 * 1024 + index * 1024 * 1024;
      bytes.set([0x27, 0x05, 0x19, 0x56], offset);
      setU32Be(bytes, offset + 12, 4096);
    }
    const reader = new CountingReader(bytes);
    const { analysis } = await analyzeFirmware(reader, "many-signatures.bin", {
      chunkSize: 2 * 1024 * 1024,
      maxHashedObjects: 0,
      maxRecursiveBytes: 1024 * 1024
    });
    expect(analysis.objects.filter((item) => item.label === "U-Boot uImage")).toHaveLength(12);
    expect(reader.readBytes).toBeLessThan(bytes.length * 1.5);
  });
});

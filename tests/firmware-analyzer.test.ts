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
import { MemoryEvidenceReader } from "../src/core/evidence/reader";
import { analyzeFirmware, buildFirmwareManifest } from "../src/features/firmware/analyzer";

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
  });
});

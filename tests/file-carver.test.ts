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
import { scanCarvableObjects } from "../src/features/file/carver";

function setUint32Be(bytes: Uint8Array, offset: number, value: number) {
  new DataView(bytes.buffer).setUint32(offset, value, false);
}

describe("firmware/file carver", () => {
  it("keeps multiple objects of the same format", () => {
    const bytes = new Uint8Array(256);
    bytes.set([0x1f, 0x8b, 0x08], 32);
    bytes.set([0x1f, 0x8b, 0x08], 96);
    const hits = scanCarvableObjects(bytes, { maxHits: 16 });
    expect(hits.filter((hit) => hit.label === "Gzip").map((hit) => hit.offset)).toEqual([32, 96]);
  });

  it("uses structural parent bounds for unresolved child formats", () => {
    const bytes = new Uint8Array(256);
    bytes.set([0x27, 0x05, 0x19, 0x56], 0);
    setUint32Be(bytes, 12, 128);
    bytes.set([0x1f, 0x8b, 0x08], 64);
    bytes.set([0x1f, 0x8b, 0x08], 100);
    const hits = scanCarvableObjects(bytes, { maxHits: 16 });
    const children = hits.filter((hit) => hit.label === "Gzip");
    expect(children).toHaveLength(2);
    expect(children.every((hit) => hit.parentOffset === 0 && hit.depth === 1)).toBe(true);
    expect(children[1].size).toBe(92);
  });

  it("resolves PNG IEND as an exact boundary", () => {
    const bytes = new Uint8Array(64);
    bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
    bytes.set([0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0], 8);
    const hit = scanCarvableObjects(bytes)[0];
    expect(hit.label).toBe("PNG");
    expect(hit.size).toBe(20);
    expect(hit.extent).toBe("exact");
    expect(hit.confidence).toBe("high");
  });

  it("resolves FAT32 and EXT filesystem extents from their volume metadata", () => {
    const fat = new Uint8Array(4096);
    const fatView = new DataView(fat.buffer);
    fatView.setUint16(11, 512, true);
    fatView.setUint32(32, 8, true);
    fat.set(new TextEncoder().encode("FAT32"), 82);
    const fatHit = scanCarvableObjects(fat).find((hit) => hit.label === "FAT32 volume");
    expect(fatHit).toMatchObject({ offset: 0, size: 4096, extent: "structural", confidence: "high" });

    const ext = new Uint8Array(4096);
    const extView = new DataView(ext.buffer);
    extView.setUint32(1024 + 4, 2, true);
    extView.setUint32(1024 + 24, 0, true);
    extView.setUint16(1024 + 56, 0xef53, true);
    const extHit = scanCarvableObjects(ext).find((hit) => hit.label === "EXT filesystem");
    expect(extHit).toMatchObject({ offset: 0, size: 2048, extent: "structural", confidence: "high" });
  });

});

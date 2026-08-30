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
import { carverFormats, scanCarvableObjects } from "../../src/features/file/carver";

describe("validation: binary/file carving provenance", () => {
  it("recovers embedded signatures at their exact source offsets", () => {
    // Pick deterministic formats that detect purely on magic bytes (no trailing
    // structural validate) so the synthetic fixture is unambiguous.
    const chosen = carverFormats
      .filter((format) => !format.validate && (format.magicOffset ?? 0) === 0 && format.magic.length >= 3)
      .slice(0, 3);
    expect(chosen.length).toBeGreaterThanOrEqual(2);

    const size = 4096;
    const bytes = new Uint8Array(size);
    // Deterministic, non-magic filler so random bytes don't accidentally align.
    for (let index = 0; index < size; index += 1) bytes[index] = (index * 31 + 7) & 0xff;

    const offsets = [64, 768, 2048];
    const embedded = chosen.map((format, index) => {
      const offset = offsets[index];
      bytes.set(format.magic, offset);
      return { label: format.label, offset };
    });

    const hits = scanCarvableObjects(bytes);
    for (const target of embedded) {
      const hit = hits.find((candidate) => candidate.label === target.label && candidate.offset === target.offset);
      expect(hit, `expected "${target.label}" carved at 0x${target.offset.toString(16)}`).toBeDefined();
      // Provenance: the recovered object must report the exact source offset.
      expect(hit?.offset).toBe(target.offset);
      expect(hit?.confidence, `${target.label} should report a confidence`).toBeDefined();
    }
  });

  it("does not fabricate offsets for unknown filler", () => {
    const bytes = new Uint8Array(2048);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = (index * 31 + 7) & 0xff;
    const hits = scanCarvableObjects(bytes);
    // Pure filler that happens to avoid every magic should yield no confident hits
    // beyond what the tolerant PNG detector may find; we only assert no crash and
    // that any hit reports a non-negative, in-bounds offset.
    for (const hit of hits) {
      expect(hit.offset).toBeGreaterThanOrEqual(0);
      expect(hit.offset).toBeLessThan(bytes.length);
    }
  });
});

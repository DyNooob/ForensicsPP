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
import { analyzeMemoryTriage } from "../src/features/memory/analyzer";

describe("memory triage", () => {
  it("finds a bounded PE header in a raw memory image", async () => {
    const bytes = new Uint8Array(4096);
    const offset = 100;
    bytes.set([0x4d, 0x5a], offset);
    new DataView(bytes.buffer).setUint32(offset + 0x3c, 0x80, true);
    bytes.set([0x50, 0x45, 0x00, 0x00], offset + 0x80);
    const view = new DataView(bytes.buffer);
    view.setUint16(offset + 0x84, 0x8664, true);
    view.setUint16(offset + 0x86, 3, true);
    const result = await analyzeMemoryTriage(new MemoryEvidenceReader(bytes), "memory.raw");
    expect(result.format).toContain("Raw memory");
    expect(result.peHits).toContainEqual(expect.objectContaining({ offset, machine: "x64", sections: 3 }));
  });
});

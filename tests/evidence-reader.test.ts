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
import { evidenceReaderFromBlob, MemoryEvidenceReader } from "../src/core/evidence/reader";

describe("EvidenceReader", () => {
  it("reads random ranges from Blob without changing the source", async () => {
    const reader = evidenceReaderFromBlob(new Blob([new Uint8Array([1, 2, 3, 4, 5, 6])]));
    expect(reader.size).toBe(6);
    expect(Array.from(await reader.read(2, 3))).toEqual([3, 4, 5]);
    expect(Array.from(await reader.slice(1, 3).read(0, 3))).toEqual([2, 3, 4]);
  });

  it("rejects invalid ranges", async () => {
    const reader = new MemoryEvidenceReader(new Uint8Array([1, 2, 3]));
    await expect(reader.read(4, 1)).rejects.toThrow(RangeError);
  });
});

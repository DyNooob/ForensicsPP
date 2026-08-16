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
import { parseZipCentralDirectory, validateZipExpansion } from "../src/features/archive/zipDirectory";

function centralDirectoryFixture(compressed: number, uncompressed: number) {
  const name = new TextEncoder().encode("payload.bin");
  const centralSize = 46 + name.length;
  const bytes = new Uint8Array(centralSize + 22);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x02014b50, true);
  view.setUint16(8, 0x0800, true);
  view.setUint16(10, 8, true);
  view.setUint32(20, compressed, true);
  view.setUint32(24, uncompressed, true);
  view.setUint16(28, name.length, true);
  bytes.set(name, 46);
  const eocd = centralSize;
  view.setUint32(eocd, 0x06054b50, true);
  view.setUint16(eocd + 8, 1, true);
  view.setUint16(eocd + 10, 1, true);
  view.setUint32(eocd + 12, centralSize, true);
  view.setUint32(eocd + 16, 0, true);
  return bytes;
}

describe("ZIP central-directory preflight", () => {
  it("reads entry sizes without inflating file data", () => {
    const directory = parseZipCentralDirectory(centralDirectoryFixture(100, 1000));
    expect(directory?.entries[0]).toMatchObject({ name: "payload.bin", compressed: 100, uncompressed: 1000 });
    expect(directory?.totalUncompressed).toBe(1000);
  });

  it("rejects a high-ratio entry before decompression", () => {
    const bytes = centralDirectoryFixture(1024, 64 * 1024 * 1024);
    expect(() => validateZipExpansion(bytes, {
      maxEntries: 10,
      maxEntryUncompressed: 128 * 1024 * 1024,
      maxTotalUncompressed: 256 * 1024 * 1024,
      maxCompressionRatio: 500,
      ratioGuardMinimum: 16 * 1024 * 1024
    })).toThrow(/compression ratio/i);
  });
});

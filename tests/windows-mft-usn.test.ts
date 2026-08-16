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
import { analyzeWindowsArtifact } from "../src/features/windows/analyzer";

function setU64(view: DataView, offset: number, value: bigint) { view.setBigUint64(offset, value, true); }

function syntheticMftRecord() {
  const bytes = new Uint8Array(1024); const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("FILE"), 0);
  view.setUint16(4, 0x30, true); view.setUint16(6, 3, true);
  view.setUint16(0x10, 2, true); view.setUint16(0x14, 0x38, true); view.setUint16(0x16, 1, true); view.setUint32(0x2c, 42, true);
  view.setUint16(0x30, 0xaaaa, true); view.setUint16(0x32, 0, true); view.setUint16(0x34, 0, true);
  view.setUint16(510, 0xaaaa, true); view.setUint16(1022, 0xaaaa, true);
  const attr = 0x38, value = attr + 24, name = "test.txt", nameBytes = new TextEncoder().encode(name.split("").join("\u0000") + "\u0000");
  const valueLength = 66 + name.length * 2, attrLength = 112;
  view.setUint32(attr, 0x30, true); view.setUint32(attr + 4, attrLength, true); bytes[attr + 8] = 0; view.setUint32(attr + 16, valueLength, true); view.setUint16(attr + 20, 24, true);
  setU64(view, value, 5n); bytes[value + 64] = name.length; bytes[value + 65] = 1; bytes.set(nameBytes.subarray(0, name.length * 2), value + 66);
  view.setUint32(attr + attrLength, 0xffffffff, true);
  return bytes;
}

function syntheticUsn() {
  const name = "alpha.txt"; const nameBytes = new TextEncoder().encode(name.split("").join("\u0000") + "\u0000");
  const length = 60 + name.length * 2; const bytes = new Uint8Array(length); const view = new DataView(bytes.buffer);
  view.setUint32(0, length, true); view.setUint16(4, 2, true); setU64(view, 8, 42n); setU64(view, 16, 5n); setU64(view, 24, 99n);
  view.setUint32(40, 0x100 | 0x80000000, true); view.setUint32(52, 0x20, true); view.setUint16(56, name.length * 2, true); view.setUint16(58, 60, true); bytes.set(nameBytes.subarray(0, name.length * 2), 60);
  return bytes;
}

describe("NTFS Windows artifacts", () => {
  it("parses MFT FILE records after update-sequence fixup", () => {
    const result = analyzeWindowsArtifact(syntheticMftRecord(), "$MFT");
    expect(result.artifactType).toBe("NTFS $MFT");
    expect(result.records?.[0]).toMatchObject({ kind: "MFT", fields: { Record: "42", Filename: "test.txt", "Parent record": "5" } });
  });

  it("parses USN v2 records and reason flags", () => {
    const result = analyzeWindowsArtifact(syntheticUsn(), "$UsnJrnl:$J");
    expect(result.artifactType).toBe("NTFS $UsnJrnl:$J");
    expect(result.records?.[0]).toMatchObject({ kind: "USN v2", fields: { Name: "alpha.txt", "File reference": "42", USN: "99" } });
    expect(result.records?.[0].fields.Reason).toContain("FILE_CREATE");
  });
});

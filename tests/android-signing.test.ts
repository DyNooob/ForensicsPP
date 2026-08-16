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
import { inspectApkSigningBlock } from "../src/features/android/signing";

const encoder = new TextEncoder();

function u32(value: number) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function u64(value: number) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
}

function concat(...parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function lp(value: Uint8Array) {
  return concat(u32(value.length), value);
}

function algorithmRecord(id: number, bytes: number[]) {
  return lp(concat(u32(id), lp(Uint8Array.from(bytes))));
}

function signerValue(scheme: "v2" | "v3" | "v3.1") {
  const digests = algorithmRecord(0x0103, [1, 2, 3, 4]);
  const certificates = new Uint8Array();
  const attrs = new Uint8Array();
  let signedData = concat(lp(digests), lp(certificates));
  if (scheme !== "v2") signedData = concat(signedData, u32(28), u32(35));
  signedData = concat(signedData, lp(attrs));

  const signatures = algorithmRecord(0x0103, [0xaa, 0xbb]);
  let signer = lp(signedData);
  if (scheme !== "v2") signer = concat(signer, u32(28), u32(35));
  signer = concat(signer, lp(signatures), lp(Uint8Array.from([0x30, 0x01, 0x00])));
  return lp(lp(signer));
}

function syntheticApk(scheme: "v2" | "v3" | "v3.1") {
  const schemeId = scheme === "v2" ? 0x7109871a : scheme === "v3" ? 0xf05368c0 : 0x1b93ad61;
  const value = signerValue(scheme);
  const pairBody = concat(u32(schemeId), value);
  const pairs = concat(u64(pairBody.length), pairBody);
  const footerSize = pairs.length + 24;
  const block = concat(u64(footerSize), pairs, u64(footerSize), encoder.encode("APK Sig Block 42"));

  const eocd = new Uint8Array(22);
  eocd.set([0x50, 0x4b, 0x05, 0x06], 0);
  new DataView(eocd.buffer).setUint32(16, block.length, true);
  return concat(block, eocd);
}

describe("APK Signing Block v2/v3/v3.1 parser", () => {
  for (const scheme of ["v2", "v3", "v3.1"] as const) {
    it(`parses a structurally valid ${scheme} signer block without claiming verification`, () => {
      const result = inspectApkSigningBlock(syntheticApk(scheme));
      expect(result.present).toBe(true);
      expect(result.schemes).toContain(scheme);
      expect(result.verified).toBe(false);
      expect(result.signers).toHaveLength(1);
      expect(result.signers[0].scheme).toBe(scheme);
      expect(result.signers[0].digests[0].name).toContain("RSA PKCS#1");
      expect(result.signers[0].signatures[0].size).toBe(2);
      if (scheme !== "v2") expect(result.signers[0]).toMatchObject({ minSdk: 28, maxSdk: 35 });
    });
  }
});

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

import { zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { createTemporaryRepairIdentity, resignApkV2 } from "../src/features/android/signingRepair";
import { verifyApkSignatures } from "../src/features/android/signingVerify";

describe("APK cryptographic signature verification and repair", () => {
  it("builds a new v2 signature that self-verifies and detects later APK tampering", async () => {
    const unsigned = zipSync({
      "AndroidManifest.xml": new TextEncoder().encode("manifest-fixture"),
      "classes.dex": Uint8Array.from([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00, 1, 2, 3, 4])
    });
    const identity = await createTemporaryRepairIdentity("Forensics++ test repair");
    const repaired = await resignApkV2(unsigned, identity, { stripJarSignatures: false });
    expect(repaired.signing.verified).toBe(true);
    expect(repaired.signing.schemes).toContain("v2");

    const tampered = repaired.bytes.slice();
    tampered[40] ^= 0x01;
    const verification = await verifyApkSignatures(tampered);
    expect(verification.verified).toBe(false);
    expect((verification.verification?.errors ?? []).join(" ")).toContain("digest");
  });
});

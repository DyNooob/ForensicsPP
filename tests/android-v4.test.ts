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
import { buildAndroidV4VerityTree } from "../src/features/android/v4Verify";

describe("APK Signature Scheme v4 verity tree", () => {
  it("is deterministic and changes when APK content changes", async () => {
    const apk = new Uint8Array(9000);
    apk.set(new TextEncoder().encode("Forensics++ APK v4 fixture"), 128);
    const first = await buildAndroidV4VerityTree(apk);
    const second = await buildAndroidV4VerityTree(apk.slice());
    expect(Array.from(first.rootHash)).toEqual(Array.from(second.rootHash));
    expect(Array.from(first.tree)).toEqual(Array.from(second.tree));
    expect(first.rootHash).toHaveLength(32);
    expect(first.tree.length % 4096).toBe(0);

    const tampered = apk.slice();
    tampered[4097] ^= 0x01;
    const changed = await buildAndroidV4VerityTree(tampered);
    expect(Array.from(changed.rootHash)).not.toEqual(Array.from(first.rootHash));
  });

  it("supports a non-empty fs-verity salt", async () => {
    const apk = new TextEncoder().encode("small-apk-fixture");
    const plain = await buildAndroidV4VerityTree(apk);
    const salted = await buildAndroidV4VerityTree(apk, Uint8Array.from([1, 2, 3, 4]));
    expect(Array.from(salted.rootHash)).not.toEqual(Array.from(plain.rootHash));
  });
});

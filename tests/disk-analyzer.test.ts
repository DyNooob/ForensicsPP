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
import { analyzeDiskImage } from "../src/features/disk/analyzer";

function syntheticMbrFat16() {
  const sectors = 64;
  const image = new Uint8Array(sectors * 512);
  const view = new DataView(image.buffer);
  image[510] = 0x55; image[511] = 0xaa;
  const entry = 446;
  image[entry + 4] = 0x06;
  view.setUint32(entry + 8, 1, true);
  view.setUint32(entry + 12, sectors - 1, true);

  const boot = 512;
  image.set(new TextEncoder().encode("MSDOS5.0"), boot + 3);
  view.setUint16(boot + 11, 512, true);
  image[boot + 13] = 1;
  view.setUint16(boot + 14, 1, true);
  image[boot + 16] = 1;
  view.setUint16(boot + 17, 16, true);
  view.setUint16(boot + 19, sectors - 1, true);
  image[boot + 21] = 0xf8;
  view.setUint16(boot + 22, 1, true);
  image.set(new TextEncoder().encode("FORENSIC   "), boot + 43);
  image.set(new TextEncoder().encode("FAT16   "), boot + 54);

  const root = boot + (1 + 1) * 512;
  image.set(new TextEncoder().encode("HELLO   TXT"), root);
  image[root + 11] = 0x20;
  view.setUint16(root + 26, 2, true);
  view.setUint32(root + 28, 5, true);
  return image;
}

describe("disk image analyzer", () => {
  it("discovers an MBR FAT16 partition and reads its root directory without loading a different API", async () => {
    const result = await analyzeDiskImage(new MemoryEvidenceReader(syntheticMbrFat16()), "disk.img");
    expect(result.scheme).toBe("MBR");
    expect(result.partitions).toHaveLength(1);
    expect(result.partitions[0]).toMatchObject({ startLba: 1, filesystem: "FAT16" });
    expect(result.partitions[0].entries).toContainEqual(expect.objectContaining({ name: "HELLO.TXT", size: 5, cluster: 2 }));
  });
});

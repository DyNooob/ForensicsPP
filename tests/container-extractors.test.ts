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

import { strToU8, zlibSync, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { containerKind, expandContainer } from "../src/features/file/containerExtractors";
import { scanRecursiveCarvableObjects } from "../src/features/file/recursiveCarver";

const limits = { maxEntries: 64, maxEntryBytes: 1024 * 1024, maxTotalBytes: 4 * 1024 * 1024 };

function tarWithFile(name: string, data: Uint8Array) {
  const header = new Uint8Array(512);
  header.set(strToU8(name).subarray(0, 100), 0);
  header.set(strToU8(data.length.toString(8).padStart(11, "0") + "\0"), 124);
  header[156] = 0x30;
  header.set(strToU8("ustar\0"), 257);
  const output = new Uint8Array(512 + Math.ceil(data.length / 512) * 512 + 1024);
  output.set(header, 0);
  output.set(data, 512);
  return output;
}

describe("container extractor registry", () => {
  it("expands ZIP, zlib, and TAR through the same interface", () => {
    const zip = zipSync({ "config.json": strToU8('{"ok":true}') });
    expect(containerKind(zip)).toBe("zip");
    expect(expandContainer(zip, limits)[0].name).toBe("config.json");

    const zlib = zlibSync(strToU8("SQLite format 3\0payload"));
    expect(containerKind(zlib)).toBe("zlib");
    expect(new TextDecoder().decode(expandContainer(zlib, limits)[0].bytes)).toContain("SQLite format 3");

    const tar = tarWithFile("etc/config.json", strToU8("hello"));
    expect(containerKind(tar)).toBe("tar");
    expect(expandContainer(tar, limits)[0].name).toBe("etc/config.json");
  });

  it("lets recursive carving descend into TAR entries", () => {
    const sqlite = new Uint8Array(512);
    sqlite.set(strToU8("SQLite format 3\0"));
    const tar = tarWithFile("data/app.db", sqlite);
    const rows = scanRecursiveCarvableObjects(tar, { maxDepth: 3, maxObjects: 64 });
    expect(rows.some((row) => row.virtualPath.includes("data/app.db") && row.label === "SQLite")).toBe(true);
  });
});

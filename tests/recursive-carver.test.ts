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
import { scanRecursiveCarvableObjects } from "../src/features/file/recursiveCarver";

describe("recursive firmware/file carver", () => {
  it("expands nested ZIP entries without recursively re-adding the whole container forever", () => {
    const sqlite = new Uint8Array(256);
    sqlite.set(new TextEncoder().encode("SQLite format 3\0"));
    const inner = zipSync({ "evidence.db": sqlite });
    const outer = zipSync({ "nested.zip": inner });
    const rows = scanRecursiveCarvableObjects(outer, { maxDepth: 4, maxObjects: 64 });
    expect(rows.some((row) => row.virtualPath.includes("nested.zip") && row.origin === "archive-entry")).toBe(true);
    expect(rows.some((row) => row.virtualPath.includes("evidence.db") && row.label === "SQLite")).toBe(true);
    expect(rows.length).toBeLessThan(20);
  });
});

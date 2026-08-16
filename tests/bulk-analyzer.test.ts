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
import { scanBulkArtifacts } from "../src/features/bulk/analyzer";

describe("bulk artifact scanner", () => {
  it("extracts typed indicators with byte offsets across encodings", async () => {
    const ascii = new TextEncoder().encode("mail analyst@example.org url https://example.org/a ip 198.51.100.7 token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature");
    const utf16 = new TextEncoder().encode("\u0000");
    const file = new Blob([ascii, utf16]);
    const result = await scanBulkArtifacts(file, "sample.bin", { chunkSize: 64, maxItems: 100 });
    expect(result.counts.Email).toBeGreaterThanOrEqual(1);
    expect(result.counts.URL).toBeGreaterThanOrEqual(1);
    expect(result.counts.IPv4).toBeGreaterThanOrEqual(1);
    expect(result.counts.JWT).toBeGreaterThanOrEqual(1);
    expect(result.items.every((item) => item.offset >= 0)).toBe(true);
  });
});

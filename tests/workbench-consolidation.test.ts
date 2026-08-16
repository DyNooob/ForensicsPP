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
import { canonicalToolId, toolIdFromHash, visibleTools } from "../src/config/app";

describe("workbench consolidation", () => {
  it("routes legacy image tools into Image Workbench", () => {
    expect(canonicalToolId("png")).toBe("image");
    expect(canonicalToolId("qr")).toBe("image");
    expect(toolIdFromHash("#png")).toBe("image");
  });

  it("routes duplicated binary utilities into Binary Workbench", () => {
    for (const tool of ["fileid", "strings", "entropy", "yara"] as const) expect(canonicalToolId(tool)).toBe("binary");
    const ids = new Set(visibleTools.map((tool) => tool.id));
    expect(ids.has("png")).toBe(false);
    expect(ids.has("qr")).toBe(false);
    expect(ids.has("fileid")).toBe(false);
    expect(ids.has("strings")).toBe(false);
    expect(ids.has("entropy")).toBe(false);
    expect(ids.has("yara")).toBe(false);
    expect(ids.has("image")).toBe(true);
    expect(ids.has("binary")).toBe(true);
  });
});

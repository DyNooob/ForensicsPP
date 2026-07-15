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
import { analyzeRegex } from "../src/features/regex/analyzer";

describe("regex analyzer", () => {
  it("returns match positions, groups and replacement output", () => {
    const result = analyzeRegex("user=(?<name>[a-z]+)", "gi", "user=alice\nuser=bob", "account=$<name>");

    expect(result.error).toBe("");
    expect(result.matches).toHaveLength(2);
    expect(result.matches[0]).toMatchObject({ value: "user=alice", line: 1, end: 10, namedGroups: { name: "alice" } });
    expect(result.replaced).toBe("account=alice\naccount=bob");
  });

  it("reports invalid expressions without throwing", () => {
    const result = analyzeRegex("(", "g", "text", "");

    expect(result.matches).toEqual([]);
    expect(result.replaced).toBe("text");
    expect(result.error).toContain("Invalid regular expression");
  });

  it("keeps source unchanged when no pattern is selected", () => {
    expect(analyzeRegex("", "g", "source", "x")).toMatchObject({ matches: [], replaced: "source", error: "" });
  });
});

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
import { launchTarget } from "../src/core/launchTarget";
import { parseUrlInput } from "../src/utils/url";
import { toolSamples } from "../src/tools/samples";
import { visibleTools } from "../src/config/app";
import { toolMatchesQuery } from "../src/utils/toolSearch";

describe("workbench input routing", () => {
  it("distinguishes timestamps from supported identifiers", () => {
    expect(launchTarget("1719795600")).toBe("timestamp");
    expect(launchTarget("1719795600000")).toBe("timestamp");
    expect(launchTarget("2026-10-13T08:21:00Z")).toBe("timestamp");
    expect(launchTarget("133649928000000000")).toBe("timestamp");
    expect(launchTarget("13800138000")).toBe("lookup");
    expect(launchTarget("11010519491231002X")).toBe("lookup");
    expect(launchTarget("4111111111111111")).toBe("lookup");
  });
  it("recognizes structured clues and exact digest lengths", () => {
    expect(launchTarget(toolSamples.jwt.en)).toBe("jwt");
    expect(launchTarget("Bearer " + toolSamples.jwt.en)).toBe("jwt");
    expect(launchTarget('GET /case HTTP/1.1\r\nHost: example.org')).toBe("http");
    expect(launchTarget('{"case":42}')).toBe("json");
    expect(launchTarget("a".repeat(64))).toBe("hash");
    expect(launchTarget("a".repeat(42))).toBe("ioc");
    expect(launchTarget("ip=192.0.2.1 user=sample")).toBe("ioc");
  });
  it("routes defanged addresses and refangs bracketed scheme separators", () => {
    const input = "hxxps[:]//example[.]org/case?id=42";
    expect(launchTarget(input)).toBe("urltool");
    expect(parseUrlInput(input).href).toBe("https://example.org/case?id=42");
  });
  it("bounds automatic detection without losing the large input's intended tool", () => {
    expect(launchTarget('{"data":"' + "x".repeat(100000) + '"}')).toBe("json");
    expect(launchTarget("x".repeat(100000))).toBe("ioc");
  });
});

describe("tool discovery", () => {
  it("finds digest tools, English terms and merged aliases in the same catalog", () => {
    const find = (query: string) => visibleTools.filter((tool) => toolMatchesQuery(tool, query)).map((tool) => tool.id);
    expect(find(" SHA256 ")).toContain("hash");
    expect(find("strings")).toContain("binary");
    expect(find("Image")).toContain("image");
    expect(find("png")).not.toContain("png");
  });
  it("provides help for every visible tool beyond the launcher", () => {
    expect(visibleTools.filter((tool) => tool.id !== "home" && (!tool.help?.zh || !tool.help.en))).toEqual([]);
  });
});

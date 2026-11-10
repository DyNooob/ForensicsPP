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
import { convertChinese } from "../src/features/codec/chinese";

describe("offline Chinese conversion", () => {
  it("disambiguates hair and development using phrases", () => {
    expect(convertChinese({ input: "头发与发展，后台与皇后。", direction: "toTraditional", region: "t" })).toBe("頭髮與發展，後臺與皇后。");
    expect(convertChinese({ input: "頭髮與發展，後臺與皇后。", direction: "toSimplified", region: "t" })).toBe("头发与发展，后台与皇后。");
  });
  it("converts Taiwan vocabulary in both directions when explicitly selected", () => {
    expect(convertChinese({ input: "软件和鼠标", direction: "toTraditional", region: "twp" })).toBe("軟體和滑鼠");
    expect(convertChinese({ input: "軟體和滑鼠", direction: "toSimplified", region: "twp" })).toBe("软件和鼠标");
    expect(convertChinese({ input: "軟體和滑鼠", direction: "toSimplified", region: "tw" })).toBe("软体和滑鼠");
  });
  it("preserves whitespace, emoji, Latin text, and empty input", () => {
    expect(convertChinese({ input: "發展\n\tA😀  123\r\n", direction: "toSimplified", region: "hk" })).toBe("发展\n\tA😀  123\r\n");
    expect(convertChinese({ input: "", direction: "toTraditional", region: "tw" })).toBe("");
  });
  it("rejects oversized text before dictionary conversion", () => {
    expect(() => convertChinese({ input: "中".repeat(700000), direction: "toSimplified", region: "t" })).toThrow("2 MiB");
  });
});

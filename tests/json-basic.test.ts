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
import { analyzeBasicJson, parseBasicJson } from "../src/features/json/basic";

describe("basic JSON analyzer", () => {
  it("formats JSON and collects bounded paths", () => {
    const result = analyzeBasicJson('{"user":{"name":"alice"},"items":[1,true]}');

    expect(result.parsed).toMatchObject({ ok: true, kind: "JSON", minified: '{"user":{"name":"alice"},"items":[1,true]}' });
    expect(result.paths.map((row) => row.path)).toEqual(["$", "$.user", "$.user.name", "$.items", "$.items[0]", "$.items[1]"]);
  });

  it("recognizes JSON Lines without changing the original parser error path", () => {
    expect(parseBasicJson('{"id":1}\n{"id":2}')).toMatchObject({ ok: true, kind: "JSONL", jsonl: '{"id":1}\n{"id":2}' });
    expect(parseBasicJson("{broken")).toMatchObject({ ok: false, value: null });
  });

  it("limits path expansion for very large arrays", () => {
    const result = analyzeBasicJson(`[${Array.from({ length: 6000 }, (_, index) => index).join(",")}]`);

    expect(result.paths).toHaveLength(5000);
  });
});

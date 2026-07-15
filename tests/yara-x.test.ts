/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import { readFile } from "node:fs/promises";
import init, { Compiler } from "@virustotal/yara-x";
import { beforeAll, describe, expect, it } from "vitest";
import { normalizeYaraXScan, type YaraXScanOutput } from "../src/features/yara/analyzer";

beforeAll(async () => {
  const wasm = await readFile(new URL("../node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm", import.meta.url));
  await init({ module_or_path: wasm });
});

function scan(ruleText: string, bytes: Uint8Array) {
  const compiler = new Compiler();
  try {
    compiler.addSource(ruleText);
    const compilerWarnings = compiler.warnings;
    const rules = compiler.build();
    try {
      const scanner = rules.scanner();
      try {
        scanner.setMaxMatchesPerPattern(200);
        scanner.setTimeoutMs(2_000);
        return normalizeYaraXScan(ruleText, bytes, "sample.bin", scanner.scan(bytes) as YaraXScanOutput, compilerWarnings);
      } finally {
        scanner.free();
      }
    } finally {
      rules.free();
    }
  } finally {
    compiler.free();
  }
}

describe("YARA-X integration", () => {
  it("supports hex jumps, alternatives and offsets", () => {
    const source = `rule advanced_hex : binary {
      strings:
        $header = { 4D 5A [1-3] (50 45 | 4E 45) }
      condition:
        $header at 0
    }`;
    const result = scan(source, new Uint8Array([0x4d, 0x5a, 0x00, 0x50, 0x45, 0x90]));

    expect(result.rows).toContainEqual(["Engine", "YARA-X"]);
    expect(result.results[0]).toMatchObject({ matched: true, rule: { name: "advanced_hex", tags: ["binary"] } });
    expect(result.results[0].hits[0].offsets).toEqual([0]);
  });

  it("keeps unmatched rules in the normalized result", () => {
    const source = `rule present { strings: $a = "needle" condition: $a }
      rule absent { strings: $b = "missing" condition: $b }`;
    const result = scan(source, new TextEncoder().encode("a needle in bytes"));

    expect(result.results.map((item) => [item.rule.name, item.matched])).toEqual([
      ["present", true],
      ["absent", false]
    ]);
  });

  it("reports compiler errors instead of silently falling back", () => {
    const compiler = new Compiler();
    try {
      expect(() => compiler.addSource("rule broken { condition: }")).toThrow();
      expect(compiler.errors.length).toBeGreaterThan(0);
    } finally {
      compiler.free();
    }
  });
});

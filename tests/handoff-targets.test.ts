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

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { tools } from "../src/config/app";

/**
 * The evidence inbox derives its "send to" dropdown from `supportsHandoff` in
 * `config/app.ts`. For a send to actually do something, the target tool must
 * subscribe to `takeToolHandoff`. These two sets must stay in lockstep — a
 * drift means either a dead dropdown entry (declared but never wired) or a
 * silent no-op (wired but not offered). This contract test fails if they ever
 * diverge again.
 */
describe("handoff targets stay in sync with config", () => {
  const declared = new Set(
    tools.filter((tool) => tool.supportsHandoff && !tool.hidden).map((tool) => tool.id)
  );

  const toolsDir = join(__dirname, "..", "src", "tools");
  const wired = new Set<string>();
  for (const file of readdirSync(toolsDir)) {
    if (!/\.tsx?$/.test(file)) continue;
    const source = readFileSync(join(toolsDir, file), "utf8");
    const pattern = /takeToolHandoff\(\s*["']([\w-]+)["']\s*\)/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(source)) !== null) {
      wired.add(match[1]);
    }
  }

  it("every declared handoff target is wired to takeToolHandoff", () => {
    expect(declared.size).toBeGreaterThan(0);
    for (const id of declared) {
      expect(wired.has(id), `config sets supportsHandoff for "${id}" but no tool subscribes via takeToolHandoff`).toBe(true);
    }
  });

  it("every tool that subscribes to takeToolHandoff is declared as a handoff target", () => {
    for (const id of wired) {
      expect(declared.has(id), `tool subscribes to takeToolHandoff("${id}") but config does not set supportsHandoff`).toBe(true);
    }
  });

  it("the evidence inbox can reach every handoff target", () => {
    // The inbox filters `supportsHandoff && !hidden`, so the reachable set must
    // equal the declared set. If this fails, the dropdown derivation drifted.
    const reachable = tools.filter((tool) => tool.supportsHandoff && !tool.hidden).map((tool) => tool.id);
    expect(new Set(reachable)).toEqual(declared);
  });
});

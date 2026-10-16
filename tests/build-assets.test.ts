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

import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { buildAssetIdentity } from "../scripts/build-assets.mjs";

describe("release cache identity", () => {
  it("rotates an inlined standalone build even when asset names stay the same", async () => {
    const root = await mkdtemp(join(tmpdir(), "fpp-cache-"));
    try {
      await writeFile(join(root, "index.html"), `<script type="module">const example = '<link href="/assets/example.js">'; old()</script>`);
      const before = await buildAssetIdentity(root);
      await writeFile(join(root, "index.html"), '<script type="module">new()</script>');
      const after = await buildAssetIdentity(root);
      expect(before.bootstrap).toEqual([]);
      expect(before.fingerprint).not.toBe(after.fingerprint);
      expect(after.bootstrap).toEqual([]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("collects entry, imported modules and CSS without prefetching lazy tools", async () => {
    const root = await mkdtemp(join(tmpdir(), "fpp-cache-"));
    try {
      await mkdir(join(root, "assets"));
      await writeFile(join(root, "assets/lazy.js"), "//unused");
      await writeFile(join(root, "index.html"), '<script src="/assets/entry.js"></script><link rel="modulepreload" href="/assets/vendor.js"><link rel="stylesheet" href="/assets/app.css">');
      expect((await buildAssetIdentity(root)).bootstrap).toEqual(["/assets/entry.js", "/assets/vendor.js", "/assets/app.css"]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

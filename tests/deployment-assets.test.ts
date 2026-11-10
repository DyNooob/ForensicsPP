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

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { retainDeploymentAssets, refreshDeploymentCacheIdentity } from "../scripts/retain-deployment-assets.mjs";
import { buildAssetIdentity } from "../scripts/build-assets.mjs";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });
async function directory() { const root = await mkdtemp(join(tmpdir(), "fpp-deployment-")); roots.push(root); await mkdir(join(root, "assets")); return root; }

describe("deployment compatibility for cached HTML", () => {
  it("retains an old entry, lazy chunk and styles without replacing the current shell or bridge", async () => {
    const current = await directory(), previous = await directory();
    await writeFile(join(current, "index.html"), "new CDN shell");
    await writeFile(join(previous, "index.html"), "old self-origin shell");
    await writeFile(join(previous, "sw.js"), "obsolete worker");
    await writeFile(join(previous, "assets/index-oldentry.js"), 'import("./Tool-oldchunk.js")');
    await writeFile(join(previous, "assets/Tool-oldchunk.js"), "export const result = 42;");
    await writeFile(join(previous, "assets/index-oldstyle.css"), "body{color:black}");
    await writeFile(join(previous, "assets/hash.worker-12345678.js"), "old implementation");
    await writeFile(join(current, "assets/hash.worker-12345678.js"), "current CDN bridge");
    const retained = await retainDeploymentAssets(current, [previous]);
    expect(retained).toHaveLength(3);
    expect(await readFile(join(current, "index.html"), "utf8")).toBe("new CDN shell");
    expect(await readFile(join(current, "assets/Tool-oldchunk.js"), "utf8")).toContain("42");
    expect(await readFile(join(current, "assets/hash.worker-12345678.js"), "utf8")).toBe("current CDN bridge");
    expect(await retainDeploymentAssets(current, [previous])).toEqual([]);
  });
  it("ignores links, non-hashed files and missing historical asset directories", async () => {
    const current = await directory(), previous = await directory();
    await writeFile(join(previous, "assets/evidence.txt"), "must not copy");
    await writeFile(join(previous, "assets/config.js"), "must not copy");
    await symlink(join(previous, "assets/config.js"), join(previous, "assets/link-12345678.js"));
    expect(await retainDeploymentAssets(current, [previous, join(previous, "missing")])).toEqual([]);
  });
  it("rotates the cache fingerprint after adding compatibility assets while preserving current bootstrap URLs", async () => {
    const current = await directory(), previous = await directory();
    await writeFile(join(current, "index.html"), '<script src="https://cdn.example/releases/new/assets/index-12345678.js"></script>');
    await writeFile(join(current, "sw.js"), 'const CACHE_VERSION = "before";\nconst BUILD_ASSETS = [];');
    const before = await buildAssetIdentity(current);
    await writeFile(join(previous, "assets/index-oldentry.js"), "old entry");
    await retainDeploymentAssets(current, [previous]);
    await refreshDeploymentCacheIdentity(current);
    const after = await buildAssetIdentity(current);
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(await readFile(join(current, "sw.js"), "utf8")).toContain(after.fingerprint);
    expect(await readFile(join(current, "sw.js"), "utf8")).toContain(JSON.stringify(after.bootstrap));
  });
});

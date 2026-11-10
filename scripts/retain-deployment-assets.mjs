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

import { copyFile, mkdir, readdir, readFile, writeFile, access } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

/** Preserve immutable URLs used by cached HTML and already-open workspaces. */
export async function retainDeploymentAssets(destination, previousRoots) {
  const target = join(destination, "assets");
  await mkdir(target, { recursive: true });
  const retained = [];
  for (const root of previousRoots) {
    const source = join(root, "assets");
    const entries = await readdir(source, { withFileTypes: true }).catch((error) => {
      if (error.code === "ENOENT") return [];
      throw error;
    });
    for (const entry of entries) {
      // Only regular, content-addressed runtime assets. Never copy an old shell,
      // SW, directory, link, deployment setting, or unrelated evidence file.
      if (!entry.isFile() || !/^[\w.-]+-[\w-]{8}\.(?:js|css|wasm|woff2?|ttf|png|svg)$/.test(entry.name)) continue;
      const output = join(target, entry.name);
      try { await access(output); continue; }
      catch (error) { if (error.code !== "ENOENT") throw error; }
      await copyFile(join(source, entry.name), output);
      retained.push(`assets/${entry.name}`);
    }
  }
  return retained;
}

export async function refreshDeploymentCacheIdentity(root, projectRoot = process.cwd()) {
  const { buildAssetIdentity } = await import(pathToFileURL(resolve(projectRoot, "scripts/build-assets.mjs")).href);
  const { fingerprint, bootstrap } = await buildAssetIdentity(root);
  const { version } = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8"));
  const path = join(root, "sw.js");
  const source = await readFile(path, "utf8");
  if (!/const CACHE_VERSION = "[^"]+";/.test(source)) throw new Error("Missing service-worker cache identity");
  await writeFile(path, source.replace(/const CACHE_VERSION = "[^"]+";/, `const CACHE_VERSION = "forensicspp-v${version}-${fingerprint}";`)
    .replace(/const BUILD_ASSETS = \[[^;]*\];/, `const BUILD_ASSETS = ${JSON.stringify(bootstrap)};`));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [destination, ...previous] = process.argv.slice(2);
  if (!destination || !previous.length) throw new Error("Usage: retain-deployment-assets.mjs <current-dist> <previous-dist> [...]");
  const retained = await retainDeploymentAssets(resolve(destination), previous.map((path) => resolve(path)));
  await refreshDeploymentCacheIdentity(resolve(destination));
  await writeFile(join(destination, "deployment-compatibility.json"), JSON.stringify({ retainedAssets: retained }, null, 2));
  console.log(`Retained ${retained.length} prior immutable assets; active HTML and worker bridges stay current.`);
}

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

import { cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { prepareLookupData } from "./prepare-lookup-data.mjs";

export const offlineCsp = "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; style-src 'self' 'unsafe-inline'; connect-src 'self' data: blob:; img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; frame-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'none'";

export async function prepareOfflineDistribution(root, projectRoot) {
  await prepareLookupData(root, { allowDownload: false });
  await cp(join(projectRoot, "packaging/portable"), root, { recursive: true });
  await cp(join(projectRoot, "LICENSE"), join(root, "LICENSE.txt"));
  await mkdir(join(root, "licenses"), { recursive: true });
  const lock = JSON.parse(await readFile(join(projectRoot, "package-lock.json"), "utf8"));
  const inventory = [];
  for (const [location, entry] of Object.entries(lock.packages)) {
    if (!location.startsWith("node_modules/") || entry.dev) continue;
    const packageRoot = join(projectRoot, location);
    let manifest;
    try { manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8")); }
    catch (error) { if (error.code === "ENOENT" && entry.optional) continue; throw error; }
    const id = `${manifest.name.replaceAll("/", "__")}@${manifest.version}`;
    const files = (await readdir(packageRoot)).filter((name) => /^(licen[sc]e|copying|notice|third.party.licen[sc]es)(\..*)?$/i.test(name));
    const copies = [];
    for (const name of files) {
      const destination = `licenses/${id}/${name}`;
      try {
        const text = await readFile(join(packageRoot, name));
        await mkdir(dirname(join(root, destination)), { recursive: true });
        await writeFile(join(root, destination), text);
        copies.push(destination);
      } catch (error) { if (error.code !== "EISDIR") throw error; }
    }
    inventory.push({ name: manifest.name, version: manifest.version, license: manifest.license ?? entry.license ?? "See upstream notices", repository: manifest.repository, files: copies });
  }
  await writeFile(join(root, "licenses/DEPENDENCIES.json"), JSON.stringify(inventory, null, 2));
  await writeFile(join(root, "THIRD_PARTY_NOTICES.txt"), [
    "Forensics++ — third-party software and data notices", "",
    "The application is MIT licensed. Third-party components retain their own licenses.",
    "Full license texts and the dependency inventory are under licenses/.",
    "CyberChef source/version and Apache-2.0 notices: cyberchef/UPSTREAM.txt, cyberchef/LICENSE.txt and cyberchef/assets/main.js.LICENSE.txt.",
    "OpenCC JS: MIT; bundled OpenCC dictionary data: Apache-2.0 (licenses/opencc-js-THIRD_PARTY_LICENSES.txt).",
    "heic-to 1.6.7, libheif 1.23.7 and libde265 1.0.16: LGPL-3.0-or-later. Corresponding source and build instructions: sources/heic-sources.tar.gz. The separately emitted heic.worker-*.js can be rebuilt/replaced independently.",
    "Lookup data versions, authors, hashes and original source URLs: lookup/SOURCES.json; upstream license texts: licenses/lookup/.", "",
    ...inventory.map((item) => `${item.name}@${item.version} — ${typeof item.license === "string" ? item.license : JSON.stringify(item.license)} — ${item.files.join(", ") || "see package metadata/upstream"}`)
  ].join("\n") + "\n");
  await mkdir(join(root, "sources"), { recursive: true });
  await cp(join(projectRoot, "release/offline-inputs/heic-sources.tar.gz"), join(root, "sources/heic-sources.tar.gz"));
  // Every HTML entry carries the same restriction, including the independently opened CyberChef.
  const secureHtml = async (folder) => {
    for (const entry of await readdir(folder, { withFileTypes: true })) {
      const path = join(folder, entry.name);
      if (entry.isDirectory()) await secureHtml(path);
      else if (entry.name.endsWith(".html")) {
        let html = await readFile(path, "utf8");
        html = html.replace(/<link\b[^>]*rel=["'](?:preconnect|dns-prefetch)["'][^>]*>/gi, "");
        html = html.replace(/<head([^>]*)>/i, `<head$1>\n<meta http-equiv="Content-Security-Policy" content="${offlineCsp}">\n<meta name="distribution" content="offline">`);
        await writeFile(path, html);
      }
    }
  };
  await secureHtml(root);
  await writeFile(join(root, "cyberchef/FPP-OFFLINE-CHANGES.txt"), "Forensics++ offline distribution adds a Content-Security-Policy and distribution marker to the bundled CyberChef HTML. The upstream engine, modules, styles, fonts and data remain unchanged. Network operations are restricted to this local origin. Original license and provenance remain in LICENSE.txt and UPSTREAM.txt.\n");
  await writeFile(join(root, "README.md"), await readFile(join(root, "OFFLINE-README.txt")));
  const packs = JSON.parse(await readFile(join(root, "lookup/SOURCES.json"), "utf8"));
  await writeFile(join(root, "OFFLINE_MANIFEST.json"), JSON.stringify({
    version: lock.version, distribution: "offline", externalRuntimeResources: false, contentSecurityPolicy: offlineCsp,
    lookup: Object.values(packs).map((pack) => ({ path: pack.path, sha256: pack.sha256, bytes: pack.bytes })),
    heicSourcesSha256: createHash("sha256").update(await readFile(join(root, "sources/heic-sources.tar.gz"))).digest("hex")
  }, null, 2));
}

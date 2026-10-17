#!/usr/bin/env node
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

import { readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { prepareLookupData } from "./prepare-lookup-data.mjs";

export async function prepareResourceCdn(root) {
  await prepareLookupData(root);
  const htmlPath = join(root, "index.html");
  let html = await readFile(htmlPath, "utf8");
  const entry = html.match(/src="(https:\/\/[^"\s]+\/releases\/[^/]+\/assets\/[^"\s]+\.js)"/);
  if (!entry) throw new Error("Full resource CDN build is missing its remote entry");
  const base = entry[1].slice(0, entry[1].lastIndexOf("/assets/"));
  html = html.replace("</head>", `<meta name="asset-cdn" content="${base}" />\n</head>`);
  await writeFile(htmlPath, html);
  const bridges = [];
  for (const name of await readdir(join(root, "assets"))) {
    if (!/\.worker-[\w-]+\.js$/.test(name)) continue;
    const source = await readFile(join(root, "assets", name));
    const payload = `runtime.${name}`;
    await writeFile(join(root, "assets", payload), source);
    const banner = source.toString().match(/^\/\*![\s\S]*?\*\//)?.[0] || "";
    await writeFile(join(root, "assets", name), `${banner}\n// Same-origin module worker bridge.\nimport ${JSON.stringify(`${base}/assets/${payload}`)};\n`);
    bridges.push(`assets/${name}`);
  }
  // CyberChef is a complete document on the CDN. Only a readiness signal is
  // sent to its parent; no input, output or evidence crosses this channel.
  const config = JSON.parse(await readFile(new URL("../src/config/cyberchef.json", import.meta.url), "utf8"));
  const chefPath = join(root, config.entry);
  let chef = await readFile(chefPath, "utf8");
  const signal = `<script>(()=>{let sent=false;const ready=()=>{if(sent||!document.getElementById("input-text"))return;sent=true;observer.disconnect();const target=new URL(document.referrer||location.href).origin;parent.postMessage("forensicspp:cyberchef-ready",target);};const observer=new MutationObserver(ready);observer.observe(document.documentElement,{childList:true,subtree:true});addEventListener("load",ready);ready();})();</script>`;
  chef = chef.replace("</body>", `${signal}</body>`);
  await writeFile(chefPath, chef);
  await writeFile(join(root, "resource-cdn.json"), JSON.stringify({ base, bridges }, null, 2));
  console.log(`Full resource CDN: ${base}; ${bridges.length} same-origin worker bridges`);
}

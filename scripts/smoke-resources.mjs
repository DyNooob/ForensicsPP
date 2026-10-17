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

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { spawn } from "node:child_process";
import assert from "node:assert/strict";
import { launchSmokeBrowser, prepareSmokePage } from "./browser-smoke.mjs";

const root = resolve("dist");
const config = JSON.parse(await readFile(resolve(root, "resource-cdn.json"), "utf8"));
const prefix = new URL(config.base).pathname;
const requests = [];
let localCdn;
async function serve(cdn) {
  const server = createServer(async (req, res) => {
    try {
      let path = new URL(req.url, "http://localhost").pathname;
      if (cdn) {
        if (path.startsWith(prefix + "/")) path = path.slice(prefix.length);
        else if (!path.startsWith("/lookup/")) throw new Error("Wrong version");
      }
      let file = resolve(root, "." + decodeURIComponent(path));
      if (!file.startsWith(root + "/") && file !== root) throw new Error("Invalid path");
      try { if ((await stat(file)).isDirectory()) file = resolve(file, "index.html"); }
      catch { if (!extname(path)) file = resolve(root, "index.html"); }
      let data = await readFile(file);
      const ext = extname(file);
      // Only replace the test origin. Chunks, worker bridges and WASM bytes
      // otherwise execute exactly as built, over two real HTTP origins.
      if ([".js", ".css", ".html", ".json"].includes(ext)) data = Buffer.from(data.toString().replaceAll(config.base, localCdn + prefix));
      requests.push({ cdn, path, bytes: data.length });
      const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json" };
      res.writeHead(200, { "Content-Type": mime[ext] || "application/octet-stream", "Access-Control-Allow-Origin": "*" });
      res.end(data);
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}
function child(script, env) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [script], { stdio: "inherit", env: { ...process.env, ...env } });
    proc.on("error", reject); proc.on("exit", code => code === 0 ? resolve() : reject(new Error(`${script}: exit ${code}`)));
  });
}
const cdn = await serve(true); localCdn = cdn.base;
const app = await serve(false);
let browser;
try {
  browser = await launchSmokeBrowser();
  const page = await prepareSmokePage(browser);
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(app.base, { waitUntil: "networkidle2" });
  console.log("Resource CDN: app shell loaded");
  const worker = config.bridges.find(path => path.includes("/yara.worker-"));
  assert(worker, "YARA bridge required");
  const result = await page.evaluate(async (url) => new Promise((resolve, reject) => {
    const worker = new Worker(url, { type: "module" });
    const timer = setTimeout(() => { worker.terminate(); reject(new Error("YARA timed out")); }, 30000);
    worker.onerror = e => { clearTimeout(timer); worker.terminate(); reject(new Error(e.message)); };
    worker.onmessage = e => { clearTimeout(timer); worker.terminate(); resolve(e.data); };
    worker.postMessage({ ruleText: 'rule resource_cdn { strings: $a = "resource-cdn" condition: $a }', data: new TextEncoder().encode("resource-cdn test").buffer, name: "fixture.bin" });
  }), app.base + "/" + worker);
  assert.equal(result.type, "result", JSON.stringify(result));
  assert(result.result.results.some(r => r.matched), "YARA must match using the CDN WASM");
  console.log("Resource CDN: real YARA worker and WASM passed");
  const lookupBridge = config.bridges.find(path => path.includes("/lookup.worker-"));
  assert(lookupBridge, "Lookup bridge required");
  const lookup = await page.evaluate(async (url) => new Promise((resolve, reject) => {
    const worker = new Worker(url, { type: "module" });
    const timer = setTimeout(() => { worker.terminate(); reject(new Error("Lookup timed out")); }, 60000);
    worker.onerror = e => { clearTimeout(timer); worker.terminate(); reject(new Error(e.message)); };
    worker.onmessage = e => {
      if (!["result", "error"].includes(e.data.type)) return;
      clearTimeout(timer); worker.terminate(); resolve(e.data);
    };
    worker.postMessage({ requestId: 1, kind: "auto", values: ["8.8.8.8", "13800138000", "11010519491231002X"], lang: "en" });
  }), app.base + "/" + lookupBridge);
  assert.equal(lookup.type, "result", JSON.stringify(lookup));
  assert.deepEqual(lookup.results.map(r => [r.kind, r.valid, r.matched]), [["ip", true, true], ["phone", true, true], ["id", true, true]]);
  assert.match(String(lookup.results[0].fields.country), /United States|美国/i);
  assert.match(lookup.results[1].summary, /北京|Beijing/i);
  assert.match(lookup.results[2].summary, /朝阳/);
  assert(requests.filter(r => r.cdn && /^\/lookup\/[^/]+\.(xdb|dat|json)$/.test(r.path)).length >= 3, "All real lookup packs must load from the CDN");
  console.log("Resource CDN: real IP, phone and administrative-code lookups passed");
  await page.goto(app.base + "/tools/cyberchef/", { waitUntil: "networkidle2" });
  await page.waitForSelector(".cyberchef-stage iframe.is-loaded", { timeout: 60000 });
  const chef = page.frames().find(f => f.url().startsWith(cdn.base + prefix + "/cyberchef/"));
  assert(chef, "CyberChef must run on the CDN origin");
  await chef.waitForSelector("#input-text");
  console.log("Resource CDN: CyberChef ready handshake passed");
  assert.deepEqual(errors, []);
  await browser.close(); browser = null;
  await child("scripts/smoke-usability.mjs", { USABILITY_URL: app.base, USABILITY_FLOWS_ONLY: "1" });
  if (process.env.RESOURCE_FULL_AUDIT === "1") await child("scripts/layout-audit.mjs", { AUDIT_URL: app.base, AUDIT_VERBOSE: "1" });
  const wrong = requests.filter(r => !r.cdn && r.path.startsWith("/assets/") && !/\.worker-[\w-]+\.js$/.test(r.path));
  assert.deepEqual(wrong, [], "Only small Worker bridges may load from the app origin");
  assert(requests.some(r => r.cdn && r.path.endsWith(".wasm")), "WASM must load from the CDN");
  console.log(`Full resource CDN smoke passed: ${requests.filter(r=>r.cdn).length} CDN requests; Worker/WASM, CyberChef, image and clipboard; no large app-origin assets.`);
} finally {
  await browser?.close();
  await Promise.all([app.server, cdn.server].map(s => new Promise(r => { s.close(r); s.closeAllConnections(); })));
}

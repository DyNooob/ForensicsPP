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

// Production-like HTTP + real-Chrome smoke test for Forensics++ tool routes.
// Serves dist/ over a real static server (no Vite dev server) and asserts:
//   - each indexable tool URL returns HTTP 200 with per-tool static metadata
//   - JS hydrates from the sub-path and the correct ToolHost opens (no flash to home)
//   - refresh / back / forward behave sanely
//   - unknown tool route resolves to the in-app NotFound (app boots from fallback)
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { join, extname, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { launchSmokeBrowser, prepareSmokePage } from "./browser-smoke.mjs";
import { SLUG_TO_TOOL, TOOL_SLUG } from "../src/seo/toolRoutes.mjs";


const root = join(fileURLToPath(import.meta.url), "..", "..", "dist");
const PORT = 8241;
const BASE = `http://127.0.0.1:${PORT}`;
const PUBLIC_BASE = "https://www.forensicspp.com";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".map": "application/json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

const VALID_SLUGS = new Set(Object.keys(SLUG_TO_TOOL));

// Alias (supplementary) slugs canonicalize to a sibling route instead of
// themselves — they must NOT be indexable duplicates. Mirrors the alias model
// in scripts/build-seo-pages.mjs (ALIAS_SLUGS) and src/seo/toolRoutes.mjs.
const ALIAS_CANONICAL = { "sqlite-wal-recovery": "sqlite-forensics" };
function canonicalSlugFor(slug) {
  return ALIAS_CANONICAL[slug] || slug;
}

async function resolveFile(urlPath) {
  const path = decodeURIComponent(urlPath.split("?")[0].split("#")[0]);
  if (path === "/") return join(root, "index.html");
  const base = join(root, normalize(path).replace(/^(\.\.[/\\])+/, ""));
  try {
    const s = await stat(base);
    if (s.isDirectory()) return join(base, "index.html");
    return base;
  } catch {
    try {
      if ((await stat(join(base, "index.html"))).isFile()) return join(base, "index.html");
    } catch {}
  }
  return null;
}

const server = createServer(async (req, res) => {
  const p = req.url.split("?")[0].split("#")[0];
  let file = await resolveFile(req.url);
  // SPA fallback (mirrors Nginx `try_files ... /index.html`): unknown
  // extension-less routes — including typo'd /tools/<slug>/ — serve the
  // app shell, which then renders the in-app NotFound (#14). Assets keep
  // root-absolute paths so the shell boots from any sub-path.
  if (!file && !extname(p)) file = join(root, "index.html");
  if (!file) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  try {
    const buf = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] || "application/octet-stream" });
    res.end(buf);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});

const TOOLS = [
  "lookup",
  "evtx-viewer",
  "sqlite-forensics",
  "apk-signature-analyzer",
  "pcap-analyzer",
  "registry-forensics",
  "firmware-analyzer",
  "binary-file-analyzer",
  "windows-artifacts",
  "image-forensics",
];

let pass = 0, fail = 0;
const fails = [];
function check(cond, msg) {
  if (cond) { pass++; } else { fail++; fails.push(msg); console.log("  ✗ " + msg); }
}

await new Promise((resolve) => server.listen(PORT, "127.0.0.1", resolve));
console.log(`static server listening on ${BASE}`);

const browser = await launchSmokeBrowser();
const page = await prepareSmokePage(browser);
page.on("pageerror", (e) => { fail++; fails.push("pageerror: " + e.message); });

async function assertToolRoute(slug, canonicalId) {
  const resp = await page.goto(`${BASE}/tools/${slug}/`, { waitUntil: "networkidle0", timeout: 30000 });
  check(resp.status() === 200, `/tools/${slug}/ HTTP ${resp.status()} (want 200)`);

  // Static metadata read from the built artifact (runtime i18n overrides the
  // live <title>, so we assert the static source, not page.title()).
  const html = await readFile(join(root, "tools", slug, "index.html"), "utf8");
  const title = (html.match(/<title>([^<]*)<\/title>/) || [])[1] || "";
  check(title.length > 0, `/tools/${slug}/ static <title> present`);
  check(!/Forensics\+\+ Workbench/i.test(title), `/tools/${slug}/ title is per-tool, not generic ("${title}")`);
  const canonical = (html.match(/<link rel="canonical" href="([^"]*)"/) || [])[1] || "";
  const expectedCanonical = `${PUBLIC_BASE}/tools/${canonicalSlugFor(slug)}/`;
  check(canonical === expectedCanonical, `/tools/${slug}/ canonical=${canonical} (want ${expectedCanonical})`);
  const h1 = (html.match(/<h1>([^<]*)<\/h1>/) || [])[1] || "";
  check(h1.length > 0, `/tools/${slug}/ static <h1>="${h1}"`);

  // Runtime: app booted from the sub-path (the base:"/" fix).
  await page.waitForFunction(() => {
    const r = document.getElementById("root");
    return r && r.children.length > 0;
  }, { timeout: 15000 }).catch(() => {});
  const booted = await page.$eval("#root", (el) => el.children.length > 0).catch(() => false);
  check(booted, `/tools/${slug}/ SPA booted (#root has children)`);
  check(!(await page.$(".tool-notfound")), `/tools/${slug}/ is NOT the NotFound state`);
  const active = await page.$(`[data-tool-id="${canonicalId}"]:not([hidden])`);
  check(!!active, `/tools/${slug}/ active ToolHost = ${canonicalId}`);
  const url = page.url().replace(/\/+$/, "");
  check(url === `${BASE}/tools/${slug}`, `/tools/${slug}/ final URL=${url}`);

  // Refresh keeps the tool (no flash to home).
  await page.reload({ waitUntil: "networkidle0" });
  const url2 = page.url().replace(/\/+$/, "");
  check(url2 === `${BASE}/tools/${slug}`, `/tools/${slug}/ refresh keeps URL=${url2}`);
  const active2 = await page.$(`[data-tool-id="${canonicalId}"]:not([hidden])`);
  check(!!active2, `/tools/${slug}/ refresh keeps active ToolHost=${canonicalId}`);
}

console.log("=== Production HTTP + Chrome smoke ===");
for (const slug of (process.env.SMOKE_RUNTIME_ONLY ? [] : TOOLS)) {
  const id = SLUG_TO_TOOL[slug];
  console.log(`-- /tools/${slug}/`);
  await assertToolRoute(slug, id);
}

console.log("-- /");
{
  const resp = await page.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  check(resp.status() === 200, `/ HTTP ${resp.status()}`);
  const title = await page.title();
  check(title.includes("Forensics++"), `/ title="${title}"`);
  const h1 = await page.$eval("h1", (el) => el.textContent).catch(() => "");
  check(!/requires JavaScript/i.test(h1), `/ H1 is not "requires JavaScript" ("${h1}")`);
}

console.log("-- /tools/not-a-real-tool/  (expect in-app NotFound via SPA fallback)");
{
  const resp = await page.goto(`${BASE}/tools/not-a-real-tool/`, { waitUntil: "networkidle0" });
  // SPA fallback serves the shell (200); the app must render NotFound, NOT home.
  check(resp.status() === 200, `/tools/not-a-real-tool/ HTTP ${resp.status()} (SPA fallback)`);
  await page.waitForFunction(() => {
    const r = document.getElementById("root");
    return r && r.children.length > 0;
  }, { timeout: 15000 }).catch(() => {});
  const booted = await page.$eval("#root", (el) => el.children.length > 0).catch(() => false);
  check(booted, `/tools/not-a-real-tool/ SPA booted from fallback`);
  const notFound = await page.$(".tool-notfound");
  check(!!notFound, `/tools/not-a-real-tool/ renders in-app NotFound (not Home)`);
}

console.log("-- history back/forward");
{
  await page.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  await page.goto(`${BASE}/tools/evtx-viewer/`, { waitUntil: "networkidle0" });
  await page.goto(`${BASE}/tools/pcap-analyzer/`, { waitUntil: "networkidle0" });
  await page.goBack({ waitUntil: "networkidle0" });
  check(page.url().replace(/\/+$/, "") === `${BASE}/tools/evtx-viewer`, `back -> evtx (got ${page.url()})`);
  await page.goForward({ waitUntil: "networkidle0" });
  check(page.url().replace(/\/+$/, "") === `${BASE}/tools/pcap-analyzer`, `forward -> pcap (got ${page.url()})`);
}

console.log("-- viewport sanity (no horizontal overflow + sidebar/header present)");
{
  const viewports = [
    { name: "desktop 1440x900", width: 1440, height: 900 },
    { name: "laptop 1280x800", width: 1280, height: 800 },
    { name: "tablet 768x1024", width: 768, height: 1024 },
    { name: "mobile 390x844", width: 390, height: 844 },
  ];
  for (const vp of viewports) {
    await page.setViewport(vp);
    await page.goto(`${BASE}/tools/evtx-viewer/`, { waitUntil: "networkidle0" });
    await page.waitForFunction(() => { const r = document.getElementById("root"); return r && r.children.length > 0; }, { timeout: 15000 }).catch(() => {});
    const metrics = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      hasSidebar: !!document.querySelector(".app-sidebar"),
      hasHeader: !!document.querySelector(".app-topbar, header"),
    }));
    check(metrics.overflow <= 2, `${vp.name}: no horizontal overflow (scrollW-clientW=${metrics.overflow})`);
    check(metrics.hasHeader, `${vp.name}: app header present`);
  }
}

// Non-indexable tools also have generated pretty URLs and must survive refresh.
console.log("-- all remaining workbench routes");
const appSource = await readFile(new URL("../src/config/app.ts", import.meta.url), "utf8");
const definitions = appSource.slice(appSource.indexOf("const toolDefinitions = ["), appSource.indexOf("] as const;"));
const otherTools = definitions.split("\n").filter((line) => line.includes('{ id: "') && !line.includes("hidden: true"))
  .map((line) => /id: "([^"]+)"/.exec(line)?.[1]).filter((id) => id && id !== "home" && !TOOL_SLUG[id]);
for (const id of (process.env.SMOKE_RUNTIME_ONLY ? [] : otherTools)) {
  await page.goto(`${BASE}/tools/${id}/`, { waitUntil: "networkidle0" });
  check(!!(await page.$(`[data-tool-id="${id}"]:not([hidden])`)), `${id} direct URL opens workbench`);
  check(!(await page.$(".tool-error-state, .tool-notfound")), `${id} workbench loaded without error`);
}

async function clickToolButton(targetPage, id, text) {
  const clicked = await targetPage.evaluate((tool, label) => {
    const root = document.querySelector(`[data-tool-id="${tool}"]:not([hidden])`);
    const button = [...(root?.querySelectorAll("button") || [])].find((el) => el.textContent.trim() === label);
    if (!button || button.disabled) return false;
    button.click(); return true;
  }, id, text);
  if (!clicked) throw new Error(`Missing enabled button ${id}: ${text}`);
}

console.log("-- fresh deep-link service worker, actual crypto/lookup/hash execution and offline reload");
const context = await browser.createBrowserContext();
const runtimePage = await prepareSmokePage(context);
await runtimePage.setViewport({ width: 1440, height: 900 });
runtimePage.on("pageerror", (error) => { fail++; fails.push("runtime pageerror: " + error.stack); });
try {
  await runtimePage.goto(`${BASE}/tools/lookup/`, { waitUntil: "networkidle0" });
  await runtimePage.waitForFunction(() => navigator.serviceWorker.controller, { timeout: 15000 });
  console.log("  service worker controlled");
  const swUrl = await runtimePage.evaluate(async () => (await navigator.serviceWorker.ready).active?.scriptURL);
  check(swUrl === `${BASE}/sw.js`, "fresh deep link registers root service worker");

  // Delay a remote data pack, then clear during the query. No real lookup data
  // or sensitive identifiers leave this deterministic test.
  const client = await runtimePage.createCDPSession();
  await client.send("Fetch.enable", { patterns: [{ urlPattern: "*cdn.jsdelivr.net*" }] });
  let pendingPack;
  client.on("Fetch.requestPaused", (event) => { pendingPack = event.requestId; });
  console.log("  starting delayed phone lookup");
  await runtimePage.type(".lookup-input", "13800138000");
  await clickToolButton(runtimePage, "lookup", "Run lookup");
  const deadline = Date.now() + 10000;
  while (!pendingPack && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  if (!pendingPack) throw new Error("Lookup did not request the expected data pack");
  await clickToolButton(runtimePage, "lookup", "Clear");
  await client.send("Fetch.failRequest", { requestId: pendingPack, errorReason: "Aborted" }).catch(() => {});
  await client.send("Fetch.disable");
  check(await runtimePage.$eval(".lookup-input", (el) => el.value === ""), "clear empties lookup input while loading");
  check(!(await runtimePage.$(".lookup-result-table tbody tr")), "cancelled lookup does not restore old rows");
  console.log("  cancellation passed; starting bank lookup");
  await runtimePage.type(".lookup-input", "4111111111111111");
  await clickToolButton(runtimePage, "lookup", "Run lookup");
  await runtimePage.waitForSelector(".lookup-result-table tbody tr");
  check(await runtimePage.$eval(".lookup-result-table", (el) => el.textContent.includes("Rules pass")), "Luhn-valid unmatched BIN stays valid after cancelling a query");

  await clickToolButton(runtimePage, "lookup", "Clear");
  pendingPack = undefined;
  await client.send("Fetch.enable", { patterns: [{ urlPattern: "*cdn.jsdelivr.net*" }] });
  await runtimePage.type(".lookup-input", "13800138000");
  await clickToolButton(runtimePage, "lookup", "Run lookup");
  const languageDeadline = Date.now() + 10000;
  while (!pendingPack && Date.now() < languageDeadline) await new Promise((resolve) => setTimeout(resolve, 50));
  if (!pendingPack) throw new Error("Missing pending pack for language-switch regression");
  await runtimePage.evaluate(() => [...document.querySelectorAll(".language-switch button")].find((el) => el.textContent.trim() === "中文").click());
  const record = Buffer.from("Fixture province|Fixture city|000000|000\0");
  const indexStart = 8 + record.length;
  const phonePack = Buffer.alloc(indexStart + 9);
  phonePack.writeUInt32LE(indexStart, 4);
  record.copy(phonePack, 8);
  phonePack.writeUInt32LE(1380013, indexStart);
  phonePack.writeUInt32LE(8, indexStart + 4);
  phonePack[indexStart + 8] = 1;
  await client.send("Fetch.fulfillRequest", { requestId: pendingPack, responseCode: 200,
    responseHeaders: [{ name: "Access-Control-Allow-Origin", value: "*" }], body: phonePack.toString("base64") });
  await client.send("Fetch.disable");
  await runtimePage.waitForSelector(".lookup-result-table tbody tr");
  check(await runtimePage.$eval(".lookup-result-table", (el) => el.textContent.includes("Fixture city")), "language switch preserves a running lookup");
  await runtimePage.evaluate(() => [...document.querySelectorAll(".language-switch button")].find((el) => el.textContent.trim() === "EN").click());

  console.log("  lookup execution passed; starting bcrypt");
  // Pagination bounds DOM work; filtering and paging leave the whole batch available.
  await runtimePage.locator('.lookup-result-controls .ant-select').click();
  await runtimePage.waitForSelector('.ant-select-item-option[title="Rules failed"]', { visible: true });
  await runtimePage.locator('.ant-select-item-option[title="Rules failed"]').click();
  await runtimePage.waitForFunction(() => document.querySelectorAll('.lookup-result-table tbody tr').length === 0);
  check(await runtimePage.$eval('.lookup-results-panel', (el) => el.textContent.includes("No results match")), "status filter keeps a clear empty-result state");
  await clickToolButton(runtimePage, "lookup", "Reset filters");
  await runtimePage.waitForSelector('.lookup-result-table tbody tr');

  await clickToolButton(runtimePage, "lookup", "Clear");
  await runtimePage.type(".lookup-input", Array.from({ length: 205 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`).join("\n"));
  await clickToolButton(runtimePage, "lookup", "Run lookup");
  await runtimePage.waitForSelector(".lookup-result-table tbody tr");
  check((await runtimePage.$$(".lookup-result-table tbody tr")).length === 100, "large lookup batch renders only one 100-row page");
  await clickToolButton(runtimePage, "lookup", "Next");
  await runtimePage.waitForFunction(() => document.querySelector(".lookup-pagination")?.textContent.includes("101–200"));
  await clickToolButton(runtimePage, "lookup", "Next");
  await runtimePage.waitForFunction(() => document.querySelectorAll(".lookup-result-table tbody tr").length === 5);
  check((await runtimePage.$$(".lookup-result-table tbody tr")).length === 5, "final lookup page contains remaining rows");
  await runtimePage.type(".lookup-result-search", "10.0.0.204");
  await runtimePage.waitForFunction(() => document.querySelectorAll(".lookup-result-table tbody tr").length === 1);
  check(true, "search works across pages and resets to the matching result");
  for (const width of [800, 390]) {
    await runtimePage.setViewport({ width, height: 900 });
    check(await runtimePage.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 2), `loaded lookup remains within ${width}px viewport`);
  }
  await runtimePage.setViewport({ width: 1440, height: 900 });

  await runtimePage.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  await runtimePage.type('textarea[aria-label="Workbench input"]', "1719795600000");
  check(await runtimePage.$eval(".home-target-select", (el) => el.textContent.includes("Time")), "home recommends timestamps instead of card lookup");
  await clickToolButton(runtimePage, "home", "Run");
  await runtimePage.waitForSelector('.timestamp-simple-input-panel');
  check(await runtimePage.$eval('.timestamp-simple-input-panel input', (el) => el.value === "1719795600000"), "home draft reaches timestamp input intact");
  await runtimePage.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  await runtimePage.type('textarea[aria-label="Workbench input"]', "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzYW1wbGUifQ.");
  await clickToolButton(runtimePage, "home", "Run");
  await runtimePage.waitForSelector('.jwt-overview-panel');
  check(await runtimePage.$eval('.jwt-token-input', (el) => el.value.startsWith("eyJ")), "home recognizes and hands off a JWT");

  await runtimePage.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  await runtimePage.type('textarea[aria-label="Workbench input"]', "sample plain text");
  await runtimePage.locator(".home-target-select").click();
  await runtimePage.waitForSelector('.ant-select-item-option[title="Evidence Hash Calculator"]', { visible: true });
  await runtimePage.locator('.ant-select-item-option[title="Evidence Hash Calculator"]').click();
  await clickToolButton(runtimePage, "home", "Run");
  await runtimePage.waitForSelector('.hash-simple-text-input');
  check(await runtimePage.$eval('.hash-simple-text-input', (el) => el.value === "sample plain text"), "manual hash target opens text hashing instead of digest verification");

  await runtimePage.goto(`${BASE}/tools/password/`, { waitUntil: "networkidle0" });
  await runtimePage.type('.password-simple-generate-grid input[type="password"]', "release-smoke-password");
  await clickToolButton(runtimePage, "password", "Generate bcrypt");
  await runtimePage.waitForFunction(() => /\$2[aby]\$/.test(document.querySelector(".password-simple-output")?.textContent || ""));
  console.log("  bcrypt execution passed");
  check(true, "browser bcrypt generates a real hash with secure randomness");

  await runtimePage.goto(`${BASE}/tools/hash/`, { waitUntil: "networkidle0" });
  await clickToolButton(runtimePage, "hash", "Load sample");
  await clickToolButton(runtimePage, "hash", "Calculate");
  const sampleHash = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
  await runtimePage.waitForFunction((digest) => document.querySelector('[data-tool-id="hash"]')?.textContent.includes(digest), {}, sampleHash);
  console.log("  hash execution passed");
  check(true, "hash worker computes the expected SHA-256");
  // Warm Home's lazy chunk, then prove a full navigation works offline.
  await runtimePage.goto(`${BASE}/`, { waitUntil: "networkidle0" });
  await runtimePage.setOfflineMode(true);
  await runtimePage.reload({ waitUntil: "networkidle0" });
  check(!!(await runtimePage.$('[data-tool-id="home"]:not([hidden])')), "installed app shell boots offline");
  await runtimePage.goto(`${BASE}/tools/hash/`, { waitUntil: "networkidle0" });
  await clickToolButton(runtimePage, "hash", "Load sample");
  await clickToolButton(runtimePage, "hash", "Calculate");
  await runtimePage.waitForFunction((digest) => document.querySelector('[data-tool-id="hash"]')?.textContent.includes(digest), {}, sampleHash);
  check(true, "previously loaded hash worker also calculates offline");
} catch (error) {
  console.log("Runtime URL:", runtimePage.url());
  console.log((await runtimePage.$eval("#root", (el) => el.innerText)).slice(-3500));
  check(false, "runtime regression: " + error.message);
} finally {
  await context.close();
}

await browser.close();
server.close();

console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
  console.log("FAILURES:\n" + fails.map((f) => " - " + f).join("\n"));
  process.exit(1);
}

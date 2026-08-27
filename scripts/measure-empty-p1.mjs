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

// P1 regression check: empty-state tools must fill the viewport-height body and
// vertically center their (short) empty card instead of leaving half-screen whitespace.
import { spawn } from "node:child_process";
import { writeFile, mkdir } from "node:fs/promises";
import { appendFileSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DEBUG = "/tmp/measure-empty-p1-debug.log";
writeFileSync(DEBUG, "");
function log(...a) { appendFileSync(DEBUG, a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ") + "\n"); }

const baseUrl = process.env.AUDIT_URL || "http://localhost:4173";
const chromePath = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const port = Number(process.env.CDP_PORT || 9246);
const legalVersion = "2026-07-13-v2";
const legacyEvidenceCleanupVersion = "2026-07-13-v1";
const screenshotDir = process.env.AUDIT_SCREENSHOT_DIR || "empty-shots-screenshots";
const saveScreenshots = process.env.AUDIT_SCREENSHOTS !== "0";

const viewport = { width: 1366, height: 900 };
const tools = ["registry", "timeline", "sql", "image"];

function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }
function getJson(pathname) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port, path: pathname }, (res) => {
      let body = ""; res.setEncoding("utf8");
      res.on("data", (c) => (body += c));
      res.on("end", () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    });
    req.on("error", reject); req.end();
  });
}
async function waitForCdp() {
  const started = Date.now();
  while (Date.now() - started < 15000) {
    try { const tabs = await getJson("/json"); if (Array.isArray(tabs) && tabs.some((t) => t.type === "page" && t.webSocketDebuggerUrl)) return tabs; } catch { /* retry */ }
    await wait(250);
  }
  throw new Error(`Chrome DevTools not ready on port ${port}.`);
}
function createCdpClient(url) {
  const ws = new WebSocket(url);
  let id = 0; const pending = new Map(); let closed = false; let onClose = null;
  ws.addEventListener("message", (event) => {
    const m = JSON.parse(event.data);
    if (!m.id || !pending.has(m.id)) return;
    const { resolve, reject } = pending.get(m.id); pending.delete(m.id);
    if (m.error) reject(new Error(JSON.stringify(m.error))); else resolve(m.result);
  });
  ws.addEventListener("error", (e) => { closed = true; const err = new Error("WS error " + (e.message || "")); for (const { reject } of pending.values()) reject(err); pending.clear(); if (onClose) onClose(err); });
  ws.addEventListener("close", () => { closed = true; const err = new Error("WS closed"); for (const { reject } of pending.values()) reject(err); pending.clear(); if (onClose) onClose(err); });
  const opened = new Promise((r) => ws.addEventListener("open", r, { once: true }));
  return {
    async ready() { await opened; },
    send(method, params = {}) { if (closed) return Promise.reject(new Error("WS closed")); return new Promise((resolve, reject) => { const n = ++id; pending.set(n, { resolve, reject }); ws.send(JSON.stringify({ id: n, method, params })); }); },
    close() { try { ws.close(); } catch { /* ignore */ } },
    onDrop(cb) { onClose = cb; }
  };
}
async function waitForRuntimeValue(client, expression, timeout = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeout) {
    const r = await client.send("Runtime.evaluate", { expression, returnByValue: true });
    if (r.result.value) return true; await wait(160);
  }
  return false;
}
async function loadToolState(client, tool) {
  await client.send("Runtime.evaluate", {
    expression: `
      localStorage.setItem("forensicspp:app.lang", JSON.stringify("zh"));
      localStorage.setItem("forensicspp:app.activeTool", JSON.stringify(${JSON.stringify(tool)}));
      localStorage.setItem("forensicspp:app.themeMode", JSON.stringify("light"));
      localStorage.setItem("forensicspp:app.sidebarCollapsed", JSON.stringify(false));
      localStorage.setItem("forensicspp:legal.acceptedVersion", JSON.stringify(${JSON.stringify(legalVersion)}));
      localStorage.setItem("forensicspp:storage.legacyEvidenceCleanupVersion", JSON.stringify(${JSON.stringify(legacyEvidenceCleanupVersion)}));
      location.hash = ${JSON.stringify(tool)};
    `, awaitPromise: true
  });
  await client.send("Page.reload", { ignoreCache: true });
  await wait(600);
  // wait for the active (non-hidden) view AND its grid to mount
  const ok = await waitForRuntimeValue(client,
    `Boolean(location.hash === ${JSON.stringify(`#${tool}`)} && document.querySelector(${JSON.stringify(`.tool-retained-view[data-tool-id="${tool}"]:not([hidden])`)}) && document.querySelector(${JSON.stringify(`.tool-retained-view[data-tool-id="${tool}"]:not([hidden]) .tool-grid, .tool-retained-view[data-tool-id="${tool}"]:not([hidden]) .sql-workbench`)}))`,
    12000);
  try {
    await client.send("Runtime.evaluate", { expression: `[...document.querySelectorAll('button')].find((b)=>(b.textContent||'').trim()==='确认并进入')?.click();`, awaitPromise: true });
    await wait(300);
  } catch { /* dialog not present */ }
  await wait(450);
  return ok;
}
async function captureViewport(client, filename) {
  const shot = await client.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  await writeFile(join(screenshotDir, filename), Buffer.from(shot.data, "base64"));
}
async function assertServerReachable() {
  return new Promise((resolve, reject) => {
    const req = request(new URL(baseUrl), { method: "HEAD" }, (res) => { res.resume(); if (res.statusCode && res.statusCode < 500) resolve(); else reject(new Error(`${baseUrl} status ${res.statusCode}`)); });
    req.on("error", reject); req.end();
  });
}

const measureExpr = `(() => {
  const topbar = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--topbar-height')) || 0;
  const vh = window.innerHeight;
  const tool = (location.hash || '').replace(/^#/, '');
  const active = document.querySelector('.tool-retained-view[data-tool-id="' + tool + '"]:not([hidden])')
    || [...document.querySelectorAll('.tool-retained-view:not([hidden])')].find((v) => v.querySelector('.tool-grid, .sql-workbench'))
    || null;
  if (!active) return { found:false, reason:'no active view for ' + tool, vh, topbar,
    allViews: [...document.querySelectorAll('.tool-retained-view')].map(v => (v.getAttribute('data-tool-id')||'') + ':' + (v.hasAttribute('hidden') ? 'hidden' : 'vis')) };
  const grids = [...active.querySelectorAll('.tool-grid, .sql-workbench')].filter(g => (g.className||'').toString().includes('empty-') || g.querySelector('.desktop-drop-zone'));
  const g = grids[0] || active.querySelector('.tool-grid') || active.querySelector('.sql-workbench');
  if (!g) return { found:false, reason:'no grid in active view', vh, topbar,
    allViews: [...document.querySelectorAll('.tool-retained-view')].map(v => (v.getAttribute('data-tool-id')||'') + ':' + (v.hasAttribute('hidden') ? 'hidden' : 'vis')) };
  const cs = getComputedStyle(g);
  const gRect = g.getBoundingClientRect();
  const card = g.querySelector('.tool-panel') || g.querySelector('.empty-state') || g.firstElementChild;
  const cRect = card ? card.getBoundingClientRect() : null;
  const expectedMin = vh - topbar - 52;
  const idealTop = cRect ? (gRect.height - cRect.height) / 2 : 0;
  const actualTop = cRect ? (cRect.top - gRect.top) : 0;
  const centered = cRect ? Math.abs(actualTop - idealTop) < 10 : false;
  return {
    found: true,
    gridClass: (g.className||'').toString().slice(0,80),
    computedMinHeight: cs.minHeight,
    computedAlignContent: cs.alignContent,
    gridHeight: Math.round(gRect.height),
    expectedMin: Math.round(expectedMin),
    cardHeight: cRect ? Math.round(cRect.height) : null,
    actualCardTop: Math.round(actualTop),
    idealCardTop: Math.round(idealTop),
    centered,
    fillsViewport: gRect.height >= expectedMin - 4,
    vh, topbar,
    hash: location.hash,
    activeToolId: tool,
    allViews: [...document.querySelectorAll('.tool-retained-view')].map(v => (v.getAttribute('data-tool-id')||'') + ':' + (v.hasAttribute('hidden') ? 'hidden' : 'vis'))
  };
})()`;

async function main() {
  await assertServerReachable();
  if (saveScreenshots) await mkdir(screenshotDir, { recursive: true });
  const report = { baseUrl, generatedAt: new Date().toISOString(), viewport, results: [] };
  const userDataDir = join(tmpdir(), `fpp-measure-empty-${Date.now()}`);
  const chrome = spawn(chromePath, [
    "--headless=new", "--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
    `--remote-debugging-port=${port}`, "--remote-allow-origins=*", `--user-data-dir=${userDataDir}`,
    "--window-size=1366,900", `${baseUrl}/#home`
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let client;
  try {
    const tabs = await waitForCdp();
    const tab = tabs.find((t) => t.type === "page");
    if (!tab) throw new Error("No page target.");
    client = createCdpClient(tab.webSocketDebuggerUrl);
    await client.ready();
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await client.send("Emulation.setDeviceMetricsOverride", { width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false });

    for (const tool of tools) {
      const ok = await loadToolState(client, tool);
      let m = null;
      if (ok) {
        await wait(400);
        const r = await client.send("Runtime.evaluate", { expression: measureExpr, returnByValue: true });
        m = r.result.value;
      }
      if (saveScreenshots) await captureViewport(client, `empty-${tool}.png`);
      const topAligned = m && /^(start|normal|flex-start|stretch)/.test((m.computedAlignContent || "").trim());
      const pass = Boolean(m && m.found && m.fillsViewport && topAligned && !m.centered);
      report.results.push({ tool, loaded: ok, pass, measure: m });
      log(`EMPTY ${tool} loaded=${ok} pass=${pass} measure=${JSON.stringify(m)}`);
    }
  } finally {
    if (client) client.close();
    try { chrome.kill("SIGKILL"); } catch { /* ignore */ }
  }
  await writeFile("empty-measure-p1.json", JSON.stringify(report.results, null, 2));
  log("DONE");
  console.log("DONE -> empty-measure-p1.json");
  process.exit(0);
}
main().catch((e) => { log("FAILED:", e && e.stack || e); console.error("FAILED:", e && e.message); process.exit(1); });

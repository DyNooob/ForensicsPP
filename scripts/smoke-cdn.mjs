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

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { launchSmokeBrowser, prepareSmokePage, serveSmokeDist } from "./browser-smoke.mjs";
import { Ecc, QrCode } from "@rc-component/qrcode/es/libs/qrcodegen.js";

// Exercises actual cross-origin ES module execution with the matching build
// bytes. This does not claim that the live CDN has already been configured.
const root = resolve(process.env.CDN_SMOKE_DIST || "dist");
const manifest = JSON.parse(await readFile("release/vendor-cdn-manifest.json", "utf8"));
const cdn = new URL(manifest.base);
const live = process.env.CDN_SMOKE_LIVE === "1";
const server = await serveSmokeDist(root);
let browser;
try {
  browser = await launchSmokeBrowser();
  const page = await prepareSmokePage(browser);
  if (!live) await page.evaluateOnNewDocument(() => { delete Navigator.prototype.serviceWorker; });
  const errors = [];
  const requests = new Set();
  const workerRequests = [];
  page.on("pageerror", (error) => errors.push(error.message));
  if (!live) await page.setRequestInterception(true);
  page.on("request", async (request) => {
    const url = new URL(request.url());
    if (live) {
      if (url.origin === cdn.origin) requests.add(url.pathname);
      else if (/\.worker-/.test(url.pathname)) workerRequests.push(url.origin);
      return;
    }
    if (url.origin !== cdn.origin) {
      if (/\.worker-/.test(url.pathname)) workerRequests.push(url.origin);
      await request.continue();
      return;
    }
    const file = manifest.files.find((file) => file.url === request.url());
    if (!file) { errors.push(`Unexpected CDN request: ${request.url()}`); await request.abort(); return; }
    requests.add(file.path);
    try {
      await request.respond({ status: 200, contentType: file.path.endsWith(".css") ? "text/css" : "text/javascript",
        headers: { "access-control-allow-origin": "*" }, body: await readFile(resolve(root, file.path)) });
    } catch (error) { errors.push(error.message); await request.abort(); }
  });
  for (const [id, slug] of [["home", ""], ["image", "image-forensics"], ["crypto", "crypto"], ["sql", "sql"], ["email", "email"], ["hash", "hash"]]) {
    await page.goto(`${server.base}/${slug ? `tools/${slug}/` : ""}`, { waitUntil: "networkidle2" });
    await page.waitForSelector(`[data-tool-id="${id}"]:not([hidden])`);
    await page.waitForFunction(() => !document.querySelector(".tool-loading-state, .tool-error-state"));
    if (id === "image") {
      const code = QrCode.encodeText("https://www.forensicspp.com/", Ecc.MEDIUM);
      const modules = Array.from({ length: code.size }, (_, y) => Array.from({ length: code.size }, (_, x) => code.getModule(x, y)));
      await page.evaluate(async (modules) => {
        const canvas = document.createElement("canvas");
        canvas.width = canvas.height = (modules.length + 8) * 6;
        const context = canvas.getContext("2d");
        context.fillStyle = "white";
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.fillStyle = "black";
        modules.forEach((row, y) => row.forEach((black, x) => { if (black) context.fillRect((x + 4) * 6, (y + 4) * 6, 6, 6); }));
        const blob = await new Promise((resolve) => canvas.toBlob(resolve));
        const transfer = new DataTransfer();
        transfer.items.add(new File([blob], "cdn-qr.png", { type: "image/png" }));
        const input = document.querySelector('[data-tool-id="image"] input[type=file]');
        input.files = transfer.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }, modules);
      await page.waitForFunction(() => document.querySelector('[data-tool-id="image"]')?.textContent.includes("cdn-qr.png"));
      await page.evaluate(() => [...document.querySelectorAll('[data-tool-id="image"] button')].find((button) => button.textContent.trim() === "QR").click());
      await page.evaluate(() => [...document.querySelectorAll('[data-tool-id="image"] button')].find((button) => button.textContent.trim() === "Scan QR").click());
      await page.waitForFunction(() => [...document.querySelectorAll('[data-tool-id="image"] textarea')].some((input) => input.value === "https://www.forensicspp.com/"));
    }
  }
  const click = (label) => page.evaluate((label) => [...document.querySelectorAll('[data-tool-id="hash"] button')].find((button) => button.textContent.trim() === label).click(), label);
  await click("Load sample");
  await click("Calculate");
  await page.waitForFunction(() => document.querySelector('[data-tool-id="hash"]')?.textContent.includes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));
  assert.equal(workerRequests.length > 0, true, "a real hash worker must execute");
  assert.equal(workerRequests.every((origin) => origin === server.base), true, "worker entry points must stay same-origin");
  assert.equal([...requests].some((file) => file.includes("vendor-jsqr-")), true, "image tool must load the QR vendor from the CDN");
  assert.deepEqual(errors, []);
  if (live) {
    await page.waitForFunction(() => navigator.serviceWorker.controller);
    await page.setOfflineMode(true);
    await page.reload({ waitUntil: "networkidle2" });
    await click("Load sample");
    await click("Calculate");
    await page.waitForFunction(() => document.querySelector('[data-tool-id="hash"]')?.textContent.includes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));
    assert.deepEqual(errors, []);
  }
  console.log(`${live ? "Live" : "Simulated"} cross-origin CDN smoke passed: ${requests.size} vendor resources, six tools and real hash worker execution${live ? ", including offline reload" : ""}.`);
} finally {
  await browser?.close();
  await server.close();
}

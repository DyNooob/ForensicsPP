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

import { launchSmokeBrowser, prepareSmokePage, serveSmokeDist } from "./browser-smoke.mjs";
import { resolve } from "node:path";
import assert from "node:assert/strict";

// Small PNG with trailing bytes exercises the >4 MiB blob preview path without
// allocating a large pixel buffer. A shell rerender must preserve its URL.
const server = await serveSmokeDist(resolve("dist"));
let browser;
try {
  browser = await launchSmokeBrowser();
  const page = await prepareSmokePage(browser);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${server.base}/tools/image-forensics/`, { waitUntil: "networkidle2", timeout: 60000 });
  await page.waitForSelector('[data-tool-id="image"] input[type=file]');
  await page.evaluate(async () => {
    const canvas = document.createElement("canvas");
    canvas.width = 16;
    canvas.height = 16;
    canvas.getContext("2d").fillRect(0, 0, 16, 16);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve));
    const bytes = new Uint8Array(4 * 1024 * 1024 + 1024);
    bytes.set(new Uint8Array(await blob.arrayBuffer()));
    const transfer = new DataTransfer();
    transfer.items.add(new File([bytes], "blob-regression.png", { type: "image/png" }));
    const input = document.querySelector('[data-tool-id="image"] input[type=file]');
    input.files = transfer.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page.waitForFunction(() => [...document.images].some((image) => image.src.startsWith("blob:")), { timeout: 60000 });
  const url = await page.evaluate(() => [...document.images].find((image) => image.src.startsWith("blob:")).src);
  const readable = () => page.evaluate(async (url) => {
    try { return (await fetch(url)).ok; } catch { return false; }
  }, url);
  assert.equal(await readable(), true, "original blob preview must be readable");
  await page.evaluate(() => [...document.querySelectorAll(".language-switch button")].find((button) => button.textContent.trim() === "中文").click());
  await page.waitForFunction(() => document.documentElement.lang.startsWith("zh"));
  assert.equal(await readable(), true, "language changes must preserve the active blob preview");
  await page.evaluate(() => [...document.querySelectorAll('[data-tool-id="image"] button')].find((button) => button.textContent.trim() === "清空").click());
  assert.equal(await readable(), false, "clearing must release the blob preview");
  assert.deepEqual(errors, [], "image analysis must not raise uncaught errors");
  console.log("Image blob lifecycle passed: upload, language change, clear.");
} finally {
  await browser?.close();
  await server.close();
}

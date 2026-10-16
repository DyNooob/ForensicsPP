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
import { readFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { launchSmokeBrowser, prepareSmokePage, serveSmokeDist } from "./browser-smoke.mjs";

// Deterministic packs exercise the real persistence path and the real Worker.
// Set SMOKE_PACK_DIR to use locally fetched copies of the pinned upstream packs.
const record = Buffer.from("Fixture province|Fixture city|100000|010\0");
const indexStart = 8 + record.length;
const phone = Buffer.alloc(indexStart + 9);
phone.writeUInt32LE(indexStart, 4); record.copy(phone, 8);
phone.writeUInt32LE(1380013, indexStart); phone.writeUInt32LE(8, indexStart + 4); phone[indexStart + 8] = 1;
const region = Buffer.from("United States|California|Fixture city|Fixture ISP|US");
const ipIndex = 256 + 65536 * 8;
const ip = Buffer.alloc(ipIndex + 14 + region.length);
const vector = 256 + (8 * 256 + 8) * 8;
ip.writeUInt32LE(ipIndex, vector); ip.writeUInt32LE(ipIndex, vector + 4);
ip.set([8,8,8,8,8,8,8,8], ipIndex);
ip.writeUInt16LE(region.length, ipIndex + 8); ip.writeUInt32LE(ipIndex + 14, ipIndex + 10); region.copy(ip, ipIndex + 14);
const id = Buffer.from(JSON.stringify({ areas: { "110105": [{ name: "Fixture district", path: "Fixture city/Fixture district", status: "active", start_year: "1980" }] } }));
const packs = { phone, ip, id };
if (process.env.SMOKE_PACK_DIR) for (const name of Object.keys(packs)) packs[name] = await readFile(resolve(process.env.SMOKE_PACK_DIR, name));
const browser = await launchSmokeBrowser();
const server = await serveSmokeDist(resolve("dist"));
const page = await prepareSmokePage(browser);
let checks = 0;
const check = (value, message) => { assert.ok(value, message); checks++; console.log("✓ " + message); };
let packRequests = 0;
let failNextPack = true;
await page.setRequestInterception(true);
page.on("request", (request) => {
  if (!request.url().includes("cdn.jsdelivr.net/gh/")) return void request.continue();
  packRequests++;
  const name = request.url().endsWith(".xdb") ? "ip" : request.url().endsWith(".dat") ? "phone" : "id";
  const failed = failNextPack; failNextPack = false;
  const respond = () => request.respond({ status: failed ? 503 : 200, headers: { "Access-Control-Allow-Origin": "*", "Content-Length": String(failed ? 5 : packs[name].length) }, body: failed ? "error" : packs[name] });
  if (name === "ip") setTimeout(() => { void respond(); }, 1500);
  else void respond();
});
const screenshots = resolve("tmp/settings-review");
await mkdir(screenshots, { recursive: true });
const capture = async (name) => {
  await page.mouse.move(5, 5);
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await page.waitForFunction(() => document.getAnimations().every((animation) => animation.effect?.getComputedTiming().iterations === Infinity || animation.playState !== 'running'));
  await page.screenshot({ path: resolve(screenshots, name) });
};
const clickText = async (selector, text) => {
  const target = await page.waitForFunction((selector, text) => [...document.querySelectorAll(selector)].find((el) => el.textContent.trim() === text && el.checkVisibility()), {}, selector, text);
  await target.asElement().click();
  await target.dispose();
};
const closeSettings = async () => {
  await page.locator('.settings-modal .ant-modal-close').click();
  await page.waitForSelector('.settings-modal', { hidden: true });
};
const clickSettings = async (label = "Settings") => {
  const headerVisible = await page.$eval('.settings-toggle', (el) => getComputedStyle(el).display !== 'none');
  await page.locator(headerVisible ? '.settings-toggle' : `.tool-sidebar button[aria-label="${label}"]`).click();
};
try {
  await page.setViewport({ width: 1440, height: 1000 });
  await page.goto(server.base + "/tools/cyberchef/", { waitUntil: "networkidle0" });
  await page.waitForSelector('.cyberchef-stage iframe.is-loaded', { timeout: 30000 });
  const frame = await (await page.$('.cyberchef-stage iframe')).contentFrame();
  check(await frame.title() === "CyberChef", "deep link embeds CyberChef rather than the app shell");
  const chefUrl = frame.url();
  check(new URL(chefUrl).pathname === "/cyberchef/CyberChef_v11.5.0.html", "embedded document resolves from the application root");
  await frame.goto(chefUrl + "#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=Rm9yZW5zaWNzKys", { waitUntil: "networkidle0" });
  await frame.waitForFunction(() => document.querySelector("#output-text")?.textContent.includes("Rm9yZW5zaWNzKys="), { timeout: 30000 });
  check(true, "CyberChef recipe executes through the bundled engine");
  const standaloneChef = await browser.newPage();
  await standaloneChef.goto(chefUrl, { waitUntil: "networkidle0" });
  check(await standaloneChef.title() === "CyberChef", "CyberChef also opens independently");
  await standaloneChef.close();
  await page.goto(server.base + "/tools/lookup/", { waitUntil: "networkidle0" });
  await page.evaluate(async () => { await navigator.serviceWorker.ready; });
  await clickSettings();
  await clickText('.settings-sidebar .ant-menu-item', 'Local Data');
  await page.waitForSelector('[data-pack="id"] button[aria-label]');
  await page.locator('[data-pack="id"] button[aria-label]').click();
  await page.waitForSelector('[data-pack="id"] [role="alert"]');
  check(!(await page.$('[data-pack="id"] .settings-pack-cached')), "failed downloads stay unlocalized with a retry action");
  for (const name of ["id", "phone", "ip"]) {
    await page.locator(`[data-pack="${name}"] button[aria-label]`).click();
    if (name === "ip") {
      await page.waitForSelector('[data-pack="ip"] [role="status"]');
      await closeSettings();
      await clickSettings();
      await clickText('.settings-sidebar .ant-menu-item', 'Local Data');
    }
    await page.waitForSelector(`[data-pack="${name}"] .settings-pack-cached`, { timeout: 30000 });
  }
  check(packRequests === 4, "localization downloads each pack once, plus the explicit retry");
  check(true, "downloads continue when settings closes and progress survives reopening");
  await capture("storage.png");
  await clickText('.settings-sidebar .ant-menu-item', 'Appearance');
  await capture("appearance.png");
  await clickText('.settings-main .ant-segmented-item', 'Dark');
  await capture("appearance-dark.png");
  await clickText('.settings-main .ant-segmented-item', 'Light');
  await page.setViewport({ width: 390, height: 844 });
  check(await page.$$eval(".settings-sidebar .ant-menu-item", (items) => new Set(items.map(el => Math.round(el.getBoundingClientRect().top))).size === 1), "mobile navigation stays in one row");
  for (const name of ['Appearance', 'Local Data', 'About', 'Open Source']) {
    await clickText('.settings-sidebar .ant-menu-item', name);
    check(await page.$eval('.settings-main', (el) => el.scrollWidth <= el.clientWidth + 1), `mobile ${name} has no horizontal overflow`);
  }
  await clickText('.settings-sidebar .ant-menu-item', 'Local Data');
  await capture("storage-mobile.png");
  await page.setViewport({ width: 1440, height: 1000 });
  await closeSettings();
  async function query(value) {
    await page.waitForSelector('.lookup-input');
    await clickText('[data-tool-id="lookup"] button', 'Clear');
    await page.type('.lookup-input', value);
    await clickText('[data-tool-id="lookup"] button', 'Run lookup');
    await page.waitForSelector('.lookup-result-table tbody tr', { timeout: 30000 });
    return page.$eval('.lookup-result-table tbody', (el) => el.innerText);
  }
  // Warm lazy chunks, then reload offline to replace the Worker and its memory.
  await query('13800138000');
  await page.setOfflineMode(true);
  await page.reload({ waitUntil: 'networkidle0' });
  for (const value of ['13800138000', '11010519491231002X', '8.8.8.8']) {
    const output = await query(value);
    check(!output.includes('No match') && !output.includes('Prefix not found'), `fresh offline Worker queries localized ${value}`);
  }
  check(packRequests === 4, "reload and subsequent lookups issue no new pack download requests");
  await page.setOfflineMode(false);
  await clickSettings();
  await clickText('.settings-sidebar .ant-menu-item', 'Local Data');
  await page.waitForFunction(() => document.querySelectorAll('.settings-pack-cached').length === 3);
  check(true, "all three localized statuses survive reload");
  const legal = await (await fetch(server.base + '/legal.html')).text();
  check(legal.includes('2026-10-13-v4') && legal.includes('本地化') && legal.includes('CyberChef'), 'updated terms describe the shipped behavior');
  await closeSettings();
  await clickText('.language-switch button', '中文');
  await clickSettings("设置");
  await clickText('.settings-sidebar .ant-menu-item', '本地数据');
  await page.waitForFunction(() => document.querySelectorAll('.settings-pack-cached').length === 3);
  await capture('storage-localized-zh.png');
  await page.evaluate(async () => { const cache = await caches.open('forensicspp-lookup-data-v1'); for (const request of await cache.keys()) if (request.url.endsWith('/areas.json')) await cache.delete(request); });
  await clickText('.settings-main button', '检查状态');
  await page.waitForSelector('[data-pack="id"] button[aria-label]');
  await capture('storage-zh.png');
  await clickText('.settings-sidebar .ant-menu-item', '外观');
  await capture('appearance-zh.png');
  console.log(`Settings/CyberChef smoke: ${checks} checks passed.`);
} catch (error) {
  await capture("failure.png");
  console.log(await page.evaluate(() => ({ url: location.href, consent: document.querySelector(".legal-consent-modal")?.textContent, accepted: localStorage.getItem("forensicspp:legal.acceptedVersion"), settings: [...document.querySelectorAll(".settings-toggle")].map(el => ({rect: el.getBoundingClientRect().toJSON(), display: getComputedStyle(el).display})) })));
  throw error;
} finally { await browser.close(); await server.close(); }

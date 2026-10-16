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

//
// Standalone (file://) hash-route smoke test for Forensics++.
// Verifies that the single-file build still opens tools via legacy hash
// routes (#evtx, #sqlite, ...) with no dependency on a server rewrite.
import { launchSmokeBrowser, prepareSmokePage, serveSmokeDist } from "./browser-smoke.mjs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SLUG_TO_TOOL } from "../src/seo/toolRoutes.mjs";
const distHtml = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.html");
const FILE_URL = "file://" + distHtml;

const browser = await launchSmokeBrowser();
const page = await prepareSmokePage(browser);
let pass = 0, fail = 0;
const fails = [];
const check = (c, m) => { c ? pass++ : (fail++, fails.push(m), console.log("  ✗ " + m)); };

// Use the registry as the single source for canonical ids (so we never
// hardcode a wrong hash like "#apk" when the real id is "apk-signature").
const slugList = [
  "evtx-viewer",
  "sqlite-forensics",
  "pcap-analyzer",
  "firmware-analyzer",
  "apk-signature-analyzer",
  "image-forensics",
];
for (const slug of slugList) {
  const id = SLUG_TO_TOOL[slug];
  await page.goto(FILE_URL + "#" + id, { waitUntil: "networkidle0", timeout: 30000 }).catch(() => {});
  await page.waitForFunction(() => {
    const r = document.getElementById("root");
    return r && r.children.length > 0;
  }, { timeout: 15000 }).catch(() => {});
  const active = await page.$(`[data-tool-id="${id}"]:not([hidden])`).catch(() => null);
  check(!!active, `file:// #${id} opens active ToolHost=${id}`);
  check(!(await page.$(".tool-error-state")), `file:// #${id} renders without an initialization error`);
  const loc = await page.evaluate(() => location.hash);
  check(loc === "#" + id, `file:// #${id} hash stable (got ${loc})`);
}

const isFile = await page.evaluate(() => location.protocol === "file:");
check(isFile, "standalone runs as file:// protocol");

await page.goto(FILE_URL + "#cyberchef", { waitUntil: "networkidle0" });
await page.waitForSelector(".cyberchef-stage iframe.is-loaded", { timeout: 30000 });
const chefFrame = await (await page.$(".cyberchef-stage iframe")).contentFrame();
check(await chefFrame.title() === "CyberChef", "file:// embeds the bundled CyberChef document");
check(chefFrame.url().includes("/dist/cyberchef/CyberChef_v11.5.0.html"), "file:// CyberChef resolves beside the app entry");

// Full worker functionality is verified over local HTTP with the inlined build.
const server = await serveSmokeDist(dirname(distHtml));
try {
  await page.goto(server.base + "/#hash", { waitUntil: "networkidle0" });
  await page.waitForSelector('[data-tool-id="hash"] .hash-simple-input-panel');
  await page.evaluate(() => [...document.querySelectorAll('[data-tool-id="hash"] button')].find((button) => button.textContent.trim() === "Load sample").click());
  await page.evaluate(() => [...document.querySelectorAll('[data-tool-id="hash"] button')].find((button) => button.textContent.trim() === "Calculate").click());
  await page.waitForFunction(() => document.querySelector('[data-tool-id="hash"]')?.textContent.includes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));
  check(true, "inlined build runs a hash Worker over HTTP");
  await page.goto(server.base + "/#sqlite", { waitUntil: "networkidle0" });
  const fileInput = await page.$('[data-tool-id="sqlite"] input[type="file"]');
  await fileInput.uploadFile(join(dirname(distHtml), "..", "tests", "fixtures", "sqlite-deleted-record.sqlite"));
  await page.waitForSelector(".sqlite-browser-grid.has-sqlite");
  check(true, "inlined build loads SQLite and its WASM over HTTP");
} catch (error) {
  console.log("Standalone runtime URL:", page.url());
  console.log((await page.$eval("#root", (el) => el.innerText)).slice(-2500));
  check(false, "inlined HTTP execution: " + error.message);
}
finally { await browser.close(); await server.close(); }

console.log(`\n=== STANDALONE RESULT: ${pass} passed, ${fail} failed ===`);
if (fail) { console.log("FAILURES:\n" + fails.map((f) => " - " + f).join("\n")); process.exit(1); }

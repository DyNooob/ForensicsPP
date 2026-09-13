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
import { createRequire } from "node:module";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SLUG_TO_TOOL } from "../src/seo/toolRoutes.mjs";
const require = createRequire(import.meta.url);
const puppeteer = require("puppeteer-core");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const distHtml = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.html");
const FILE_URL = "file://" + distHtml;

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--allow-file-access-from-files"],
});
const page = await browser.newPage();
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
  const loc = await page.evaluate(() => location.hash);
  check(loc === "#" + id, `file:// #${id} hash stable (got ${loc})`);
}

const isFile = await page.evaluate(() => location.protocol === "file:");
check(isFile, "standalone runs as file:// protocol");

await browser.close();
console.log(`\n=== STANDALONE RESULT: ${pass} passed, ${fail} failed ===`);
if (fail) { console.log("FAILURES:\n" + fails.map((f) => " - " + f).join("\n")); process.exit(1); }

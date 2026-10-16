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

import puppeteer from "puppeteer-core";
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { resolve, extname } from "node:path";

export async function launchSmokeBrowser() {
  const executablePath = process.env.CHROME_PATH || [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"
  ].find(existsSync);
  if (!executablePath) throw new Error("Chrome not found. Set CHROME_PATH to a Chrome/Chromium executable.");
  return puppeteer.launch({ executablePath, headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
}

export async function prepareSmokePage(browser) {
  const source = await readFile(new URL("../src/config/app.ts", import.meta.url), "utf8");
  const legalVersion = /export const legalVersion = "([^"]+)"/.exec(source)?.[1];
  if (!legalVersion) throw new Error("Missing legal version");
  const page = await browser.newPage();
  await page.evaluateOnNewDocument((version) => {
    // Test preferences belong to the app document, not embedded tools or their
    // opaque data:/blob: frames, where touching localStorage throws.
    if (window.top !== window || !["http:", "https:", "file:"].includes(location.protocol)) return;
    localStorage.setItem("forensicspp:legal.acceptedVersion", JSON.stringify(version));
    localStorage.setItem("forensicspp:app.lang", JSON.stringify("en"));
  }, legalVersion);
  return page;
}

export async function serveSmokeDist(root) {
  const server = createServer(async (req, res) => {
    try {
      const pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
      let file = resolve(root, `.${pathname}`);
      if (file !== root && !file.startsWith(root + "/")) { res.writeHead(403); res.end(); return; }
      try { if ((await stat(file)).isDirectory()) file = resolve(file, "index.html"); }
      catch { if (!extname(pathname)) file = resolve(root, "index.html"); }
      const data = await readFile(file);
      const mime = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".css": "text/css" };
      res.writeHead(200, { "content-type": mime[extname(file)] || "application/octet-stream" });
      res.end(data);
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}

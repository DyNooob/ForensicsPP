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

import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { launchSmokeBrowser, prepareSmokePage, serveSmokeDist } from './browser-smoke.mjs';
import { verifyOfflineDistribution } from './verify-offline.mjs';

const root = resolve(process.env.OFFLINE_ROOT || 'dist');
await verifyOfflineDistribution(root);
const source = await readFile('src/config/app.ts', 'utf8');
const defs = source.slice(source.indexOf('const toolDefinitions = ['), source.indexOf('] as const;'));
const ids = defs.split('\n').filter(line => line.includes('{ id: "') && !line.includes('hidden: true')).map(line => /id: "([^"]+)"/.exec(line)?.[1]).filter(Boolean);
const server = process.env.OFFLINE_PROTOCOL === 'http' ? await serveSmokeDist(root) : null;
const entry = server ? server.base + '/' : pathToFileURL(resolve(root, 'index.html')).href;
// All HTTP(S) traffic except loopback is forced into a closed proxy, including Worker traffic.
const browser = await launchSmokeBrowser({ blockExternal: true });
const page = await prepareSmokePage(browser);
const errors = [], external = [], policy = [], checks = [];
page.on('pageerror', error => errors.push(error.message));
page.on('request', request => { if (/^https?:/.test(request.url()) && (!server || new URL(request.url()).origin !== server.base)) external.push(request.url()); });
await page.evaluateOnNewDocument(() => document.addEventListener('securitypolicyviolation', event => {
  if (/^https?:/.test(event.blockedURI)) console.error('OFFLINE_POLICY_VIOLATION:' + event.blockedURI);
}));
page.on('console', msg => { if (msg.text().startsWith('OFFLINE_POLICY_VIOLATION:')) policy.push(msg.text()); });
const click = async (root, label) => {
  const handle = await page.evaluateHandle((root, label) => [...document.querySelectorAll(root + ' button')].find(el => el.textContent.trim() === label), root, label);
  assert(handle.asElement(), 'Missing action: ' + label); await handle.asElement().click(); await handle.dispose();
};
const goto = async id => { await page.goto(entry + '#' + id, { waitUntil: 'networkidle2', timeout: 60000 }); await page.waitForSelector(`[data-tool-id="${id}"]:not([hidden])`, { timeout: 30000 }); };
const setText = async (selector, text) => page.$eval(selector, (el, text) => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(el, text); el.dispatchEvent(new Event('input', { bubbles: true })); }, text);
try {
  await page.setViewport({ width: 1440, height: 1000 });
  for (const id of ids) {
    await goto(id);
    assert.equal(await page.$('.tool-error-state'), null, id + ' must initialize');
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), id + ' must fit the viewport');
    checks.push({ tool: id, initialized: true });
    console.log('Offline tool initialized:', id);
  }
  await goto('lookup');
  for (const input of ['13800138000', '11010519491231002X', '8.8.8.8']) {
    await page.$eval('.lookup-input', (el, text) => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(el, text); el.dispatchEvent(new Event('input', { bubbles: true })); }, input);
    await click('[data-tool-id="lookup"]', 'Run lookup');
    await page.waitForFunction(() => Boolean(document.querySelector('.lookup-result-table tbody tr') || document.querySelector('.lookup-results-panel tbody tr')), { timeout: 60000 });
    const body = await page.$eval('[data-tool-id="lookup"]', el => el.innerText);
    assert(!/download failed|invalid data|lookup data pack:|查询失败/i.test(body), input + ' must use bundled data');
    assert(body.includes(input));
    await click('[data-tool-id="lookup"]', 'Clear');
    console.log('Cold offline lookup passed:', input);
  }
  await goto('chinese');
  await setText('.chinese-converter textarea:not([readonly])', '头发与发展，后台与皇后。');
  await page.focus('.chinese-converter textarea');
  await page.keyboard.down('Control'); await page.keyboard.down('Shift'); await page.keyboard.press('Enter'); await page.keyboard.up('Shift'); await page.keyboard.up('Control');
  await page.waitForFunction(() => document.querySelector('.chinese-converter textarea[readonly]')?.value === '頭髮與發展，後臺與皇后。', { timeout: 60000 });
  await page.screenshot({ path: resolve('tmp/offline-chinese-desktop.png'), fullPage: true });
  await page.setViewport({ width: 390, height: 844 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await page.screenshot({ path: resolve('tmp/offline-chinese-mobile.png'), fullPage: true });
  await page.setViewport({ width: 1440, height: 1000 });
  await goto('hash'); await click('[data-tool-id="hash"]', 'Load sample'); await click('[data-tool-id="hash"]', 'Calculate');
  await page.waitForFunction(() => document.querySelector('[data-tool-id="hash"]')?.textContent.includes('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'), { timeout: 60000 });
  await goto('sqlite');
  await (await page.$('[data-tool-id="sqlite"] input[type=file]')).uploadFile(resolve('tests/fixtures/sqlite-deleted-record.sqlite'));
  await page.waitForSelector('.sqlite-browser-grid.has-sqlite', { timeout: 60000 });
  await goto('binary');
  await page.evaluate(() => {
    const transfer = new DataTransfer(); transfer.items.add(new File(['portable-file runtime fixture'], 'portable.bin'));
    const input = document.querySelector('[data-tool-id="binary"] input[type=file]'); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await page.waitForSelector('.binary-workbench.has-binary', { timeout: 60000 });
  await click('[data-tool-id="binary"]', 'YARA');
  await setText('.yara-simple-editor', 'rule portable_file { strings: $a = "portable-file" condition: $a }');
  await click('[data-tool-id="binary"]', 'Scan current file');
  await page.waitForFunction(() => document.querySelector('.binary-yara-panel .finding-item strong')?.textContent === 'portable_file', { timeout: 60000 });
  console.log('Direct offline YARA WASM match passed');
  await goto('documentforensics');
  await page.evaluate(() => {
    const objects = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>', '<< /Length 0 >>\nstream\n\nendstream', '<< /Title (Portable PDF) /Author (Forensics++) >>'];
    let pdf = '%PDF-1.7\n'; const offsets = [0];
    objects.forEach((body, index) => { offsets.push(pdf.length); pdf += `${index + 1} 0 obj\n${body}\nendobj\n`; });
    const xref = pdf.length;
    pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const offset of offsets.slice(1)) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
    pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    const transfer = new DataTransfer(); transfer.items.add(new File([pdf], 'portable.pdf', { type: 'application/pdf' }));
    const input = document.querySelector('[data-tool-id="documentforensics"] input[type=file]'); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await click('[data-tool-id="documentforensics"]', 'Inspect document');
  await page.waitForSelector('.document-forensics-results', { timeout: 60000 });
  assert((await page.$eval('.document-forensics-results', el => el.innerText)).includes('PDF'));
  await page.evaluate(() => [...document.querySelectorAll('[data-tool-id="documentforensics"] button')].find(button => button.textContent.trim().startsWith('Metadata (')).click());
  assert((await page.$eval('.document-forensics-results', el => el.innerText)).includes('Portable PDF'));
  console.log('Direct offline PDF worker passed');
  await goto('cyberchef'); await page.waitForSelector('.cyberchef-stage iframe.is-loaded', { timeout: 30000 });
  const frame = await (await page.$('.cyberchef-stage iframe')).contentFrame();
  await frame.goto(frame.url() + "#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=Rm9yZW5zaWNzKys", { waitUntil: 'networkidle2' });
  await frame.waitForFunction(() => document.querySelector('#output-text')?.textContent.includes('Rm9yZW5zaWNzKys='), { timeout: 30000 });
  if (process.env.HEIC_FIXTURE) {
    await goto('image');
    await (await page.$('[data-tool-id="image"] input[type=file]')).uploadFile(resolve(process.env.HEIC_FIXTURE));
    await page.waitForSelector('.image-metadata-highlights', { timeout: 120000 });
    assert(await page.$eval('.image-viewer-img', el => el.naturalWidth > 1000));
    assert(await page.$eval('.image-metadata', el => el.innerText.includes('iPhone XS Max')));
    await page.evaluate(() => [...document.querySelectorAll('.language-switch button')].find(button => button.textContent.trim() === '中文').click());
    await page.waitForFunction(() => document.documentElement.lang.startsWith('zh'));
    await page.screenshot({ path: resolve('tmp/offline-heic-desktop.png'), fullPage: true });
  }
  assert.deepEqual(errors, [], 'No uncaught browser errors');
  assert.deepEqual(external, [], 'No remote runtime requests');
  assert.deepEqual(policy, [], 'No blocked remote resource attempts');
  // Prove the policy rejects an explicit external connection, without allowing any egress.
  assert.equal(await page.evaluate(async () => { try { await fetch('https://offline-must-block.invalid/'); return false; } catch { return true; } }), true);
  await mkdir('tmp', { recursive: true });
  await writeFile('tmp/offline-smoke-report.json', JSON.stringify({ protocol: new URL(entry).protocol, tools: checks, external, errors, coldLookupPacks: 3, chineseShortcut: true, hashWorker: true, sqliteWasm: true, yaraWasm: true, pdfWorker: true, cyberchefRecipe: true, heic: Boolean(process.env.HEIC_FIXTURE), externalPolicyBlocked: true }, null, 2));
  console.log(`Offline smoke passed: ${ids.length} tools, cold lookup data, Chinese, hash, SQLite WASM, CyberChef${process.env.HEIC_FIXTURE ? ', HEIC' : ''}; zero remote requests.`);
} catch (error) {
  await mkdir('tmp', { recursive: true });
  await writeFile('tmp/offline-smoke-failure.txt', JSON.stringify({ url: page.url(), errors, external, policy, text: await page.$eval('body', el => el.innerText) }, null, 2));
  throw error;
} finally { await browser.close(); if (server) await server.close(); }

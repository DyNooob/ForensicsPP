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

import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
await mkdir('tmp', { recursive: true });
import {launchSmokeBrowser,prepareSmokePage,serveSmokeDist} from './browser-smoke.mjs';
import {TOOL_SLUG} from '../src/seo/toolRoutes.mjs';
const source=await readFile('src/config/app.ts','utf8');const defs=source.slice(source.indexOf('const toolDefinitions = ['),source.indexOf('] as const;'));
const ids=defs.split('\n').filter(l=>l.includes('{ id: "')&&!l.includes('hidden: true')).map(l=>/id: "([^"]+)"/.exec(l)?.[1]).filter(Boolean);
const server = process.env.USABILITY_URL ? null : await serveSmokeDist(resolve('dist'));
const base=process.env.USABILITY_URL || server.base;const prefix='usability';
const browser=await launchSmokeBrowser();const page=await prepareSmokePage(browser);const results=[];
try{for(const viewport of (process.env.USABILITY_FLOWS_ONLY ? [] : [{width:1280,height:640},{width:390,height:844}])){
 await page.setViewport(viewport);
 for(const id of ids){
 try{
 await page.goto(`${base}/${id==='home'?'':`tools/${TOOL_SLUG[id]||id}/`}`,{waitUntil:'networkidle2',timeout:30000});
 await page.waitForSelector(`[data-tool-id="${id}"]:not([hidden])`);
 await page.waitForFunction(()=>!document.querySelector('.tool-loading-state'));
 await page.evaluate(()=>{
 const setter=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
 for(const el of document.querySelectorAll('[data-tool-id]:not([hidden]) textarea:not([readonly])')){
 if(!el.getBoundingClientRect().width)continue;
 setter.call(el,Array.from({length:60},(_,i)=>`Line ${i+1}: Long input 0123456789 abcdefghijklmnopqrstuvwxyz`).join('\n'));
 el.dispatchEvent(new Event('input',{bubbles:true}));
 }
 });
 await page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));
 const state=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth-document.documentElement.clientWidth,editors:[...document.querySelectorAll('[data-tool-id]:not([hidden]) textarea')].filter(e=>e.getBoundingClientRect().width).map(e=>({class:e.className,readonly:e.readOnly,valueLength:e.value.length,height:Math.round(e.getBoundingClientRect().height),lineHeight:parseFloat(getComputedStyle(e).lineHeight),scrollHeight:e.scrollHeight,auto:e.dataset.autoSize})),error:document.querySelector('.tool-error-state')?.textContent}));
 results.push({id,viewport,...state});
 if(['http','json'].includes(id)&&viewport.width===1280)await page.screenshot({path:`tmp/ui-${prefix}-${id}.png`,fullPage:true});
 }catch(e){results.push({id,viewport,error:e.message})}
 }
 console.log(prefix,viewport.width,'complete');await writeFile(`tmp/ui-editors-${prefix}.json`,JSON.stringify(results,null,2));
}console.log(JSON.stringify({tools:ids.length,cases:results.length,errors:results.filter(r=>r.error),small:results.flatMap(r=>r.editors?.filter(e=>e.height<e.lineHeight*5&&!e.readonly).map(e=>({id:r.id,viewport:r.viewport,...e}))||[])}));

assert.equal(results.filter(r => r.error || r.overflow > 1 || r.editors?.some(e => e.valueLength > 1000 && !e.readonly && e.height < 150)).length, 0, 'all visible editors must remain readable at both viewport sizes');
await verifyClipboardAndImage(page, base);
}finally{await browser.close(); await server?.close()}


async function clickLabel(page, selector, label) {
  const handle = await page.evaluateHandle((selector, label) => [...document.querySelectorAll(selector + ' button')].find((button) => button.textContent.trim() === label), selector, label);
  const button = handle.asElement();
  assert(button, `Missing button: ${label}`);
  await button.click();
  await handle.dispose();
}

async function verifyClipboardAndImage(page, base) {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.setViewport({ width: 1440, height: 900 });
  await page.goto(base + '/', { waitUntil: 'networkidle2' });
  const png = await page.evaluate(async () => {
    const canvas = document.createElement('canvas'); canvas.width = 1024; canvas.height = 640;
    const context = canvas.getContext('2d'); context.fillStyle = '#4968aa'; context.fillRect(0, 0, 1024, 640);
    context.clearRect(150, 100, 500, 300);
    return Array.from(new Uint8Array(await (await new Promise((resolve) => canvas.toBlob(resolve))).arrayBuffer()));
  });
  const pasteFiles = (files) => page.evaluate((files) => {
    const transfer = new DataTransfer();
    files.forEach(({ name, bytes, type }) => transfer.items.add(new File([new Uint8Array(bytes)], name, { type })));
    document.body.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: transfer }));
  }, files);
  await pasteFiles([{ name: 'screenshot-native.png', bytes: png, type: 'image/png' }]);
  await page.waitForFunction(() => document.querySelector('[data-tool-id="image"]')?.textContent.includes('screenshot-native.png'));
  const imageRoot = '[data-tool-id="image"]';
  await clickLabel(page, imageRoot, '100%');
  assert.equal(await page.$eval('.image-viewer-img', (image) => Math.round(image.getBoundingClientRect().width) === image.naturalWidth), true, '100% must show native image pixels');
  await page.focus('.image-viewer-viewport');
  await page.keyboard.press('0');
  assert.equal(await page.$eval('.image-viewer-viewport', (view) => view.querySelector('img').getBoundingClientRect().width <= view.clientWidth + 1), true, 'fit must contain the full image');
  await clickLabel(page, imageRoot, 'Expand');
  await page.waitForSelector('.image-lightbox-modal');
  await page.waitForFunction(() => document.querySelector('.image-lightbox-modal')?.contains(document.activeElement));
  await page.keyboard.press('Escape');
  await page.waitForSelector('.image-lightbox-modal', { hidden: true });
  assert.equal(await page.evaluate(() => document.activeElement?.textContent.trim()), 'Expand', 'closing preview restores keyboard focus');
  await page.screenshot({ path: 'tmp/ui-image-overview-desktop.png', fullPage: true });
  await page.setViewport({ width: 390, height: 844 });
  await page.screenshot({ path: 'tmp/ui-image-overview-mobile.png', fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), true);
  await page.setViewport({ width: 1440, height: 900 });
  await clickLabel(page, imageRoot, 'Structure');
  await page.waitForSelector('.image-metadata-controls input');
  await page.type('.image-metadata-controls input', 'not-a-real-field');
  await page.waitForFunction(() => document.querySelector('.image-metadata')?.textContent.includes('No matching metadata'));
  await page.screenshot({ path: 'tmp/ui-image-metadata-search.png', fullPage: true });
  await mkdir('tmp/ui-downloads', { recursive: true });
  const metadataPath = resolve('tmp/ui-downloads/screenshot-native-metadata.json');
  await rm(metadataPath, { force: true });
  const downloads = await page.createCDPSession();
  await downloads.send('Page.setDownloadBehavior', { behavior: 'allow', downloadPath: resolve('tmp/ui-downloads') });
  await clickLabel(page, imageRoot, 'Export all metadata');
  let exported;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { exported = JSON.parse(await readFile(metadataPath, 'utf8')); break; } catch { await new Promise(resolve => setTimeout(resolve,100)); }
  }
  assert.equal(Boolean(exported && Object.keys(exported).length >= 5), true, 'metadata export must include every field even when the search has no matches');
  await downloads.detach();
  await clickLabel(page, imageRoot, 'Overview');
  await page.evaluate((bytes) => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { read: async () => [{ types: ['image/png', 'text/html'], getType: async () => new Blob([new Uint8Array(bytes)], { type: 'image/png' }) }] } }), png);
  await page.evaluate(() => document.querySelector('.image-source-panel').dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 500, clientY: 150 })));
  await page.waitForSelector('.clipboard-context-menu button');
  await page.click('.clipboard-context-menu button');
  await page.waitForFunction(() => document.querySelector('[data-tool-id="image"]')?.textContent.includes('clipboard-'));
  await page.goto(base + '/tools/hash/', { waitUntil: 'networkidle2' });
  await pasteFiles([{ name: 'clipboard-first.txt', bytes: [65,66,67], type: 'text/plain' }, { name: 'clipboard-second.bin', bytes: [1,2,3], type: 'application/octet-stream' }]);
  await page.waitForFunction(() => document.querySelector('[data-tool-id="hash"]')?.textContent.includes('clipboard-first.txt') && document.querySelector('[data-tool-id="hash"]')?.textContent.includes('clipboard-second.bin'));
  await page.goto(base + '/', { waitUntil: 'networkidle2' });
  await pasteFiles([{ name: 'automatic-binary.bin', bytes: [0,1,2,3,65,66,67], type: 'application/octet-stream' }]);
  await page.waitForFunction(() => document.querySelector('[data-tool-id="binary"]:not([hidden])')?.textContent.includes('automatic-binary.bin'));
  await page.goto(base + '/tools/json/', { waitUntil: 'networkidle2' });
  await page.$eval('textarea:not([readonly])', (field) => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(field,JSON.stringify(Array.from({length:120},(_,i)=>({id:i,value:'long output row'})))); field.dispatchEvent(new Event('input',{bubbles:true})); });
  await clickLabel(page, '[data-tool-id="json"]', 'Process JSON');
  await page.waitForFunction(() => document.querySelector('[data-tool-id="json"] textarea[readonly]')?.value.length > 1000);
  assert.equal(await page.$$eval('[data-tool-id="json"] textarea', (fields) => fields.every(field => field.getBoundingClientRect().height >= 300)), true, 'both input and generated output must remain readable after processing');
  await clickLabel(page, '[data-tool-id="json"]', 'Clear');
  await page.waitForFunction(() => document.querySelector('[data-tool-id="json"] textarea')?.value === '' && document.querySelector('[data-tool-id="json"] textarea').getBoundingClientRect().height < 300);
  await page.goto(base + '/', { waitUntil: 'networkidle2' });
  const source = '.home-command-box textarea';
  await page.focus(source);
  await page.$eval(source, (field) => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(field, 'abc def'); field.dispatchEvent(new Event('input', { bubbles: true })); });
  await page.$eval(source, (field) => field.setSelectionRange(4,7));
  const intercepted = await page.$eval(source, (field) => { const data = new DataTransfer(); data.setData('text/plain','regular text'); const event = new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data }); field.dispatchEvent(event); return event.defaultPrevented; });
  assert.equal(intercepted, false, 'native text paste must not be intercepted');
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { read: async () => [{ types: ['text/plain'], getType: async () => new Blob(['pasted'], { type: 'text/plain' }) }] } }));
  await page.click('.tool-topbar .clipboard-paste-button');
  await page.waitForFunction(() => document.querySelector('.home-command-box textarea').value === 'abc pasted');
  await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { read: async () => { throw new DOMException('Denied', 'NotAllowedError'); } } }));
  await page.click('.tool-topbar .clipboard-paste-button');
  await page.waitForFunction(() => document.querySelector('.clipboard-notice')?.textContent.includes('Ctrl/Cmd+V'));
  await pasteFiles([{ name: 'clipboard-after-denial.png', bytes: png, type: 'image/png' }]);
  await page.waitForFunction(() => document.querySelector('[data-tool-id="image"]')?.textContent.includes('clipboard-after-denial.png'));
  assert.deepEqual(errors, [], 'clipboard and image workflows must not raise uncaught errors');
  console.log('Usability passed: 35 tools at two sizes, native file paste, context-menu paste, multi-file import, text selection, permission fallback, image zoom and accessible preview.');
}

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
import { pathToFileURL } from "node:url";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import assert from "node:assert/strict";
const root = resolve(process.env.SMOKE_ROOT || "dist");
const offline = existsSync(resolve(root, "OFFLINE_MANIFEST.json"));
const server = offline ? null : await serveSmokeDist(root);
const entry = offline ? pathToFileURL(resolve(root, "index.html")).href : server.base + "/";
let browser;
try {
  await mkdir("tmp/image-recovery-qa", { recursive: true });
  browser = await launchSmokeBrowser({ blockExternal: true });
  const page = await prepareSmokePage(browser);
  // Force repair to overlap the automatic scan timer. A background scan must
  // never abort an explicit repair when its worker takes longer than 120 ms.
  await page.evaluateOnNewDocument(() => {
    const BaseWorker = window.Worker;
    window.Worker = class extends BaseWorker {
      postMessage(message, ...options) {
        if (message.action === "repair") setTimeout(() => super.postMessage(message, ...options), 350);
        else super.postMessage(message, ...options);
      }
    };
  });
  const errors=[], failed=[];
  page.on("pageerror",e=>errors.push(e.message));
  page.on("response",r=>{ if(r.status()>=400)failed.push(`${r.status()} ${r.url()}`); });
  await page.setViewport({ width: 1440, height: 1000 });
  await page.goto(`${entry}${offline ? "#image" : "tools/image-forensics/"}`,{waitUntil:"networkidle2"});
  await page.waitForSelector('[data-tool-id="image"] input[type=file]');
  await page.evaluate(()=>[...document.querySelectorAll('.language-switch button')].find(b=>b.textContent.trim()==="中文").click());
  const upload=async (huge=false)=>{
    await page.evaluate(async huge=>{
      const canvas=document.createElement("canvas");canvas.width=73;canvas.height=41;
      const ctx=canvas.getContext("2d");const image=ctx.createImageData(73,41);
      for(let y=0;y<41;y++)for(let x=0;x<73;x++){
        const i=(y*73+x)*4; image.data.set([x*3,y*5,(x+y)*2,255],i);
      }
      ctx.putImageData(image,0,0);
      const blob=await new Promise(r=>canvas.toBlob(r,"image/png"));
      const original=new Uint8Array(await blob.arrayBuffer());
      const bytes=original.slice();const view=new DataView(bytes.buffer);
      view.setUint32(16,huge?0xffffffff:73);view.setUint32(20,huge?0xffffffff:2);
      window.__recoveryExpected={bytes:Array.from(original),pixels:Array.from(image.data)};
      const transfer=new DataTransfer();transfer.items.add(new File([bytes],huge?"both-dimensions-tampered.png":"height-hidden.png",{type:"image/png"}));
      const input=document.querySelector('[data-tool-id="image"] input[type=file]');input.files=transfer.files;input.dispatchEvent(new Event("change",{bubbles:true}));
    },huge);
    await page.waitForSelector('.image-review-section [data-severity="danger"]',{timeout:60000});
    await page.waitForFunction(()=>[...document.querySelectorAll('[data-tool-id="image"] button')].some(b=>b.textContent.trim()==="修复"&&!b.disabled));
  };
  const click=async text=>{
    await page.waitForFunction(text=>[...document.querySelectorAll('[data-tool-id="image"] button')].some(b=>b.textContent.trim()===text&&!b.disabled),{timeout:60000},text);
    await page.evaluate(text=>[...document.querySelectorAll('[data-tool-id="image"] button')].find(b=>b.textContent.trim()===text&&!b.disabled).click(),text);
  };
  const verifyRecovered=async()=>{
    await click("修复");await click("恢复宽高 / 检查修复");
    try { await page.waitForFunction(()=>document.querySelector('.image-simple-repair-panel')?.innerText.includes("恢复尺寸 73 × 41"),{timeout:60000}); }
    catch (error) { await page.screenshot({path:resolve("tmp/image-recovery-qa/failure.png"),fullPage:true}); await writeFile("tmp/image-recovery-qa/failure.txt",await page.$eval("body",el=>el.innerText)); throw error; }
    await page.waitForFunction(()=>document.querySelector('.image-repair-preview-grid img')?.complete,{timeout:60000});
    const verification=await page.evaluate(async()=>{
      const img=document.querySelector('.image-repair-preview-grid img');
      const bytes=new Uint8Array(await (await fetch(img.src)).arrayBuffer());
      const canvas=document.createElement("canvas");canvas.width=img.naturalWidth;canvas.height=img.naturalHeight;
      canvas.getContext("2d").drawImage(img,0,0);
      const pixels=canvas.getContext("2d").getImageData(0,0,canvas.width,canvas.height).data;
      return {width:img.naturalWidth,height:img.naturalHeight,bytesMatch:bytes.length===window.__recoveryExpected.bytes.length&&bytes.every((b,i)=>b===window.__recoveryExpected.bytes[i]),pixelsMatch:pixels.length===window.__recoveryExpected.pixels.length&&pixels.every((p,i)=>p===window.__recoveryExpected.pixels[i])};
    });
    assert.deepEqual(verification,{width:73,height:41,bytesMatch:true,pixelsMatch:true});
  };
  console.log("Checking ordinary dimensions");
  await upload();
  const overview=await page.$eval('.image-review-section',el=>el.innerText);
  assert(overview.includes("PNG 校验失败"));assert(!overview.includes("CRC mismatch"));
  assert.equal(await page.$$eval('.image-review-summary button',els=>els.length),4);
  await page.screenshot({path:resolve("tmp/image-recovery-qa/overview-desktop.png"),fullPage:true});
  await verifyRecovered();
  await page.screenshot({path:resolve("tmp/image-recovery-qa/recovered-desktop.png"),fullPage:true});
  await page.setViewport({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),"recovery fits mobile viewport");
  await page.screenshot({path:resolve("tmp/image-recovery-qa/recovered-mobile.png"),fullPage:true});
  await page.setViewport({width:1440,height:1000});
  await click("分析此副本");
  await page.waitForFunction(()=>document.querySelector('.image-source-file')?.innerText.includes("recovered-1") && document.querySelector('.image-simple-preview img')?.naturalHeight === 41,{timeout:60000});
  console.log("Recovered copy can be analyzed as a complete image");
  console.log("Checking oversized dimensions");
  await upload(true);await verifyRecovered();
  console.log("Checking Chinese navigation");
  await page.goto(`${entry}#chinese`,{waitUntil:"networkidle2"});
  await page.waitForSelector('[data-tool-id="chinese"] textarea:not([readonly])');
  assert.equal(await page.$eval('[data-tool-id="chinese"]',el=>el.hidden),false);
  await page.$eval('.chinese-converter textarea:not([readonly])',(el)=>{
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(el,'头发与发展，后台与皇后。');el.dispatchEvent(new Event('input',{bubbles:true}));
  });
  await page.focus('.chinese-converter textarea');
  await page.keyboard.down('Control');await page.keyboard.down('Shift');await page.keyboard.press('Enter');await page.keyboard.up('Shift');await page.keyboard.up('Control');
  await page.waitForFunction(()=>document.querySelector('.chinese-converter textarea[readonly]')?.value==='頭髮與發展，後臺與皇后。',{timeout:60000});
  await page.evaluate(()=>[...document.querySelectorAll('.language-switch button')].find(b=>b.textContent.trim()==="中文").click());
  await page.evaluate(()=>{if(document.querySelector('.sidebar-collapsed'))document.querySelector('.top-menu-toggle').click();});
  await page.waitForSelector('.tool-nav [aria-current="page"]');
  await page.$eval('.tool-nav [aria-current="page"]',el=>el.scrollIntoView({block:"center"}));
  await page.screenshot({path:resolve("tmp/image-recovery-qa/chinese-sidebar.png"),fullPage:true});
  await page.goto(`${entry}#codec`,{waitUntil:"networkidle2"});
  await page.waitForSelector('[data-tool-id="codec"] .codec-simple-panel');
  assert.equal(await page.$$eval('[data-tool-id="codec"] .chinese-converter',els=>els.length),0);
  assert.deepEqual(errors,[]);assert.deepEqual(failed,[]);
  console.log("Image recovery browser regression passed: Chinese severity, cropped and oversized IHDR, exact original PNG bytes and pixels, mobile layout, dedicated Chinese sidebar tool and offline keyboard conversion.");
} finally { await browser?.close(); if (server) await server.close(); }

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

import { describe, expect, it } from "vitest";
import { zlibSync } from "fflate";
import { crc32 } from "../src/utils/binary";
import { recoverPngDimensions } from "../src/features/png/dimensionRecovery";
import { parsePngFile } from "../src/features/png/parser";

function chunk(type: string, data: Uint8Array) {
  const bytes = new Uint8Array(data.length + 12), view = new DataView(bytes.buffer);
  view.setUint32(0, data.length); bytes.set(new TextEncoder().encode(type), 4); bytes.set(data, 8);
  view.setUint32(8 + data.length, crc32(bytes.subarray(4, 8 + data.length))); return bytes;
}
function fixture(width = 73, height = 41, color = 6, depth = 8, interlace = 0) {
  const ihdr = new Uint8Array(13), v = new DataView(ihdr.buffer);
  v.setUint32(0, width); v.setUint32(4, height); ihdr.set([depth, color, 0, 0, interlace], 8);
  const bits = ({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[color] ?? 4) * depth;
  const passes = interlace ? [[0,0,8,8],[4,0,8,8],[0,4,4,8],[2,0,4,4],[0,2,2,4],[1,0,2,2],[0,1,1,2]] : [[0,0,1,1]];
  const data: number[] = [];
  for (const [x,y,dx,dy] of passes) {
    const w = Math.max(0, Math.ceil((width-x)/dx)), h = Math.max(0, Math.ceil((height-y)/dy));
    if (!w) continue;
    for (let row = 0; row < h; row++) {
      data.push(row % 5);
      for(let b=0; b<Math.ceil(w*bits/8); b++) data.push((b*31+row*17+91)%256);
    }
  }
  const compressed = zlibSync(Uint8Array.from(data)), mid = Math.floor(compressed.length / 2);
  const parts = [Uint8Array.from([137,80,78,71,13,10,26,10]),chunk("IHDR",ihdr),chunk("tEXt",new TextEncoder().encode("note\0keep evidence")),chunk("IDAT",compressed.slice(0,mid)),chunk("IDAT",compressed.slice(mid)),chunk("IEND",new Uint8Array()),new TextEncoder().encode("trailer")];
  const bytes = new Uint8Array(parts.reduce((n,p)=>n+p.length,0)); let offset=0;
  for(const p of parts) {bytes.set(p,offset);offset+=p.length;} return bytes;
}
function tamper(bytes: Uint8Array, width: number, height: number, rewriteCrc = false) {
  const out=bytes.slice(), v=new DataView(out.buffer);v.setUint32(16,width);v.setUint32(20,height);
  if(rewriteCrc)v.setUint32(29,crc32(out.subarray(12,29)));return out;
}

describe("PNG dimension recovery", () => {
  it.each([[2,41],[73,2],[2,2],[0xffffffff,0xffffffff],[0,0]])("recovers changed width/height %i × %i using original CRC and all scanlines", async(w,h)=>{
    const original=fixture(), changed=tamper(original,w,h);
    const r=await recoverPngDimensions(changed);
    expect(r.status).toBe("recovered"); expect(r.candidates).toHaveLength(1);
    expect(r.candidates[0]).toMatchObject({width:73,height:41,crcMatch:true});
    expect(r.candidates[0].bytes).toEqual(original); // includes metadata, multiple IDATs, trailer
    expect(new DataView(changed.buffer).getUint32(16)).toBe(w); // original evidence untouched
  });
  it.each([[0,1],[0,2],[0,4],[0,8],[0,16],[2,8],[2,16],[3,1],[3,4],[4,8],[4,16],[6,8],[6,16]])("handles color %i depth %i",async(color,depth)=>{
    expect((await recoverPngDimensions(tamper(fixture(73,41,color,depth),1,1))).candidates[0]).toMatchObject({width:73,height:41,crcMatch:true});
  });
  it.each([[1,1],[2,3],[73,41],[19,17]])("handles Adam7 %i × %i",async(w,h)=>{
    const original=fixture(w,h,6,8,1);const r=await recoverPngDimensions(tamper(original,200,300));
    expect(r.status).toBe("recovered");expect(r.candidates[0].bytes).toEqual(original);
  });
  it("uses scanlines as uncertain candidates when the CRC was also overwritten",async()=>{
    const r=await recoverPngDimensions(tamper(fixture(),73,2,true));
    expect(r.status).toBe("ambiguous");expect(r.reason).toBe("scanlines-only");
    expect(r.candidates.some(c=>c.width===73&&c.height===41&&!c.crcMatch)).toBe(true);
  });
  it("does not claim dimensions were restored for a healthy file",async()=>{
    expect((await recoverPngDimensions(fixture())).status).toBe("consistent");
  });
  it("does not treat an invalid zlib stream as CRC-verified dimension recovery",async()=>{
    const bytes=tamper(fixture(),1,1);const idat=parsePngFile(bytes).chunks.find(c=>c.type==="IDAT")!;
    bytes[idat.dataOffset]^=255;
    expect(await recoverPngDimensions(bytes)).toMatchObject({status:"unavailable",reason:"invalid-idat",candidates:[]});
  });
  it("reports the decompression limit",async()=>{
    const original=fixture();const ihdr=original.subarray(8,33);
    const large=zlibSync(new Uint8Array(64*1024*1024+1));
    const idat=chunk("IDAT",large);const bytes=new Uint8Array(8+ihdr.length+idat.length+12);
    bytes.set(original.subarray(0,8));bytes.set(ihdr,8);bytes.set(idat,33);bytes.set(chunk("IEND",new Uint8Array()),33+idat.length);
    expect(await recoverPngDimensions(bytes)).toMatchObject({status:"unavailable",reason:"inflate-limit",candidates:[]});
  });
  it("rejects unsupported headers and short IHDR without out-of-bounds reads",async()=>{
    const original=fixture();original[24]=3;
    expect((await recoverPngDimensions(original)).reason).toBe("unsupported-header");
    const short=new Uint8Array([...original.subarray(0,8),...chunk("IHDR",new Uint8Array()),...chunk("IEND",new Uint8Array())]);
    expect(()=>parsePngFile(short)).not.toThrow();expect((await recoverPngDimensions(short)).reason).toBe("missing-critical");
  });
});

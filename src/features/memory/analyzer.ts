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

import type { EvidenceReader } from "../../core/evidence/reader";
import { formatBytes } from "../../utils/files";

export type MemoryModule={base:string;size:number;timestamp:string;name:string};
export type MemoryPeHit={offset:number;peOffset:number;machine:string;sections:number};
export type MemoryTriage={name:string;size:number;format:string;rows:Array<[string,string]>;modules:MemoryModule[];peHits:MemoryPeHit[];warnings:string[]};

function ascii(b:Uint8Array,o:number,n:number){return o>=0&&o+n<=b.length?String.fromCharCode(...b.subarray(o,o+n)):""} function v(b:Uint8Array){return new DataView(b.buffer,b.byteOffset,b.byteLength)}
function machine(value:number){return ({0x14c:"x86",0x8664:"x64",0x1c0:"ARM",0xaa64:"ARM64"} as Record<number,string>)[value]??`0x${value.toString(16).toUpperCase()}`}
function minidumpString(bytes:Uint8Array,rva:number){if(rva<0||rva+4>bytes.length)return"";const len=v(bytes).getUint32(rva,true);if(len>64*1024||rva+4+len>bytes.length)return"";return new TextDecoder("utf-16le").decode(bytes.subarray(rva+4,rva+4+len)).replace(/\0+$/g,"")}
function isoUnix(seconds:number){if(!seconds)return"--";const d=new Date(seconds*1000);return Number.isNaN(d.getTime())?"--":d.toISOString()}

function parseMinidump(bytes:Uint8Array,name:string,size:number):MemoryTriage{const view=v(bytes),rows:Array<[string,string]>=[],modules:MemoryModule[]=[],warnings:string[]=[];const streams=Math.min(view.getUint32(8,true),4096),dir=view.getUint32(12,true),timestamp=view.getUint32(20,true),flags=view.getBigUint64(24,true);rows.push(["Streams",String(streams)],["Timestamp",isoUnix(timestamp)],["Flags",`0x${flags.toString(16).toUpperCase()}`]);
  const dirs:Array<{type:number,size:number,rva:number}>=[];for(let i=0;i<streams&&dir+i*12+12<=bytes.length;i++){const o=dir+i*12;dirs.push({type:view.getUint32(o,true),size:view.getUint32(o+4,true),rva:view.getUint32(o+8,true)})}rows.push(["Stream types",dirs.map(d=>d.type).join(", ")||"--"]);
  const sys=dirs.find(d=>d.type===7);if(sys&&sys.rva+32<=bytes.length){const o=sys.rva,arch=view.getUint16(o,true),processors=bytes[o+6],major=view.getUint32(o+8,true),minor=view.getUint32(o+12,true),build=view.getUint32(o+16,true);rows.push(["Architecture",({0:"x86",5:"ARM",9:"x64",12:"ARM64"} as Record<number,string>)[arch]??String(arch)],["Processors",String(processors)],["OS",`${major}.${minor}.${build}`]);}
  const exception=dirs.find(d=>d.type===6);if(exception&&exception.rva+32<=bytes.length){rows.push(["Exception thread",String(view.getUint32(exception.rva,true))],["Exception code",`0x${view.getUint32(exception.rva+8,true).toString(16).toUpperCase()}`]);}
  const mod=dirs.find(d=>d.type===4);if(mod&&mod.rva+4<=bytes.length){const count=Math.min(view.getUint32(mod.rva,true),8192);let o=mod.rva+4;for(let i=0;i<count&&o+108<=bytes.length;i++,o+=108){const base=view.getBigUint64(o,true),imageSize=view.getUint32(o+8,true),time=view.getUint32(o+16,true),nameRva=view.getUint32(o+20,true);modules.push({base:`0x${base.toString(16).toUpperCase()}`,size:imageSize,timestamp:isoUnix(time),name:minidumpString(bytes,nameRva)||"--"});}rows.push(["Modules",String(modules.length)]);}
  const memory64=dirs.find(d=>d.type===9);if(memory64&&memory64.rva+16<=bytes.length)rows.push(["Memory64 ranges",String(Number(view.getBigUint64(memory64.rva,true)))],["Memory64 data RVA",`0x${view.getBigUint64(memory64.rva+8,true).toString(16).toUpperCase()}`]);
  warnings.push("Memory triage parses Minidump metadata and performs bounded PE-header discovery; it is not a Volatility-compatible kernel object parser.");return{name,size,format:"Windows Minidump",rows,modules,peHits:[],warnings};}

export async function analyzeMemoryTriage(reader:EvidenceReader,name:string,signal?:AbortSignal):Promise<MemoryTriage>{const head=await reader.read(0,Math.min(reader.size,8*1024*1024),{signal});let result:MemoryTriage;if(ascii(head,0,4)==="MDMP")result=parseMinidump(head,name,reader.size);else result={name,size:reader.size,format:"Raw memory / unknown dump",rows:[["Size",formatBytes(reader.size)],["Header",Array.from(head.subarray(0,16),b=>b.toString(16).padStart(2,"0")).join(" ").toUpperCase()]],modules:[],peHits:[],warnings:["Raw-memory mode performs bounded signature triage only; OS symbol-based process/VAD/network reconstruction is outside this browser-native parser."]};
  const chunkSize=8*1024*1024,overlap=4096,maxScan=Math.min(reader.size,512*1024*1024);let base=0;const seen=new Set<number>();while(base<maxScan&&result.peHits.length<2048){const start=Math.max(0,base-(base?overlap:0)),end=Math.min(maxScan,base+chunkSize),bytes=await reader.read(start,end-start,{signal}),view=v(bytes);for(let i=0;i+0x40<bytes.length&&result.peHits.length<2048;i++){if(bytes[i]!==0x4d||bytes[i+1]!==0x5a)continue;const pe=view.getUint32(i+0x3c,true);if(pe>1024*1024||i+pe+24>bytes.length||ascii(bytes,i+pe,4)!=="PE\0\0")continue;const absolute=start+i;if(seen.has(absolute))continue;seen.add(absolute);result.peHits.push({offset:absolute,peOffset:pe,machine:machine(view.getUint16(i+pe+4,true)),sections:view.getUint16(i+pe+6,true)});i+=1;}base=end;}
  result.rows.push(["PE headers found",String(result.peHits.length)],["PE scan scope",formatBytes(maxScan)]);return result;}

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

export type BulkArtifact = { type:string; value:string; offset:number; encoding:"ASCII"|"UTF-16LE"|"UTF-16BE"; context:string };
export type BulkScanResult = { name:string; size:number; scannedBytes:number; items:BulkArtifact[]; counts:Record<string,number>; truncated:boolean };
export type BulkScanOptions = { signal?:AbortSignal; chunkSize?:number; maxItems?:number; onProgress?:(loaded:number,total:number)=>void };

type Pattern={type:string;regex:RegExp;validate?:(value:string)=>boolean};
const ipValid=(v:string)=>v.split(".").length===4&&v.split(".").every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255);
const patterns:Pattern[]=[
  {type:"URL",regex:/\bhttps?:\/\/[^\s<>"'\]\[(){}]{4,2048}/gi},
  {type:"Email",regex:/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b/gi},
  {type:"IPv4",regex:/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,validate:ipValid},
  {type:"IPv6",regex:/\b(?:[0-9A-F]{1,4}:){2,7}[0-9A-F]{0,4}\b/gi},
  {type:"MAC",regex:/\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi},
  {type:"JWT",regex:/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}\b/g},
  {type:"UUID",regex:/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi},
  {type:"Ethereum",regex:/\b0x[0-9a-f]{40}\b/gi},
  {type:"Bitcoin",regex:/\b(?:bc1[ac-hj-np-z02-9]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,61})\b/g},
  {type:"PEM",regex:/-----BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE KEY|PUBLIC KEY|CERTIFICATE)-----/g},
  {type:"Windows path",regex:/\b[A-Z]:\\(?:[^\x00-\x1f<>:"|?*\\/]+\\)*[^\x00-\x1f<>:"|?*\\/]{1,260}/gi},
  {type:"UNC path",regex:/\\\\[A-Za-z0-9_.-]+\\[^\x00-\x1f<>:"|?*]{1,512}/g},
  {type:"Unix path",regex:/(?:^|[\s"'])\/(?:etc|home|root|var|tmp|usr|opt|data|sdcard|storage|system|vendor)\/[A-Za-z0-9_./@+,:=-]{2,512}/g},
  {type:"Registry path",regex:/\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT)\\[A-Za-z0-9_\\ .{}()@-]{3,512}/gi},
  {type:"Android package",regex:/\b(?:com|org|net|io|cn|app)\.[a-zA-Z][\w]*(?:\.[a-zA-Z][\w]*){1,8}\b/g},
  {type:"User-Agent",regex:/\b(?:Mozilla\/5\.0|Dalvik\/\d|okhttp\/\d|curl\/\d|Wget\/\d)[^\r\n\x00]{0,400}/gi},
  {type:"Domain",regex:/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|dev|app|top|xyz|info|biz|edu|gov|co|me|tech|cloud|local)\b/gi}
];

function abortError(){return new DOMException("Bulk scan cancelled","AbortError");}
function printableContext(text:string,start:number,end:number){return text.slice(Math.max(0,start-48),Math.min(text.length,end+48)).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g,".").slice(0,300);}
function scanText(text:string,baseOffset:number,encoding:BulkArtifact["encoding"],byteScale:number,output:BulkArtifact[],seen:Set<string>,maxItems:number){
  for(const pattern of patterns){pattern.regex.lastIndex=0;let match:RegExpExecArray|null;while((match=pattern.regex.exec(text))&&output.length<maxItems){let value=match[0].trim().replace(/^["']/,"");if(!value||pattern.validate&&!pattern.validate(value))continue;const relative=match.index+(match[0].length-value.length);const offset=baseOffset+relative*byteScale;const key=`${pattern.type}|${value.toLowerCase()}|${offset}`;if(seen.has(key))continue;seen.add(key);output.push({type:pattern.type,value:value.slice(0,2048),offset,encoding,context:printableContext(text,match.index,match.index+match[0].length)});if(pattern.regex.lastIndex===match.index)pattern.regex.lastIndex++;}}
}
function decodeUtf16Be(bytes:Uint8Array){const swapped=new Uint8Array(bytes.length-(bytes.length%2));for(let i=0;i<swapped.length;i+=2){swapped[i]=bytes[i+1];swapped[i+1]=bytes[i];}return new TextDecoder("utf-16le").decode(swapped);}

export async function scanBulkArtifacts(file:Blob,name:string,options:BulkScanOptions={}):Promise<BulkScanResult>{
  const chunkSize=Math.max(256*1024,options.chunkSize??4*1024*1024),maxItems=Math.max(1,options.maxItems??10000),overlap=4096;const output:BulkArtifact[]=[];const seen=new Set<string>();let offset=0;options.onProgress?.(0,file.size);
  while(offset<file.size&&output.length<maxItems){if(options.signal?.aborted)throw abortError();const start=Math.max(0,offset-(offset?overlap:0)),end=Math.min(file.size,offset+chunkSize);const bytes=new Uint8Array(await file.slice(start,end).arrayBuffer());if(options.signal?.aborted)throw abortError();
    const ascii=new TextDecoder("windows-1252").decode(bytes);scanText(ascii,start,"ASCII",1,output,seen,maxItems);
    const evenStart=start%2===0?start:start+1,localEven=evenStart-start;const u16=bytes.subarray(localEven,bytes.length-((bytes.length-localEven)%2));if(u16.length>=8){scanText(new TextDecoder("utf-16le").decode(u16),evenStart,"UTF-16LE",2,output,seen,maxItems);scanText(decodeUtf16Be(u16),evenStart,"UTF-16BE",2,output,seen,maxItems);}
    offset=end;options.onProgress?.(offset,file.size);
  }
  output.sort((a,b)=>a.offset-b.offset||a.type.localeCompare(b.type));const counts:Record<string,number>={};for(const item of output)counts[item.type]=(counts[item.type]??0)+1;return{name,size:file.size,scannedBytes:Math.min(offset,file.size),items:output,counts,truncated:output.length>=maxItems||offset<file.size};
}

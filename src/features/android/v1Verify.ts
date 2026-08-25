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

import { unzipSync } from "fflate";
import { validateZipExpansion } from "../archive/zipDirectory";

export type JarV1Verification = {
  present: boolean;
  verified: boolean;
  signerBase: string;
  manifestEntries: number;
  verifiedEntries: number;
  sfManifestDigestVerified: boolean;
  cmsSignatureVerified: boolean;
  signerCertificateSha256: string;
  errors: string[];
  warnings: string[];
};

type DerNode={tag:number,start:number,contentStart:number,end:number};
function readDerNode(bytes:Uint8Array,offset:number,limit:number):DerNode|null{if(offset<0||offset+2>limit)return null;const tag=bytes[offset];let c=offset+1,first=bytes[c++],len=0;if((first&0x80)===0)len=first;else{const n=first&0x7f;if(!n||n>4||c+n>limit)return null;for(let i=0;i<n;i++)len=len*256+bytes[c+i];c+=n;}const end=c+len;return end<=limit&&end>=c?{tag,start:offset,contentStart:c,end}:null;}
function children(bytes:Uint8Array,node:DerNode){const out:DerNode[]=[];let c=node.contentStart;while(c<node.end&&out.length<512){const n=readDerNode(bytes,c,node.end);if(!n||n.end<=c)return[];out.push(n);c=n.end;}return c===node.end?out:[];}
function oid(bytes:Uint8Array,node:DerNode){if(node.tag!==0x06||node.contentStart>=node.end)return"";const first=bytes[node.contentStart],parts=[Math.floor(first/40),first%40];let value=0;for(let i=node.contentStart+1;i<node.end;i++){value=(value<<7)|(bytes[i]&0x7f);if(!(bytes[i]&0x80)){parts.push(value);value=0;}}return parts.join(".");}
function certificateSpki(cert:Uint8Array){const root=readDerNode(cert,0,cert.length),tbs=root?children(cert,root)[0]:null;if(!root||root.tag!==0x30||!tbs)return null;const fields=children(cert,tbs);let i=fields[0]?.tag===0xa0?1:0;i+=5;const spki=fields[i];return spki?.tag===0x30?cert.slice(spki.start,spki.end):null;}
function spkiCurve(spki:Uint8Array){const root=readDerNode(spki,0,spki.length),alg=root?children(spki,root)[0]:null,parts=alg?children(spki,alg):[];const curve=parts[1]?oid(spki,parts[1]):"";return ({"1.2.840.10045.3.1.7":"P-256","1.3.132.0.34":"P-384","1.3.132.0.35":"P-521"} as Record<string,string>)[curve]??"";}
function curveWidth(curve:string){return curve==="P-256"?32:curve==="P-384"?48:curve==="P-521"?66:0;}
function derIntegerToFixed(bytes:Uint8Array,node:DerNode,width:number){let raw=bytes.subarray(node.contentStart,node.end);while(raw.length>1&&raw[0]===0)raw=raw.subarray(1);if(!width||raw.length>width)return null;const out=new Uint8Array(width);out.set(raw,width-raw.length);return out;}
function ecdsaDerToRaw(signature:Uint8Array,width:number){const root=readDerNode(signature,0,signature.length),parts=root?children(signature,root):[];if(!root||root.tag!==0x30||root.end!==signature.length||parts.length!==2||parts.some(n=>n.tag!==0x02))return null;const r=derIntegerToFixed(signature,parts[0],width),s=derIntegerToFixed(signature,parts[1],width);if(!r||!s)return null;const out=new Uint8Array(width*2);out.set(r,0);out.set(s,width);return out;}
function base64Bytes(value:string){try{const raw=atob(value.replace(/\s+/g,""));return Uint8Array.from(raw,c=>c.charCodeAt(0));}catch{return new Uint8Array();}}
function equal(a:Uint8Array,b:Uint8Array){if(a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a[i]^b[i];return x===0;}
async function digest(bytes:Uint8Array,name:"SHA-1"|"SHA-256"|"SHA-384"|"SHA-512"){return new Uint8Array(await crypto.subtle.digest(name,bytes.slice().buffer));}
function digestName(label:string):"SHA-1"|"SHA-256"|"SHA-384"|"SHA-512"|null{const x=label.toUpperCase().replace(/_/g,"-");if(x.includes("SHA-512"))return"SHA-512";if(x.includes("SHA-384"))return"SHA-384";if(x.includes("SHA-256"))return"SHA-256";if(x.includes("SHA1")||x.includes("SHA-1"))return"SHA-1";return null;}
function parseManifestSections(bytes:Uint8Array){const text=new TextDecoder().decode(bytes).replace(/\r\n/g,"\n").replace(/\r/g,"\n");const rawSections=text.split(/\n\n+/);return rawSections.map(section=>{const logical:string[]=[];for(const line of section.split("\n")){if(line.startsWith(" ")&&logical.length)logical[logical.length-1]+=line.slice(1);else logical.push(line);}const values=new Map<string,string>();for(const line of logical){const i=line.indexOf(": ");if(i>0)values.set(line.slice(0,i),line.slice(i+2));}return values;});}
async function verifyManifest(files:Record<string,Uint8Array>,manifest:Uint8Array){const sections=parseManifestSections(manifest);let verified=0,entries=0;const errors:string[]=[],warnings:string[]=[];for(const section of sections.slice(1)){const name=section.get("Name");if(!name)continue;entries++;const data=files[name];if(!data){errors.push(`Manifest entry is missing from APK: ${name}`);continue;}const digestField=Array.from(section.entries()).find(([key])=>/-Digest$/i.test(key)&&digestName(key));if(!digestField){warnings.push(`No supported digest in MANIFEST.MF for ${name}`);continue;}const alg=digestName(digestField[0])!;const actual=await digest(data,alg),expected=base64Bytes(digestField[1]);if(equal(actual,expected))verified++;else errors.push(`${name}: ${alg} digest mismatch.`);}return{entries,verified,errors,warnings};}
function findAttributeDigest(cms:Uint8Array,signedAttrs:DerNode){for(const attr of children(cms,signedAttrs)){const parts=children(cms,attr);if(parts.length<2||oid(cms,parts[0])!=="1.2.840.113549.1.9.4")continue;const set=parts[1],value=children(cms,set)[0];if(value?.tag===0x04)return cms.slice(value.contentStart,value.end);}return new Uint8Array();}
function extractCms(cms:Uint8Array){const root=readDerNode(cms,0,cms.length);if(!root)return null;const ci=children(cms,root),wrapper=ci.find(n=>(n.tag&0xe0)===0xa0);const signedData=wrapper?children(cms,wrapper)[0]:null;if(!signedData)return null;const fields=children(cms,signedData);const certContainer=fields.find(n=>n.tag===0xa0),signerSet=fields.find(n=>n.tag===0x31&&n.start>(certContainer?.start??0));if(!certContainer||!signerSet)return null;const certs:Uint8Array[]=[];let c=certContainer.contentStart;while(c<certContainer.end&&certs.length<32){const n=readDerNode(cms,c,certContainer.end);if(!n)break;if(n.tag===0x30)certs.push(cms.slice(n.start,n.end));c=n.end;}const signer=children(cms,signerSet)[0];if(!signer)return null;const parts=children(cms,signer);if(parts.length<5)return null;const digestAlg=children(cms,parts[2])[0],hashOid=digestAlg?oid(cms,digestAlg):"";let i=3,signedAttrs:DerNode|null=null;if(parts[i]?.tag===0xa0){signedAttrs=parts[i];i++;}const signatureAlg=parts[i],signature=parts[i+1];if(!signatureAlg||signature?.tag!==0x04)return null;const sigOid=oid(cms,children(cms,signatureAlg)[0]);return{certs,hashOid,sigOid,signedAttrs,signature:cms.slice(signature.contentStart,signature.end)};}
const HASH_OIDS:Record<string,"SHA-1"|"SHA-256"|"SHA-384"|"SHA-512">={"1.3.14.3.2.26":"SHA-1","2.16.840.1.101.3.4.2.1":"SHA-256","2.16.840.1.101.3.4.2.2":"SHA-384","2.16.840.1.101.3.4.2.3":"SHA-512"};
async function verifyCms(cmsBytes:Uint8Array,sf:Uint8Array){const parsed=extractCms(cmsBytes);if(!parsed)return{verified:false,certSha256:"",errors:["PKCS#7/CMS SignedData could not be parsed."],warnings:[]};const errors:string[]=[],warnings:string[]=[];const hash=HASH_OIDS[parsed.hashOid];if(!hash)return{verified:false,certSha256:"",errors:[`Unsupported CMS digest algorithm ${parsed.hashOid||"unknown"}.`],warnings};let signedBytes=sf;if(parsed.signedAttrs){const messageDigest=findAttributeDigest(cmsBytes,parsed.signedAttrs),actual=await digest(sf,hash);if(!messageDigest.length||!equal(messageDigest,actual))errors.push("CMS signedAttrs messageDigest does not match .SF content.");signedBytes=cmsBytes.slice(parsed.signedAttrs.start,parsed.signedAttrs.end);signedBytes[0]=0x31;}
  for(const cert of parsed.certs){const spki=certificateSpki(cert);if(!spki)continue;const certSha=Array.from(await digest(cert,"SHA-256"),b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();try{let key:CryptoKey,ok=false;if(parsed.sigOid.startsWith("1.2.840.113549.1.1.")){key=await crypto.subtle.importKey("spki",spki.buffer as ArrayBuffer,{name:"RSASSA-PKCS1-v1_5",hash},false,["verify"]);ok=await crypto.subtle.verify({name:"RSASSA-PKCS1-v1_5"},key,parsed.signature as unknown as BufferSource,signedBytes as unknown as BufferSource);}else if(parsed.sigOid.startsWith("1.2.840.10045.4.3.")){const curve=spkiCurve(spki);if(!curve){warnings.push("ECDSA signer curve is unsupported.");continue;}key=await crypto.subtle.importKey("spki",spki.buffer as ArrayBuffer,{name:"ECDSA",namedCurve:curve},false,["verify"]);const raw=ecdsaDerToRaw(parsed.signature,curveWidth(curve));if(raw)ok=await crypto.subtle.verify({name:"ECDSA",hash},key,raw as unknown as BufferSource,signedBytes as unknown as BufferSource).catch(()=>false);if(!ok)ok=await crypto.subtle.verify({name:"ECDSA",hash},key,parsed.signature as unknown as BufferSource,signedBytes as unknown as BufferSource).catch(()=>false);}else{warnings.push(`Unsupported CMS signature algorithm ${parsed.sigOid}.`);continue;}if(ok)return{verified:!errors.length,certSha256:certSha,errors,warnings};}catch(e){warnings.push(e instanceof Error?e.message:String(e));}}
  errors.push("CMS signer signature did not verify against any embedded certificate.");return{verified:false,certSha256:"",errors,warnings};}

export type JarV1ManifestSf = {
  manifestEntries: number;
  verifiedEntries: number;
  sfManifestDigestVerified: boolean;
  perSectionTotal: number;
  perSectionVerified: number;
  errors: string[];
  warnings: string[];
};

export async function verifyJarV1ManifestAndSf(files: Record<string,Uint8Array>, manifest: Uint8Array, sf: Uint8Array): Promise<JarV1ManifestSf> {
  const mf = await verifyManifest(files, manifest);
  const sfSections = parseManifestSections(sf);
  const main = sfSections[0] ?? new Map<string,string>();
  const manifestDigestField = Array.from(main.entries()).find(([key]) => /Digest-Manifest$/i.test(key) && digestName(key));
  let sfManifestDigestVerified = false;
  const errors: string[] = [...mf.errors];
  const warnings: string[] = [...mf.warnings];
  if (manifestDigestField) {
    const alg = digestName(manifestDigestField[0])!;
    const actual = await digest(manifest, alg);
    sfManifestDigestVerified = equal(actual, base64Bytes(manifestDigestField[1]));
    if (!sfManifestDigestVerified) errors.push(`${alg} digest of MANIFEST.MF does not match the .SF main section.`);
  }
  const mfSectionsByName = new Map<string, Map<string,string>>(
    parseManifestSections(manifest).slice(1).filter((s) => s.get("Name")).map((s) => [s.get("Name")!, s])
  );
  let perSectionTotal = 0;
  let perSectionVerified = 0;
  for (const section of sfSections.slice(1)) {
    const name = section.get("Name");
    if (!name) continue;
    const field = Array.from(section.entries()).find(([key]) => /-Digest$/i.test(key) && digestName(key));
    if (!field) continue;
    perSectionTotal++;
    const mfSection = mfSectionsByName.get(name);
    if (!mfSection) { errors.push(`${name}: listed in .SF but absent from MANIFEST.MF`); continue; }
    const mfField = Array.from(mfSection.entries()).find(([key]) => /-Digest$/i.test(key) && digestName(key));
    if (!mfField) { warnings.push(`${name}: no digest in MANIFEST.MF`); continue; }
    if (field[1].trim() === mfField[1].trim()) perSectionVerified++;
    else errors.push(`${name}: .SF per-section digest does not match the MANIFEST.MF digest.`);
  }
  if (!sfManifestDigestVerified && perSectionTotal === 0) warnings.push("The .SF file has no whole-manifest digest and no per-section digests; v1 signature cannot fully attest MANIFEST.MF.");
  return { manifestEntries: mf.entries, verifiedEntries: mf.verified, sfManifestDigestVerified, perSectionTotal, perSectionVerified, errors, warnings };
}

export async function verifyJarV1Signature(apkBytes:Uint8Array):Promise<JarV1Verification>{const empty:JarV1Verification={present:false,verified:false,signerBase:"",manifestEntries:0,verifiedEntries:0,sfManifestDigestVerified:false,cmsSignatureVerified:false,signerCertificateSha256:"",errors:[],warnings:[]};try{validateZipExpansion(apkBytes,{maxEntries:20000,maxEntryUncompressed:256*1024*1024,maxTotalUncompressed:1024*1024*1024,maxCompressionRatio:500,ratioGuardMinimum:4*1024*1024});const files=unzipSync(apkBytes),manifest=files["META-INF/MANIFEST.MF"]??files["META-INF/manifest.mf"];const sfName=Object.keys(files).find(n=>/^META-INF\/[^/]+\.SF$/i.test(n)),sigName=sfName?Object.keys(files).find(n=>new RegExp(`^META-INF/${sfName.split("/").pop()!.replace(/\.SF$/i,"").replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}\\.(?:RSA|EC|DSA)$`,"i").test(n)):undefined;if(!manifest||!sfName||!sigName)return empty;const sf=files[sfName],cms=files[sigName],base=sfName.split("/").pop()!.replace(/\.SF$/i,"");const msf=await verifyJarV1ManifestAndSf(files,manifest,sf);const cmsResult=await verifyCms(cms,sf);const attestedAll=msf.sfManifestDigestVerified||(msf.perSectionTotal>0&&msf.perSectionVerified===msf.perSectionTotal&&msf.perSectionTotal>=msf.manifestEntries);const errors=[...msf.errors,...cmsResult.errors];const warnings=[...msf.warnings,...cmsResult.warnings];return{present:true,verified:msf.verifiedEntries===msf.manifestEntries&&msf.manifestEntries>0&&attestedAll&&cmsResult.verified&&!errors.length,signerBase:base,manifestEntries:msf.manifestEntries,verifiedEntries:msf.verifiedEntries,sfManifestDigestVerified:msf.sfManifestDigestVerified,cmsSignatureVerified:cmsResult.verified,signerCertificateSha256:cmsResult.certSha256,errors,warnings};}catch(e){return{...empty,present:true,errors:[e instanceof Error?e.message:String(e)]};}}

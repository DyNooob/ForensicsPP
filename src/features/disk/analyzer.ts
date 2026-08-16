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

export type DiskFileEntry = { name: string; kind: string; size: number; cluster: number; deleted: boolean };

export type DiskPartition = {
  index: number;
  scheme: "MBR" | "GPT" | "whole-disk";
  type: string;
  typeCode: string;
  name: string;
  bootable: boolean;
  startLba: number;
  sectors: number;
  startOffset: number;
  size: number;
  filesystem: string;
  rows: Array<[string, string]>;
  entries: DiskFileEntry[];
};

export type DiskAnalysis = {
  name: string;
  size: number;
  sectorSize: number;
  scheme: string;
  rows: Array<[string, string]>;
  partitions: DiskPartition[];
  warnings: string[];
};

function view(bytes: Uint8Array) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }
function ascii(bytes: Uint8Array, offset: number, length: number) { return offset >= 0 && offset + length <= bytes.length ? new TextDecoder("windows-1252").decode(bytes.subarray(offset, offset + length)).replace(/\0/g, "").trim() : ""; }
function utf16le(bytes: Uint8Array, offset: number, length: number) { return offset >= 0 && offset + length <= bytes.length ? new TextDecoder("utf-16le").decode(bytes.subarray(offset, offset + length)).replace(/\0+$/g, "").trim() : ""; }
function safeBig(value: bigint) { return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null; }
function guid(bytes: Uint8Array, offset: number) {
  if (offset + 16 > bytes.length) return "";
  const v=view(bytes), a=v.getUint32(offset,true).toString(16).padStart(8,"0"), b=v.getUint16(offset+4,true).toString(16).padStart(4,"0"), c=v.getUint16(offset+6,true).toString(16).padStart(4,"0");
  const tail=Array.from(bytes.subarray(offset+8,offset+16),x=>x.toString(16).padStart(2,"0"));
  return `${a}-${b}-${c}-${tail.slice(0,2).join("")}-${tail.slice(2).join("")}`.toUpperCase();
}
function isZeroGuid(bytes: Uint8Array, offset: number) { for(let i=0;i<16;i++) if(bytes[offset+i]) return false; return true; }

const MBR_TYPES: Record<number,string> = { 0x01:"FAT12",0x04:"FAT16 <32M",0x05:"Extended",0x06:"FAT16",0x07:"NTFS/exFAT/HPFS",0x0b:"FAT32",0x0c:"FAT32 LBA",0x0e:"FAT16 LBA",0x0f:"Extended LBA",0x82:"Linux swap",0x83:"Linux filesystem",0x8e:"Linux LVM",0xa5:"FreeBSD",0xab:"Apple boot",0xaf:"Apple HFS/HFS+",0xee:"GPT protective",0xef:"EFI System" };
const GPT_TYPES: Record<string,string> = {
  "C12A7328-F81F-11D2-BA4B-00A0C93EC93B":"EFI System",
  "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7":"Microsoft Basic Data",
  "E3C9E316-0B5C-4DB8-817D-F92DF00215AE":"Microsoft Reserved",
  "0FC63DAF-8483-4772-8E79-3D69D8477DE4":"Linux filesystem",
  "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F":"Linux swap",
  "CA7D7CCB-63ED-4C53-861C-1742536059CC":"Linux LUKS",
  "48465300-0000-11AA-AA11-00306543ECAC":"Apple HFS/HFS+",
  "7C3457EF-0000-11AA-AA11-00306543ECAC":"Apple APFS"
};


function parseFatDirectory(bytes:Uint8Array){const entries:DiskFileEntry[]=[];let lfn:string[]=[];for(let o=0;o+32<=bytes.length&&entries.length<4096;o+=32){const first=bytes[o];if(first===0)break;const attr=bytes[o+11];if(attr===0x0f){const piece=[bytes.subarray(o+1,o+11),bytes.subarray(o+14,o+26),bytes.subarray(o+28,o+32)].map(x=>new TextDecoder("utf-16le").decode(x)).join("").replace(/[\u0000\uffff]/g,"");lfn.unshift(piece);continue;}if(attr&0x08){lfn=[];continue;}const deleted=first===0xe5;const rawName=new TextDecoder("windows-1252").decode(bytes.subarray(o,o+8)).trim(),rawExt=new TextDecoder("windows-1252").decode(bytes.subarray(o+8,o+11)).trim();const short=(rawExt?`${rawName}.${rawExt}`:rawName).replace(/^å/,"?");const name=(lfn.join("")||short).trim();lfn=[];if(!name)continue;const v=view(bytes),cluster=((v.getUint16(o+20,true)<<16)|v.getUint16(o+26,true))>>>0,size=v.getUint32(o+28,true);entries.push({name,kind:attr&0x10?"directory":"file",size,cluster,deleted});}return entries;}
async function readFatRoot(reader:EvidenceReader,partition:DiskPartition,boot:Uint8Array,signal?:AbortSignal){const v=view(boot),bps=v.getUint16(11,true),spc=boot[13],reserved=v.getUint16(14,true),fats=boot[16],rootEntries=v.getUint16(17,true),fat16=v.getUint16(22,true),fat32=v.getUint32(36,true),is32=ascii(boot,82,5)==="FAT32";if(!bps||!spc)return[];if(!is32){const fatSize=fat16,rootSectors=Math.ceil(rootEntries*32/bps),start=(reserved+fats*fatSize)*bps;const data=await reader.read(partition.startOffset+start,Math.min(rootSectors*bps,4*1024*1024),{signal});return parseFatDirectory(data);}const fatSize=fat32,rootCluster=v.getUint32(44,true),firstData=reserved+fats*fatSize,clusterBytes=spc*bps;const start=(firstData+(rootCluster-2)*spc)*bps;const data=await reader.read(partition.startOffset+start,Math.min(clusterBytes,4*1024*1024),{signal});return parseFatDirectory(data);}

async function probeFilesystem(reader: EvidenceReader, partition: DiskPartition, signal?: AbortSignal) {
  const firstSize=Math.min(partition.size, 128*1024);
  if(firstSize<=0) return partition;
  const bytes=await reader.read(partition.startOffset, firstSize, {signal}); const v=view(bytes); const rows:Array<[string,string]>=[]; let filesystem="Unknown"; partition.entries=[];
  if(bytes.length>=512 && ascii(bytes,3,8)==="NTFS") {
    filesystem="NTFS"; const bps=v.getUint16(11,true), spc=bytes[13], total=safeBig(v.getBigUint64(40,true)), mft=safeBig(v.getBigUint64(48,true)), mirror=safeBig(v.getBigUint64(56,true));
    rows.push(["Bytes/sector",String(bps)],["Sectors/cluster",String(spc)],["Cluster size",bps&&spc?formatBytes(bps*spc):"--"],["Total sectors",total==null?"--":String(total)],["$MFT LCN",mft==null?"--":String(mft)],["$MFTMirr LCN",mirror==null?"--":String(mirror)],["Volume serial",Array.from(bytes.subarray(72,80),b=>b.toString(16).padStart(2,"0")).reverse().join("").toUpperCase()]);
  } else if(bytes.length>=512 && ascii(bytes,3,8)==="EXFAT") {
    filesystem="exFAT"; const sectorShift=bytes[108], clusterShift=bytes[109], serial=v.getUint32(100,true); rows.push(["Bytes/sector",String(1<<sectorShift)],["Sectors/cluster",String(1<<clusterShift)],["Cluster heap offset",String(v.getUint32(88,true))],["Cluster count",String(v.getUint32(92,true))],["Root directory cluster",String(v.getUint32(96,true))],["Volume serial",serial.toString(16).padStart(8,"0").toUpperCase()]);
  } else if(bytes.length>=90 && (ascii(bytes,54,5)==="FAT12" || ascii(bytes,54,5)==="FAT16" || ascii(bytes,82,5)==="FAT32")) {
    filesystem=ascii(bytes,82,5).startsWith("FAT32")?"FAT32":ascii(bytes,54,5).startsWith("FAT12")?"FAT12":"FAT16"; const bps=v.getUint16(11,true),spc=bytes[13],reserved=v.getUint16(14,true),fats=bytes[16]; partition.entries=await readFatRoot(reader,partition,bytes,signal); rows.push(["Bytes/sector",String(bps)],["Sectors/cluster",String(spc)],["Reserved sectors",String(reserved)],["FAT copies",String(fats)],["Volume label",ascii(bytes,filesystem==="FAT32"?71:43,11)||"--"],["Filesystem label",ascii(bytes,filesystem==="FAT32"?82:54,8)||"--"]); if(filesystem==="FAT32")rows.push(["Root cluster",String(v.getUint32(44,true))]); rows.push(["Root directory entries",String(partition.entries.length)]);
  } else if(bytes.length>=2048 && v.getUint16(1024+56,true)===0xef53) {
    filesystem="EXT2/3/4"; const logBlock=v.getUint32(1024+24,true),blockSize=1024*(2**logBlock),features=v.getUint32(1024+96,true); rows.push(["Inodes",String(v.getUint32(1024,true))],["Blocks",String(v.getUint32(1024+4,true))],["Block size",formatBytes(blockSize)],["Volume name",ascii(bytes,1024+120,16)||"--"],["UUID",guidExt(bytes,1024+104)],["Incompat features",`0x${features.toString(16).toUpperCase()}`]);
  } else if(bytes.length>=0x9000 && ascii(bytes,0x8001,5)==="CD001") {
    filesystem="ISO9660"; rows.push(["Volume identifier",ascii(bytes,0x8028,32)||"--"],["Volume space blocks",String(v.getUint32(0x8050,true))],["Logical block size",String(v.getUint16(0x8080,true))]);
  }
  partition.filesystem=filesystem; partition.rows=rows; return partition;
}
function guidExt(bytes:Uint8Array,offset:number){return Array.from(bytes.subarray(offset,offset+16),b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();}

async function parseGpt(reader: EvidenceReader, sectorSize:number, signal?:AbortSignal) {
  const header=await reader.read(sectorSize,sectorSize,{signal}); if(ascii(header,0,8)!=="EFI PART")return null; const v=view(header); const entryLba=safeBig(v.getBigUint64(72,true)), count=Math.min(v.getUint32(80,true),4096), entrySize=v.getUint32(84,true); if(entryLba==null||entrySize<128||entrySize>4096)return null;
  const requested=Math.min(count*entrySize,16*1024*1024); const entries=await reader.read(entryLba*sectorSize,Math.min(requested,reader.size-entryLba*sectorSize),{signal}); const partitions:DiskPartition[]=[];
  for(let i=0;i<count&&i*entrySize+128<=entries.length;i++){const o=i*entrySize;if(isZeroGuid(entries,o))continue;const ev=view(entries);const first=safeBig(ev.getBigUint64(o+32,true)),last=safeBig(ev.getBigUint64(o+40,true));if(first==null||last==null||last<first)continue;const sectors=last-first+1,typeCode=guid(entries,o),name=utf16le(entries,o+56,Math.min(72,entrySize-56));partitions.push({index:i+1,scheme:"GPT",type:GPT_TYPES[typeCode]??"GPT partition",typeCode,name,bootable:false,startLba:first,sectors,startOffset:first*sectorSize,size:sectors*sectorSize,filesystem:"Unknown",rows:[],entries:[]});}
  const rows: Array<[string, string]> = [["GPT revision",`0x${v.getUint32(8,true).toString(16).toUpperCase()}`],["Disk GUID",guid(header,56)],["Partition entries",String(count)],["Partition entry size",String(entrySize)]]; return {partitions,rows};
}

export async function analyzeDiskImage(reader:EvidenceReader,name:string,signal?:AbortSignal):Promise<DiskAnalysis>{
  const warnings:string[]=[]; const head=await reader.read(0,Math.min(reader.size,128*1024),{signal}); if(head.length<512)throw new Error("Disk image is smaller than one sector."); const hv=view(head); const hasMbr=head[510]===0x55&&head[511]===0xaa; let sectorSize=512; let gpt=await parseGpt(reader,512,signal); if(!gpt&&reader.size>=8192) { const probe=await reader.read(4096,4096,{signal}); if(ascii(probe,0,8)==="EFI PART"){sectorSize=4096;gpt=await parseGpt(reader,4096,signal);} }
  let partitions:DiskPartition[]=[]; const rows:Array<[string,string]>=[["Image",name],["Size",formatBytes(reader.size)],["Random-access reader","File.slice() / EvidenceReader"],["Sector size",String(sectorSize)]]; let scheme="Unknown / unpartitioned";
  if(gpt){scheme="GPT";partitions=gpt.partitions;rows.push(...gpt.rows);} else if(hasMbr){scheme="MBR";for(let i=0;i<4;i++){const o=446+i*16,type=head[o+4],start=hv.getUint32(o+8,true),sectors=hv.getUint32(o+12,true);if(!type||!sectors)continue;partitions.push({index:i+1,scheme:"MBR",type:MBR_TYPES[type]??"MBR partition",typeCode:`0x${type.toString(16).padStart(2,"0").toUpperCase()}`,name:"",bootable:head[o]===0x80,startLba:start,sectors,startOffset:start*512,size:sectors*512,filesystem:"Unknown",rows:[],entries:[]});} if(partitions.some(p=>["0x05","0x0F"].includes(p.typeCode)))warnings.push("Extended/logical MBR partitions are identified, but EBR chain traversal is not yet expanded in this view.");}
  if(!partitions.length){partitions=[{index:1,scheme:"whole-disk",type:"Whole image",typeCode:"--",name:name,bootable:false,startLba:0,sectors:Math.floor(reader.size/sectorSize),startOffset:0,size:reader.size,filesystem:"Unknown",rows:[],entries:[]}];}
  for(const partition of partitions){if(partition.startOffset>=reader.size){warnings.push(`Partition ${partition.index} starts beyond image size.`);continue;} if(partition.startOffset+partition.size>reader.size){warnings.push(`Partition ${partition.index} extends beyond image size; filesystem probe is bounded to available bytes.`);partition.size=Math.max(0,reader.size-partition.startOffset);} await probeFilesystem(reader,partition,signal);}
  rows.push(["Partition scheme",scheme],["Partitions",String(partitions.length)]); return {name,size:reader.size,sectorSize,scheme,rows,partitions,warnings};
}

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

import React from "react";
import { AButton, ALinearProgress, InfoTable, PanelTitle, ToolPanelHeader } from "../components/ui";
import { evidenceReaderFromBlob } from "../core/evidence/reader";
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { analyzeDiskImage, type DiskAnalysis } from "../features/disk/analyzer";
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";

export function DiskImageTool({ t, active=true }:{t:(typeof copy)["zh"];active?:boolean}){
  const english=t.waiting==="Waiting"; const [analysis,setAnalysis]=React.useState<DiskAnalysis|null>(null); const [loading,setLoading]=React.useState(false); const [error,setError]=React.useState(""); const input=React.useRef<HTMLInputElement|null>(null); const abort=React.useRef<AbortController|null>(null);
  React.useEffect(()=>()=>abort.current?.abort(),[]); React.useEffect(()=>{if(!active){abort.current?.abort();setLoading(false)}},[active]);
  const load=async(file?:File)=>{if(!file||!active)return;abort.current?.abort();const controller=new AbortController();abort.current=controller;setLoading(true);setError("");setAnalysis(null);try{const result=await analyzeDiskImage(evidenceReaderFromBlob(file),file.name,controller.signal);if(!controller.signal.aborted)setAnalysis(result);}catch(e){if(!controller.signal.aborted)setError(e instanceof Error?e.message:String(e));}finally{if(abort.current===controller)abort.current=null;if(!controller.signal.aborted)setLoading(false)}};
  const loadRef=React.useRef(load); loadRef.current=load;
  React.useEffect(()=>{if(!active)return;const consume=()=>{const handoff=takeToolHandoff("disk");if(handoff)void loadRef.current(handoff.file)};consume();return subscribeToolHandoff("disk",consume)},[active]);
  return <div className="tool-grid disk-image-workbench">
    <div className="tool-panel wide-panel"><PanelTitle title={english?"Disk image":"磁盘镜像"}/><input ref={input} type="file" aria-hidden="true" tabIndex={-1} accept=".dd,.raw,.img,.iso,*/*" onChange={e=>{const f=e.currentTarget.files?.[0];e.currentTarget.value="";void load(f)}}/><div className="desktop-drop-zone" role="button" tabIndex={0} onClick={()=>input.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();void load(e.dataTransfer.files?.[0])}}><strong>{analysis?.name??(english?"Open DD / RAW / IMG / ISO":"打开 DD / RAW / IMG / ISO")}</strong><span>{analysis?`${analysis.scheme} · ${formatBytes(analysis.size)}`:(english?"Random-access analysis; the whole image is not loaded into memory.":"随机读取分析，不会把整块镜像载入内存。")}</span></div><div className="action-row"><AButton variant="filled" onClick={()=>input.current?.click()}>{t.selectFile}</AButton><AButton variant="text" disabled={!analysis&&!error} onClick={()=>{abort.current?.abort();setAnalysis(null);setError("")}}>{t.clear}</AButton></div>{loading&&<ALinearProgress/>}{error&&<div className="empty-state error-state">{error}</div>}</div>
    {analysis&&<div className="tool-panel wide-panel"><ToolPanelHeader title={english?"Partition map":"分区映射"} subtitle={`${analysis.scheme} · ${analysis.partitions.length}`}/><InfoTable rows={analysis.rows}/>{analysis.warnings.map((w,i)=><div className="empty-state error-state" key={i}>{w}</div>)}<div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>#</th><th>{english?"Scheme":"分区表"}</th><th>{english?"Type":"类型"}</th><th>{english?"Name":"名称"}</th><th>{english?"Start":"起始"}</th><th>{english?"Size":"大小"}</th><th>{english?"Filesystem":"文件系统"}</th></tr></thead><tbody>{analysis.partitions.map(p=><tr key={`${p.scheme}-${p.index}`}><td>{p.index}</td><td>{p.scheme}</td><td>{p.type}<br/><small>{p.typeCode}</small></td><td>{p.name||"--"}</td><td>LBA {p.startLba}<br/><small>0x{p.startOffset.toString(16).toUpperCase()}</small></td><td>{formatBytes(p.size)}</td><td>{p.filesystem}{p.rows.length?<details><summary>{english?"metadata":"元数据"}</summary><InfoTable rows={p.rows}/></details>:null}{p.entries.length?<details><summary>{english?`root entries (${p.entries.length})`:`根目录 (${p.entries.length})`}</summary><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english?"Name":"名称"}</th><th>{english?"Kind":"类型"}</th><th>{english?"Size":"大小"}</th><th>Cluster</th><th>{english?"State":"状态"}</th></tr></thead><tbody>{p.entries.map((entry,i)=><tr key={`${entry.name}-${i}`}><td>{entry.name}</td><td>{entry.kind}</td><td>{formatBytes(entry.size)}</td><td>{entry.cluster}</td><td>{entry.deleted?(english?"deleted":"已删除"):(english?"live":"现存")}</td></tr>)}</tbody></table></div></details>:null}</td></tr>)}</tbody></table></div></div>}
  </div>
}

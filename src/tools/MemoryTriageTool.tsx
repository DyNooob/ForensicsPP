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

import React from "react";import{AButton,ALinearProgress,InfoTable,PanelTitle,ToolPanelHeader}from"../components/ui";import{evidenceReaderFromBlob}from"../core/evidence/reader";import{analyzeMemoryTriage,type MemoryTriage}from"../features/memory/analyzer";import{copy}from"../i18n";import{formatBytes}from"../utils/files";
export function MemoryTriageTool({t,active=true}:{t:(typeof copy)["zh"];active?:boolean}){const english=t.waiting==="Waiting";const[r,setR]=React.useState<MemoryTriage|null>(null),[loading,setLoading]=React.useState(false),[error,setError]=React.useState("");const input=React.useRef<HTMLInputElement|null>(null),abort=React.useRef<AbortController|null>(null);React.useEffect(()=>()=>abort.current?.abort(),[]);const load=async(f?:File)=>{if(!f||!active)return;abort.current?.abort();const c=new AbortController();abort.current=c;setLoading(true);setError("");setR(null);try{const x=await analyzeMemoryTriage(evidenceReaderFromBlob(f),f.name,c.signal);if(!c.signal.aborted)setR(x)}catch(e){if(!c.signal.aborted)setError(e instanceof Error?e.message:String(e))}finally{if(!c.signal.aborted)setLoading(false)}};return <div className="tool-grid memory-triage-workbench"><div className="tool-panel wide-panel"><PanelTitle title={english?"Memory / minidump triage":"内存 / Minidump 初筛"}/><input ref={input} type="file" aria-hidden="true" tabIndex={-1} accept=".dmp,.mdmp,.raw,.mem,*/*" onChange={e=>{const f=e.currentTarget.files?.[0];e.currentTarget.value="";void load(f)}}/><div className="desktop-drop-zone" role="button" tabIndex={0} onClick={()=>input.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();void load(e.dataTransfer.files?.[0])}}><strong>{r?.name??(english?"Open memory dump":"打开内存镜像")}</strong><span>{r?`${r.format} · ${formatBytes(r.size)}`:(english?"Minidump metadata + bounded PE discovery; raw dumps stay random-access.":"解析 Minidump 元数据并对 RAW 内存进行有限 PE 定位，不整文件载入。")}</span></div><div className="action-row"><AButton variant="filled" onClick={()=>input.current?.click()}>{t.selectFile}</AButton><AButton variant="text" disabled={!r&&!error&&!loading} onClick={()=>{abort.current?.abort();setR(null);setError("");setLoading(false)}}>{t.clear}</AButton></div>{loading&&<ALinearProgress/>}{error&&<div className="empty-state error-state">{error}</div>}</div>{r&&<div className="tool-panel wide-panel"><ToolPanelHeader title={r.format} subtitle={formatBytes(r.size)}/><InfoTable rows={r.rows}/>{r.warnings.map((w,i)=><div className="empty-state" key={i}>{w}</div>)}{r.modules.length?<><PanelTitle title={english?"Modules":"模块"}/><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english?"Base":"基址"}</th><th>{english?"Size":"大小"}</th><th>{english?"Timestamp":"时间"}</th><th>{english?"Module":"模块"}</th></tr></thead><tbody>{r.modules.map((m,i)=><tr key={`${m.base}-${i}`}><td>{m.base}</td><td>{formatBytes(m.size)}</td><td>{m.timestamp}</td><td>{m.name}</td></tr>)}</tbody></table></div></>:null}{r.peHits.length?<><PanelTitle title={english?"PE candidates":"PE 候选"}/><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english?"Offset":"偏移"}</th><th>PE</th><th>{english?"Machine":"架构"}</th><th>{english?"Sections":"节"}</th></tr></thead><tbody>{r.peHits.slice(0,2048).map((h,i)=><tr key={`${h.offset}-${i}`}><td>0x{h.offset.toString(16).toUpperCase()}</td><td>+0x{h.peOffset.toString(16).toUpperCase()}</td><td>{h.machine}</td><td>{h.sections}</td></tr>)}</tbody></table></div></>:null}</div>}</div>}

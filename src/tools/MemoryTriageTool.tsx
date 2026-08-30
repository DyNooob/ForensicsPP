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

import React from "react";import{AButton,ALinearProgress,InfoTable,PanelTitle,ToolPanelHeader}from"../components/ui";import{evidenceReaderFromBlob}from"../core/evidence/reader";import{useToolRuntime}from"../core/runtime";import{analyzeMemoryTriage,type MemoryTriage}from"../features/memory/analyzer";import{copy}from"../i18n";import{formatBytes}from"../utils/files";import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";import { buildMemoryEnvelope } from "../features/memory/envelope";
export function MemoryTriageTool({t,active=true}:{t:(typeof copy)["zh"];active?:boolean}){const english=t.waiting==="Waiting";const[r,setR]=React.useState<MemoryTriage|null>(null);const input=React.useRef<HTMLInputElement|null>(null);const rt=useToolRuntime("memory",active);const loading=rt.status==="running";const error=rt.error?.error??"";const load=async(f?:File)=>{if(!f||!active)return;const startedAt=new Date().toISOString();rt.cancel();setR(null);let reqId=0;try{const x=await rt.run(({signal,requestId})=>{reqId=requestId;return analyzeMemoryTriage(evidenceReaderFromBlob(f),f.name,signal);},{stage:"memory triage",recovery:"reset"});rt.commit(reqId,()=>{setR(x);publishAnalysisResult("memory",buildMemoryEnvelope(x,{startedAt,completedAt:new Date().toISOString()}));});}catch{}};return <div className="tool-grid memory-triage-workbench"><div className="tool-panel wide-panel"><PanelTitle title={t.memory_minidump_triage}/><input ref={input} type="file" aria-hidden="true" tabIndex={-1} accept=".dmp,.mdmp,.raw,.mem,*/*" onChange={e=>{const f=e.currentTarget.files?.[0];e.currentTarget.value="";void load(f)}}/><div className="desktop-drop-zone" role="button" tabIndex={0} onClick={()=>input.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();void load(e.dataTransfer.files?.[0])}}><strong>{r?.name??(t.open_memory_dump)}</strong><span>{r?`${r.format} · ${formatBytes(r.size)}`:(t.minidump_metadata_bounded_pe_discovery_raw_dumps_stay_random_access)}</span></div><div className="action-row"><AButton variant="filled" onClick={()=>input.current?.click()}>{t.selectFile}</AButton><AButton variant="text" disabled={!r&&!error&&!loading} onClick={()=>{rt.reset();setR(null);clearAnalysisResult("memory");}}>{t.clear}</AButton></div>{loading&&<ALinearProgress/>}{error&&<div className="empty-state error-state">{error}</div>}</div>{r&&<div className="tool-panel wide-panel"><ToolPanelHeader title={r.format} subtitle={formatBytes(r.size)}/><InfoTable rows={r.rows}/>{r.warnings.map((w,i)=><div className="empty-state" key={i}>{w}</div>)}{r.modules.length?<><PanelTitle title={t.modules}/><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.base}</th><th>{t.fileSize}</th><th>{t.timestamp_2}</th><th>{t.module}</th></tr></thead><tbody>{r.modules.map((m,i)=><tr key={`${m.base}-${i}`}><td>{m.base}</td><td>{formatBytes(m.size)}</td><td>{m.timestamp}</td><td>{m.name}</td></tr>)}</tbody></table></div></>:null}{r.peHits.length?<><PanelTitle title={t.pe_candidates}/><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.stringOffset}</th><th>PE</th><th>{t.machine}</th><th>{t.sections}</th></tr></thead><tbody>{r.peHits.slice(0,2048).map((h,i)=><tr key={`${h.offset}-${i}`}><td>0x{h.offset.toString(16).toUpperCase()}</td><td>+0x{h.peOffset.toString(16).toUpperCase()}</td><td>{h.machine}</td><td>{h.sections}</td></tr>)}</tbody></table></div></>:null}</div>}</div>}

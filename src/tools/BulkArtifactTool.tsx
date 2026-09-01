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
import { scanBulkArtifacts, type BulkScanResult } from "../features/bulk/analyzer";
import { useToolRuntime } from "../core/runtime";
import { buildBulkEnvelope } from "../features/bulk/envelope";
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { publishAnalysisResult } from "../features/analysis/resultStore";
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";

export function BulkArtifactTool({t,active=true}:{t:(typeof copy)["zh"];active?:boolean}){const english=t.waiting==="Waiting";const[result,setResult]=React.useState<BulkScanResult|null>(null);const[progress,setProgress]=React.useState(0);const[filter,setFilter]=React.useState("");const input=React.useRef<HTMLInputElement|null>(null);const rt=useToolRuntime("bulk",active);const reqRef=React.useRef(0);const loading=rt.status==="running";const error=rt.error?.error??"";const load=async(file?:File)=>{if(!file||!active)return;const myReq=++reqRef.current;rt.cancel();setResult(null);setProgress(0);try{const r=await rt.run(({signal})=>scanBulkArtifacts(file,file.name,{signal,maxItems:10000,onProgress:(n,total)=>{if(myReq===reqRef.current)setProgress(total?n/total:0)}}),{stage:"bulk artifact scan",recovery:"reset"});if(myReq!==reqRef.current)return;setResult(r);publishAnalysisResult("bulk",buildBulkEnvelope(r,{}));}catch{}};const items=React.useMemo(()=>{const q=filter.trim().toLowerCase();return(result?.items??[]).filter(i=>!q||i.type.toLowerCase().includes(q)||i.value.toLowerCase().includes(q));},[result,filter]);const loadRef=React.useRef(load);loadRef.current=load;React.useEffect(()=>{if(!active)return;const consume=()=>{const h=takeToolHandoff("bulk");if(h)void loadRef.current(h.file)};consume();return subscribeToolHandoff("bulk",consume)},[active]);return <div className="tool-grid bulk-artifact-workbench"><div className="tool-panel wide-panel"><PanelTitle title={t.bulk_artifact_scanner}/><input ref={input} type="file" aria-hidden="true" tabIndex={-1} onChange={e=>{const f=e.currentTarget.files?.[0];e.currentTarget.value="";void load(f)}}/><div className="desktop-drop-zone" role="button" tabIndex={0} onClick={()=>input.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();void load(e.dataTransfer.files?.[0])}}><strong>{result?.name??(t.open_any_large_file)}</strong><span>{result?`${formatBytes(result.scannedBytes)} / ${formatBytes(result.size)}`:(t.streaming_extraction_of_ioc_like_and_forensic_strings_with_byte_offsets)}</span></div><div className="action-row"><AButton variant="filled" onClick={()=>input.current?.click()}>{t.selectFile}</AButton><AButton variant="text" disabled={!loading&&!result&&!error} onClick={()=>{rt.reset();setResult(null);setProgress(0)}}>{t.clear}</AButton></div>{loading&&<><ALinearProgress/><small>{(progress*100).toFixed(1)}%</small></>}{error&&<div className="empty-state error-state">{error}</div>}</div>{result&&<div className="tool-panel wide-panel"><ToolPanelHeader title={t.extracted_artifacts} subtitle={`${result.items.length}${result.truncated?"+":""}`}/><InfoTable rows={[[t.scanned,`${formatBytes(result.scannedBytes)} / ${formatBytes(result.size)}`],[t.encodings,"ASCII / UTF-16LE / UTF-16BE"],[t.counts,Object.entries(result.counts).map(([k,v])=>`${k}: ${v}`).join(" · ")||"--"],[t.truncated,result.truncated?"yes":"no"]]}/><input className="text-input" value={filter} onChange={e=>setFilter(e.currentTarget.value)} placeholder={t.filter_type_value}/><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.stringOffset}</th><th>{t.componentType}</th><th>{t.stringEncoding}</th><th>{t.httpHeaderValue}</th><th>{t.regexContext}</th></tr></thead><tbody>{items.slice(0,5000).map((item,i)=><tr key={`${item.offset}-${item.type}-${i}`}><td>0x{item.offset.toString(16).toUpperCase()}</td><td>{item.type}</td><td>{item.encoding}</td><td>{item.value}</td><td>{item.context}</td></tr>)}</tbody></table></div></div>}</div>}

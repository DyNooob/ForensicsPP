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
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";

export function BulkArtifactTool({t,active=true}:{t:(typeof copy)["zh"];active?:boolean}){const english=t.waiting==="Waiting";const[result,setResult]=React.useState<BulkScanResult|null>(null);const[error,setError]=React.useState("");const[loading,setLoading]=React.useState(false);const[progress,setProgress]=React.useState(0);const[filter,setFilter]=React.useState("");const input=React.useRef<HTMLInputElement|null>(null);const abort=React.useRef<AbortController|null>(null);React.useEffect(()=>()=>abort.current?.abort(),[]);React.useEffect(()=>{if(!active)abort.current?.abort()},[active]);
const load=async(file?:File)=>{if(!file||!active)return;abort.current?.abort();const c=new AbortController();abort.current=c;setLoading(true);setError("");setResult(null);setProgress(0);try{const r=await scanBulkArtifacts(file,file.name,{signal:c.signal,maxItems:10000,onProgress:(n,total)=>setProgress(total?n/total:0)});if(!c.signal.aborted)setResult(r);}catch(e){if(!c.signal.aborted)setError(e instanceof Error?e.message:String(e));}finally{if(abort.current===c)abort.current=null;if(!c.signal.aborted)setLoading(false)}};const items=React.useMemo(()=>{const q=filter.trim().toLowerCase();return(result?.items??[]).filter(i=>!q||i.type.toLowerCase().includes(q)||i.value.toLowerCase().includes(q));},[result,filter]);return <div className="tool-grid bulk-artifact-workbench"><div className="tool-panel wide-panel"><PanelTitle title={english?"Bulk artifact scanner":"批量痕迹扫描"}/><input ref={input} type="file" aria-hidden="true" tabIndex={-1} onChange={e=>{const f=e.currentTarget.files?.[0];e.currentTarget.value="";void load(f)}}/><div className="desktop-drop-zone" role="button" tabIndex={0} onClick={()=>input.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();void load(e.dataTransfer.files?.[0])}}><strong>{result?.name??(english?"Open any large file":"打开任意大文件")}</strong><span>{result?`${formatBytes(result.scannedBytes)} / ${formatBytes(result.size)}`:(english?"Streaming extraction of IOC-like and forensic strings with byte offsets.":"流式提取 URL、域名、IP、路径、JWT、密钥标记等，并保留字节偏移。")}</span></div><div className="action-row"><AButton variant="filled" onClick={()=>input.current?.click()}>{t.selectFile}</AButton><AButton variant="text" disabled={!loading&&!result&&!error} onClick={()=>{abort.current?.abort();setLoading(false);setResult(null);setError("");setProgress(0)}}>{t.clear}</AButton></div>{loading&&<><ALinearProgress/><small>{(progress*100).toFixed(1)}%</small></>}{error&&<div className="empty-state error-state">{error}</div>}</div>{result&&<div className="tool-panel wide-panel"><ToolPanelHeader title={english?"Extracted artifacts":"提取结果"} subtitle={`${result.items.length}${result.truncated?"+":""}`}/><InfoTable rows={[[english?"Scanned":"扫描",`${formatBytes(result.scannedBytes)} / ${formatBytes(result.size)}`],[english?"Encodings":"编码","ASCII / UTF-16LE / UTF-16BE"],[english?"Counts":"分类",Object.entries(result.counts).map(([k,v])=>`${k}: ${v}`).join(" · ")||"--"],[english?"Truncated":"截断",result.truncated?"yes":"no"]]}/><input className="text-input" value={filter} onChange={e=>setFilter(e.currentTarget.value)} placeholder={english?"Filter type/value":"筛选类型或内容"}/><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english?"Offset":"偏移"}</th><th>{english?"Type":"类型"}</th><th>{english?"Encoding":"编码"}</th><th>{english?"Value":"值"}</th><th>{english?"Context":"上下文"}</th></tr></thead><tbody>{items.slice(0,5000).map((item,i)=><tr key={`${item.offset}-${item.type}-${i}`}><td>0x{item.offset.toString(16).toUpperCase()}</td><td>{item.type}</td><td>{item.encoding}</td><td>{item.value}</td><td>{item.context}</td></tr>)}</tbody></table></div></div>}</div>}

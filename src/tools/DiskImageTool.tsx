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
import { useToolRuntime } from "../core/runtime";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { buildDiskImageEnvelope } from "../features/disk/envelope";
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";

export function DiskImageTool({ t, active=true }:{t:(typeof copy)["zh"];active?:boolean}){
  const english=t.waiting==="Waiting";
  const [analysis,setAnalysis]=React.useState<DiskAnalysis|null>(null);
  const input=React.useRef<HTMLInputElement|null>(null);
  const rt=useToolRuntime("disk",active);

  const load=async(file?:File)=>{
    if(!file||!active)return;
    rt.cancel();
    const startedAt=new Date().toISOString();
    setAnalysis(null);
    let reqId=0;
    try{
      const result=await rt.run(
        ({signal,requestId})=>{reqId=requestId;return analyzeDiskImage(evidenceReaderFromBlob(file),file.name,signal);},
        {stage:"disk image analysis",recovery:"reset"}
      );
      rt.commit(reqId,()=>{
        setAnalysis(result);
        publishAnalysisResult("disk", buildDiskImageEnvelope(result, { startedAt, completedAt: new Date().toISOString() }));
      });
    }catch{
      // rt.error already carries ToolErrorInfo; UI renders rt.error?.error
    }
  };
  const loadRef=React.useRef(load); loadRef.current=load;
  React.useEffect(()=>{if(!active)return;const consume=()=>{const handoff=takeToolHandoff("disk");if(handoff)void loadRef.current(handoff.file)};consume();return subscribeToolHandoff("disk",consume)},[active]);

  const loading=rt.status==="running";
  const error=rt.error?.error??"";

  return <div className="tool-grid disk-image-workbench">
    <div className="tool-panel wide-panel"><PanelTitle title={t.disk_image}/><input ref={input} type="file" aria-hidden="true" tabIndex={-1} accept=".dd,.raw,.img,.iso,*/*" onChange={e=>{const f=e.currentTarget.files?.[0];e.currentTarget.value="";void load(f)}}/><div className="desktop-drop-zone" role="button" tabIndex={0} onClick={()=>input.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();void load(e.dataTransfer.files?.[0])}}><strong>{analysis?.name??(t.open_dd_raw_img_iso)}</strong><span>{analysis?`${analysis.scheme} · ${formatBytes(analysis.size)}`:(t.random_access_analysis_the_whole_image_is_not_loaded_into_memory)}</span></div><div className="action-row"><AButton variant="filled" onClick={()=>input.current?.click()}>{t.selectFile}</AButton><AButton variant="text" disabled={!analysis&&!error} onClick={()=>{rt.reset();setAnalysis(null);clearAnalysisResult("disk");}}>{t.clear}</AButton></div>{loading&&<ALinearProgress/>}{error&&<div className="empty-state error-state">{error}</div>}</div>
    {analysis&&<div className="tool-panel wide-panel"><ToolPanelHeader title={t.partition_map} subtitle={`${analysis.scheme} · ${analysis.partitions.length}`}/><InfoTable rows={analysis.rows}/>{analysis.warnings.map((w,i)=><div className="empty-state error-state" key={i}>{w}</div>)}<div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>#</th><th>{t.scheme}</th><th>{t.componentType}</th><th>{t.name}</th><th>{t.start}</th><th>{t.fileSize}</th><th>{t.filesystem}</th></tr></thead><tbody>{analysis.partitions.map(p=><tr key={`${p.scheme}-${p.index}`}><td>{p.index}</td><td>{p.scheme}</td><td>{p.type}<br/><small>{p.typeCode}</small></td><td>{p.name||"--"}</td><td>LBA {p.startLba}<br/><small>0x{p.startOffset.toString(16).toUpperCase()}</small></td><td>{formatBytes(p.size)}</td><td>{p.filesystem}{p.rows.length?<details><summary>{t.metadata}</summary><InfoTable rows={p.rows}/></details>:null}{p.entries.length?<details><summary>{english?`root entries (${p.entries.length})`:`根目录 (${p.entries.length})`}</summary><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.name}</th><th>{t.kind}</th><th>{t.fileSize}</th><th>Cluster</th><th>{t.state}</th></tr></thead><tbody>{p.entries.map((entry,i)=><tr key={`${entry.name}-${i}`}><td>{entry.name}</td><td>{entry.kind}</td><td>{formatBytes(entry.size)}</td><td>{entry.cluster}</td><td>{entry.deleted?(t.deleted):(t.live)}</td></tr>)}</tbody></table></div></details>:null}</td></tr>)}</tbody></table></div></div>}
  </div>
}

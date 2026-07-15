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
import { AButton, ALinearProgress, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { persistableDocumentAnalysis, type DocumentAnalysis } from "../features/document/analyzer";
import { copy } from "../i18n";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

const MAX_FILE_BYTES = 128 * 1024 * 1024;
type View = "summary" | "findings" | "metadata" | "structure" | "extracts";

function analyzeInWorker(file: File, signal: AbortSignal) {
  return file.arrayBuffer().then(async (bytes) => {
    if (signal.aborted) throw new DOMException("Analysis cancelled", "AbortError");
    const signature = new TextDecoder("ascii").decode(new Uint8Array(bytes, 0, Math.min(8, bytes.byteLength)));
    if (signature.startsWith("%PDF-")) {
      const result = await (await import("../features/document/pdf")).analyzePdf(new Uint8Array(bytes), file.name);
      if (signal.aborted) throw new DOMException("Analysis cancelled", "AbortError");
      return result;
    }
    return runWorkerTask<{ name: string; bytes: ArrayBuffer }, DocumentAnalysis>({
      createWorker: () => new Worker(new URL("../features/document/document.worker.ts", import.meta.url), { type: "module" }),
      request: { name: file.name, bytes },
      transfer: [bytes],
      signal,
      timeoutMs: 120_000
    });
  });
}

export function DocumentForensicsTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [file, setFile] = React.useState<File | null>(null);
  const [analysis, setAnalysis] = React.useState<DocumentAnalysis | null>(null);
  const [view, setView] = React.useState<View>("summary");
  const [filter, setFilter] = React.useState("");
  const [findingCategory, setFindingCategory] = React.useState("all");
  const [structureKind, setStructureKind] = React.useState("all");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dragActive, setDragActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const workspace = useToolWorkspace<DocumentAnalysis>({
    id: "document-forensics",
    version: 2,
    isValid: (value): value is DocumentAnalysis => Boolean(value && typeof value === "object" && typeof (value as DocumentAnalysis).name === "string" && Array.isArray((value as DocumentAnalysis).entries) && Array.isArray((value as DocumentAnalysis).findings)),
    onRestore: (value) => {
      setAnalysis(value);
      setView("summary");
      setError("");
    }
  });

  const choose = (next?: File) => {
    if (!next) return;
    workspace.clear();
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
    setFile(null);
    setAnalysis(null);
    setView("summary");
    setFilter("");
    setFindingCategory("all");
    setStructureKind("all");
    if (next.size <= 0 || next.size > MAX_FILE_BYTES) {
      setError(english ? "The document is empty or exceeds 128 MiB." : "文档为空或超过 128 MiB。" );
      return;
    }
    setFile(next);
    setError("");
  };

  const analyze = async () => {
    if (!file || loading) return;
    setLoading(true);
    setError("");
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const result = await analyzeInWorker(file, controller.signal);
      setAnalysis(result);
      workspace.save(persistableDocumentAnalysis(result));
      setView("summary");
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setAnalysis(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(false);
      }
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
  };

  const clear = () => {
    workspace.clear();
    cancel();
    setFile(null);
    setAnalysis(null);
    setView("summary");
    setFilter("");
    setFindingCategory("all");
    setStructureKind("all");
    setError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  React.useEffect(() => () => {
    abortRef.current?.abort();
  }, []);
  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
  }, [active]);
  const entries = React.useMemo(() => {
    const query = filter.trim().toLowerCase();
    return (analysis?.entries ?? []).filter((entry) => (structureKind === "all" || entry.kind === structureKind) && (!query || `${entry.name} ${entry.kind}`.toLowerCase().includes(query)));
  }, [analysis, filter, structureKind]);
  const findings = React.useMemo(() => (analysis?.findings ?? []).filter((item) => findingCategory === "all" || item.category === findingCategory), [analysis, findingCategory]);
  const findingCategories = React.useMemo(() => Array.from(new Set((analysis?.findings ?? []).map((item) => item.category))), [analysis]);
  const structureKinds = React.useMemo(() => Array.from(new Set((analysis?.entries ?? []).map((item) => item.kind))).sort(), [analysis]);

  const downloadExtract = (index: number) => {
    const extract = analysis?.extracts[index];
    if (!extract) return;
    const bytes = extract.bytes.slice();
    downloadBlob(extract.name, new Blob([bytes.buffer], { type: "application/octet-stream" }));
  };

  const exportJson = () => {
    if (!analysis) return;
    const serializable = { ...analysis, extracts: analysis.extracts.map(({ bytes: _bytes, ...extract }) => extract) };
    downloadTextFile(`document-forensics-${Date.now()}.json`, JSON.stringify(serializable, null, 2), "application/json;charset=utf-8");
  };

  const views: View[] = ["summary", "findings", "metadata", "structure", "extracts"];
  const labels: Record<View, [string, string]> = {
    summary: ["摘要", "Summary"], findings: ["检查结果", "Findings"], metadata: ["元数据", "Metadata"], structure: ["结构", "Structure"], extracts: ["可提取内容", "Extracts"]
  };
  const categoryLabel = (category: string) => {
    if (english) return category;
    return ({ metadata: "元数据", external: "外部关系", embedded: "嵌入内容", macro: "宏", action: "动作", structure: "结构" } as Record<string, string>)[category] ?? category;
  };

  return <div className={`tool-grid document-forensics-workbench ${analysis ? "has-document-forensics" : "empty-document-forensics"}`}>
    <section className="tool-panel wide-panel">
      <ToolPanelHeader title={english ? "Office / PDF source" : "Office / PDF 文档"} actions={<AButton variant="text" disabled={!file && !analysis && !error} onClick={clear}>{t.clear}</AButton>} />
      <input className="hidden-file-input" ref={inputRef} type="file" accept=".pdf,.doc,.xls,.ppt,.docx,.xlsx,.pptx,.docm,.xlsm,.pptm,.dotm,.xlam" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; choose(file); }} />
      <div className={`desktop-drop-zone ${dragActive ? "active" : ""}`} role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => { event.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={(event) => { event.preventDefault(); setDragActive(false); choose(event.dataTransfer.files?.[0]); }}>
        <strong>{file?.name || (english ? "Select an Office or PDF document" : "选择 Office 或 PDF 文档")}</strong>
        <span>{file ? formatBytes(file.size) : "PDF · DOC/XLS/PPT · DOCX/XLSX/PPTX"}</span>
      </div>
      <div className="button-row"><AButton variant="outlined" onClick={() => inputRef.current?.click()}>{english ? "Select file" : "选择文件"}</AButton><AButton variant="filled" disabled={!file || loading} onClick={() => void analyze()}>{english ? "Inspect document" : "检查文档"}</AButton>{loading && <AButton variant="outlined" onClick={cancel}>{english ? "Cancel" : "取消"}</AButton>}</div>
      {loading && <><ALinearProgress /><div className="tool-loading-state">{english ? "Inspecting document structure..." : "正在检查文档结构..."}</div></>}
      {error && <div className="empty-state error-state">{error}</div>}
    </section>

    {analysis && <section className="tool-panel wide-panel document-forensics-results">
      <ToolPanelHeader title={analysis.name} subtitle={`${analysis.kind} · ${analysis.subtype}`} actions={<AButton variant="outlined" onClick={exportJson}>JSON</AButton>} />
      <ASegmentedGroup className="document-forensics-tabs" value={view} selects="single">{views.map((item) => { const count = item === "findings" ? analysis.findings.length : item === "metadata" ? analysis.metadata.length : item === "structure" ? analysis.entries.length : item === "extracts" ? analysis.extracts.length : 0; return <ASegmentedButton key={item} value={item} onClick={() => setView(item)}>{labels[item][english ? 1 : 0]}{item !== "summary" ? ` (${count})` : ""}</ASegmentedButton>; })}</ASegmentedGroup>

      {view === "summary" && <InfoTable rows={[[english ? "Container" : "容器", `${analysis.kind} · ${analysis.subtype}`], [english ? "File size" : "文件大小", formatBytes(analysis.size)], [english ? "Pages" : "页数", analysis.pages ? String(analysis.pages) : "--"], [english ? "Revisions" : "修订次数", analysis.revisions ? String(analysis.revisions) : "--"], [english ? "Package parts / streams" : "部件 / 流", String(analysis.entries.length)], [english ? "External relationships" : "外部关系", String(analysis.findings.filter((item) => item.category === "external").length)], [english ? "Embedded / macro items" : "嵌入 / 宏项目", String(analysis.findings.filter((item) => item.category === "embedded" || item.category === "macro").length)], [english ? "Encrypted" : "加密", analysis.encrypted ? (english ? "Yes" : "是") : (english ? "No indication" : "未发现标记")], ...(analysis.notes.length ? [[english ? "Notes" : "备注", analysis.notes.join("; ")] as [string, string]] : [])]} />}

      {view === "findings" && (analysis.findings.length ? <><div className="document-forensics-filter"><ASelect aria-label={english ? "Filter check category" : "筛选检查类别"} value={findingCategory} onChange={setFindingCategory} options={[{ value: "all", label: english ? "All categories" : "全部类别" }, ...findingCategories.map((category) => ({ value: category, label: categoryLabel(category) }))]} /><span>{findings.length}/{analysis.findings.length}</span></div><div className="table-scroll document-forensics-table"><table className="data-table"><thead><tr><th>{english ? "Category" : "类别"}</th><th>{english ? "Check" : "检查项"}</th><th>{english ? "Location" : "位置"}</th><th>{english ? "Detail" : "详情"}</th></tr></thead><tbody>{findings.map((finding, index) => <tr key={`${finding.location}:${finding.label}:${index}`}><td>{categoryLabel(finding.category)}</td><td>{finding.label}</td><td>{finding.location}</td><td>{finding.detail}</td></tr>)}</tbody></table></div></> : <div className="empty-state">{english ? "No structural issue was found by the supported checks." : "在支持的检查范围内没有发现结构问题。"}</div>)}

      {view === "metadata" && (analysis.metadata.length ? <InfoTable rows={analysis.metadata} /> : <div className="empty-state">{english ? "No readable document metadata." : "没有可读取的文档元数据。"}</div>)}

      {view === "structure" && <><div className="document-forensics-filter document-structure-filter"><input className="text-input" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter path or stream" : "筛选路径或流"} aria-label={english ? "Filter document structure" : "筛选文档结构"} /><ASelect aria-label={english ? "Filter structure type" : "筛选结构类型"} value={structureKind} onChange={setStructureKind} options={[{ value: "all", label: english ? "All types" : "全部类型" }, ...structureKinds.map((kind) => ({ value: kind, label: kind }))]} /><span>{entries.length}/{analysis.entries.length}</span></div><div className="table-scroll document-forensics-table"><table className="data-table"><thead><tr><th>{english ? "Path / stream" : "路径 / 流"}</th><th>{english ? "Kind" : "类型"}</th><th>{english ? "Size" : "大小"}</th></tr></thead><tbody>{entries.map((entry, index) => <tr key={`${entry.name}:${index}`}><td>{entry.name}</td><td>{entry.kind}</td><td>{formatBytes(entry.size)}</td></tr>)}</tbody></table></div></>}

      {view === "extracts" && (analysis.extracts.length ? <div className="table-scroll document-forensics-table"><table className="data-table"><thead><tr><th>{english ? "Name" : "名称"}</th><th>{english ? "Kind" : "类型"}</th><th>{english ? "Size" : "大小"}</th><th>{english ? "Action" : "操作"}</th></tr></thead><tbody>{analysis.extracts.map((extract, index) => { const available = extract.bytes.byteLength >= extract.size && extract.size > 0; return <tr key={extract.id}><td>{extract.name}</td><td>{extract.kind}</td><td>{formatBytes(extract.size)}</td><td><AButton variant="text" disabled={!available} title={!available ? (english ? "Re-analyze the document to extract this item." : "请重新分析文档后提取此项。") : undefined} onClick={() => downloadExtract(index)}>{available ? (english ? "Save" : "保存") : (english ? "Re-analyze" : "需重新分析")}</AButton></td></tr>; })}</tbody></table></div> : <div className="empty-state">{english ? "No extractable embedded item." : "没有可提取的嵌入项。"}</div>)}
    </section>}
  </div>;
}

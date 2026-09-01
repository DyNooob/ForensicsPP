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
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { useStaleRunGuard } from "../core/runtime";
import { AButton, ALinearProgress, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { persistableDocumentAnalysis, type DocumentAnalysis } from "../features/document/analyzer";
import { copy } from "../i18n";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { buildDocumentForensicsEnvelope } from "../features/document/envelope";

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
  const guard = useStaleRunGuard(active);
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
    if (!next || !active) return;
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
      setError(t.the_document_is_empty_or_exceeds_128_mib);
      return;
    }
    setFile(next);
    setError("");
  };

  const analyze = async (targetFile: File | null = file) => {
    if (!active || !targetFile) return;
    const requestId = guard.next();
    abortRef.current?.abort();
    setLoading(true);
    setError("");
    const startedAt = new Date().toISOString();
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const result = await analyzeInWorker(targetFile, controller.signal);
      if (!guard.isCurrent(requestId) || controller.signal.aborted) return;
      guard.commit(requestId, () => {
        setAnalysis(result);
        workspace.save(persistableDocumentAnalysis(result));
        setView("summary");
        publishAnalysisResult("documentforensics", buildDocumentForensicsEnvelope(result, { startedAt, completedAt: new Date().toISOString() }));
      });
    } catch (caught) {
      if (!active || (caught instanceof DOMException && caught.name === "AbortError")) return;
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
    guard.next();
    setFile(null);
    setAnalysis(null);
    setView("summary");
    setFilter("");
    setFindingCategory("all");
    setStructureKind("all");
    setError("");
    if (inputRef.current) inputRef.current.value = "";
    clearAnalysisResult("documentforensics");
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
  const chooseRef = React.useRef(choose);
  chooseRef.current = choose;
  const analyzeRef = React.useRef(analyze);
  analyzeRef.current = analyze;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("documentforensics");
      if (!handoff) return;
      chooseRef.current(handoff.file);
      void analyzeRef.current(handoff.file);
    };
    consume();
    return subscribeToolHandoff("documentforensics", consume);
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
      <ToolPanelHeader title={t.office_pdf_source} actions={<AButton variant="text" disabled={!file && !analysis && !error} onClick={clear}>{t.clear}</AButton>} />
      <input className="hidden-file-input" ref={inputRef} type="file" accept=".pdf,.doc,.xls,.ppt,.docx,.xlsx,.pptx,.docm,.xlsm,.pptm,.dotm,.xlam" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; choose(file); }} />
      <div className={`desktop-drop-zone ${dragActive ? "active" : ""}`} role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => { event.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={(event) => { event.preventDefault(); setDragActive(false); choose(event.dataTransfer.files?.[0]); }}>
        <strong>{file?.name || (t.select_an_office_or_pdf_document)}</strong>
        <span>{file ? formatBytes(file.size) : "PDF · DOC/XLS/PPT · DOCX/XLSX/PPTX"}</span>
      </div>
      <div className="button-row"><AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.select_file}</AButton><AButton variant="filled" disabled={!file || loading} onClick={() => void analyze()}>{t.inspect_document}</AButton>{loading && <AButton variant="outlined" onClick={cancel}>{t.cancelEdit}</AButton>}</div>
      {loading && <><ALinearProgress /><div className="tool-loading-state">{t.inspecting_document_structure}</div></>}
      {error && <div className="empty-state error-state">{error}</div>}
    </section>

    {analysis && <section className="tool-panel wide-panel document-forensics-results">
      <ToolPanelHeader title={analysis.name} subtitle={`${analysis.kind} · ${analysis.subtype}`} actions={<AButton variant="outlined" onClick={exportJson}>JSON</AButton>} />
      <ASegmentedGroup className="document-forensics-tabs" value={view} selects="single">{views.map((item) => { const count = item === "findings" ? analysis.findings.length : item === "metadata" ? analysis.metadata.length : item === "structure" ? analysis.entries.length : item === "extracts" ? analysis.extracts.length : 0; return <ASegmentedButton key={item} value={item} onClick={() => setView(item)}>{labels[item][english ? 1 : 0]}{item !== "summary" ? ` (${count})` : ""}</ASegmentedButton>; })}</ASegmentedGroup>

      {view === "summary" && <InfoTable rows={[[t.container, `${analysis.kind} · ${analysis.subtype}`], [t.file_size, formatBytes(analysis.size)], [t.pages, analysis.pages ? String(analysis.pages) : "--"], [t.revisions, analysis.revisions ? String(analysis.revisions) : "--"], [t.package_parts_streams, String(analysis.entries.length)], [t.external_relationships, String(analysis.findings.filter((item) => item.category === "external").length)], [t.embedded_macro_items, String(analysis.findings.filter((item) => item.category === "embedded" || item.category === "macro").length)], [t.encrypted, analysis.encrypted ? (t.yes) : (t.no_indication)], ...(analysis.notes.length ? [[t.entryRisk, analysis.notes.join("; ")] as [string, string]] : [])]} />}

      {view === "findings" && (analysis.findings.length ? <><div className="document-forensics-filter"><ASelect aria-label={t.filter_check_category} value={findingCategory} onChange={setFindingCategory} options={[{ value: "all", label: t.all_categories }, ...findingCategories.map((category) => ({ value: category, label: categoryLabel(category) }))]} /><span>{findings.length}/{analysis.findings.length}</span></div><div className="table-scroll document-forensics-table"><table className="data-table"><thead><tr><th>{t.category}</th><th>{t.check}</th><th>{t.location}</th><th>{t.detail}</th></tr></thead><tbody>{findings.map((finding, index) => <tr key={`${finding.location}:${finding.label}:${index}`}><td>{categoryLabel(finding.category)}</td><td>{finding.label}</td><td>{finding.location}</td><td>{finding.detail}</td></tr>)}</tbody></table></div></> : <div className="empty-state">{t.no_structural_issue_was_found_by_the_supported_checks}</div>)}

      {view === "metadata" && (analysis.metadata.length ? <InfoTable rows={analysis.metadata} /> : <div className="empty-state">{t.no_readable_document_metadata}</div>)}

      {view === "structure" && <><div className="document-forensics-filter document-structure-filter"><input className="text-input" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={t.filter_path_or_stream} aria-label={t.filter_document_structure} /><ASelect aria-label={t.filter_structure_type} value={structureKind} onChange={setStructureKind} options={[{ value: "all", label: t.all_types }, ...structureKinds.map((kind) => ({ value: kind, label: kind }))]} /><span>{entries.length}/{analysis.entries.length}</span></div><div className="table-scroll document-forensics-table"><table className="data-table"><thead><tr><th>{t.path_stream}</th><th>{t.kind}</th><th>{t.fileSize}</th></tr></thead><tbody>{entries.map((entry, index) => <tr key={`${entry.name}:${index}`}><td>{entry.name}</td><td>{entry.kind}</td><td>{formatBytes(entry.size)}</td></tr>)}</tbody></table></div></>}

      {view === "extracts" && (analysis.extracts.length ? <div className="table-scroll document-forensics-table"><table className="data-table"><thead><tr><th>{t.name}</th><th>{t.kind}</th><th>{t.fileSize}</th><th>{t.action}</th></tr></thead><tbody>{analysis.extracts.map((extract, index) => { const available = extract.bytes.byteLength >= extract.size && extract.size > 0; return <tr key={extract.id}><td>{extract.name}</td><td>{extract.kind}</td><td>{formatBytes(extract.size)}</td><td><AButton variant="text" disabled={!available} title={!available ? (t.re_analyze_the_document_to_extract_this_item) : undefined} onClick={() => downloadExtract(index)}>{available ? (t.save) : (t.re_analyze)}</AButton></td></tr>; })}</tbody></table></div> : <div className="empty-state">{t.no_extractable_embedded_item}</div>)}
    </section>}
  </div>;
}

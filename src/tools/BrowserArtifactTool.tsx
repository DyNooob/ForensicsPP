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
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import {
  browserArtifactRecordsToCsv,
  persistableBrowserArtifactAnalysis,
  type BrowserArtifactAnalysis,
  type BrowserArtifactInput,
  type BrowserArtifactRecord
} from "../features/browserArtifacts/analyzer";
import { buildBrowserArtifactEnvelope } from "../features/browserArtifacts/envelope";
import { useStaleRunGuard } from "../core/runtime";
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { publishAnalysisResult } from "../features/analysis/resultStore";
import { downloadTextFile, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const PAGE_SIZE = 200;

type View = "overview" | BrowserArtifactRecord["category"] | "files";

function viewLabel(view: View, english: boolean) {
  const labels: Record<View, [string, string]> = {
    overview: ["概览", "Overview"],
    visits: ["访问", "Visits"],
    downloads: ["下载", "Downloads"],
    cookies: ["Cookie", "Cookies"],
    logins: ["登录", "Logins"],
    autofill: ["自动填充", "Autofill"],
    extensions: ["扩展", "Extensions"],
    files: ["来源文件", "Files"]
  };
  return labels[view][english ? 1 : 0];
}

export function BrowserArtifactTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [selectedFiles, setSelectedFiles] = React.useState<File[]>([]);
  const [analysis, setAnalysis] = React.useState<BrowserArtifactAnalysis | null>(null);
  const [view, setView] = React.useState<View>("overview");
  const [filter, setFilter] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [selectedRecordId, setSelectedRecordId] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [progress, setProgress] = React.useState("");
  const [error, setError] = React.useState("");
  const [dragActive, setDragActive] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const folderInputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const guard = useStaleRunGuard(active);
  const directoryProps = { webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement> & Record<string, string>;
  const workspace = useToolWorkspace<BrowserArtifactAnalysis>({
    id: "browser-artifacts",
    version: 2,
    isValid: (value): value is BrowserArtifactAnalysis => Boolean(value && typeof value === "object" && Array.isArray((value as BrowserArtifactAnalysis).records) && Array.isArray((value as BrowserArtifactAnalysis).files)),
    onRestore: (value) => {
      setAnalysis(value);
      setView("overview");
      setError("");
    }
  });

  const queueFiles = (files?: FileList | File[] | null) => {
    if (!active) return [];
    cancel();
    workspace.clear();
    const next = Array.from(files ?? []).filter((file) => {
      const name = file.name.toLowerCase();
      return file.size > 0 && (
        ["history", "cookies", "login data", "web data", "places.sqlite", "cookies.sqlite", "bookmarks", "preferences", "logins.json"].includes(name)
        || /\.(?:sqlite|sqlite3|db)$/i.test(name)
      );
    });
    if (!next.length) {
      setSelectedFiles([]);
      setAnalysis(null);
      setView("overview");
      setFilter("");
      setPage(0);
      setSelectedRecordId("");
      setError(t.no_supported_browser_data_file_was_selected);
      return [];
    }
    const tooLarge = next.find((file) => file.size > MAX_FILE_BYTES);
    const total = next.reduce((sum, file) => sum + file.size, 0);
    if (tooLarge || total > MAX_TOTAL_BYTES) {
      setSelectedFiles([]);
      setAnalysis(null);
      setView("overview");
      setFilter("");
      setPage(0);
      setSelectedRecordId("");
      setError(tooLarge
        ? (english ? `${tooLarge.name} exceeds the 128 MiB per-file limit.` : `${tooLarge.name} 超过单文件 128 MiB 限制。`)
        : (t.the_selected_files_exceed_the_256_mib_total_limit));
      return [];
    }
    setSelectedFiles(next);
    setAnalysis(null);
    setView("overview");
    setFilter("");
    setPage(0);
    setSelectedRecordId("");
    setError("");
    return next;
  };

  const analyze = async (files?: File[]) => {
    const sourceFiles = files ?? selectedFiles;
    if (!active || !sourceFiles.length || (!files && loading)) return;
    const requestId = guard.next();
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setLoading(true);
    setProgress("");
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const inputs: Array<Omit<BrowserArtifactInput, "bytes"> & { bytes: ArrayBuffer }> = [];
      for (const [index, file] of sourceFiles.entries()) {
        if (controller.signal.aborted) return;
        setProgress(english ? `Reading ${index + 1}/${sourceFiles.length}: ${file.name}` : `正在读取 ${index + 1}/${sourceFiles.length}：${file.name}`);
        inputs.push({
          name: file.name,
          path: file.webkitRelativePath || file.name,
          size: file.size,
          bytes: await file.arrayBuffer()
        });
        if (controller.signal.aborted) return;
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
      if (controller.signal.aborted) return;
      setProgress(t.parsing_browser_data);
      const result = await runWorkerTask<{ inputs: typeof inputs }, BrowserArtifactAnalysis>({
        createWorker: () => new Worker(new URL("../features/browserArtifacts/browser-artifacts.worker.ts", import.meta.url), { type: "module" }),
        request: { inputs },
        transfer: inputs.map((input) => input.bytes),
        signal: controller.signal,
        timeoutMs: 120_000
      });
      if (abortRef.current !== controller || controller.signal.aborted) return;
      guard.commit(requestId, () => {
        setAnalysis(result);
        workspace.save(persistableBrowserArtifactAnalysis(result));
        publishAnalysisResult("browserartifacts", buildBrowserArtifactEnvelope(result));
        if (!result.records.length) setError(t.files_opened_but_no_supported_browser_records_were_found);
      });
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      if (abortRef.current === controller && active) {
        setAnalysis(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(false);
        setProgress("");
      }
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
    setProgress("");
  };

  const clear = () => {
    guard.next();
    workspace.clear();
    cancel();
    setSelectedFiles([]);
    setAnalysis(null);
    setView("overview");
    setFilter("");
    setPage(0);
    setSelectedRecordId("");
    setError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (folderInputRef.current) folderInputRef.current.value = "";
  };

  React.useEffect(() => () => abortRef.current?.abort(), []);
  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
    setProgress("");
  }, [active]);
  const queueFilesRef = React.useRef(queueFiles);
  queueFilesRef.current = queueFiles;
  const analyzeRef = React.useRef(analyze);
  analyzeRef.current = analyze;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("browserartifacts");
      if (!handoff) return;
      const files = queueFilesRef.current([handoff.file]);
      if (files.length) void analyzeRef.current(files);
    };
    consume();
    return subscribeToolHandoff("browserartifacts", consume);
  }, [active]);

  const categoryRecords = React.useMemo(() => analysis && view !== "overview" && view !== "files"
    ? analysis.records.filter((record) => record.category === view)
    : [], [analysis, view]);
  const deferredFilter = React.useDeferredValue(filter);
  const filteredRecords = React.useMemo(() => {
    const query = deferredFilter.trim().toLowerCase();
    if (!query) return categoryRecords;
    return categoryRecords.filter((record) => [record.time, record.browser, record.profile, record.primary, record.secondary, record.detail, record.source].join(" ").toLowerCase().includes(query));
  }, [categoryRecords, deferredFilter]);
  const pageCount = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const visibleRecords = filteredRecords.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selectedBytes = selectedFiles.reduce((sum, file) => sum + file.size, 0);
  const selectedRecord = categoryRecords.find((record) => record.id === selectedRecordId) ?? null;

  React.useEffect(() => setPage(0), [filter, view]);
  React.useEffect(() => { if (page >= pageCount) setPage(pageCount - 1); }, [page, pageCount]);

  const views: View[] = ["overview", "visits", "downloads", "cookies", "logins", "autofill", "extensions", "files"];

  return (
    <div className={`tool-grid browser-artifact-workbench ${analysis ? "has-browser-artifacts" : "empty-browser-artifacts"}`}>
      <section className="tool-panel wide-panel browser-artifact-source-panel">
        <ToolPanelHeader
          title={t.browser_data}
          actions={<AButton variant="text" disabled={!selectedFiles.length && !analysis && !error} onClick={clear}>{t.clear}</AButton>}
        />
        <input className="hidden-file-input" ref={fileInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { queueFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        <input className="hidden-file-input" ref={folderInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} {...directoryProps} onChange={(event) => { queueFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        <div
          className={`desktop-drop-zone ${dragActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(event) => { event.preventDefault(); setDragActive(false); queueFiles(event.dataTransfer.files); }}
        >
          <strong>{selectedFiles.length ? (english ? `${selectedFiles.length} supported files selected` : `已选择 ${selectedFiles.length} 个文件`) : (t.select_browser_data_files)}</strong>
          <span>{selectedFiles.length ? formatBytes(selectedBytes) : "Chrome / Edge / Firefox: History, Cookies, Login Data, Web Data, Bookmarks, Preferences"}</span>
        </div>
        <div className="button-row">
          <AButton variant="outlined" onClick={() => fileInputRef.current?.click()}>{t.select_files}</AButton>
          <AButton variant="outlined" onClick={() => folderInputRef.current?.click()}>{t.select_profile_folder}</AButton>
          <AButton variant="filled" disabled={!selectedFiles.length || loading} onClick={() => void analyze()}>{loading ? (t.parsing) : (t.parse_data)}</AButton>
          {loading && <AButton variant="outlined" onClick={cancel}>{t.cancelEdit}</AButton>}
        </div>
        {loading && <><ALinearProgress /><div className="tool-loading-state">{progress}</div></>}
        {error && <div className="empty-state error-state">{error}</div>}
      </section>

      {analysis && (
        <section className="tool-panel wide-panel browser-artifact-results-panel">
          <ToolPanelHeader
            title={t.parsed_browser_data}
            subtitle={`${analysis.records.length.toLocaleString()} ${t.records}`}
            actions={view !== "overview" && view !== "files" ? <AButton variant="outlined" disabled={!filteredRecords.length} onClick={() => downloadTextFile(`browser-${view}-${Date.now()}.csv`, browserArtifactRecordsToCsv(filteredRecords), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton> : undefined}
          />
          <ASegmentedGroup className="browser-artifact-tabs" value={view} selects="single">
            {views.map((item) => {
              const count = item === "files" ? analysis.files.length : item === "overview" ? analysis.records.length : analysis.counts[item];
              return <ASegmentedButton key={item} value={item} onClick={() => { setView(item); setSelectedRecordId(""); }}>{viewLabel(item, english)} ({count})</ASegmentedButton>;
            })}
          </ASegmentedGroup>
          {analysis.files.some((file) => file.truncated) && <div className="pcap-stream-notice" role="status">{t.at_least_one_source_file_reached_the_50_000_record_limit_use_the_original_database_for_a_complete_export}</div>}
          {analysis.snapshotLimited && <div className="pcap-stream-notice" role="status">{t.this_restored_workspace_keeps_a_bounded_record_snapshot_re_open_the_original_files_for_a_complete_export}</div>}

          {view === "overview" && (
            <div className="browser-artifact-overview">
              <InfoTable rows={[
                [t.browsers, analysis.browsers.join(", ") || "--"],
                [t.profiles, analysis.profiles.join(", ") || "--"],
                [t.parsed_files, `${analysis.files.filter((file) => file.status === "parsed").length}/${analysis.files.length}`],
                [t.time_range, analysis.firstTime ? `${analysis.firstTime} → ${analysis.lastTime}` : "--"],
                [t.visits_downloads, `${analysis.counts.visits} / ${analysis.counts.downloads}`],
                [t.cookies_logins, `${analysis.counts.cookies} / ${analysis.counts.logins}`],
                [t.autofill_extensions, `${analysis.counts.autofill} / ${analysis.counts.extensions}`]
              ]} />
            </div>
          )}

          {view === "files" && <div className="table-scroll browser-artifact-table-scroll"><table className="data-table"><thead><tr><th>{t.sourceFile}</th><th>{t.data_type}</th><th>{t.browser}</th><th>Profile</th><th>{t.fileSize}</th><th>{t.records_2}</th><th>{t.status}</th></tr></thead><tbody>{analysis.files.map((file) => <tr key={file.path}><td>{file.path}</td><td>{file.artifact}</td><td>{file.browser}</td><td>{file.profile}</td><td>{formatBytes(file.size)}</td><td>{file.records}{file.truncated ? "+" : ""}</td><td title={file.detail}>{file.truncated ? (t.limited) : file.status}</td></tr>)}</tbody></table></div>}

          {view !== "overview" && view !== "files" && (
            <>
              <div className="browser-artifact-toolbar"><input className="text-input" aria-label={t.filter_browser_records} value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={t.filter_url_title_profile_path_or_detail} /><span>{filteredRecords.length}/{categoryRecords.length}</span></div>
              <div className="table-scroll browser-artifact-table-scroll"><table className="data-table browser-artifact-table"><thead><tr><th>{t.time}</th><th>{t.primary}</th><th>{t.secondary}</th><th>{t.browser_profile}</th><th>{t.iocSource}</th></tr></thead><tbody>{visibleRecords.map((record) => <tr className={record.id === selectedRecordId ? "selected-row" : ""} key={record.id} tabIndex={0} onClick={() => setSelectedRecordId(record.id)} onKeyDown={(event) => { if (event.key === "Enter") setSelectedRecordId(record.id); }}><td>{record.time || "--"}</td><td title={record.primary}>{record.primary || "--"}</td><td title={record.secondary}>{record.secondary || "--"}</td><td>{record.browser}<br /><small>{record.profile}</small></td><td title={record.source}>{record.source}</td></tr>)}</tbody></table></div>
              {filteredRecords.length > PAGE_SIZE && <div className="browser-artifact-pagination"><span>{page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, filteredRecords.length)} / {filteredRecords.length}</span><div className="button-row compact-buttons"><AButton variant="text" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{t.previous}</AButton><AButton variant="text" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{t.next}</AButton></div></div>}
              {selectedRecord && <div className="browser-artifact-detail"><ToolPanelHeader title={selectedRecord.primary || viewLabel(view, english)} subtitle={selectedRecord.time || selectedRecord.source} /><InfoTable rows={[
                [t.category, viewLabel(selectedRecord.category, english)],
                [t.secondary, selectedRecord.secondary || "--"],
                ["URL", selectedRecord.url || "--"],
                [t.jsonPath, selectedRecord.path || "--"],
                [t.browser_profile, `${selectedRecord.browser} / ${selectedRecord.profile}`],
                [t.iocSource, selectedRecord.source],
                [t.details, selectedRecord.detail || "--"]
              ]} /></div>}
            </>
          )}
        </section>
      )}
    </div>
  );
}

/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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
  type BrowserArtifactAnalysis,
  type BrowserArtifactInput,
  type BrowserArtifactRecord
} from "../features/browserArtifacts/analyzer";
import { downloadTextFile, formatBytes } from "../utils/files";

const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
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

export function BrowserArtifactTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [selectedFiles, setSelectedFiles] = React.useState<File[]>([]);
  const [analysis, setAnalysis] = React.useState<BrowserArtifactAnalysis | null>(null);
  const [view, setView] = React.useState<View>("overview");
  const [filter, setFilter] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dragActive, setDragActive] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const folderInputRef = React.useRef<HTMLInputElement | null>(null);
  const workerRef = React.useRef<Worker | null>(null);
  const directoryProps = { webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement> & Record<string, string>;

  const queueFiles = (files?: FileList | File[] | null) => {
    const next = Array.from(files ?? []).filter((file) => {
      const name = file.name.toLowerCase();
      return file.size > 0 && (
        ["history", "cookies", "login data", "web data", "places.sqlite", "cookies.sqlite", "bookmarks", "preferences", "logins.json"].includes(name)
        || /\.(?:sqlite|sqlite3|db)$/i.test(name)
      );
    });
    if (!next.length) {
      setError(english ? "No supported browser data file was selected." : "没有选择支持的浏览器数据文件。");
      return;
    }
    const tooLarge = next.find((file) => file.size > MAX_FILE_BYTES);
    const total = next.reduce((sum, file) => sum + file.size, 0);
    if (tooLarge || total > MAX_TOTAL_BYTES) {
      setError(tooLarge
        ? (english ? `${tooLarge.name} exceeds the 256 MiB per-file limit.` : `${tooLarge.name} 超过单文件 256 MiB 限制。`)
        : (english ? "The selected files exceed the 512 MiB total limit." : "所选文件总大小超过 512 MiB。"));
      return;
    }
    setSelectedFiles(next);
    setAnalysis(null);
    setView("overview");
    setFilter("");
    setPage(0);
    setError("");
  };

  const analyze = async () => {
    if (!selectedFiles.length || loading) return;
    setLoading(true);
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const inputs: Array<Omit<BrowserArtifactInput, "bytes"> & { bytes: ArrayBuffer }> = [];
      for (const file of selectedFiles) {
        inputs.push({
          name: file.name,
          path: file.webkitRelativePath || file.name,
          size: file.size,
          bytes: await file.arrayBuffer()
        });
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
      const result = await new Promise<BrowserArtifactAnalysis>((resolve, reject) => {
        const worker = new Worker(new URL("../features/browserArtifacts/browser-artifacts.worker.ts", import.meta.url), { type: "module" });
        workerRef.current = worker;
        worker.onmessage = (event: MessageEvent<{ type: "result"; result: BrowserArtifactAnalysis } | { type: "error"; error: string }>) => {
          worker.terminate();
          workerRef.current = null;
          if (event.data.type === "result") resolve(event.data.result);
          else reject(new Error(event.data.error));
        };
        worker.onerror = (event) => {
          worker.terminate();
          workerRef.current = null;
          reject(new Error(event.message || "Browser artifact worker failed."));
        };
        worker.postMessage({ inputs }, inputs.map((input) => input.bytes));
      });
      setAnalysis(result);
      if (!result.records.length) setError(english ? "Files opened, but no supported browser records were found." : "文件已打开，但未找到支持的浏览器记录。" );
    } catch (caught) {
      setAnalysis(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const cancel = () => {
    workerRef.current?.terminate();
    workerRef.current = null;
    setLoading(false);
  };

  const clear = () => {
    cancel();
    setSelectedFiles([]);
    setAnalysis(null);
    setView("overview");
    setFilter("");
    setPage(0);
    setError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (folderInputRef.current) folderInputRef.current.value = "";
  };

  React.useEffect(() => () => workerRef.current?.terminate(), []);

  const categoryRecords = React.useMemo(() => analysis && view !== "overview" && view !== "files"
    ? analysis.records.filter((record) => record.category === view)
    : [], [analysis, view]);
  const filteredRecords = React.useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return categoryRecords;
    return categoryRecords.filter((record) => [record.time, record.browser, record.profile, record.primary, record.secondary, record.detail, record.source].join(" ").toLowerCase().includes(query));
  }, [categoryRecords, filter]);
  const pageCount = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const visibleRecords = filteredRecords.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selectedBytes = selectedFiles.reduce((sum, file) => sum + file.size, 0);

  React.useEffect(() => setPage(0), [filter, view]);
  React.useEffect(() => { if (page >= pageCount) setPage(pageCount - 1); }, [page, pageCount]);

  const views: View[] = ["overview", "visits", "downloads", "cookies", "logins", "autofill", "extensions", "files"];

  return (
    <div className={`tool-grid browser-artifact-workbench ${analysis ? "has-browser-artifacts" : "empty-browser-artifacts"}`}>
      <section className="tool-panel wide-panel browser-artifact-source-panel">
        <ToolPanelHeader
          title={english ? "Browser data" : "选择浏览器数据"}
          actions={<AButton variant="text" disabled={!selectedFiles.length && !analysis && !error} onClick={clear}>{t.clear}</AButton>}
        />
        <input className="hidden-file-input" ref={fileInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => queueFiles(event.target.files)} />
        <input className="hidden-file-input" ref={folderInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} {...directoryProps} onChange={(event) => queueFiles(event.target.files)} />
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
          <strong>{selectedFiles.length ? (english ? `${selectedFiles.length} supported files selected` : `已选择 ${selectedFiles.length} 个文件`) : (english ? "Select browser data files" : "选择浏览器数据文件")}</strong>
          <span>{selectedFiles.length ? formatBytes(selectedBytes) : "Chrome / Edge / Firefox: History, Cookies, Login Data, Web Data, Bookmarks, Preferences"}</span>
        </div>
        <div className="button-row">
          <AButton variant="outlined" onClick={() => fileInputRef.current?.click()}>{english ? "Select files" : "选择文件"}</AButton>
          <AButton variant="outlined" onClick={() => folderInputRef.current?.click()}>{english ? "Select profile folder" : "选择 Profile 目录"}</AButton>
          <AButton variant="filled" disabled={!selectedFiles.length || loading} onClick={() => void analyze()}>{loading ? (english ? "Parsing..." : "正在解析...") : (english ? "Parse data" : "开始解析")}</AButton>
          {loading && <AButton variant="outlined" onClick={cancel}>{english ? "Cancel" : "取消"}</AButton>}
        </div>
        {loading && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </section>

      {analysis && (
        <section className="tool-panel wide-panel browser-artifact-results-panel">
          <ToolPanelHeader
            title={english ? "Parsed browser data" : "解析结果"}
            subtitle={`${analysis.records.length.toLocaleString()} ${english ? "records" : "条记录"}`}
            actions={view !== "overview" && view !== "files" ? <AButton variant="outlined" disabled={!filteredRecords.length} onClick={() => downloadTextFile(`browser-${view}-${Date.now()}.csv`, browserArtifactRecordsToCsv(filteredRecords), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton> : undefined}
          />
          <ASegmentedGroup className="browser-artifact-tabs" value={view} selects="single">
            {views.map((item) => {
              const count = item === "files" ? analysis.files.length : item === "overview" ? analysis.records.length : analysis.counts[item];
              return <ASegmentedButton key={item} value={item} onClick={() => setView(item)}>{viewLabel(item, english)} ({count})</ASegmentedButton>;
            })}
          </ASegmentedGroup>

          {view === "overview" && (
            <div className="browser-artifact-overview">
              <InfoTable rows={[
                [english ? "Browsers" : "浏览器", analysis.browsers.join(", ") || "--"],
                [english ? "Profiles" : "Profile", analysis.profiles.join(", ") || "--"],
                [english ? "Parsed files" : "解析文件", `${analysis.files.filter((file) => file.status === "parsed").length}/${analysis.files.length}`],
                [english ? "Time range" : "时间范围", analysis.firstTime ? `${analysis.firstTime} → ${analysis.lastTime}` : "--"],
                [english ? "Visits / downloads" : "访问 / 下载", `${analysis.counts.visits} / ${analysis.counts.downloads}`],
                [english ? "Cookies / logins" : "Cookie / 登录", `${analysis.counts.cookies} / ${analysis.counts.logins}`],
                [english ? "Autofill / extensions" : "自动填充 / 扩展", `${analysis.counts.autofill} / ${analysis.counts.extensions}`]
              ]} />
            </div>
          )}

          {view === "files" && <div className="table-scroll browser-artifact-table-scroll"><table className="data-table"><thead><tr><th>{english ? "File" : "文件"}</th><th>{english ? "Data type" : "数据类型"}</th><th>{english ? "Browser" : "浏览器"}</th><th>Profile</th><th>{english ? "Size" : "大小"}</th><th>{english ? "Records" : "记录"}</th><th>{english ? "Status" : "状态"}</th></tr></thead><tbody>{analysis.files.map((file) => <tr key={file.path}><td>{file.path}</td><td>{file.artifact}</td><td>{file.browser}</td><td>{file.profile}</td><td>{formatBytes(file.size)}</td><td>{file.records}</td><td title={file.detail}>{file.status}</td></tr>)}</tbody></table></div>}

          {view !== "overview" && view !== "files" && (
            <>
              <div className="browser-artifact-toolbar"><input className="text-input" aria-label={english ? "Filter browser records" : "筛选浏览器记录"} value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter URL, title, profile, path, or detail" : "筛选 URL、标题、Profile、路径或详情"} /><span>{filteredRecords.length}/{categoryRecords.length}</span></div>
              <div className="table-scroll browser-artifact-table-scroll"><table className="data-table browser-artifact-table"><thead><tr><th>{english ? "Time" : "时间"}</th><th>{english ? "Primary" : "主要字段"}</th><th>{english ? "Secondary" : "次要字段"}</th><th>{english ? "Browser / Profile" : "浏览器 / Profile"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Details" : "详情"}</th></tr></thead><tbody>{visibleRecords.map((record) => <tr key={record.id}><td>{record.time || "--"}</td><td title={record.primary}>{record.primary || "--"}</td><td title={record.secondary}>{record.secondary || "--"}</td><td>{record.browser}<br /><small>{record.profile}</small></td><td title={record.source}>{record.source}</td><td title={record.detail}>{record.detail}</td></tr>)}</tbody></table></div>
              {filteredRecords.length > PAGE_SIZE && <div className="browser-artifact-pagination"><span>{page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, filteredRecords.length)} / {filteredRecords.length}</span><div className="button-row compact-buttons"><AButton variant="text" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton><AButton variant="text" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton></div></div>}
            </>
          )}
        </section>
      )}
    </div>
  );
}

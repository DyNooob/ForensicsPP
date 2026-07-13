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
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, PanelTitle, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { WindowsArtifactAnalysis } from "../models";
import { formatBytes } from "../utils/files";

type Services = {
  analyzeWindowsArtifact: (bytes: Uint8Array, name: string) => WindowsArtifactAnalysis;
};

const MAX_FILE_BYTES = 64 * 1024 * 1024;
type ResultView = "overview" | "fields" | "timestamps" | "paths" | "text";

export function WindowsArtifactTool({ t, services }: { t: (typeof copy)["zh"]; services: Services }) {
  const english = t.waiting === "Waiting";
  const [analysis, setAnalysis] = React.useState<WindowsArtifactAnalysis | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const [view, setView] = React.useState<ResultView>("overview");
  const [pathFilter, setPathFilter] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  React.useEffect(() => () => { requestRef.current += 1; }, []);

  const loadFile = async (file?: File) => {
    if (!file) return;
    const requestId = ++requestRef.current;
    setDropActive(false);
    setError("");
    setAnalysis(null);
    setView("overview");
    setPathFilter("");
    if (file.size > MAX_FILE_BYTES) {
      setError(english ? "The file exceeds the 64 MiB limit." : "文件超过 64 MiB 限制。");
      return;
    }
    setLoading(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (requestId !== requestRef.current) return;
      setAnalysis(services.analyzeWindowsArtifact(bytes, file.name));
    } catch (caught) {
      if (requestId === requestRef.current) {
        setAnalysis(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (requestId === requestRef.current) setLoading(false);
    }
  };

  const clear = () => {
    requestRef.current += 1;
    setAnalysis(null);
    setError("");
    setLoading(false);
    setDropActive(false);
    setView("overview");
    setPathFilter("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const detailRows = analysis?.rows.filter(([name]) => !["Name", "Size", "Artifact type"].includes(name)) ?? [];
  const visiblePaths = React.useMemo(() => {
    const query = pathFilter.trim().toLowerCase();
    return (analysis?.strings ?? []).filter((item) => !query || item.value.toLowerCase().includes(query));
  }, [analysis, pathFilter]);
  const textAvailable = Boolean(analysis?.textPreview && /Zone\.Identifier|Registry Export/i.test(analysis.artifactType));
  const views = React.useMemo(() => analysis ? [
    { id: "overview" as const, label: english ? "Overview" : "概览", count: 0 },
    { id: "fields" as const, label: english ? "Fields" : "字段", count: detailRows.length },
    ...(analysis.timeline.length ? [{ id: "timestamps" as const, label: english ? "Timestamps" : "时间", count: analysis.timeline.length }] : []),
    ...(analysis.strings.length ? [{ id: "paths" as const, label: english ? "Paths" : "路径", count: analysis.strings.length }] : []),
    ...(textAvailable ? [{ id: "text" as const, label: english ? "Text" : "文本", count: 0 }] : [])
  ] : [], [analysis, detailRows.length, english, textAvailable]);

  return (
    <div className={`tool-grid windows-artifact-workbench ${analysis ? "has-windows" : "empty-windows"}`}>
      <div className="tool-panel wide-panel windows-source-panel">
        <PanelTitle title={english ? "Windows file" : "选择 Windows 文件"} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".lnk,.pf,.reg,.txt,*/*" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void loadFile(file); }} />
        <div
          className={`desktop-drop-zone ${dropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); void loadFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{analysis?.name || t.dropFileTitle}</strong>
          <span>{analysis ? `${analysis.artifactType} · ${formatBytes(analysis.size)}` : (english ? "LNK, Prefetch, Zone.Identifier, or REG" : "支持 LNK、Prefetch、Zone.Identifier 和 REG")}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!analysis && !error && !loading} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {analysis && (
          <div className="tool-panel wide-panel windows-results-panel">
            <ToolPanelHeader title={analysis.artifactType} subtitle={`${analysis.name} · ${formatBytes(analysis.size)}`} />
            <ASegmentedGroup className="windows-result-tabs" value={view} selects="single">
              {views.map((item) => <ASegmentedButton key={item.id} value={item.id} onClick={() => setView(item.id)}>{item.label}{item.count ? ` (${item.count})` : ""}</ASegmentedButton>)}
            </ASegmentedGroup>

            {view === "overview" &&
            <InfoTable rows={[
              [english ? "Name" : "名称", analysis.name],
              [english ? "Type" : "类型", analysis.artifactType],
              [t.fileSize, formatBytes(analysis.size)],
              [english ? "Parsed fields" : "解析字段", String(detailRows.length)],
              [english ? "Timestamps" : "时间记录", String(analysis.timeline.length)],
              [english ? "Paths" : "路径", String(analysis.strings.length)]
            ]} />
            }

            {view === "fields" &&
            <InfoTable rows={detailRows.length ? detailRows : [[english ? "Result" : "结果", "--"]]} />
            }

            {view === "timestamps" && (
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>UTC</th><th>{english ? "Format" : "格式"}</th><th>{english ? "Context" : "说明"}</th></tr></thead>
                  <tbody>{analysis.timeline.map((event) => (
                    <tr key={event.id}><td>{event.iso}</td><td>{event.format}</td><td>{event.context}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}

            {view === "paths" && (
              <>
              <div className="windows-path-filter"><input className="text-input" value={pathFilter} onChange={(event) => setPathFilter(event.currentTarget.value)} placeholder={english ? "Filter paths" : "筛选路径"} aria-label={english ? "Filter paths" : "筛选路径"} /><span>{visiblePaths.length}/{analysis.strings.length}</span></div>
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Value" : "值"}</th></tr></thead>
                  <tbody>{visiblePaths.map((item) => (
                    <tr key={item.id}><td>0x{item.offset.toString(16).toUpperCase()}</td><td>{item.value}</td></tr>
                  ))}</tbody>
                </table>
              </div>
              </>
          )}

          {view === "text" && textAvailable && (
              <div className="windows-text-view">
                <div className="panel-heading-row">
                <span />
                <AButton variant="text" onClick={() => void navigator.clipboard.writeText(analysis.textPreview)}>{t.copy}</AButton>
              </div>
              <textarea className="single-textarea windows-preview-textarea" value={analysis.textPreview} readOnly />
            </div>
          )}
          </div>
      )}
    </div>
  );
}

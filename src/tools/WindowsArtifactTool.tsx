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
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { WindowsArtifactAnalysis } from "../models";
import { formatBytes } from "../utils/files";

type Services = {
  analyzeWindowsArtifact: (bytes: Uint8Array, name: string) => WindowsArtifactAnalysis;
};

const MAX_FILE_BYTES = 64 * 1024 * 1024;

export function WindowsArtifactTool({ t, services }: { t: (typeof copy)["zh"]; services: Services }) {
  const english = t.waiting === "Waiting";
  const [analysis, setAnalysis] = React.useState<WindowsArtifactAnalysis | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const loadFile = async (file?: File) => {
    if (!file) return;
    setDropActive(false);
    setError("");
    if (file.size > MAX_FILE_BYTES) {
      setError(english ? "The file exceeds the 64 MiB limit." : "文件超过 64 MiB 限制。");
      return;
    }
    setLoading(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      setAnalysis(services.analyzeWindowsArtifact(bytes, file.name));
    } catch (caught) {
      setAnalysis(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setAnalysis(null);
    setError("");
    setLoading(false);
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const detailRows = analysis?.rows.filter(([name]) => !["Name", "Size", "Artifact type"].includes(name)) ?? [];

  return (
    <div className={`tool-grid windows-artifact-workbench ${analysis ? "has-windows" : "empty-windows"}`}>
      <div className="tool-panel wide-panel windows-source-panel">
        <PanelTitle title={english ? "Windows file" : "选择 Windows 文件"} />
        <input ref={inputRef} type="file" accept=".lnk,.pf,.reg,.txt,*/*" onChange={(event) => void loadFile(event.target.files?.[0])} />
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
          <AButton variant="text" disabled={!analysis && !error} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {analysis && (
        <>
          <div className="tool-panel wide-panel windows-summary-panel">
            <PanelTitle title={t.summary} />
            <InfoTable rows={[
              [english ? "Name" : "名称", analysis.name],
              [english ? "Type" : "类型", analysis.artifactType],
              [t.fileSize, formatBytes(analysis.size)],
              [english ? "Parsed fields" : "解析字段", String(detailRows.length)],
              [english ? "Timestamps" : "时间记录", String(analysis.timeline.length)],
              [english ? "Paths" : "路径", String(analysis.strings.length)]
            ]} />
          </div>

          <div className="tool-panel wide-panel windows-fields-panel">
            <PanelTitle title={english ? "Parsed fields" : "解析字段"} />
            <InfoTable rows={detailRows.length ? detailRows : [[english ? "Result" : "结果", "--"]]} />
          </div>

          {analysis.timeline.length > 0 && (
            <div className="tool-panel wide-panel windows-time-panel">
              <PanelTitle title={english ? "Timestamps" : "时间记录"} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>UTC</th><th>{english ? "Format" : "格式"}</th><th>{english ? "Context" : "说明"}</th></tr></thead>
                  <tbody>{analysis.timeline.map((event) => (
                    <tr key={event.id}><td>{event.iso}</td><td>{event.format}</td><td>{event.context}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            </div>
          )}

          {analysis.strings.length > 0 && (
            <div className="tool-panel wide-panel windows-paths-panel">
              <PanelTitle title={english ? "Paths" : "路径"} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Value" : "值"}</th></tr></thead>
                  <tbody>{analysis.strings.map((item) => (
                    <tr key={item.id}><td>0x{item.offset.toString(16).toUpperCase()}</td><td>{item.value}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            </div>
          )}

          {analysis.textPreview && /Zone\.Identifier|Registry Export/i.test(analysis.artifactType) && (
            <div className="tool-panel wide-panel windows-preview-panel">
              <div className="panel-heading-row">
                <PanelTitle title={english ? "Text preview" : "文本预览"} />
                <AButton variant="text" onClick={() => void navigator.clipboard.writeText(analysis.textPreview)}>{t.copy}</AButton>
              </div>
              <textarea className="single-textarea windows-preview-textarea" value={analysis.textPreview} readOnly />
            </div>
          )}
        </>
      )}
    </div>
  );
}

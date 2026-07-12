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
import type { PngAnalysis } from "../models";
import { downloadBlob, formatBytes } from "../utils/files";

type Services = {
  analyzePngEvidence: (bytes: Uint8Array, name: string) => PngAnalysis;
};

const MAX_PNG_BYTES = 128 * 1024 * 1024;

export function PngTool({ t, services }: { t: (typeof copy)["zh"]; services: Services }) {
  const english = t.waiting === "Waiting";
  const [analysis, setAnalysis] = React.useState<PngAnalysis | null>(null);
  const [previewUrl, setPreviewUrl] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  React.useEffect(() => () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
  }, [previewUrl]);

  const loadFile = async (file?: File) => {
    if (!file) return;
    setDropActive(false);
    setError("");
    if (file.size > MAX_PNG_BYTES) {
      setError(english ? "The PNG exceeds the 128 MiB limit." : "PNG 文件超过 128 MiB 限制。");
      return;
    }
    setLoading(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const next = services.analyzePngEvidence(bytes, file.name);
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      setPreviewUrl(URL.createObjectURL(file));
      setAnalysis(next);
    } catch (caught) {
      setAnalysis(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl("");
    setAnalysis(null);
    setError("");
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const row = (name: string) => analysis?.rows.find(([key]) => key === name)?.[1] ?? "--";
  const badCrc = analysis?.chunks.filter((chunk) => !chunk.ok) ?? [];
  const hasIend = analysis?.chunks.some((chunk) => chunk.type === "IEND") ?? false;

  const downloadTrailer = () => {
    if (!analysis?.trailer.length) return;
    const bytes = new Uint8Array(analysis.trailer.length);
    bytes.set(analysis.trailer);
    downloadBlob(`${analysis.name}.trailer.bin`, new Blob([bytes], { type: "application/octet-stream" }));
  };

  return (
    <div className={`tool-grid png-workbench ${analysis ? "has-png" : "empty-png"}`}>
      <div className="tool-panel wide-panel png-source-panel">
        <PanelTitle title="PNG" />
        <input ref={inputRef} type="file" accept="image/png,.png" onChange={(event) => void loadFile(event.target.files?.[0])} />
        <div
          className={`desktop-drop-zone ${dropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); }
          }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); void loadFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{analysis?.name || t.dropFileTitle}</strong>
          <span>{analysis ? `${formatBytes(analysis.size)} · ${analysis.chunks.length} chunks` : t.dropFileHint}</span>
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
          <div className="tool-panel wide-panel png-overview-panel">
            <PanelTitle title={t.summary} />
            <div className="png-core-overview">
              <div className="png-preview-surface">
                {previewUrl ? <img src={previewUrl} alt={analysis.name} /> : <div className="empty-state">--</div>}
              </div>
              <InfoTable rows={[
                [english ? "Name" : "名称", analysis.name],
                [english ? "Dimensions" : "尺寸", `${row("Width")} × ${row("Height")}`],
                [english ? "Bit depth" : "位深", row("Bit depth")],
                [english ? "Color type" : "颜色类型", row("Color type")],
                ["Chunks", String(analysis.chunks.length)],
                ["CRC", badCrc.length ? `${badCrc.length} mismatch` : "OK"],
                ["IEND", hasIend ? (english ? "Present" : "存在") : (english ? "Missing" : "缺失")],
                [english ? "Trailer" : "尾部数据", formatBytes(analysis.trailer.length)]
              ]} />
            </div>
          </div>

          <div className="tool-panel wide-panel png-chunks-panel">
            <PanelTitle title="Chunks" />
            <div className="table-scroll png-chunk-scroll">
              <table className="data-table">
                <thead><tr><th>#</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Length" : "长度"}</th><th>CRC</th></tr></thead>
                <tbody>{analysis.chunks.map((chunk, index) => (
                  <tr className={chunk.ok ? "" : "soft-selected-row"} key={`${chunk.offset}-${chunk.type}`}>
                    <td>{index + 1}</td><td>{chunk.type}</td><td>0x{chunk.offset.toString(16).toUpperCase()}</td><td>{formatBytes(chunk.length)}</td><td>{chunk.ok ? "OK" : `${chunk.crc} / ${chunk.computed}`}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </div>

          {analysis.textEntries.length > 0 && (
            <div className="tool-panel wide-panel png-text-panel">
              <PanelTitle title={english ? "Text metadata" : "文本元数据"} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>Chunk</th><th>{english ? "Keyword" : "关键字"}</th><th>{english ? "Text" : "文本"}</th></tr></thead>
                  <tbody>{analysis.textEntries.map((entry, index) => (
                    <tr key={`${entry.offset}-${index}`}><td>{entry.chunk}</td><td>{entry.keyword || "--"}</td><td>{entry.text}</td></tr>
                  ))}</tbody>
                </table>
              </div>
            </div>
          )}

          {analysis.trailer.length > 0 && (
            <div className="tool-panel wide-panel png-trailer-panel">
              <div className="panel-heading-row">
                <PanelTitle title={english ? "Data after IEND" : "IEND 后数据"} />
                <AButton variant="outlined" onClick={downloadTrailer}>{english ? "Save bytes" : "保存数据"}</AButton>
              </div>
              <InfoTable rows={[
                [english ? "Size" : "大小", formatBytes(analysis.trailer.length)],
                [english ? "Detected signatures" : "识别签名", analysis.trailerSignatures.map((item) => item.label).join(", ") || "--"]
              ]} />
              <textarea aria-label={english ? "PNG trailing data preview" : "PNG 尾部数据预览"} className="single-textarea compact-textarea" value={analysis.trailerPreview} readOnly />
            </div>
          )}
        </>
      )}
    </div>
  );
}

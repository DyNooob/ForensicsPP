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
import { AButton, AInputNumber, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { FileAnalysis, FileEmbeddedSignature } from "../models";
import { downloadBlob, formatBytes } from "../utils/files";

type HexRow = { offset: number; hex: string; ascii: string };

export type BinaryToolServices = {
  analyzeFileBytes: (bytes: Uint8Array, name: string, size: number, options?: { includeHash?: boolean; includeSideEvidence?: boolean; includeEmbeddedHashes?: boolean }) => FileAnalysis;
  binaryHexDumpRows: (bytes: Uint8Array, start: number, length: number, width?: number) => HexRow[];
  parseByteOffset: (value: string, max: number, fallback?: number) => number;
};

export function BinaryTool({ t, services }: { t: (typeof copy)["zh"]; services: BinaryToolServices }) {
  const { analyzeFileBytes, binaryHexDumpRows, parseByteOffset } = services;
  const english = t.waiting === "Waiting";
  const [analysis, setAnalysis] = React.useState<FileAnalysis | null>(null);
  const [bytes, setBytes] = React.useState<Uint8Array>(() => new Uint8Array());
  const [fileName, setFileName] = React.useState("");
  const [offsetInput, setOffsetInput] = React.useState("0");
  const [viewLength, setViewLength] = React.useState(512);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  React.useEffect(() => () => { requestRef.current += 1; }, []);
  const offset = React.useMemo(() => parseByteOffset(offsetInput, Math.max(0, bytes.length - 1), 0), [bytes.length, offsetInput, parseByteOffset]);
  const hexRows = React.useMemo(() => binaryHexDumpRows(bytes, offset, viewLength), [binaryHexDumpRows, bytes, offset, viewLength]);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    const requestId = ++requestRef.current;
    setDropActive(false);
    setError("");
    setAnalysis(null);
    setBytes(new Uint8Array());
    setFileName("");
    setOffsetInput("0");
    setLoading(false);
    if (file.size > 128 * 1024 * 1024) {
      setError(english ? "File exceeds the 128 MiB browser analysis limit." : "文件超过 128 MiB 浏览器分析上限。");
      return;
    }
    setLoading(true);
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const nextBytes = new Uint8Array(await file.arrayBuffer());
      if (requestId !== requestRef.current) return;
      const nextAnalysis = analyzeFileBytes(nextBytes, file.name, file.size, {
        includeHash: false,
        includeSideEvidence: false,
        includeEmbeddedHashes: false
      });
      setBytes(nextBytes);
      setFileName(file.name);
      setOffsetInput("0");
      setAnalysis(nextAnalysis);
    } catch (caught) {
      if (requestId === requestRef.current) {
        setAnalysis(null);
        setBytes(new Uint8Array());
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (requestId === requestRef.current) setLoading(false);
    }
  };

  const clear = () => {
    requestRef.current += 1;
    setAnalysis(null);
    setBytes(new Uint8Array());
    setFileName("");
    setOffsetInput("0");
    setViewLength(512);
    setError("");
    setLoading(false);
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const downloadSlice = () => {
    if (!bytes.length) return;
    const slice = bytes.slice(offset, Math.min(bytes.length, offset + viewLength));
    downloadBlob(`${fileName || "binary"}-0x${offset.toString(16).toUpperCase()}-${slice.length}.bin`, new Blob([slice.buffer], { type: "application/octet-stream" }));
  };

  const downloadTrailer = () => {
    if (!analysis?.trailerBytes.length) return;
    const copy = analysis.trailerBytes.slice();
    downloadBlob(`${fileName || "binary"}-trailer.bin`, new Blob([copy.buffer], { type: "application/octet-stream" }));
  };

  const downloadEmbedded = (payload: FileEmbeddedSignature, index: number) => {
    const copy = payload.bytes.slice();
    downloadBlob(`${fileName || "binary"}-embedded-${index + 1}-0x${payload.offset.toString(16).toUpperCase()}.${payload.extension}`, new Blob([copy.buffer], { type: payload.mime }));
  };

  const rowValue = (key: string) => analysis?.rows.find(([label]) => label === key)?.[1] ?? "--";
  const parsedFormat = analysis?.binaryRows.find(([key]) => key === "Format")?.[1] ?? "";
  const primaryType = parsedFormat || rowValue("Detected Type");
  const summaryRows: Array<[string, string]> = analysis ? [
    [english ? "Name" : "名称", rowValue("Name")],
    [t.fileSize, rowValue("Size")],
    [english ? "Type" : "类型", primaryType],
    [english ? "Extension" : "扩展名", rowValue("Extension")],
    [english ? "Extension match" : "扩展名匹配", rowValue("Extension match")],
    [english ? "Entropy" : "熵值", rowValue("Entropy")],
    [english ? "Content" : "内容类型", rowValue("Content profile")],
    [t.embeddedSignatures, rowValue("Embedded payloads")]
  ] : [];
  const sectionColumns = React.useMemo(() => analysis?.sections.length ? Array.from(new Set(analysis.sections.flatMap((section) => Object.keys(section)))) : [], [analysis?.sections]);
  const structuralFindings = React.useMemo(() => (analysis?.findings ?? []).filter((finding) => !/side evidence|IOC|timestamp|strings/i.test(`${finding.title} ${finding.detail}`)), [analysis?.findings]);

  return (
    <div className={`tool-grid binary-workbench ${analysis ? "has-binary" : "empty-binary"}`}>
      <div className="tool-panel wide-panel binary-source-panel">
        <PanelTitle title={english ? "Binary source" : "二进制文件"} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
        <div
          className={`desktop-drop-zone ${isDropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDropActive(true);
          }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDropActive(false);
            void handleFile(event.dataTransfer.files?.[0]);
          }}
        >
          <strong>{fileName || t.dropFileTitle}</strong>
          <span>{analysis ? `${primaryType} · ${formatBytes(analysis.size)}` : t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!analysis && !error && !loading} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <ALinearProgress />}
        {error && <pre className="result-box">{error}</pre>}
      </div>

      {analysis && (
        <>
          <div className="tool-panel wide-panel binary-summary-panel">
            <PanelTitle title={t.binaryInfo} />
            <InfoTable rows={summaryRows} />
          </div>

          <div className="tool-panel wide-panel binary-hex-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Hex viewer" : "Hex 查看器"} />
              <div className="button-row compact-buttons">
                <AButton variant="text" disabled={!hexRows.length} onClick={() => void navigator.clipboard.writeText(hexRows.map((row) => `${row.offset.toString(16).padStart(8, "0").toUpperCase()}  ${row.hex.padEnd(47)}  ${row.ascii}`).join("\n"))}>{t.copy}</AButton>
                <AButton variant="text" disabled={!bytes.length} onClick={downloadSlice}>{english ? "Save slice" : "保存片段"}</AButton>
              </div>
            </div>
            <div className="binary-hex-controls">
              <label><span>{english ? "Offset" : "偏移"}</span><input className="text-input" value={offsetInput} onChange={(event) => setOffsetInput(event.currentTarget.value)} placeholder="0 or 0x100" /></label>
              <label><span>{english ? "Length" : "长度"}</span><AInputNumber min={16} max={4096} step={16} value={viewLength} onChange={(value) => setViewLength(Math.min(4096, Math.max(16, value ?? 512)))} /></label>
            </div>
            <div className="table-scroll compact-scroll">
              <table className="data-table binary-hex-table">
                <thead><tr><th>Offset</th><th>Hex</th><th>ASCII</th></tr></thead>
                <tbody>{hexRows.map((row) => <tr key={row.offset}><td><code>{row.offset.toString(16).padStart(8, "0").toUpperCase()}</code></td><td><code>{row.hex}</code></td><td><code>{row.ascii}</code></td></tr>)}</tbody>
              </table>
            </div>
          </div>

          {analysis.binaryRows.length ? (
            <div className="tool-panel wide-panel binary-structure-panel">
              <PanelTitle title={english ? "Format structure" : "格式结构"} />
              <InfoTable rows={analysis.binaryRows} />
            </div>
          ) : null}

          {analysis.sections.length ? (
            <div className="tool-panel wide-panel binary-sections-panel">
              <PanelTitle title={t.sectionTable} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr>{sectionColumns.map((column) => <th key={column}>{column}</th>)}</tr></thead>
                  <tbody>{analysis.sections.map((section, index) => <tr key={index}>{sectionColumns.map((column) => <td key={column}>{section[column] ?? "--"}</td>)}</tr>)}</tbody>
                </table>
              </div>
            </div>
          ) : null}

          {analysis.embeddedSignatures.length ? (
            <div className="tool-panel wide-panel binary-embedded-panel">
              <PanelTitle title={t.embeddedSignatures} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Type" : "类型"}</th><th>{english ? "Offset" : "偏移"}</th><th>{t.fileSize}</th><th>{t.preview}</th><th>{t.download}</th></tr></thead>
                  <tbody>{analysis.embeddedSignatures.map((payload, index) => <tr key={`${payload.label}-${payload.offset}`}><td>{payload.label}</td><td>0x{payload.offset.toString(16).toUpperCase()}</td><td>{formatBytes(payload.size)}</td><td>{payload.preview || "--"}</td><td><AButton variant="text" onClick={() => downloadEmbedded(payload, index)}>{t.download}</AButton></td></tr>)}</tbody>
                </table>
              </div>
            </div>
          ) : null}

          {analysis.trailerBytes.length ? (
            <div className="tool-panel wide-panel binary-trailer-panel">
              <div className="panel-heading-row"><PanelTitle title={t.trailerData} /><AButton variant="text" onClick={downloadTrailer}>{t.download}</AButton></div>
              <InfoTable rows={analysis.trailerRows} />
              <textarea className="single-textarea compact-textarea" value={analysis.trailerPreview || "--"} readOnly />
            </div>
          ) : null}

          {structuralFindings.length ? (
            <div className="tool-panel wide-panel binary-findings-panel">
              <PanelTitle title={english ? "Structure notes" : "结构提示"} />
              <div className="finding-list">{structuralFindings.map((finding) => <div className={`finding-item ${finding.level}`} key={`${finding.title}-${finding.detail}`}><strong>{finding.title}</strong><span>{finding.detail}</span></div>)}</div>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

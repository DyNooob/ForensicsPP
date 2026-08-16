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

import { copyText } from "../utils/clipboard";
import React from "react";
import { AButton, AInputNumber, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { FileAnalysis, FileEmbeddedSignature } from "../models";
import { analyzerForArtifact, analyzerTargetLabel } from "../core/analyzerRouting";
import { downloadBlob, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { evidenceReaderFromBlob, readEvidenceFully } from "../core/evidence/reader";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { appVersion, type ToolId } from "../config/app";
import { runWorkerTask } from "../utils/workerTask";
import type { BinaryWorkerRequest } from "../features/file/file.worker";
import { dispatchToolHandoff, subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";

type HexRow = { offset: number; hex: string; ascii: string };
const MAX_PERSISTED_BINARY_BYTES = 8 * 1024 * 1024;
type BinaryWorkspace = { analysis: FileAnalysis; bytes: Uint8Array; fileName: string; offsetInput: string; viewLength: number };

function isBinaryWorkspace(value: unknown): value is BinaryWorkspace {
  return Boolean(value && typeof value === "object" && "analysis" in value && "bytes" in value && "fileName" in value && "viewLength" in value);
}

function persistableBinaryAnalysis(analysis: FileAnalysis): FileAnalysis {
  return { ...analysis, embeddedSignatures: analysis.embeddedSignatures.map((payload) => ({ ...payload, bytes: new Uint8Array() })), trailerBytes: new Uint8Array() };
}

export type BinaryToolServices = {
  binaryHexDumpRows: (bytes: Uint8Array, start: number, length: number, width?: number) => HexRow[];
  parseByteOffset: (value: string, max: number, fallback?: number) => number;
};

export function BinaryTool({ t, services, active = true, setActiveTool }: { t: (typeof copy)["zh"]; services: BinaryToolServices; active?: boolean; setActiveTool?: (tool: ToolId, options?: { replaceHash?: boolean }) => void }) {
  const { binaryHexDumpRows, parseByteOffset } = services;
  const english = t.waiting === "Waiting";
  const [analysis, setAnalysis] = React.useState<FileAnalysis | null>(null);
  const [bytes, setBytes] = React.useState<Uint8Array>(() => new Uint8Array());
  const [fileName, setFileName] = React.useState("");
  const [offsetInput, setOffsetInput] = React.useState("0");
  const [viewLength, setViewLength] = React.useState(512);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [storageNotice, setStorageNotice] = React.useState("");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  const abortRef = React.useRef<AbortController | null>(null);
  const workspace = useToolWorkspace<BinaryWorkspace>({
    id: "binary",
    version: 2,
    isValid: isBinaryWorkspace,
    onRestore: (restored) => {
      setAnalysis(restored.analysis);
      setBytes(restored.bytes);
      setFileName(restored.fileName);
      setOffsetInput(restored.offsetInput);
      setViewLength(restored.viewLength);
      setStorageNotice(restored.analysis.size > MAX_PERSISTED_BINARY_BYTES && !restored.bytes.byteLength
        ? (english ? "This file is available for the current session only; reopen it after a refresh." : "当前文件仅在本次打开期间可用，刷新后请重新选择文件。")
        : "");
      setError("");
    }
  });
  React.useEffect(() => () => {
    requestRef.current += 1;
    abortRef.current?.abort();
  }, []);
  React.useEffect(() => {
    if (active) return;
    requestRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
  }, [active]);
  const offset = React.useMemo(() => parseByteOffset(offsetInput, Math.max(0, bytes.length - 1), 0), [bytes.length, offsetInput, parseByteOffset]);
  const hexRows = React.useMemo(() => binaryHexDumpRows(bytes, offset, viewLength), [binaryHexDumpRows, bytes, offset, viewLength]);

  const handleFile = async (file: File | undefined) => {
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    abortRef.current?.abort();
    setDropActive(false);
    setError("");
    setStorageNotice("");
    workspace.clear();
    clearAnalysisResult("binary");
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
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const reader = evidenceReaderFromBlob(file);
      const startedAt = new Date().toISOString();
      const nextBytes = await readEvidenceFully(reader, { signal: controller.signal });
      if (requestId !== requestRef.current) return;
      const workerBytes = nextBytes.slice();
      const nextAnalysis = await runWorkerTask<BinaryWorkerRequest, FileAnalysis>({
        createWorker: () => new Worker(new URL("../features/file/file.worker.ts", import.meta.url), { type: "module" }),
        request: {
          bytes: workerBytes.buffer,
          name: file.name,
          size: file.size,
          options: { includeHash: false, includeSideEvidence: false, includeEmbeddedHashes: false }
        },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 180_000
      });
      if (!active || requestId !== requestRef.current || controller.signal.aborted) return;
      setBytes(nextBytes);
      setFileName(file.name);
      setOffsetInput("0");
      setAnalysis(nextAnalysis);
      const completedAt = new Date().toISOString();
      const detectedType = nextAnalysis.binaryRows.find(([key]) => key === "Format")?.[1]
        ?? nextAnalysis.rows.find(([key]) => key === "Detected Type")?.[1]
        ?? "Unknown";
      publishAnalysisResult("binary", {
        schemaVersion: "1",
        id: `binary-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        analyzer: { id: "binary", version: appVersion },
        source: [{
          name: file.name,
          size: file.size,
          type: file.type || "application/octet-stream",
          lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : ""
        }],
        run: { startedAt, completedAt, parameters: { fullBufferAnalysis: true, maxBytes: 128 * 1024 * 1024 } },
        summary: {
          title: english ? "Binary / firmware analysis" : "二进制 / 固件分析",
          text: english
            ? `${detectedType}; ${nextAnalysis.embeddedSignatures.length} embedded object(s) detected.`
            : `${detectedType}；检测到 ${nextAnalysis.embeddedSignatures.length} 个嵌入对象。`,
          metrics: [
            { label: english ? "File" : "文件", value: file.name },
            { label: english ? "Size" : "大小", value: formatBytes(file.size) },
            { label: english ? "Detected type" : "识别类型", value: detectedType },
            { label: english ? "Embedded objects" : "嵌入对象", value: String(nextAnalysis.embeddedSignatures.length) }
          ]
        },
        findings: nextAnalysis.findings.map((finding) => ({ level: finding.level, title: finding.title, detail: finding.detail })),
        indicators: nextAnalysis.stringAnalysis.iocs.slice(0, 500).map((ioc) => ({
          type: ioc.type,
          value: ioc.value,
          normalized: ioc.normalized,
          source: file.name,
          context: ioc.context
        })),
        artifacts: nextAnalysis.embeddedSignatures.map((payload, index) => ({
          id: `embedded-${index}-${payload.offset}`,
          label: payload.label,
          kind: "embedded-file",
          offset: payload.offset,
          size: payload.size,
          sha256: payload.sha256 || undefined,
          mime: payload.mime,
          extension: payload.extension,
          parentId: payload.parentOffset == null ? undefined : `embedded-parent-${payload.parentOffset}`,
          depth: payload.depth,
          confidence: payload.confidence
        })),
        timeline: nextAnalysis.stringAnalysis.timeline.slice(0, 1000).map(({ iso, local, raw, format, line, source, context, epochMs }) => ({
          iso, local, raw, format, line, source, context, ...(epochMs == null ? {} : { epochMs })
        })),
        limitations: [
          { code: "BINARY_FULL_BUFFER_LIMIT", detail: english ? "The current structural analyzer reads files up to 128 MiB into memory; the new EvidenceReader layer is ready for future random-access analyzers." : "当前结构分析器仍会将不超过 128 MiB 的文件读入内存；新的 EvidenceReader 已作为后续随机访问分析器底层。" },
          ...(nextAnalysis.embeddedSignatures.some((payload) => payload.extent === "heuristic" || payload.extent === "unknown")
            ? [{ code: "CARVER_HEURISTIC_EXTENT", detail: english ? "Some embedded-object boundaries are heuristic or unresolved and must be verified before evidentiary use." : "部分嵌入对象边界属于启发式估计或尚未解析，作为证据使用前需要复核。" }]
            : [])
        ],
        data: { detectedType, rows: nextAnalysis.rows, binaryRows: nextAnalysis.binaryRows, sectionCount: nextAnalysis.sections.length }
      });
      setStorageNotice(file.size > MAX_PERSISTED_BINARY_BYTES
        ? (english ? "This file is available for the current session only; it is not restored automatically." : "当前文件仅在本次打开期间保留，不会自动恢复。")
        : "");
      workspace.save({ analysis: persistableBinaryAnalysis(nextAnalysis), bytes: file.size <= MAX_PERSISTED_BINARY_BYTES ? nextBytes : new Uint8Array(), fileName: file.name, offsetInput: "0", viewLength: 512 });
    } catch (caught) {
      if (requestId === requestRef.current && !(caught instanceof DOMException && caught.name === "AbortError")) {
        setAnalysis(null);
        setBytes(new Uint8Array());
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      if (requestId === requestRef.current) setLoading(false);
    }
  };

  const handleFileRef = React.useRef(handleFile);
  handleFileRef.current = handleFile;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("binary");
      if (handoff) void handleFileRef.current(handoff.file);
    };
    consume();
    return subscribeToolHandoff("binary", consume);
  }, [active]);

  const clear = () => {
    requestRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    workspace.clear();
    clearAnalysisResult("binary");
    setAnalysis(null);
    setBytes(new Uint8Array());
    setFileName("");
    setOffsetInput("0");
    setViewLength(512);
    setError("");
    setStorageNotice("");
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

  const analyzeEmbedded = (payload: FileEmbeddedSignature, index: number) => {
    if (!payload.bytes.length || !setActiveTool) return;
    const targetTool = analyzerForArtifact(payload);
    const copy = payload.bytes.slice();
    const name = `${fileName || "binary"}-embedded-${index + 1}-0x${payload.offset.toString(16).toUpperCase()}.${payload.extension}`;
    dispatchToolHandoff({
      sourceTool: "binary",
      targetTool,
      label: `${payload.label} @ 0x${payload.offset.toString(16).toUpperCase()}`,
      file: new File([copy.buffer], name, { type: payload.mime || "application/octet-stream" })
    });
    setActiveTool(targetTool);
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
        {storageNotice && <div className="tool-storage-note" role="status">{storageNotice}</div>}
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
                <AButton variant="text" disabled={!hexRows.length} onClick={() => void copyText(hexRows.map((row) => `${row.offset.toString(16).padStart(8, "0").toUpperCase()}  ${row.hex.padEnd(47)}  ${row.ascii}`).join("\n"))}>{t.copy}</AButton>
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
                  <thead><tr><th>{english ? "Type" : "类型"}</th><th>{english ? "Location / path" : "位置 / 路径"}</th><th>{t.fileSize}</th><th>{english ? "Origin" : "来源"}</th><th>{english ? "Boundary" : "边界"}</th><th>{english ? "Confidence" : "置信度"}</th><th>{t.preview}</th><th>{english ? "Actions" : "操作"}</th></tr></thead>
                  <tbody>{analysis.embeddedSignatures.map((payload, index) => <tr key={`${payload.virtualPath ?? payload.label}-${payload.offset}-${index}`}><td>{payload.label}</td><td>{payload.virtualPath && payload.origin !== "signature" ? payload.virtualPath : `0x${payload.offset.toString(16).toUpperCase()}${payload.virtualPath ? ` · ${payload.virtualPath}` : ""}`}</td><td>{formatBytes(payload.size)}</td><td>{payload.origin ?? "signature"}</td><td>{payload.extent ?? "--"}</td><td>{payload.confidence ?? "--"}</td><td title={payload.detail}>{payload.preview || "--"}</td><td><div className="button-row compact-buttons"><AButton variant="text" disabled={!payload.bytes.length} onClick={() => downloadEmbedded(payload, index)}>{payload.bytes.length ? t.download : (english ? "Guarded" : "受限")}</AButton><AButton variant="text" disabled={!payload.bytes.length || !setActiveTool} onClick={() => analyzeEmbedded(payload, index)}>{english ? `Analyze → ${analyzerTargetLabel(analyzerForArtifact(payload), true)}` : `分析 → ${analyzerTargetLabel(analyzerForArtifact(payload), false)}`}</AButton></div></td></tr>)}</tbody>
                </table>
              </div>
            </div>
          ) : null}

          {analysis.trailerBytes.length ? (
            <div className="tool-panel wide-panel binary-trailer-panel">
              <div className="panel-heading-row"><PanelTitle title={t.trailerData} /><AButton variant="text" disabled={!analysis.trailerBytes.length} onClick={downloadTrailer}>{t.download}</AButton></div>
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

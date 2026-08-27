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
import { AButton, AInputNumber, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { EntropyAnalysis, FileAnalysis, FileEmbeddedSignature, StringsAnalysis, YaraScanResult } from "../models";
import { analyzerForArtifact, analyzerTargetLabel } from "../core/analyzerRouting";
import { downloadBlob, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { evidenceReaderFromBlob, readEvidenceFully } from "../core/evidence/reader";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { appVersion, type ToolId } from "../config/app";
import { runWorkerTask } from "../utils/workerTask";
import type { BinaryWorkerRequest } from "../features/file/file.worker";
import { dispatchToolHandoff, subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { useStoredState } from "../utils/storage";

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
  yaraRuleTemplates: Array<{ id: string; label: string; rule: string }>;
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
  const [binaryPage, setBinaryPage] = React.useState<"overview" | "hex" | "structure" | "strings" | "entropy" | "yara" | "embedded">(() => {
    if (typeof window === "undefined") return "overview";
    const legacy = window.location.hash.replace(/^#/, "").toLowerCase();
    if (legacy === "strings") return "strings";
    if (legacy === "entropy") return "entropy";
    if (legacy === "yara") return "yara";
    return legacy === "fileid" ? "overview" : "overview";
  });
  const [stringsAnalysis, setStringsAnalysis] = React.useState<StringsAnalysis | null>(null);
  const [stringsLoading, setStringsLoading] = React.useState(false);
  const [entropyAnalysis, setEntropyAnalysis] = React.useState<EntropyAnalysis | null>(null);
  const [entropyLoading, setEntropyLoading] = React.useState(false);
  const [yaraRules, setYaraRules] = useStoredState("binary.yara.rules.v1", services.yaraRuleTemplates[0]?.rule ?? "");
  const [yaraResult, setYaraResult] = React.useState<YaraScanResult | null>(null);
  const [yaraScanning, setYaraScanning] = React.useState(false);
  React.useEffect(() => {
    if (!active || typeof window === "undefined") return;
    const legacy = window.location.hash.replace(/^#/, "").toLowerCase();
    if (legacy === "strings") setBinaryPage("strings");
    else if (legacy === "entropy") setBinaryPage("entropy");
    else if (legacy === "yara") setBinaryPage("yara");
    else if (legacy === "fileid") setBinaryPage("overview");
  }, [active]);

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
    setBinaryPage("overview");
    setStringsAnalysis(null);
    setEntropyAnalysis(null);
    setYaraResult(null);
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
    setBinaryPage("overview");
    setStringsAnalysis(null);
    setEntropyAnalysis(null);
    setYaraResult(null);
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

  const runStringsAnalysis = async () => {
    if (!bytes.length || stringsLoading) return;
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setStringsLoading(true);
    setError("");
    try {
      const workerBytes = bytes.slice();
      const result = await runWorkerTask<{ bytes: Uint8Array; minLength: number }, StringsAnalysis>({
        createWorker: () => new Worker(new URL("../workers/strings.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes: workerBytes, minLength: 5 },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 120_000
      });
      if (!controller.signal.aborted) setStringsAnalysis(result);
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setStringsLoading(false);
    }
  };

  const runEntropyAnalysis = async () => {
    if (!bytes.length || entropyLoading) return;
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setEntropyLoading(true);
    setError("");
    try {
      const workerBytes = bytes.slice();
      const result = await runWorkerTask<{ bytes: Uint8Array; blockSize: number }, EntropyAnalysis>({
        createWorker: () => new Worker(new URL("../workers/entropy.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes: workerBytes, blockSize: Math.max(1024, Math.ceil(workerBytes.length / 4096)) },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 120_000
      });
      if (!controller.signal.aborted) setEntropyAnalysis(result);
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setEntropyLoading(false);
    }
  };

  const runYaraScan = async () => {
    if (!bytes.length || !yaraRules.trim() || yaraScanning) return;
    if (new TextEncoder().encode(yaraRules).byteLength > 2 * 1024 * 1024) {
      setError(english ? "YARA rules are limited to 2 MiB." : "YARA 规则不能超过 2 MiB。");
      return;
    }
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setYaraScanning(true);
    setError("");
    try {
      const sample = bytes.length > 32 * 1024 * 1024 ? bytes.slice(0, 32 * 1024 * 1024) : bytes.slice();
      const result = await runWorkerTask<{ ruleText: string; data: ArrayBuffer; name: string; timeoutMs: number }, YaraScanResult>({
        createWorker: () => new Worker(new URL("../features/yara/yara.worker.ts", import.meta.url), { type: "module" }),
        request: { ruleText: yaraRules, data: sample.buffer, name: fileName || "binary", timeoutMs: 10_000 },
        transfer: [sample.buffer],
        signal: controller.signal,
        timeoutMs: 20_000
      });
      if (!controller.signal.aborted) setYaraResult(result);
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setYaraScanning(false);
    }
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
  const matchedYara = yaraResult?.results.filter((item) => item.matched) ?? [];
  const effectiveStrings = stringsAnalysis ?? analysis?.stringAnalysis ?? null;
  const stringItems = effectiveStrings?.items ?? [];

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
          <ASegmentedGroup className="binary-page-tabs wide-panel" value={binaryPage} selects="single" aria-label={english ? "Binary workbench pages" : "二进制工作台分页"}>
            <ASegmentedButton value="overview" onClick={() => setBinaryPage("overview")}>{english ? "Overview" : "概览"}</ASegmentedButton>
            <ASegmentedButton value="hex" onClick={() => setBinaryPage("hex")}>Hex</ASegmentedButton>
            <ASegmentedButton value="structure" onClick={() => setBinaryPage("structure")}>{english ? "Structure" : "结构"}</ASegmentedButton>
            <ASegmentedButton value="strings" onClick={() => setBinaryPage("strings")}>{english ? "Strings / IOC" : "字符串 / IOC"}</ASegmentedButton>
            <ASegmentedButton value="entropy" onClick={() => setBinaryPage("entropy")}>{english ? "Entropy" : "熵"}</ASegmentedButton>
            <ASegmentedButton value="yara" onClick={() => setBinaryPage("yara")}>YARA</ASegmentedButton>
            <ASegmentedButton value="embedded" onClick={() => setBinaryPage("embedded")}>{english ? "Embedded" : "嵌入对象"}</ASegmentedButton>
          </ASegmentedGroup>
          {binaryPage === "overview" && <div className="tool-panel wide-panel binary-summary-panel">
            <PanelTitle title={t.binaryInfo} />
            <InfoTable rows={summaryRows} />
            {analysis.signatures.length > 0 && <><PanelTitle title={english ? "Matched signatures" : "匹配签名"} /><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Signature" : "签名"}</th><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Extensions" : "扩展名"}</th></tr></thead><tbody>{analysis.signatures.map((signature) => <tr key={`${signature.label}-${signature.offset}`}><td>{signature.label}</td><td>0x{signature.offset.toString(16).toUpperCase()}</td><td>{signature.extensions.map((item) => `.${item}`).join(", ")}</td></tr>)}</tbody></table></div></>}
          </div>}

          {binaryPage === "hex" && <div className="tool-panel wide-panel binary-hex-panel">
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
          </div>}

          {binaryPage === "structure" && analysis.binaryRows.length ? (
            <div className="tool-panel wide-panel binary-structure-panel">
              <PanelTitle title={english ? "Format structure" : "格式结构"} />
              <InfoTable rows={analysis.binaryRows} />
            </div>
          ) : null}

          {binaryPage === "structure" && analysis.sections.length ? (
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

          {binaryPage === "embedded" && analysis.embeddedSignatures.length ? (
            <div className="tool-panel wide-panel binary-embedded-panel">
              <PanelTitle title={t.embeddedSignatures} />
              <div className="table-scroll compact-scroll">
                <table className="data-table">
                  <thead><tr><th>{english ? "Type" : "类型"}</th><th>{english ? "Location / path" : "位置 / 路径"}</th><th>{t.fileSize}</th><th>{english ? "Origin" : "来源"}</th><th>{english ? "Boundary" : "边界"}</th><th>{english ? "Confidence" : "置信度"}</th><th>{t.preview}</th><th>{english ? "Actions" : "操作"}</th></tr></thead>
                  <tbody>{analysis.embeddedSignatures.map((payload, index) => <tr key={`${payload.virtualPath ?? payload.label}-${payload.offset}-${index}`}><td>{payload.label}{payload.repaired ? <span className="repaired-badge" title={payload.repairNote ?? ""}>{english ? " repaired" : " 已修复"}</span> : null}</td><td>{payload.virtualPath && payload.origin !== "signature" ? payload.virtualPath : `0x${payload.offset.toString(16).toUpperCase()}${payload.virtualPath ? ` · ${payload.virtualPath}` : ""}`}</td><td>{formatBytes(payload.size)}</td><td>{payload.origin ?? "signature"}</td><td title={payload.repairNote ?? undefined}>{payload.extent ?? "--"}</td><td>{payload.confidence ?? "--"}</td><td title={payload.detail}>{payload.preview ? (payload.preview.length > 80 ? <details className="embedded-preview-shell"><summary className="embedded-preview-summary">{payload.preview.slice(0, 80)}…</summary><pre className="mono-block embedded-preview-full">{payload.preview}</pre></details> : payload.preview) : "--"}</td><td><div className="button-row compact-buttons"><AButton variant="text" disabled={!payload.bytes.length} onClick={() => downloadEmbedded(payload, index)}>{payload.bytes.length ? t.download : (english ? "Guarded" : "受限")}</AButton><AButton variant="text" disabled={!payload.bytes.length || !setActiveTool} onClick={() => analyzeEmbedded(payload, index)}>{english ? `Analyze → ${analyzerTargetLabel(analyzerForArtifact(payload), true)}` : `分析 → ${analyzerTargetLabel(analyzerForArtifact(payload), false)}`}</AButton></div></td></tr>)}</tbody>
                </table>
              </div>
            </div>
          ) : null}

          {binaryPage === "embedded" && analysis.trailerBytes.length ? (
            <div className="tool-panel wide-panel binary-trailer-panel">
              <div className="panel-heading-row"><PanelTitle title={t.trailerData} /><AButton variant="text" disabled={!analysis.trailerBytes.length} onClick={downloadTrailer}>{t.download}</AButton></div>
              <InfoTable rows={analysis.trailerRows} />
              <textarea className="single-textarea compact-textarea" value={analysis.trailerPreview || "--"} readOnly />
            </div>
          ) : null}

          {binaryPage === "strings" && <div className="tool-panel wide-panel binary-strings-panel">
            <div className="panel-heading-row"><PanelTitle title={english ? "Strings / IOC / timeline" : "字符串 / IOC / 时间线"} /><AButton variant="filled" disabled={stringsLoading || !bytes.length} onClick={() => void runStringsAnalysis()}>{stringsLoading ? (english ? "Scanning..." : "扫描中...") : (stringsAnalysis ? (english ? "Rescan" : "重新扫描") : (english ? "Scan full file" : "扫描完整文件"))}</AButton></div>
            {stringsLoading && <ALinearProgress />}
            {!stringsAnalysis && !stringsLoading && <div className="tool-storage-note">{english ? "Strings/IOC are scanned on demand so opening Binary Workbench does not duplicate a full-file pass." : "字符串 / IOC 按需扫描，避免打开二进制工作台时重复遍历整个文件。"}</div>}
            <InfoTable rows={[
              [english ? "Scope" : "扫描范围", stringsAnalysis ? (english ? "Full opened file" : "当前完整文件") : analysis.sideEvidenceScope],
              [english ? "Strings" : "字符串", String(stringItems.length)],
              ["IOC", String(effectiveStrings?.iocs.length ?? 0)],
              [english ? "Timestamps" : "时间戳", String(effectiveStrings?.timeline.length ?? 0)]
            ]} />
            {stringItems.length > 0 && <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Encoding" : "编码"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Value" : "内容"}</th></tr></thead><tbody>{stringItems.slice(0, 1500).map((item, index) => <tr key={`${item.offset}-${index}`}><td>0x{item.offset.toString(16).toUpperCase()}</td><td>{item.encoding}</td><td>{item.detectedType}</td><td title={item.value}>{item.value.slice(0, 300)}</td></tr>)}</tbody></table></div>}
            {(effectiveStrings?.iocs.length ?? 0) > 0 && <><PanelTitle title="IOC" /><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{english ? "Type" : "类型"}</th><th>{english ? "Value" : "值"}</th><th>{english ? "Context" : "上下文"}</th></tr></thead><tbody>{effectiveStrings?.iocs.slice(0, 500).map((item) => <tr key={item.id}><td>{item.type}</td><td>{item.normalized}</td><td>{item.context}</td></tr>)}</tbody></table></div></>}
          </div>}

          {binaryPage === "entropy" && <div className="tool-panel wide-panel binary-entropy-panel">
            <div className="panel-heading-row"><PanelTitle title={english ? "Entropy analysis" : "熵分析"} /><AButton variant="filled" disabled={entropyLoading || !bytes.length} onClick={() => void runEntropyAnalysis()}>{entropyLoading ? (english ? "Analyzing..." : "分析中...") : (entropyAnalysis ? (english ? "Recalculate" : "重新计算") : (english ? "Analyze entropy" : "分析熵"))}</AButton></div>
            {entropyLoading && <ALinearProgress />}
            {!entropyAnalysis && !entropyLoading && <div className="empty-state">{english ? "Detailed entropy is calculated on demand so opening Binary Workbench does not scan the file twice." : "详细熵分析按需执行，避免打开二进制工作台时重复扫描文件。"}</div>}
            {entropyAnalysis && <><InfoTable rows={entropyAnalysis.rows} /><div className="firmware-entropy-chart" role="img" aria-label={english ? "Entropy map" : "熵图"}>{entropyAnalysis.blocks.slice(0, 4096).map((block, index) => <button key={`${block.offset}-${index}`} type="button" className={`firmware-entropy-bar ${block.level === "warn" ? "high" : block.classification.includes("padding") ? "sparse" : "structured"}`} style={{ height: `${Math.max(3, block.entropy / 8 * 100)}%` }} title={`0x${block.offset.toString(16).toUpperCase()} · ${block.entropy.toFixed(4)} · ${block.classification}`} onClick={() => { setOffsetInput(String(block.offset)); setBinaryPage("hex"); }} />)}</div></>}
          </div>}

          {binaryPage === "yara" && <div className="tool-panel wide-panel binary-yara-panel">
            <div className="panel-heading-row"><PanelTitle title="YARA" /><div className="button-row compact-buttons">{services.yaraRuleTemplates.map((template) => <AButton key={template.id} variant="text" onClick={() => { setYaraRules(template.rule); setYaraResult(null); }}>{template.label}</AButton>)}</div></div>
            <textarea className="single-textarea yara-simple-editor" value={yaraRules} onChange={(event) => { setYaraRules(event.target.value); setYaraResult(null); }} placeholder={english ? "Paste YARA rules" : "粘贴 YARA 规则"} />
            <div className="action-row"><AButton variant="filled" disabled={yaraScanning || !bytes.length || !yaraRules.trim()} onClick={() => void runYaraScan()}>{yaraScanning ? (english ? "Scanning..." : "扫描中...") : (english ? "Scan current file" : "扫描当前文件")}</AButton></div>
            {bytes.length > 32 * 1024 * 1024 && <div className="tool-storage-note">{english ? "YARA scans the first 32 MiB in the browser workbench." : "浏览器工作台中的 YARA 扫描当前文件前 32 MiB。"}</div>}
            {yaraResult && <><InfoTable rows={[[english ? "Rules" : "规则", String(yaraResult.results.length)], [english ? "Matched" : "命中", String(matchedYara.length)]]} />{matchedYara.length ? <div className="finding-list">{matchedYara.map((item) => <div className="finding-item warn" key={item.rule.name}><strong>{item.rule.name}</strong><span>{item.hits.filter((hit) => hit.count).map((hit) => `${hit.id}: ${hit.count}`).join(" · ") || (english ? "Rule matched" : "规则命中")}</span></div>)}</div> : <div className="empty-state">{english ? "No rule matched." : "没有规则命中。"}</div>}</>}
          </div>}

          {binaryPage === "overview" && structuralFindings.length ? (
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

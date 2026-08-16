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
import { AButton, ALinearProgress, InfoTable, PanelTitle, ToolFactGrid, ToolPanelHeader } from "../components/ui";
import { analyzerTargetLabel } from "../core/analyzerRouting";
import { evidenceReaderFromBlob, type EvidenceReader } from "../core/evidence/reader";
import { dispatchToolHandoff } from "../core/toolHandoff";
import { appVersion, type ToolId } from "../config/app";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { buildFirmwareManifest, materializeFirmwareObject, type FirmwareAnalysisSession, type FirmwareObject } from "../features/firmware/analyzer";
import type { FirmwareWorkerProgress, FirmwareWorkerRequest } from "../features/firmware/firmware.worker";
import { copy } from "../i18n";
import { downloadBlob, formatBytes } from "../utils/files";
import { runWorkerTask } from "../utils/workerTask";

const MAX_ACTION_BYTES = 256 * 1024 * 1024;

function hexPreview(bytes: Uint8Array, baseOffset: number) {
  const lines: string[] = [];
  for (let row = 0; row < bytes.length; row += 16) {
    const chunk = bytes.subarray(row, row + 16);
    const hex = Array.from(chunk, (value) => value.toString(16).padStart(2, "0").toUpperCase()).join(" ").padEnd(16 * 3 - 1, " ");
    const ascii = Array.from(chunk, (value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
    lines.push(`${(baseOffset + row).toString(16).padStart(8, "0").toUpperCase()}  ${hex}  |${ascii}|`);
  }
  return lines.join("\n");
}

function entropyLabel(classification: string, english: boolean) {
  const labels: Record<string, [string, string]> = {
    sparse: ["稀疏/填充", "Sparse / padding"],
    structured: ["结构化", "Structured"],
    high: ["高熵", "High entropy"],
    "very-high": ["极高熵", "Very high entropy"]
  };
  return labels[classification]?.[english ? 1 : 0] ?? classification;
}

export function FirmwareAnalyzerTool({
  t,
  active = true,
  setActiveTool
}: {
  t: (typeof copy)["zh"];
  active?: boolean;
  setActiveTool?: (tool: ToolId, options?: { replaceHash?: boolean }) => void;
}) {
  const english = t.waiting === "Waiting";
  const [session, setSession] = React.useState<FirmwareAnalysisSession | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [progress, setProgress] = React.useState({ loaded: 0, total: 0, phase: "scan" as "scan" | "resolve" | "recursive" });
  const [filter, setFilter] = React.useState("");
  const [selectedId, setSelectedId] = React.useState("");
  const [preview, setPreview] = React.useState("");
  const [previewOffset, setPreviewOffset] = React.useState(0);
  const [busyObjectId, setBusyObjectId] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const readerRef = React.useRef<EvidenceReader | null>(null);
  const fileRef = React.useRef<File | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const requestRef = React.useRef(0);

  React.useEffect(() => () => abortRef.current?.abort(), []);
  React.useEffect(() => {
    if (active) return;
    requestRef.current += 1;
    abortRef.current?.abort();
    setLoading(false);
  }, [active]);

  const clear = React.useCallback(() => {
    requestRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    readerRef.current = null;
    fileRef.current = null;
    setSession(null);
    setError("");
    setLoading(false);
    setFilter("");
    setSelectedId("");
    setPreview("");
    setPreviewOffset(0);
    setProgress({ loaded: 0, total: 0, phase: "scan" });
    clearAnalysisResult("firmware");
    if (inputRef.current) inputRef.current.value = "";
  }, []);

  const publish = React.useCallback((file: File, next: FirmwareAnalysisSession, startedAt: string, completedAt: string) => {
    const analysis = next.analysis;
    publishAnalysisResult("firmware", {
      schemaVersion: "1",
      id: `firmware-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      analyzer: { id: "firmware", version: appVersion },
      source: [{ name: file.name, size: file.size, type: file.type || "application/octet-stream", lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : "", sha256: analysis.sha256 }],
      run: { startedAt, completedAt, parameters: { chunkSize: analysis.chunkSize, recursive: analysis.recursive, localOnly: true } },
      summary: {
        title: english ? "Firmware / embedded-file analysis" : "固件 / 嵌入文件分析",
        text: english
          ? `${analysis.objects.length} object(s) identified across ${Object.keys(analysis.categories).length} forensic categories.`
          : `识别 ${analysis.objects.length} 个对象，覆盖 ${Object.keys(analysis.categories).length} 类取证结构。`,
        metrics: [
          { label: english ? "Source SHA-256" : "源文件 SHA-256", value: analysis.sha256 },
          { label: english ? "Objects" : "对象数", value: String(analysis.objects.length) },
          { label: english ? "Filesystems" : "文件系统", value: String(analysis.categories.Filesystem ?? 0) },
          { label: english ? "Executables" : "可执行文件", value: String(analysis.categories.Executable ?? 0) }
        ]
      },
      findings: [
        ...analysis.warnings.map((detail) => ({ level: "warn", title: english ? "Firmware scan limitation" : "固件扫描限制", detail })),
        ...analysis.entropy.filter((block) => block.classification === "very-high").slice(0, 64).map((block) => ({ level: "warn", title: english ? "Very-high entropy region" : "极高熵区域", detail: `0x${block.offset.toString(16).toUpperCase()} - 0x${block.endOffset.toString(16).toUpperCase()} · ${block.entropy.toFixed(4)} bits/byte` }))
      ],
      indicators: [],
      artifacts: analysis.objects.slice(0, 5000).map((object) => ({ id: object.id, label: object.label, kind: "embedded-file", offset: object.offset, size: object.size, sha256: object.sha256, mime: object.mime, extension: object.extension, parentId: object.parentId, depth: object.depth, confidence: object.confidence })),
      timeline: [],
      limitations: [
        ...(analysis.objects.some((object) => object.extent === "heuristic" || object.extent === "unknown") ? [{ code: "FIRMWARE_BOUNDARY_CONFIDENCE", detail: english ? "Heuristic/unresolved carve boundaries require independent verification." : "启发式或未解析的 carving 边界需要独立复核。" }] : []),
        ...(analysis.warnings.some((warning) => warning.includes("recursive expansion")) ? [{ code: "FIRMWARE_RECURSION_BUDGET", detail: english ? "Recursive container expansion is budgeted; remaining carved containers can be sent to their analyzers individually." : "递归容器展开受预算限制；剩余 carved container 仍可单独交给对应分析器。" }] : [])
      ],
      data: { counts: analysis.counts, categories: analysis.categories, architectures: analysis.architectures, interestingPaths: analysis.interestingPaths, timings: analysis.timings, manifestSchema: "forensicspp.firmware-manifest/v1" }
    });
  }, [english]);

  const handleFile = React.useCallback(async (file?: File) => {
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setSession(null);
    setSelectedId("");
    setPreview("");
    setError("");
    setLoading(true);
    clearAnalysisResult("firmware");
    const reader = evidenceReaderFromBlob(file);
    readerRef.current = reader;
    fileRef.current = file;
    const startedAt = new Date().toISOString();
    try {
      const next = await runWorkerTask<FirmwareWorkerRequest, FirmwareAnalysisSession, FirmwareWorkerProgress>({
        createWorker: () => new Worker(new URL("../features/firmware/firmware.worker.ts", import.meta.url), { type: "module" }),
        request: { file },
        signal: controller.signal,
        timeoutMs: 15 * 60_000,
        onProgress: ({ loaded, total, phase }) => {
          if (requestId === requestRef.current) setProgress({ loaded, total, phase });
        }
      });
      if (controller.signal.aborted || requestId !== requestRef.current) return;
      setSession(next);
      publish(file, next, startedAt, new Date().toISOString());
      const first = next.analysis.objects[0];
      if (first) setSelectedId(first.id);
    } catch (caught) {
      if (!controller.signal.aborted && requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      if (!controller.signal.aborted && requestId === requestRef.current) setLoading(false);
    }
  }, [active, publish]);

  const selected = React.useMemo(() => session?.analysis.objects.find((object) => object.id === selectedId) ?? null, [session, selectedId]);
  const visibleObjects = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (session?.analysis.objects ?? []).filter((object) => !q || [object.label, object.virtualPath, object.architecture ?? "", object.sha256 ?? "", object.analyzer].join(" ").toLowerCase().includes(q));
  }, [filter, session]);

  const showPreview = React.useCallback(async (offset: number, object?: FirmwareObject | null) => {
    const reader = readerRef.current;
    if (!reader || !session) return;
    try {
      let bytes: Uint8Array | null = null;
      let base = offset;
      if (object && object.origin !== "signature") {
        const retained = session.retained.get(object.id);
        if (retained) {
          bytes = retained.subarray(0, Math.min(512, retained.length));
          base = 0;
        }
      }
      if (!bytes) bytes = await reader.read(offset, Math.min(512, Math.max(0, reader.size - offset)));
      setPreviewOffset(base);
      setPreview(hexPreview(bytes, base));
    } catch (caught) {
      setPreview(caught instanceof Error ? caught.message : String(caught));
    }
  }, [session]);

  React.useEffect(() => {
    if (selected) void showPreview(selected.offset, selected);
  }, [selected, showPreview]);

  const materialize = React.useCallback(async (object: FirmwareObject) => {
    if (!session || !readerRef.current || object.size <= 0 || object.size > MAX_ACTION_BYTES) return null;
    const controller = new AbortController();
    setBusyObjectId(object.id);
    try {
      return await materializeFirmwareObject(readerRef.current, session, object, controller.signal);
    } finally {
      setBusyObjectId("");
    }
  }, [session]);

  const downloadObject = React.useCallback(async (object: FirmwareObject) => {
    const bytes = await materialize(object);
    if (!bytes) return;
    const sourceName = fileRef.current?.name || "firmware";
    downloadBlob(`${sourceName}-0x${object.offset.toString(16).toUpperCase()}.${object.extension || "bin"}`, new Blob([bytes.slice()], { type: object.mime || "application/octet-stream" }));
  }, [materialize]);

  const analyzeObject = React.useCallback(async (object: FirmwareObject) => {
    if (!setActiveTool) return;
    const bytes = await materialize(object);
    if (!bytes) return;
    const sourceName = fileRef.current?.name || "firmware";
    dispatchToolHandoff({
      sourceTool: "firmware",
      targetTool: object.analyzer,
      label: `${object.label} · ${object.virtualPath}`,
      file: new File([bytes.slice()], `${sourceName}-0x${object.offset.toString(16).toUpperCase()}.${object.extension || "bin"}`, { type: object.mime || "application/octet-stream" })
    });
    setActiveTool(object.analyzer);
  }, [materialize, setActiveTool]);

  const exportManifest = React.useCallback(() => {
    if (!session) return;
    const manifest = JSON.stringify(buildFirmwareManifest(session.analysis), null, 2);
    downloadBlob(`${session.analysis.name}.firmware-manifest.json`, new Blob([manifest], { type: "application/json" }));
  }, [session]);

  const phaseLabel = progress.phase === "scan"
    ? (english ? "Scanning signatures / entropy / SHA-256" : "扫描签名 / 熵 / SHA-256")
    : progress.phase === "resolve"
      ? (english ? "Resolving object boundaries" : "解析对象边界")
      : (english ? "Recursive container analysis" : "递归容器分析");
  const progressRatio = progress.total ? Math.min(1, progress.loaded / progress.total) : 0;

  return (
    <div className="tool-grid firmware-workbench">
      <div className="tool-panel wide-panel firmware-source-panel">
        <PanelTitle title={english ? "Firmware Analyzer" : "固件分析"} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".bin,.img,.rom,.fw,.trx,.chk,.ubi,.ubifs,.squashfs,.jffs2,.tar,.gz,.zip,.apk,*/*" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
        <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void handleFile(event.dataTransfer.files?.[0]); }}>
          <strong>{session?.analysis.name ?? (english ? "Open firmware / raw image" : "打开固件 / 原始镜像")}</strong>
          <span>{session ? `${formatBytes(session.analysis.size)} · SHA-256 ${session.analysis.sha256.slice(0, 16)}…` : (english ? "Streaming signature scan, boundary resolution, entropy map, recursive container expansion, and analyzer handoff." : "流式签名扫描、边界解析、熵图、递归容器展开和 Analyzer 联动。")}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="outlined" disabled={!session} onClick={exportManifest}>{english ? "Export manifest" : "导出扫描清单"}</AButton>
          <AButton variant="text" disabled={!session && !loading && !error} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <div className="firmware-progress"><ALinearProgress /><small>{phaseLabel} · {(progressRatio * 100).toFixed(1)}%</small></div>}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {session && <>
        <div className="tool-panel wide-panel">
          <ToolPanelHeader title={english ? "Firmware triage" : "固件初筛"} subtitle={`${session.analysis.objects.length}${session.analysis.truncated ? "+" : ""} ${english ? "objects" : "个对象"}`} />
          <ToolFactGrid items={[
            { label: "SHA-256", value: session.analysis.sha256.slice(0, 24) + "…", copyValue: session.analysis.sha256 },
            { label: english ? "Filesystems" : "文件系统", value: String(session.analysis.categories.Filesystem ?? 0) },
            { label: english ? "Executables" : "可执行文件", value: String(session.analysis.categories.Executable ?? 0) },
            { label: english ? "Containers" : "容器/压缩", value: String(session.analysis.categories.Container ?? 0) },
            { label: english ? "Databases" : "数据库", value: String(session.analysis.categories.Database ?? 0) },
            { label: english ? "Recursive" : "递归", value: session.analysis.recursive ? (english ? "automatic" : "自动") : (english ? "selective" : "选择性") }
          ]} />
          <InfoTable rows={[
            [english ? "Architectures" : "架构", Object.entries(session.analysis.architectures).map(([key, value]) => `${key}: ${value}`).join(" · ") || "--"],
            [english ? "Categories" : "分类", Object.entries(session.analysis.categories).map(([key, value]) => `${key}: ${value}`).join(" · ") || "--"],
            [english ? "Chunk size" : "扫描块", formatBytes(session.analysis.chunkSize)],
            [english ? "Scan time" : "扫描耗时", `${(session.analysis.timings.scanMs / 1000).toFixed(2)} s`],
            [english ? "Resolve time" : "边界解析耗时", `${(session.analysis.timings.resolveMs / 1000).toFixed(2)} s`],
            [english ? "Recursive time" : "递归耗时", `${(session.analysis.timings.recursiveMs / 1000).toFixed(2)} s`],
            [english ? "Total time" : "总耗时", `${(session.analysis.timings.totalMs / 1000).toFixed(2)} s`],
            [english ? "Interesting paths" : "关注路径", String(session.analysis.interestingPaths.length)]
          ]} />
          {session.analysis.warnings.map((warning, index) => <div className="empty-state warning-state" key={`${warning}-${index}`}>{warning}</div>)}
          {session.analysis.interestingPaths.length > 0 && <details className="firmware-interesting"><summary>{english ? `Interesting expanded paths (${session.analysis.interestingPaths.length})` : `关注的展开路径 (${session.analysis.interestingPaths.length})`}</summary><pre>{session.analysis.interestingPaths.join("\n")}</pre></details>}
        </div>

        <div className="tool-panel wide-panel firmware-entropy-panel">
          <ToolPanelHeader title={english ? "Entropy map" : "熵图"} subtitle={english ? "Click a block to preview its bytes" : "点击区块预览对应字节"} />
          <div className="firmware-entropy-chart" role="img" aria-label={english ? "Firmware entropy map" : "固件熵图"}>
            {session.analysis.entropy.map((block, index) => <button key={`${block.offset}-${index}`} type="button" className={`firmware-entropy-bar ${block.classification}`} style={{ height: `${Math.max(3, block.entropy / 8 * 100)}%` }} title={`0x${block.offset.toString(16).toUpperCase()} · ${block.entropy.toFixed(4)} · ${entropyLabel(block.classification, english)}`} onClick={() => void showPreview(block.offset, null)} />)}
          </div>
          <div className="firmware-entropy-legend"><span>{english ? "0 bits/byte" : "0 bit/字节"}</span><span>{english ? "High / compressed / encrypted candidate" : "高熵 / 压缩 / 加密候选"}</span><span>8 bits/byte</span></div>
        </div>

        <div className="tool-panel wide-panel firmware-object-panel">
          <ToolPanelHeader title={english ? "Embedded objects" : "嵌入对象"} subtitle={english ? "Offsets are source-relative for signature hits; expanded entries use virtual paths." : "签名命中的偏移相对源文件；展开条目使用虚拟路径。"} />
          <input className="text-input" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter type, path, architecture, SHA-256…" : "筛选类型、路径、架构、SHA-256…"} />
          <div className="table-scroll firmware-object-scroll"><table className="data-table"><thead><tr><th>{english ? "Object" : "对象"}</th><th>{english ? "Offset / path" : "偏移 / 路径"}</th><th>{english ? "Size" : "大小"}</th><th>{english ? "Boundary" : "边界"}</th><th>{english ? "Confidence" : "可信度"}</th><th>{english ? "Architecture" : "架构"}</th><th>SHA-256</th><th>{english ? "Actions" : "操作"}</th></tr></thead><tbody>
            {visibleObjects.slice(0, 5000).map((object) => {
              const actionDisabled = object.size <= 0 || object.size > MAX_ACTION_BYTES || busyObjectId === object.id || (object.origin !== "signature" && !session.retained.has(object.id));
              return <tr key={object.id} className={selectedId === object.id ? "selected-row" : ""} onClick={() => setSelectedId(object.id)}><td><span style={{ paddingLeft: `${Math.min(8, object.depth) * 14}px` }}>{object.depth ? "↳ " : ""}{object.label}</span><br/><small>{object.origin}</small></td><td>{object.origin === "signature" ? `0x${object.offset.toString(16).toUpperCase()}` : object.virtualPath}</td><td>{formatBytes(object.size)}</td><td title={object.detail}>{object.extent}</td><td>{object.confidence}</td><td>{object.architecture || "--"}</td><td title={object.sha256}>{object.sha256 ? `${object.sha256.slice(0, 14)}…` : "--"}</td><td><div className="button-row compact-buttons"><AButton variant="text" disabled={actionDisabled} onClick={(event) => { event.stopPropagation(); void downloadObject(object); }}>{english ? "Extract" : "提取"}</AButton><AButton variant="text" disabled={actionDisabled || !setActiveTool} onClick={(event) => { event.stopPropagation(); void analyzeObject(object); }}>{english ? `Analyze → ${analyzerTargetLabel(object.analyzer, true)}` : `分析 → ${analyzerTargetLabel(object.analyzer, false)}`}</AButton></div></td></tr>;
            })}
          </tbody></table></div>
        </div>

        <div className="tool-panel wide-panel firmware-preview-panel">
          <ToolPanelHeader title={english ? "Hex context" : "十六进制上下文"} subtitle={`0x${previewOffset.toString(16).toUpperCase()}`} />
          {selected && <InfoTable rows={[
            [english ? "Object" : "对象", selected.label],
            [english ? "Virtual path" : "虚拟路径", selected.virtualPath],
            [english ? "Analyzer" : "目标分析器", analyzerTargetLabel(selected.analyzer, english)],
            [english ? "Boundary evidence" : "边界依据", selected.detail]
          ]} />}
          <pre className="mono-block firmware-hex-preview">{preview || (english ? "Select an object or entropy block." : "选择对象或熵区块。")}</pre>
        </div>
      </>}
    </div>
  );
}

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
import { dispatchToolHandoff, subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { useToolRuntime } from "../core/runtime";
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
  const rt = useToolRuntime("firmware", active);
  const [session, setSession] = React.useState<FirmwareAnalysisSession | null>(null);
  const [progress, setProgress] = React.useState({ loaded: 0, total: 0, phase: "scan" as "scan" | "resolve" | "recursive" });
  const [filter, setFilter] = React.useState("");
  const [selectedId, setSelectedId] = React.useState("");
  const [preview, setPreview] = React.useState("");
  const [previewOffset, setPreviewOffset] = React.useState(0);
  const [busyObjectId, setBusyObjectId] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const readerRef = React.useRef<EvidenceReader | null>(null);
  const fileRef = React.useRef<File | null>(null);
  const loading = rt.status === "running";
  const error = rt.error?.error ?? "";

  const clear = () => {
    rt.reset();
    readerRef.current = null;
    fileRef.current = null;
    setSession(null);
    setFilter("");
    setSelectedId("");
    setPreview("");
    setPreviewOffset(0);
    setProgress({ loaded: 0, total: 0, phase: "scan" });
    clearAnalysisResult("firmware");
    if (inputRef.current) inputRef.current.value = "";
  };

  const publish = React.useCallback((file: File, next: FirmwareAnalysisSession, startedAt: string, completedAt: string) => {
    const analysis = next.analysis;
    publishAnalysisResult("firmware", {
      schemaVersion: "1",
      id: `firmware-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      analyzer: { id: "firmware", version: appVersion },
      source: [{ name: file.name, size: file.size, type: file.type || "application/octet-stream", lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : "", sha256: analysis.sha256 }],
      run: { startedAt, completedAt, parameters: { chunkSize: analysis.chunkSize, recursive: analysis.recursive, localOnly: true } },
      summary: {
        title: t.firmware_embedded_file_analysis,
        text: english
          ? `${analysis.objects.length} object(s) identified across ${Object.keys(analysis.categories).length} forensic categories.`
          : `识别 ${analysis.objects.length} 个对象，覆盖 ${Object.keys(analysis.categories).length} 类取证结构。`,
        metrics: [
          { label: t.source_sha_256, value: analysis.sha256 },
          { label: t.objects, value: String(analysis.objects.length) },
          { label: t.filesystems, value: String(analysis.categories.Filesystem ?? 0) },
          { label: t.executables, value: String(analysis.categories.Executable ?? 0) }
        ]
      },
      findings: [
        ...analysis.warnings.map((detail) => ({ level: "warn", title: t.firmware_scan_limitation, detail })),
        ...analysis.entropy.filter((block) => block.classification === "very-high").slice(0, 64).map((block) => ({ level: "warn", title: t.very_high_entropy_region, detail: `0x${block.offset.toString(16).toUpperCase()} - 0x${block.endOffset.toString(16).toUpperCase()} · ${block.entropy.toFixed(4)} bits/byte` }))
      ],
      indicators: [],
      artifacts: analysis.objects.slice(0, 5000).map((object) => ({ id: object.id, label: object.label, kind: "embedded-file", offset: object.offset, size: object.size, sha256: object.sha256, mime: object.mime, extension: object.extension, parentId: object.parentId, depth: object.depth, confidence: object.confidence })),
      timeline: [],
      limitations: [
        ...(analysis.objects.some((object) => object.extent === "heuristic" || object.extent === "unknown") ? [{ code: "FIRMWARE_BOUNDARY_CONFIDENCE", detail: t.heuristic_unresolved_carve_boundaries_require_independent_verification }] : []),
        ...(analysis.warnings.some((warning) => warning.includes("recursive expansion")) ? [{ code: "FIRMWARE_RECURSION_BUDGET", detail: t.recursive_container_expansion_is_budgeted_remaining_carved_containers_can_be_sent_to_their_analyzers_individually }] : [])
      ],
      data: { counts: analysis.counts, categories: analysis.categories, architectures: analysis.architectures, interestingPaths: analysis.interestingPaths, timings: analysis.timings, manifestSchema: "forensicspp.firmware-manifest/v1" }
    });
  }, [english]);

  const handleFile = async (file?: File) => {
    if (!file || !active) return;
    rt.cancel();
    let reqId = 0;
    setSession(null);
    setSelectedId("");
    setPreview("");
    setProgress({ loaded: 0, total: 0, phase: "scan" });
    clearAnalysisResult("firmware");
    const reader = evidenceReaderFromBlob(file);
    readerRef.current = reader;
    fileRef.current = file;
    const startedAt = new Date().toISOString();
    try {
      const next = await rt.run(
        ({ signal, requestId }) => {
          reqId = requestId;
          return runWorkerTask<FirmwareWorkerRequest, FirmwareAnalysisSession, FirmwareWorkerProgress>({
            createWorker: () => new Worker(new URL("../features/firmware/firmware.worker.ts", import.meta.url), { type: "module" }),
            request: { file },
            signal,
            timeoutMs: 15 * 60_000,
            onProgress: ({ loaded, total, phase }) => {
              rt.commit(reqId, () => setProgress({ loaded, total, phase }));
            }
          });
        },
        { stage: "firmware scan", recovery: "reset" }
      );
      rt.commit(reqId, () => {
        setSession(next);
        publish(file, next, startedAt, new Date().toISOString());
        const first = next.analysis.objects[0];
        if (first) setSelectedId(first.id);
      });
    } catch {
      // rt.error already carries ToolErrorInfo; UI renders rt.error?.error
    }
  };

  const handleFileRef = React.useRef(handleFile);
  handleFileRef.current = handleFile;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("firmware");
      if (handoff) handleFileRef.current(handoff.file);
    };
    consume();
    return subscribeToolHandoff("firmware", consume);
  }, [active]);

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
    ? (t.scanning_signatures_entropy_sha_256)
    : progress.phase === "resolve"
      ? (t.resolving_object_boundaries)
      : (t.recursive_container_analysis);
  const progressRatio = progress.total ? Math.min(1, progress.loaded / progress.total) : 0;

  return (
    <div className="tool-grid firmware-workbench">
      <div className="tool-panel wide-panel firmware-source-panel">
        <PanelTitle title={t.firmware} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".bin,.img,.rom,.fw,.trx,.chk,.ubi,.ubifs,.squashfs,.jffs2,.tar,.gz,.zip,.apk,*/*" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
        <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void handleFile(event.dataTransfer.files?.[0]); }}>
          <strong>{session?.analysis.name ?? (t.open_firmware_raw_image)}</strong>
          <span>{session ? `${formatBytes(session.analysis.size)} · SHA-256 ${session.analysis.sha256.slice(0, 16)}…` : (t.streaming_signature_scan_boundary_resolution_entropy_map_recursive_container_expansion_and_analyzer_handoff)}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="outlined" disabled={!session} onClick={exportManifest}>{t.export_manifest}</AButton>
          <AButton variant="text" disabled={!session && !loading && !error} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <div className="firmware-progress"><ALinearProgress /><small>{phaseLabel} · {(progressRatio * 100).toFixed(1)}%</small></div>}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {session && <>
        <div className="tool-panel wide-panel">
          <ToolPanelHeader title={t.firmware_triage} subtitle={`${session.analysis.objects.length}${session.analysis.truncated ? "+" : ""} ${t.objects_2}`} />
          <ToolFactGrid items={[
            { label: "SHA-256", value: session.analysis.sha256.slice(0, 24) + "…", copyValue: session.analysis.sha256 },
            { label: t.filesystems, value: String(session.analysis.categories.Filesystem ?? 0) },
            { label: t.executables, value: String(session.analysis.categories.Executable ?? 0) },
            { label: t.containers, value: String(session.analysis.categories.Container ?? 0) },
            { label: t.databases, value: String(session.analysis.categories.Database ?? 0) },
            { label: t.recursive, value: session.analysis.recursive ? (t.automatic) : (t.selective) }
          ]} />
          <InfoTable rows={[
            [t.architectures, Object.entries(session.analysis.architectures).map(([key, value]) => `${key}: ${value}`).join(" · ") || "--"],
            [t.categories, Object.entries(session.analysis.categories).map(([key, value]) => `${key}: ${value}`).join(" · ") || "--"],
            [t.chunk_size, formatBytes(session.analysis.chunkSize)],
            [t.scan_time, `${(session.analysis.timings.scanMs / 1000).toFixed(2)} s`],
            [t.resolve_time, `${(session.analysis.timings.resolveMs / 1000).toFixed(2)} s`],
            [t.recursive_time, `${(session.analysis.timings.recursiveMs / 1000).toFixed(2)} s`],
            [t.total_time, `${(session.analysis.timings.totalMs / 1000).toFixed(2)} s`],
            [t.interesting_paths, String(session.analysis.interestingPaths.length)]
          ]} />
          {session.analysis.warnings.map((warning, index) => <div className="empty-state warning-state" key={`${warning}-${index}`}>{warning}</div>)}
          {session.analysis.interestingPaths.length > 0 && <details className="firmware-interesting"><summary>{english ? `Interesting expanded paths (${session.analysis.interestingPaths.length})` : `关注的展开路径 (${session.analysis.interestingPaths.length})`}</summary><pre>{session.analysis.interestingPaths.join("\n")}</pre></details>}
        </div>

        <div className="tool-panel wide-panel firmware-entropy-panel">
          <ToolPanelHeader title={t.entropy_map} subtitle={t.click_a_block_to_preview_its_bytes} />
          <div className="firmware-entropy-chart" role="img" aria-label={t.firmware_entropy_map}>
            {session.analysis.entropy.map((block, index) => <button key={`${block.offset}-${index}`} type="button" className={`firmware-entropy-bar ${block.classification}`} style={{ height: `${Math.max(3, block.entropy / 8 * 100)}%` }} title={`0x${block.offset.toString(16).toUpperCase()} · ${block.entropy.toFixed(4)} · ${entropyLabel(block.classification, english)}`} onClick={() => void showPreview(block.offset, null)} />)}
          </div>
          <div className="firmware-entropy-legend"><span>{t.k_0_bits_byte}</span><span>{t.high_compressed_encrypted_candidate}</span><span>8 bits/byte</span></div>
        </div>

        <div className="tool-panel wide-panel firmware-object-panel">
          <ToolPanelHeader title={t.embedded_objects} subtitle={t.offsets_are_source_relative_for_signature_hits_expanded_entries_use_virtual_paths} />
          <input className="text-input" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={t.filter_type_path_architecture_sha_256} />
          <div className="table-scroll firmware-object-scroll"><table className="data-table"><thead><tr><th>{t.object}</th><th>{t.offset_path}</th><th>{t.fileSize}</th><th>{t.boundary}</th><th>{t.identifyConfidence}</th><th>{t.architecture}</th><th>SHA-256</th><th>{t.commandGroupActions}</th></tr></thead><tbody>
            {visibleObjects.slice(0, 5000).map((object) => {
              const actionDisabled = object.size <= 0 || object.size > MAX_ACTION_BYTES || busyObjectId === object.id || (object.origin !== "signature" && !session.retained.has(object.id));
              return <tr key={object.id} className={selectedId === object.id ? "selected-row" : ""} onClick={() => setSelectedId(object.id)}><td><span style={{ paddingLeft: `${Math.min(8, object.depth) * 14}px` }}>{object.depth ? "↳ " : ""}{object.label}</span><br/><small>{object.origin}</small></td><td>{object.origin === "signature" ? `0x${object.offset.toString(16).toUpperCase()}` : object.virtualPath}</td><td>{formatBytes(object.size)}</td><td title={object.detail}>{object.extent}</td><td>{object.confidence}</td><td>{object.architecture || "--"}</td><td title={object.sha256}>{object.sha256 ? `${object.sha256.slice(0, 14)}…` : "--"}</td><td><div className="button-row compact-buttons"><AButton variant="text" disabled={actionDisabled} onClick={(event) => { event.stopPropagation(); void downloadObject(object); }}>{t.extract}</AButton><AButton variant="text" disabled={actionDisabled || !setActiveTool} onClick={(event) => { event.stopPropagation(); void analyzeObject(object); }}>{english ? `Analyze → ${analyzerTargetLabel(object.analyzer, true)}` : `分析 → ${analyzerTargetLabel(object.analyzer, false)}`}</AButton></div></td></tr>;
            })}
          </tbody></table></div>
        </div>

        <div className="tool-panel wide-panel firmware-preview-panel">
          <ToolPanelHeader title={t.hex_context} subtitle={`0x${previewOffset.toString(16).toUpperCase()}`} />
          {selected && <InfoTable rows={[
            [t.object, selected.label],
            [t.virtual_path, selected.virtualPath],
            [t.analyzer, analyzerTargetLabel(selected.analyzer, english)],
            [t.boundary_evidence, selected.detail]
          ]} />}
          <pre className="mono-block firmware-hex-preview">{preview || (t.select_an_object_or_entropy_block)}</pre>
        </div>
      </>}
    </div>
  );
}

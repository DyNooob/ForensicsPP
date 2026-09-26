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
import { ArrowLeftOutlined, DownloadOutlined, FolderOpenOutlined, RightOutlined } from "@ant-design/icons";
import { AButton, ALinearProgress, ATextField, ToolPanelHeader } from "../components/ui";
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import type { PlistWorkerRequest } from "../features/plist/plist.worker";
import { plistChildren, plistJson, plistPreview, plistType, type PlistValue } from "../features/plist/analyzer";
import { buildPlistEnvelope } from "../features/plist/envelope";
import { copy } from "../i18n";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";
import { publishAnalysisResult } from "../features/analysis/resultStore";

const LIMIT = 64 * 1024 * 1024;
const MAX_PERSISTED_PLIST_BYTES = 8 * 1024 * 1024;
type PlistWorkspace = { format: string; root: PlistValue; stack: Array<{ path: string; value: PlistValue }>; query: string; fileName: string; fileSize: number };

function isPlistWorkspace(value: unknown): value is PlistWorkspace {
  return Boolean(value && typeof value === "object" && "format" in value && "root" in value && "fileName" in value && "fileSize" in value && Array.isArray((value as PlistWorkspace).stack));
}

export function PlistTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const [file, setFile] = React.useState<File | null>(null);
  const [format, setFormat] = React.useState("");
  const [root, setRoot] = React.useState<PlistValue | undefined>(undefined);
  const [stack, setStack] = React.useState<Array<{ path: string; value: PlistValue }>>([]);
  const [query, setQuery] = React.useState("");
  const [error, setError] = React.useState("");
  const [storageNotice, setStorageNotice] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [fileMeta, setFileMeta] = React.useState<{ name: string; size: number } | null>(null);
  const requestRef = React.useRef(0);
  const abortRef = React.useRef<AbortController | null>(null);
  const workspace = useToolWorkspace<PlistWorkspace>({
    id: "plist",
    version: 1,
    isValid: isPlistWorkspace,
    onRestore: (restored) => {
      setFile(null);
      setFileMeta({ name: restored.fileName, size: restored.fileSize });
      setFormat(restored.format);
      setRoot(restored.root);
      setStack(restored.stack);
      setQuery(restored.query);
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
  const current = stack[stack.length - 1] ?? null;
  const children = React.useMemo(() => current ? plistChildren(current.value, current.path).filter((entry) => !query.trim() || `${entry.key} ${entry.preview} ${entry.type}`.toLowerCase().includes(query.trim().toLowerCase())) : [], [current, query]);

  const open = async (next: File | undefined) => {
    if (!next || !active) return;
    const requestId = ++requestRef.current;
    abortRef.current?.abort();
    workspace.clear();
    setFile(next);
    setFileMeta({ name: next.name, size: next.size });
    setRoot(undefined);
    setStack([]);
    setFormat("");
    setQuery("");
    setStorageNotice(next.size > MAX_PERSISTED_PLIST_BYTES
      ? (t.this_file_is_available_for_the_current_session_only_files_over_8_mib_are_not_restored_automatically)
      : "");
    setLoading(false);
    if (next.size > LIMIT) { setError(t.plist_exceeds_the_64_mib_limit); return; }
    setLoading(true);
    const controller = new AbortController();
    abortRef.current = controller;
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const bytes = new Uint8Array(await next.arrayBuffer());
      if (!active || requestId !== requestRef.current) return;
      const workerBytes = bytes.slice();
      const parsed = await runWorkerTask<PlistWorkerRequest, { format: string; value: PlistValue }>({
        createWorker: () => new Worker(new URL("../features/plist/plist.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes: workerBytes.buffer },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 120_000
      });
      if (!active || requestId !== requestRef.current || controller.signal.aborted) return;
      const nextStack = [{ path: "$", value: parsed.value }];
      setFormat(parsed.format); setRoot(parsed.value); setStack(nextStack); setQuery("");
      publishAnalysisResult("plist", buildPlistEnvelope({ format: parsed.format, value: parsed.value, name: next.name, size: next.size }));
      if (next.size <= MAX_PERSISTED_PLIST_BYTES) workspace.save({ format: parsed.format, root: parsed.value, stack: nextStack, query: "", fileName: next.name, fileSize: next.size });
    } catch (caught) {
      if (requestId === requestRef.current && !(caught instanceof DOMException && caught.name === "AbortError")) {
        setError(caught instanceof Error ? caught.message : String(caught));
        setRoot(undefined);
        setStack([]);
      }
    }
    finally {
      if (abortRef.current === controller) abortRef.current = null;
      if (requestId === requestRef.current) setLoading(false);
    }
  };
  const openRef = React.useRef(open);
  openRef.current = open;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("plist");
      if (handoff) void openRef.current(handoff.file);
    };
    consume();
    return subscribeToolHandoff("plist", consume);
  }, [active]);
  const clear = () => {
    requestRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    workspace.clear(); setFile(null); setFileMeta(null); setRoot(undefined); setStack([]); setFormat(""); setQuery(""); setError(""); setStorageNotice(""); setLoading(false); if (inputRef.current) inputRef.current.value = "";
  };
  const exportData = () => { if (root !== undefined) downloadTextFile(`${file?.name || "plist"}.json`, plistJson(root), "application/json;charset=utf-8"); };
  const downloadValue = (value: PlistValue, key: string) => {
    if (!(value instanceof Uint8Array)) return;
    const bytes = value.slice();
    downloadBlob(key || "plist-data.bin", new Blob([bytes.buffer], { type: "application/octet-stream" }));
  };

  return (
    <div className="tool-grid browser-tool-workbench">
      <div className="tool-panel wide-panel browser-source-panel">
        <ToolPanelHeader title={t.plist_browser} subtitle={root !== undefined ? `${format.toUpperCase()} · ${formatBytes(file?.size ?? fileMeta?.size ?? 0)}` : undefined} />
        <input ref={inputRef} className="hidden-file-input" type="file" aria-hidden="true" tabIndex={-1} accept=".plist,.strings,.xml,application/x-plist" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void open(file); }} />
        {!current && !loading && <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void open(event.dataTransfer.files?.[0]); }}><strong>{file?.name || (t.open_a_plist_file)}</strong><span>XML · bplist00</span></div>}
        <div className="action-row"><AButton variant="filled" disabled={loading} onClick={() => inputRef.current?.click()}><FolderOpenOutlined /> {t.selectFile}</AButton><AButton variant="outlined" disabled={root === undefined} onClick={exportData}><DownloadOutlined /> JSON</AButton><AButton variant="text" disabled={!file && root === undefined && !error} onClick={clear}>{t.clear}</AButton></div>
        {loading && <ALinearProgress />}
      {error && <div className="empty-state error-state">{error}</div>}
      {storageNotice && <div className="tool-storage-note" role="status">{storageNotice}</div>}
      </div>
      {current && <div className="tool-panel wide-panel browser-data-panel">
        <div className="browser-toolbar"><AButton variant="text" disabled={stack.length <= 1} title={t.back} onClick={() => setStack((items) => items.slice(0, -1))}><ArrowLeftOutlined /></AButton><code className="browser-path">{current.path}</code><ATextField value={query} allowClear placeholder={t.filter_current_level} onChange={(event) => setQuery(event.currentTarget.value)} /></div>
        {children.length ? <div className="table-scroll"><table className="data-table browser-data-table"><thead><tr><th>{t.key}</th><th>{t.componentType}</th><th>{t.httpHeaderValue}</th><th /></tr></thead><tbody>{children.map((entry) => { const navigable = entry.type === "dict" || entry.type === "array"; return <tr key={entry.path} className={navigable ? "clickable-row" : ""} onDoubleClick={() => navigable && setStack((items) => [...items, { path: entry.path, value: entry.value }])}><td>{entry.key}</td><td>{entry.type}</td><td className="browser-value-cell">{entry.preview}</td><td>{navigable ? <AButton variant="text" title={t.open} onClick={() => setStack((items) => [...items, { path: entry.path, value: entry.value }])}><RightOutlined /></AButton> : entry.type === "data" ? <AButton variant="text" title={t.download_data} onClick={() => downloadValue(entry.value, entry.key)}><DownloadOutlined /></AButton> : null}</td></tr>; })}</tbody></table></div> : <div className="empty-state">{t.no_matching_entries}</div>}
        {!children.length && !["dict", "array"].includes(plistType(current.value)) && <pre className="result-box">{plistPreview(current.value)}</pre>}
      </div>}
    </div>
  );
}

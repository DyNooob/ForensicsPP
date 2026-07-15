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
import { AButton, ALinearProgress, ATextField, PanelTitle } from "../components/ui";
import type { PlistWorkerRequest } from "../features/plist/plist.worker";
import { plistChildren, plistJson, plistPreview, plistType, type PlistValue } from "../features/plist/analyzer";
import { copy } from "../i18n";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

const LIMIT = 64 * 1024 * 1024;
const MAX_PERSISTED_PLIST_BYTES = 8 * 1024 * 1024;
type PlistWorkspace = { format: string; root: PlistValue; stack: Array<{ path: string; value: PlistValue }>; query: string; fileName: string; fileSize: number };

function isPlistWorkspace(value: unknown): value is PlistWorkspace {
  return Boolean(value && typeof value === "object" && "format" in value && "root" in value && "fileName" in value && "fileSize" in value && Array.isArray((value as PlistWorkspace).stack));
}

export function PlistTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const inputRef = React.useRef<HTMLInputElement | null>(null);
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
    if (!next) return;
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
      ? (english ? "This file is available for the current session only; files over 8 MiB are not restored automatically." : "当前文件仅在本次打开期间可用；超过 8 MiB 的文件不会自动恢复。")
      : "");
    setLoading(false);
    if (next.size > LIMIT) { setError(english ? "Plist exceeds the 64 MiB limit." : "Plist 超过 64 MiB 解析上限。"); return; }
    setLoading(true);
    const controller = new AbortController();
    abortRef.current = controller;
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const bytes = new Uint8Array(await next.arrayBuffer());
      if (requestId !== requestRef.current) return;
      const workerBytes = bytes.slice();
      const parsed = await runWorkerTask<PlistWorkerRequest, { format: string; value: PlistValue }>({
        createWorker: () => new Worker(new URL("../features/plist/plist.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes: workerBytes.buffer },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 120_000
      });
      if (requestId !== requestRef.current || controller.signal.aborted) return;
      const nextStack = [{ path: "$", value: parsed.value }];
      setFormat(parsed.format); setRoot(parsed.value); setStack(nextStack); setQuery("");
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
        <div className="panel-heading-row"><PanelTitle title={english ? "Plist browser" : "Plist 浏览器"} />{root !== undefined && <span className="status-pill">{format.toUpperCase()} · {formatBytes(file?.size ?? fileMeta?.size ?? 0)}</span>}</div>
        <input ref={inputRef} className="hidden-file-input" type="file" aria-hidden="true" tabIndex={-1} accept=".plist,.strings,.xml,application/x-plist" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void open(file); }} />
        {!current && !loading && <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void open(event.dataTransfer.files?.[0]); }}><strong>{file?.name || (english ? "Open a Plist file" : "打开 Plist 文件")}</strong><span>XML · bplist00</span></div>}
        <div className="action-row"><AButton variant="filled" disabled={loading} onClick={() => inputRef.current?.click()}><FolderOpenOutlined /> {t.selectFile}</AButton><AButton variant="outlined" disabled={root === undefined} onClick={exportData}><DownloadOutlined /> JSON</AButton><AButton variant="text" disabled={!file && root === undefined && !error} onClick={clear}>{t.clear}</AButton></div>
        {loading && <ALinearProgress />}
      {error && <div className="empty-state error-state">{error}</div>}
      {storageNotice && <div className="tool-storage-note" role="status">{storageNotice}</div>}
      </div>
      {current && <div className="tool-panel wide-panel browser-data-panel">
        <div className="browser-toolbar"><AButton variant="text" disabled={stack.length <= 1} title={english ? "Back" : "返回"} onClick={() => setStack((items) => items.slice(0, -1))}><ArrowLeftOutlined /></AButton><code className="browser-path">{current.path}</code><ATextField value={query} allowClear placeholder={english ? "Filter current level" : "筛选当前层级"} onChange={(event) => setQuery(event.currentTarget.value)} /></div>
        {children.length ? <div className="table-scroll"><table className="data-table browser-data-table"><thead><tr><th>{english ? "Key" : "键"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Value" : "值"}</th><th /></tr></thead><tbody>{children.map((entry) => { const navigable = entry.type === "dict" || entry.type === "array"; return <tr key={entry.path} className={navigable ? "clickable-row" : ""} onDoubleClick={() => navigable && setStack((items) => [...items, { path: entry.path, value: entry.value }])}><td>{entry.key}</td><td>{entry.type}</td><td className="browser-value-cell">{entry.preview}</td><td>{navigable ? <AButton variant="text" title={english ? "Open" : "打开"} onClick={() => setStack((items) => [...items, { path: entry.path, value: entry.value }])}><RightOutlined /></AButton> : entry.type === "data" ? <AButton variant="text" title={english ? "Download data" : "下载数据"} onClick={() => downloadValue(entry.value, entry.key)}><DownloadOutlined /></AButton> : null}</td></tr>; })}</tbody></table></div> : <div className="empty-state">{english ? "No matching entries" : "没有匹配项"}</div>}
        {!children.length && !["dict", "array"].includes(plistType(current.value)) && <pre className="result-box">{plistPreview(current.value)}</pre>}
      </div>}
    </div>
  );
}

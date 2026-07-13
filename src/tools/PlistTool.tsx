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
import { ArrowLeftOutlined, DownloadOutlined, FolderOpenOutlined, RightOutlined } from "@ant-design/icons";
import { AButton, ALinearProgress, ATextField, PanelTitle } from "../components/ui";
import { parsePlist, plistChildren, plistJson, plistPreview, plistType, type PlistValue } from "../features/plist/analyzer";
import { copy } from "../i18n";
import { downloadBlob, downloadTextFile, formatBytes } from "../utils/files";

const LIMIT = 64 * 1024 * 1024;

export function PlistTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const [file, setFile] = React.useState<File | null>(null);
  const [format, setFormat] = React.useState("");
  const [root, setRoot] = React.useState<PlistValue | undefined>(undefined);
  const [stack, setStack] = React.useState<Array<{ path: string; value: PlistValue }>>([]);
  const [query, setQuery] = React.useState("");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const requestRef = React.useRef(0);
  React.useEffect(() => () => { requestRef.current += 1; }, []);
  const current = stack[stack.length - 1] ?? null;
  const children = React.useMemo(() => current ? plistChildren(current.value, current.path).filter((entry) => !query.trim() || `${entry.key} ${entry.preview} ${entry.type}`.toLowerCase().includes(query.trim().toLowerCase())) : [], [current, query]);

  const open = async (next: File | undefined) => {
    if (!next) return;
    const requestId = ++requestRef.current;
    setFile(next);
    setRoot(undefined);
    setStack([]);
    setFormat("");
    setQuery("");
    setLoading(false);
    if (next.size > LIMIT) { setError(english ? "Plist exceeds the 64 MiB limit." : "Plist 超过 64 MiB 解析上限。"); return; }
    setLoading(true);
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const bytes = new Uint8Array(await next.arrayBuffer());
      if (requestId !== requestRef.current) return;
      const parsed = parsePlist(bytes);
      setFormat(parsed.format); setRoot(parsed.value); setStack([{ path: "$", value: parsed.value }]); setQuery("");
    } catch (caught) { if (requestId === requestRef.current) { setError(caught instanceof Error ? caught.message : String(caught)); setRoot(undefined); setStack([]); } }
    finally { if (requestId === requestRef.current) setLoading(false); }
  };
  const clear = () => { requestRef.current += 1; setFile(null); setRoot(undefined); setStack([]); setFormat(""); setQuery(""); setError(""); setLoading(false); if (inputRef.current) inputRef.current.value = ""; };
  const exportData = () => { if (root !== undefined) downloadTextFile(`${file?.name || "plist"}.json`, plistJson(root), "application/json;charset=utf-8"); };
  const downloadValue = (value: PlistValue, key: string) => {
    if (!(value instanceof Uint8Array)) return;
    const bytes = value.slice();
    downloadBlob(key || "plist-data.bin", new Blob([bytes.buffer], { type: "application/octet-stream" }));
  };

  return (
    <div className="tool-grid browser-tool-workbench">
      <div className="tool-panel wide-panel browser-source-panel">
        <div className="panel-heading-row"><PanelTitle title={english ? "Plist browser" : "Plist 浏览器"} />{root !== undefined && <span className="status-pill">{format.toUpperCase()} · {formatBytes(file?.size ?? 0)}</span>}</div>
        <input ref={inputRef} className="hidden-file-input" type="file" aria-hidden="true" tabIndex={-1} accept=".plist,.strings,.xml,application/x-plist" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void open(file); }} />
        {!current && !loading && <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void open(event.dataTransfer.files?.[0]); }}><strong>{file?.name || (english ? "Open a Plist file" : "打开 Plist 文件")}</strong><span>XML · bplist00</span></div>}
        <div className="action-row"><AButton variant="filled" disabled={loading} onClick={() => inputRef.current?.click()}><FolderOpenOutlined /> {t.selectFile}</AButton><AButton variant="outlined" disabled={root === undefined} onClick={exportData}><DownloadOutlined /> JSON</AButton><AButton variant="text" disabled={!file && root === undefined && !error} onClick={clear}>{t.clear}</AButton></div>
        {loading && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>
      {current && <div className="tool-panel wide-panel browser-data-panel">
        <div className="browser-toolbar"><AButton variant="text" disabled={stack.length <= 1} title={english ? "Back" : "返回"} onClick={() => setStack((items) => items.slice(0, -1))}><ArrowLeftOutlined /></AButton><code className="browser-path">{current.path}</code><ATextField value={query} allowClear placeholder={english ? "Filter current level" : "筛选当前层级"} onChange={(event) => setQuery(event.currentTarget.value)} /></div>
        {children.length ? <div className="table-scroll"><table className="data-table browser-data-table"><thead><tr><th>{english ? "Key" : "键"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Value" : "值"}</th><th /></tr></thead><tbody>{children.map((entry) => { const navigable = entry.type === "dict" || entry.type === "array"; return <tr key={entry.path} className={navigable ? "clickable-row" : ""} onDoubleClick={() => navigable && setStack((items) => [...items, { path: entry.path, value: entry.value }])}><td>{entry.key}</td><td>{entry.type}</td><td className="browser-value-cell">{entry.preview}</td><td>{navigable ? <AButton variant="text" title={english ? "Open" : "打开"} onClick={() => setStack((items) => [...items, { path: entry.path, value: entry.value }])}><RightOutlined /></AButton> : entry.type === "data" ? <AButton variant="text" title={english ? "Download data" : "下载数据"} onClick={() => downloadValue(entry.value, entry.key)}><DownloadOutlined /></AButton> : null}</td></tr>; })}</tbody></table></div> : <div className="empty-state">{english ? "No matching entries" : "没有匹配项"}</div>}
        {!children.length && !["dict", "array"].includes(plistType(current.value)) && <pre className="result-box">{plistPreview(current.value)}</pre>}
      </div>}
    </div>
  );
}

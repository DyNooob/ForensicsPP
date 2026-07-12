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
import { ArrowLeftOutlined, FolderOpenOutlined, RightOutlined } from "@ant-design/icons";
import { AButton, ALinearProgress, ATextField, InfoTable, PanelTitle } from "../components/ui";
import type { RegistryHive } from "../features/registry/analyzer";
import { copy } from "../i18n";
import { formatBytes } from "../utils/files";

const LIMIT = 1024 * 1024 * 1024;

function parseInWorker(buffer: ArrayBuffer, workerRef: React.MutableRefObject<Worker | null>) {
  return new Promise<RegistryHive>((resolve, reject) => {
    const worker = new Worker(new URL("../features/registry/registry.worker.ts", import.meta.url), { type: "module" });
    workerRef.current = worker;
    worker.onmessage = (event: MessageEvent<{ ok: boolean; hive?: RegistryHive; error?: string }>) => { worker.terminate(); workerRef.current = null; event.data.ok && event.data.hive ? resolve(event.data.hive) : reject(new Error(event.data.error || "Hive parsing failed.")); };
    worker.onerror = (event) => { worker.terminate(); workerRef.current = null; reject(new Error(event.message)); };
    worker.postMessage(buffer, [buffer]);
  });
}

export function RegistryTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const workerRef = React.useRef<Worker | null>(null);
  const [file, setFile] = React.useState<File | null>(null);
  const [hive, setHive] = React.useState<RegistryHive | null>(null);
  const [selectedId, setSelectedId] = React.useState(0);
  const [query, setQuery] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  React.useEffect(() => () => workerRef.current?.terminate(), []);
  const selected = hive?.keys[selectedId] ?? null;
  const children = React.useMemo(() => selected && hive ? selected.children.map((id) => hive.keys[id]).filter(Boolean) : [], [hive, selected]);
  const searchResults = React.useMemo(() => { const needle = query.trim().toLowerCase(); if (!needle || !hive) return []; return hive.keys.filter((key) => key.path.toLowerCase().includes(needle) || key.values.some((value) => `${value.name} ${value.value}`.toLowerCase().includes(needle))).slice(0, 300); }, [hive, query]);
  const open = async (next: File | undefined) => {
    if (!next) return;
    if (next.size > LIMIT) { setError(english ? "Hive exceeds the 1 GiB limit." : "Hive 超过 1 GiB 解析上限。"); return; }
    setLoading(true); setFile(next); setError(""); setHive(null);
    try { const result = await parseInWorker(await next.arrayBuffer(), workerRef); setHive(result); setSelectedId(result.rootId); }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)); }
    finally { setLoading(false); }
  };
  const clear = () => { workerRef.current?.terminate(); workerRef.current = null; setFile(null); setHive(null); setSelectedId(0); setQuery(""); setLoading(false); setError(""); if (inputRef.current) inputRef.current.value = ""; };

  return <div className="tool-grid browser-tool-workbench">
    <div className="tool-panel wide-panel browser-source-panel"><div className="panel-heading-row"><PanelTitle title={english ? "Registry Hive browser" : "注册表 Hive 浏览器"} />{hive && <span className="status-pill">{hive.keys.length} {english ? "keys" : "个键"} · {formatBytes(file?.size ?? 0)}</span>}</div><input ref={inputRef} className="hidden-file-input" type="file" onChange={(event) => void open(event.target.files?.[0])} />{!hive && !loading && <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void open(event.dataTransfer.files?.[0]); }}><strong>{english ? "Open a Registry Hive" : "打开注册表 Hive"}</strong><span>NTUSER.DAT · SOFTWARE · SYSTEM · SAM · SECURITY</span></div>}<div className="action-row"><AButton variant="filled" onClick={() => inputRef.current?.click()}><FolderOpenOutlined /> {t.selectFile}</AButton><AButton variant="text" disabled={!file && !hive} onClick={clear}>{t.clear}</AButton></div>{loading && <ALinearProgress />}{error && <pre className="result-box">{error}</pre>}{hive && hive.warnings.length > 0 && <pre className="result-box">{hive.warnings.map((warning) => english ? warning.replace("主序列号与次序列号不一致，Hive 可能需要事务日志恢复。", "Primary and secondary sequence numbers differ; transaction logs may be required.").replace("Hive 文件头校验和不匹配。", "Hive header checksum does not match.") : warning).join("\n")}</pre>}</div>
    {hive && selected && <><div className="tool-panel browser-tree-panel"><PanelTitle title={english ? "Keys" : "键"} /><ATextField allowClear value={query} placeholder={english ? "Search keys and values" : "搜索键和值"} onChange={(event) => setQuery(event.currentTarget.value)} />{query.trim() ? <div className="browser-key-list">{searchResults.map((key) => <button type="button" key={key.id} onClick={() => { setSelectedId(key.id); setQuery(""); }}><span>{key.name}</span><small>{key.path}</small></button>)}</div> : <><div className="browser-toolbar"><AButton variant="text" disabled={selected.parentId == null} title={english ? "Up" : "上一级"} onClick={() => selected.parentId != null && setSelectedId(selected.parentId)}><ArrowLeftOutlined /></AButton><code className="browser-path">{selected.path}</code></div><div className="browser-key-list">{children.map((key) => <button type="button" key={key.id} onClick={() => setSelectedId(key.id)}><span>{key.name}</span><small>{key.values.length} {english ? "values" : "个值"}</small><RightOutlined /></button>)}</div></>}</div>
    <div className="tool-panel browser-detail-panel"><PanelTitle title={selected.name} /><InfoTable rows={[[english ? "Path" : "路径", selected.path], [english ? "Last write" : "最后写入", selected.lastWrite], [english ? "Subkeys" : "子键", String(selected.children.length)], [english ? "Values" : "值", String(selected.values.length)]]} />{selected.values.length ? <div className="table-scroll"><table className="data-table browser-data-table"><thead><tr><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Data" : "数据"}</th></tr></thead><tbody>{selected.values.map((value, index) => <tr key={`${value.name}-${index}`}><td>{value.name}</td><td>{value.type}</td><td className="browser-value-cell">{value.value || "--"}</td></tr>)}</tbody></table></div> : <div className="empty-state">{english ? "This key has no values" : "当前键没有值"}</div>}</div></>}
  </div>;
}

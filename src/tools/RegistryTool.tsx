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
import { AButton, ALinearProgress, ATextField, InfoTable, PanelTitle, ToolPanelHeader } from "../components/ui";
import type { RegistryHive } from "../features/registry/analyzer";
import { copy } from "../i18n";
import { downloadTextFile, formatBytes } from "../utils/files";
import { runWorkerTask } from "../utils/workerTask";
import { useToolWorkspace } from "../utils/useToolWorkspace";

const LIMIT = 256 * 1024 * 1024;
const MAX_PERSISTED_REGISTRY_BYTES = 8 * 1024 * 1024;
type RegistryWorkspace = { hive: RegistryHive; selectedId: number; query: string; valueFilter: string; fileName: string; fileSize: number };

function isRegistryWorkspace(value: unknown): value is RegistryWorkspace {
  return Boolean(value && typeof value === "object" && "hive" in value && "selectedId" in value && "fileName" in value && "fileSize" in value);
}

export function RegistryTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const [file, setFile] = React.useState<File | null>(null);
  const [hive, setHive] = React.useState<RegistryHive | null>(null);
  const [selectedId, setSelectedId] = React.useState(0);
  const [query, setQuery] = React.useState("");
  const [valueFilter, setValueFilter] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [storageNotice, setStorageNotice] = React.useState("");
  const [fileMeta, setFileMeta] = React.useState<{ name: string; size: number } | null>(null);
  const workspace = useToolWorkspace<RegistryWorkspace>({
    id: "registry",
    version: 1,
    isValid: isRegistryWorkspace,
    onRestore: (restored) => {
      setFile(null);
      setFileMeta({ name: restored.fileName, size: restored.fileSize });
      setHive(restored.hive);
      setSelectedId(restored.selectedId);
      setQuery(restored.query);
      setValueFilter(restored.valueFilter);
      setError("");
    }
  });
  React.useEffect(() => () => abortRef.current?.abort(), []);
  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
  }, [active]);
  const selected = hive?.keys[selectedId] ?? null;
  const children = React.useMemo(() => selected && hive ? selected.children.map((id) => hive.keys[id]).filter(Boolean) : [], [hive, selected]);
  const searchResults = React.useMemo(() => { const needle = query.trim().toLowerCase(); if (!needle || !hive) return []; return hive.keys.filter((key) => key.path.toLowerCase().includes(needle) || key.values.some((value) => `${value.name} ${value.value}`.toLowerCase().includes(needle))).slice(0, 300); }, [hive, query]);
  const visibleValues = React.useMemo(() => {
    const needle = valueFilter.trim().toLowerCase();
    return (selected?.values ?? []).filter((value) => !needle || `${value.name} ${value.type} ${value.value}`.toLowerCase().includes(needle));
  }, [selected, valueFilter]);
  const open = async (next: File | undefined) => {
    if (!next) return;
    abortRef.current?.abort();
    abortRef.current = null;
    workspace.clear();
    setFile(next);
    setFileMeta({ name: next.name, size: next.size });
    setHive(null);
    setSelectedId(0);
    setQuery("");
    setValueFilter("");
    setStorageNotice(next.size > MAX_PERSISTED_REGISTRY_BYTES
      ? (english ? "This file is available for the current session only; files over 8 MiB are not restored automatically." : "当前文件仅在本次打开期间可用；超过 8 MiB 的文件不会自动恢复。")
      : "");
    setLoading(false);
    if (next.size > LIMIT) {
      setError(english ? "Hive exceeds the 256 MiB limit." : "Hive 超过 256 MiB 解析上限。");
      return;
    }
    setLoading(true);
    setError("");
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const bytes = await next.arrayBuffer();
      if (controller.signal.aborted) return;
      const result = await runWorkerTask<{ bytes: ArrayBuffer }, RegistryHive>({
        createWorker: () => new Worker(new URL("../features/registry/registry.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes },
        transfer: [bytes],
        signal: controller.signal,
        timeoutMs: 180_000
      });
      if (controller.signal.aborted) return;
      setHive(result);
      setSelectedId(result.rootId);
      setQuery("");
      setValueFilter("");
      if (next.size <= MAX_PERSISTED_REGISTRY_BYTES) workspace.save({ hive: result, selectedId: result.rootId, query: "", valueFilter: "", fileName: next.name, fileSize: next.size });
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(false);
      }
    }
  };
  const clear = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    workspace.clear();
    setFile(null);
    setFileMeta(null);
    setHive(null);
    setSelectedId(0);
    setQuery("");
    setValueFilter("");
    setLoading(false);
    setError("");
    setStorageNotice("");
    if (inputRef.current) inputRef.current.value = "";
  };
  const selectKey = (id: number) => { setSelectedId(id); setQuery(""); setValueFilter(""); };
  const exportCurrentKey = () => {
    if (!selected) return;
    downloadTextFile(`${selected.name || "registry-key"}.json`, JSON.stringify({ path: selected.path, lastWrite: selected.lastWrite, values: selected.values }, null, 2), "application/json;charset=utf-8");
  };

  return <div className="tool-grid browser-tool-workbench registry-browser-workbench">
    <section className="tool-panel wide-panel browser-source-panel">
      <div className="panel-heading-row"><PanelTitle title={english ? "Registry Hive browser" : "注册表 Hive 浏览器"} />{hive && <span className="status-pill">{hive.keys.length} {english ? "keys" : "个键"} · {formatBytes(file?.size ?? fileMeta?.size ?? 0)}</span>}</div>
      <input ref={inputRef} className="hidden-file-input" type="file" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void open(file); }} />
      {!hive && !loading && <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void open(event.dataTransfer.files?.[0]); }}><strong>{english ? "Open a Registry Hive" : "打开 Registry Hive"}</strong><span>NTUSER.DAT · SOFTWARE · SYSTEM · SAM · SECURITY</span></div>}
      <div className="action-row"><AButton variant="filled" onClick={() => inputRef.current?.click()}><FolderOpenOutlined /> {t.selectFile}</AButton><AButton variant="text" disabled={!file && !hive} onClick={clear}>{t.clear}</AButton></div>
      {loading && <ALinearProgress />}
      {error && <div className="empty-state error-state">{error}</div>}
      {storageNotice && <div className="tool-storage-note" role="status">{storageNotice}</div>}
      {hive && hive.warnings.length > 0 && <div className="empty-state registry-warning-list">{hive.warnings.map((warning) => english ? warning.replace("主序列号与次序列号不一致，Hive 可能需要事务日志恢复。", "Primary and secondary sequence numbers differ; transaction logs may be required.").replace("Hive 文件头校验和不匹配。", "Hive header checksum does not match.") : warning).join("\n")}</div>}
    </section>

    {hive && selected && <>
      <section className="tool-panel browser-tree-panel">
        <ToolPanelHeader title={english ? "Keys" : "键"} subtitle={query.trim() ? `${searchResults.length}${searchResults.length === 300 ? "+" : ""}` : `${children.length}`} />
        <ATextField allowClear value={query} placeholder={english ? "Search keys and values" : "搜索键和值"} onChange={(event) => setQuery(event.currentTarget.value)} />
        {query.trim() ? <div className="browser-key-list">{searchResults.map((key) => <button type="button" key={key.id} onClick={() => selectKey(key.id)}><span>{key.name}</span><small>{key.path}</small></button>)}</div> : <>
          <div className="browser-toolbar"><AButton variant="text" disabled={selected.parentId == null} title={english ? "Up" : "上一级"} onClick={() => selected.parentId != null && selectKey(selected.parentId)}><ArrowLeftOutlined /></AButton><code className="browser-path" title={selected.path}>{selected.path}</code></div>
          <div className="browser-key-list">{children.map((key) => <button type="button" key={key.id} onClick={() => selectKey(key.id)}><span>{key.name}</span><small>{key.values.length} {english ? "values" : "个值"}</small><RightOutlined /></button>)}{!children.length && <div className="empty-state">{english ? "No subkeys" : "没有子键"}</div>}</div>
        </>}
      </section>

      <section className="tool-panel browser-detail-panel">
        <ToolPanelHeader title={selected.name} subtitle={selected.lastWrite} actions={<AButton variant="outlined" onClick={exportCurrentKey}><DownloadOutlined /> JSON</AButton>} />
        <InfoTable rows={[[english ? "Path" : "路径", selected.path], [english ? "Subkeys" : "子键", String(selected.children.length)], [english ? "Values" : "值", String(selected.values.length)]]} />
        {selected.values.length ? <><ATextField className="browser-value-filter" allowClear value={valueFilter} placeholder={english ? "Filter current values" : "筛选当前值"} onChange={(event) => setValueFilter(event.currentTarget.value)} /><div className="table-scroll browser-value-table-scroll"><table className="data-table browser-data-table"><thead><tr><th>{english ? "Name" : "名称"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Data" : "数据"}</th></tr></thead><tbody>{visibleValues.map((value, index) => <tr key={`${value.name}-${index}`}><td>{value.name}</td><td>{value.type}</td><td className="browser-value-cell">{value.value || "--"}</td></tr>)}</tbody></table></div></> : <div className="empty-state">{english ? "This key has no values" : "当前键没有值"}</div>}
      </section>
    </>}
  </div>;
}

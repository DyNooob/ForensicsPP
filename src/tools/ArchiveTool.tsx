/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import { copyText } from "../utils/clipboard";
import React from "react";
import { AButton, ALinearProgress, ASelect, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { ArchiveWorkerRequest } from "../features/archive/archive.worker";
import { downloadBlob, formatBytes } from "../utils/files";
import { hexPreview, previewText } from "../utils/binary";
import { hashBytesInWorker } from "../features/hash/task";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

type EntryMeta = {
  name: string;
  method: number;
  compressed: number;
  uncompressed: number;
  encrypted: boolean;
};

type ArchiveEntry = EntryMeta & {
  data?: Uint8Array;
};

type ArchiveState = {
  name: string;
  size: number;
  kind: string;
  entries: ArchiveEntry[];
  skipped: number;
};

type ArchiveWorkspace = {
  archive: Omit<ArchiveState, "entries"> & { entries: EntryMeta[] };
  selectedName: string;
  query: string;
  entryType: "all" | "files" | "directories" | "encrypted";
  sortBy: "path" | "size";
};

function isArchiveWorkspace(value: unknown): value is ArchiveWorkspace {
  return Boolean(value && typeof value === "object" && "archive" in value && "selectedName" in value && "entryType" in value && "sortBy" in value);
}

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 2000;

function decodeEntryName(nameBytes: Uint8Array, utf8: boolean) {
  if (utf8) return new TextDecoder().decode(nameBytes);
  try { return new TextDecoder("windows-1252").decode(nameBytes); } catch { return new TextDecoder().decode(nameBytes); }
}

export function parseArchiveEntries(bytes: Uint8Array): { entries: EntryMeta[]; skipped: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries: EntryMeta[] = [];
  let eocdOffset = -1;
  for (let offset = Math.max(0, bytes.length - 65_557); offset + 22 <= bytes.length; offset += 1) {
    if (view.getUint32(offset, true) === 0x06054b50) eocdOffset = offset;
  }
  if (eocdOffset < 0) return { entries, skipped: 0 };
  const declaredEntries = view.getUint16(eocdOffset + 10, true);
  let offset = view.getUint32(eocdOffset + 16, true);
  while (offset + 46 <= bytes.length && entries.length < MAX_ENTRIES && view.getUint32(offset, true) === 0x02014b50) {
    const flags = view.getUint16(offset + 8, true);
    const method = view.getUint16(offset + 10, true);
    const compressed = view.getUint32(offset + 20, true);
    const uncompressed = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const nameOffset = offset + 46;
    if (nameOffset + nameLength > bytes.length) break;
    const name = decodeEntryName(bytes.subarray(nameOffset, nameOffset + nameLength), Boolean(flags & 0x800));
    entries.push({ name, method, compressed, uncompressed, encrypted: Boolean(flags & 1) });
    offset = nameOffset + nameLength + extraLength + commentLength;
  }
  return { entries, skipped: Math.max(0, declaredEntries - entries.length) };
}

function inferKind(name: string, entries: EntryMeta[]) {
  const names = new Set(entries.map((entry) => entry.name.toLowerCase()));
  if (names.has("androidmanifest.xml") && entries.some((entry) => /^classes\d*\.dex$/i.test(entry.name))) return "APK";
  if (names.has("meta-inf/manifest.mf") && entries.some((entry) => /\.class$/i.test(entry.name))) return "JAR";
  if (names.has("[content_types].xml") && entries.some((entry) => /^word\//i.test(entry.name))) return "DOCX / OOXML";
  if (names.has("[content_types].xml") && entries.some((entry) => /^xl\//i.test(entry.name))) return "XLSX / OOXML";
  if (names.has("[content_types].xml") && entries.some((entry) => /^ppt\//i.test(entry.name))) return "PPTX / OOXML";
  if (/\.apk$/i.test(name)) return "APK / ZIP";
  if (/\.jar$/i.test(name)) return "JAR / ZIP";
  return "ZIP";
}

function methodLabel(method: number) {
  if (method === 0) return "Stored";
  if (method === 8) return "Deflate";
  return String(method);
}

function isImage(name: string) {
  return /\.(png|jpe?g|gif|webp|bmp)$/i.test(name);
}

function mimeForName(name: string) {
  const extension = name.split(".").pop()?.toLowerCase();
  return ({ png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", bmp: "image/bmp" } as Record<string, string>)[extension ?? ""] ?? "application/octet-stream";
}

export function ArchiveTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [archive, setArchive] = React.useState<ArchiveState | null>(null);
  const [selectedName, setSelectedName] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [entryType, setEntryType] = React.useState<"all" | "files" | "directories" | "encrypted">("all");
  const [sortBy, setSortBy] = React.useState<"path" | "size">("path");
  const [loading, setLoading] = React.useState(false);
  const [loadingEntry, setLoadingEntry] = React.useState("");
  const [entryHashes, setEntryHashes] = React.useState<Record<string, string>>({});
  const [entryHashingKey, setEntryHashingKey] = React.useState("");
  const [entryHashError, setEntryHashError] = React.useState("");
  const [error, setError] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const archiveBytesRef = React.useRef<Uint8Array | null>(null);
  const requestRef = React.useRef(0);
  const entryAbortRef = React.useRef<AbortController | null>(null);
  const entryHashAbortRef = React.useRef<AbortController | null>(null);
  const workspace = useToolWorkspace<ArchiveWorkspace>({
    id: "archive",
    version: 1,
    isValid: isArchiveWorkspace,
    onRestore: (restored) => {
      setArchive(restored.archive);
      setSelectedName(restored.selectedName);
      setQuery(restored.query);
      setEntryType(restored.entryType);
      setSortBy(restored.sortBy);
      archiveBytesRef.current = null;
      setError("");
    }
  });
  React.useEffect(() => () => {
    requestRef.current += 1;
    entryAbortRef.current?.abort();
    entryHashAbortRef.current?.abort();
    archiveBytesRef.current = null;
  }, []);

  React.useEffect(() => {
    if (active) return;
    requestRef.current += 1;
    entryAbortRef.current?.abort();
    entryAbortRef.current = null;
    entryHashAbortRef.current?.abort();
    entryHashAbortRef.current = null;
    setLoading(false);
    setLoadingEntry("");
    setEntryHashingKey("");
  }, [active]);

  const entries = archive?.entries ?? [];
  const visibleEntries = React.useMemo(() => {
    const value = query.trim().toLowerCase();
    return entries
      .filter((entry) => {
        if (value && !entry.name.toLowerCase().includes(value)) return false;
        if (entryType === "files" && entry.name.endsWith("/")) return false;
        if (entryType === "directories" && !entry.name.endsWith("/")) return false;
        if (entryType === "encrypted" && !entry.encrypted) return false;
        return true;
      })
      .sort((left, right) => sortBy === "size" ? right.uncompressed - left.uncompressed || left.name.localeCompare(right.name) : left.name.localeCompare(right.name));
  }, [entries, entryType, query, sortBy]);
  const selected = entries.find((entry) => entry.name === selectedName) ?? null;
  const imageUrl = React.useMemo(() => {
    if (!selected?.data || !isImage(selected.name)) return "";
    const bytes = new Uint8Array(selected.data.length);
    bytes.set(selected.data);
    return URL.createObjectURL(new Blob([bytes.buffer], { type: mimeForName(selected.name) }));
  }, [selected]);

  React.useEffect(() => () => { if (imageUrl) URL.revokeObjectURL(imageUrl); }, [imageUrl]);

  const loadFile = async (file?: File) => {
    if (!file) return;
    const requestId = ++requestRef.current;
    entryAbortRef.current?.abort();
    entryHashAbortRef.current?.abort();
    entryHashAbortRef.current = null;
    setDropActive(false);
    setError("");
    workspace.clear();
    archiveBytesRef.current = null;
    setArchive(null);
    setSelectedName("");
    setQuery("");
    setEntryType("all");
    setSortBy("path");
    setLoadingEntry("");
    setEntryHashes({});
    setEntryHashingKey("");
    setEntryHashError("");
    setLoading(false);
    if (file.size > MAX_ARCHIVE_BYTES) {
      setError(english ? "The archive exceeds the 256 MiB limit." : "压缩包超过 256 MiB 限制。");
      return;
    }
    setLoading(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (requestId !== requestRef.current) return;
      const parsed = parseArchiveEntries(bytes);
      if (!parsed.entries.length) throw new Error(english ? "No ZIP entries were found." : "未找到 ZIP 条目。");
      archiveBytesRef.current = bytes;
      const nextEntries = parsed.entries.map((entry) => ({ ...entry, data: undefined }));
      const firstFile = nextEntries.find((entry) => !entry.name.endsWith("/"));
      const nextArchive = { name: file.name, size: file.size, kind: inferKind(file.name, parsed.entries), entries: nextEntries, skipped: parsed.skipped } satisfies ArchiveState;
      setArchive(nextArchive);
      setSelectedName(firstFile?.name ?? "");
      setQuery("");
      setEntryType("all");
      setSortBy("path");
      workspace.save({ archive: nextArchive, selectedName: firstFile?.name ?? "", query: "", entryType: "all", sortBy: "path" });
    } catch (caught) {
      if (requestId === requestRef.current) {
        setArchive(null);
        archiveBytesRef.current = null;
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (requestId === requestRef.current) setLoading(false);
    }
  };

  const clear = () => {
    requestRef.current += 1;
    entryAbortRef.current?.abort();
    entryAbortRef.current = null;
    entryHashAbortRef.current?.abort();
    entryHashAbortRef.current = null;
    workspace.clear();
    archiveBytesRef.current = null;
    setArchive(null);
    setSelectedName("");
    setQuery("");
    setEntryType("all");
    setSortBy("path");
    setError("");
    setLoading(false);
    setLoadingEntry("");
    setEntryHashes({});
    setEntryHashingKey("");
    setEntryHashError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const loadEntry = async (entry: ArchiveEntry) => {
    const bytes = archiveBytesRef.current;
    if (entry.data) return entry.data;
    if (!bytes || entry.name.endsWith("/") || entry.encrypted || loadingEntry) return null;
    const ratio = entry.compressed > 0 ? entry.uncompressed / entry.compressed : 0;
    if (entry.uncompressed > MAX_ENTRY_BYTES || (ratio > 500 && entry.uncompressed > 16 * 1024 * 1024)) {
      setError(english ? "This entry is too large or expands too aggressively for browser preview." : "该条目过大或解压倍率过高，无法在浏览器中预览。");
      return null;
    }
    setLoadingEntry(entry.name);
    setError("");
    const controller = new AbortController();
    entryAbortRef.current = controller;
    try {
      const workerBytes = bytes.slice();
      const extracted = await runWorkerTask<ArchiveWorkerRequest, ArrayBuffer>({
        createWorker: () => new Worker(new URL("../features/archive/archive.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes: workerBytes.buffer, entryName: entry.name },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 120_000
      });
      if (controller.signal.aborted) return null;
      const data = new Uint8Array(extracted);
      setArchive((current) => current ? { ...current, entries: current.entries.map((item) => item.name === entry.name ? { ...item, data } : item) } : current);
      return data;
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
      return null;
    } finally {
      if (entryAbortRef.current === controller) entryAbortRef.current = null;
      setLoadingEntry("");
    }
  };

  const downloadEntry = async () => {
    if (!selected) return;
    const data = selected.data ?? await loadEntry(selected);
    if (!data) return;
    const bytes = new Uint8Array(data.length);
    bytes.set(data);
    downloadBlob(selected.name.split("/").pop() || "entry.bin", new Blob([bytes], { type: "application/octet-stream" }));
  };

  const hashSelectedEntry = async () => {
    if (!selected || selected.name.endsWith("/") || selected.encrypted || entryHashingKey) return;
    const key = selected.name;
    if (entryHashes[key]) return;
    const requestId = requestRef.current;
    setEntryHashingKey(key);
    setEntryHashError("");
    const controller = new AbortController();
    entryHashAbortRef.current?.abort();
    entryHashAbortRef.current = controller;
    try {
      const data = selected.data ?? await loadEntry(selected);
      if (!data) return;
      const dataCopy = new Uint8Array(data.length);
      dataCopy.set(data);
      const result = await hashBytesInWorker(dataCopy, ["sha256"], { signal: controller.signal });
      if (controller.signal.aborted || requestId !== requestRef.current) return;
      if (!result.sha256) throw new Error(english ? "SHA-256 calculation returned no result." : "SHA-256 计算没有返回结果。");
      setEntryHashes((current) => ({ ...current, [key]: result.sha256 ?? "" }));
    } catch (caught) {
      if (requestId === requestRef.current && !(caught instanceof DOMException && caught.name === "AbortError")) setEntryHashError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (entryHashAbortRef.current === controller) entryHashAbortRef.current = null;
      if (requestId === requestRef.current) setEntryHashingKey("");
    }
  };

  const totalUncompressed = entries.reduce((sum, entry) => sum + entry.uncompressed, 0);
  const fileCount = entries.filter((entry) => !entry.name.endsWith("/")).length;
  const directoryCount = entries.filter((entry) => entry.name.endsWith("/")).length;
  const encryptedCount = entries.filter((entry) => entry.encrypted).length;
  const selectedPreview = selected?.data ? previewText(selected.data, 12000) : "";
  const selectedHex = selected?.data ? hexPreview(selected.data, 256) : "";

  return (
    <div className={`tool-grid archive-workbench ${archive ? "has-archive" : "empty-archive"}`}>
      <div className="tool-panel wide-panel archive-source-panel">
        <PanelTitle title={t.archive} />
        <input className="hidden-file-input" ref={inputRef} type="file" tabIndex={-1} aria-hidden="true" accept=".zip,.apk,.jar,.docx,.xlsx,.pptx,.docm,.xlsm,.pptm" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void loadFile(file); }} />
        <div className={`desktop-drop-zone ${dropActive ? "active" : ""}`} role="button" tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }} onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); setDropActive(false); void loadFile(event.dataTransfer.files?.[0]); }}>
          <strong>{archive?.name || t.dropFileTitle}</strong>
          <span>{archive ? `${archive.kind} · ${fileCount} ${english ? "files" : "个文件"}` : t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!archive && !error && !loading} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {archive && <>
        <div className="tool-panel wide-panel archive-summary-panel">
          <PanelTitle title={t.summary} />
          <InfoTable rows={[
            [english ? "Type" : "类型", archive.kind],
            [english ? "Archive size" : "压缩包大小", formatBytes(archive.size)],
            [english ? "Files" : "文件", String(fileCount)],
            [english ? "Directories" : "目录", String(directoryCount)],
            [english ? "Uncompressed size" : "解压后大小", formatBytes(totalUncompressed)],
            [english ? "Encrypted entries" : "加密条目", String(encryptedCount)],
            ...(archive.skipped ? [[english ? "Not listed" : "未列出条目", String(archive.skipped)] as [string, string]] : [])
          ]} />
        </div>

        <div className="archive-browser-layout wide-panel">
          <div className="tool-panel archive-entry-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Files" : "文件"} />
              <span className="status-pill">{visibleEntries.length}/{entries.length}</span>
            </div>
            <div className="archive-list-toolbar">
              <input className="text-input" aria-label={english ? "Search archive paths" : "搜索压缩包路径"} value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={english ? "Search path" : "搜索路径"} />
              <ASelect aria-label={english ? "Entry type" : "条目类型"} value={entryType} onChange={(value) => setEntryType(value as typeof entryType)} options={[
                { value: "all", label: english ? "All" : "全部" },
                { value: "files", label: english ? "Files" : "文件" },
                { value: "directories", label: english ? "Directories" : "目录" },
                { value: "encrypted", label: english ? "Encrypted" : "加密" }
              ]} />
              <ASelect aria-label={english ? "Sort entries" : "条目排序"} value={sortBy} onChange={(value) => setSortBy(value as typeof sortBy)} options={[
                { value: "path", label: english ? "Path" : "路径" },
                { value: "size", label: english ? "Size" : "大小" }
              ]} />
            </div>
            <div className="archive-file-list">
              {visibleEntries.map((entry) => (
                  <button className={entry.name === selectedName ? "active" : ""} type="button" key={entry.name} onClick={() => { setSelectedName(entry.name); setEntryHashError(""); }}>
                  <span>{entry.name}</span>
                  <small>{entry.name.endsWith("/") ? (english ? "Directory" : "目录") : formatBytes(entry.uncompressed)}</small>
                </button>
              ))}
              {!visibleEntries.length && <div className="empty-state">--</div>}
            </div>
          </div>

          <div className="tool-panel archive-preview-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Preview" : "预览"} />
              <div className="button-row compact-buttons"><AButton variant="filled" disabled={!selected || Boolean(selected.data) || selected.encrypted || selected.name.endsWith("/") || Boolean(loadingEntry)} onClick={() => selected && void loadEntry(selected)}>{loadingEntry ? (english ? "Loading..." : "正在提取...") : (english ? "Load preview" : "加载预览")}</AButton><AButton variant="outlined" disabled={!selected || selected.encrypted || selected.name.endsWith("/") || Boolean(loadingEntry)} onClick={() => void downloadEntry()}>{english ? "Save entry" : "保存条目"}</AButton></div>
            </div>
            {selected ? <>
              <InfoTable rows={[
                [english ? "Path" : "路径", selected.name],
                [english ? "Size" : "大小", formatBytes(selected.uncompressed)],
                [english ? "Compressed" : "压缩后", formatBytes(selected.compressed)],
                [english ? "Method" : "方式", methodLabel(selected.method)],
                [english ? "Encrypted" : "加密", selected.encrypted ? (english ? "Yes" : "是") : (english ? "No" : "否")]
              ]} />
              <div className="archive-entry-integrity">
                <span>SHA-256</span>
                {entryHashes[selected.name]
                  ? <button type="button" className="archive-entry-hash" title={t.copy} onClick={() => void copyText(entryHashes[selected.name])}>{entryHashes[selected.name]}</button>
                  : <AButton variant="text" disabled={selected.encrypted || selected.name.endsWith("/") || Boolean(entryHashingKey) || Boolean(loadingEntry)} onClick={() => void hashSelectedEntry()}>{entryHashingKey === selected.name ? (english ? "Calculating..." : "计算中...") : (english ? "Calculate" : "计算")}</AButton>}
              </div>
              {entryHashError && <div className="empty-state error-state">{entryHashError}</div>}
              {imageUrl ? <div className="archive-image-preview"><img src={imageUrl} alt={selected.name} /></div> : selected.data ? (
                <textarea aria-label={english ? "Archive entry preview" : "压缩包条目预览"} className="single-textarea archive-entry-preview" value={selectedPreview || selectedHex || "--"} readOnly />
              ) : <div className="empty-state">{selected.encrypted ? (english ? "Encrypted entry cannot be previewed." : "加密条目无法预览。") : (english ? "This entry was not extracted for preview." : "该条目未提取预览。")}</div>}
            </> : <div className="empty-state">--</div>}
          </div>
        </div>
      </>}
    </div>
  );
}

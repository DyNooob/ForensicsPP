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
import { unzip } from "fflate";
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import { downloadBlob, formatBytes } from "../utils/files";
import { hexPreview, previewText } from "../utils/binary";

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

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_EXTRACTED_BYTES = 256 * 1024 * 1024;
const MAX_ENTRIES = 2000;

function parseLocalEntries(bytes: Uint8Array): EntryMeta[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries: EntryMeta[] = [];
  let offset = 0;
  while (offset + 30 <= bytes.length && entries.length < MAX_ENTRIES) {
    if (view.getUint32(offset, true) !== 0x04034b50) {
      offset += 1;
      continue;
    }
    const flags = view.getUint16(offset + 6, true);
    const method = view.getUint16(offset + 8, true);
    const compressed = view.getUint32(offset + 18, true);
    const uncompressed = view.getUint32(offset + 22, true);
    const nameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    const nameOffset = offset + 30;
    if (nameOffset + nameLength > bytes.length) break;
    const nameBytes = bytes.subarray(nameOffset, nameOffset + nameLength);
    let name = new TextDecoder().decode(nameBytes);
    if (!(flags & 0x800)) {
      try { name = new TextDecoder("windows-1252").decode(nameBytes); } catch { /* UTF-8 fallback is already available. */ }
    }
    entries.push({ name, method, compressed, uncompressed, encrypted: Boolean(flags & 1) });
    const next = nameOffset + nameLength + extraLength + compressed;
    offset = next > offset ? next : offset + 1;
  }
  return entries;
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

export function ArchiveTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [archive, setArchive] = React.useState<ArchiveState | null>(null);
  const [selectedName, setSelectedName] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const entries = archive?.entries ?? [];
  const visibleEntries = React.useMemo(() => {
    const value = query.trim().toLowerCase();
    return entries.filter((entry) => !value || entry.name.toLowerCase().includes(value));
  }, [entries, query]);
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
    setDropActive(false);
    setError("");
    if (file.size > MAX_ARCHIVE_BYTES) {
      setError(english ? "The archive exceeds the 256 MiB limit." : "压缩包超过 256 MiB 限制。");
      return;
    }
    setLoading(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const metadata = parseLocalEntries(bytes);
      if (!metadata.length) throw new Error(english ? "No ZIP entries were found." : "未找到 ZIP 条目。");
      let extractedBytes = 0;
      let extractedFiles = 0;
      let skipped = 0;
      const extracted: Record<string, Uint8Array> = await new Promise<Record<string, Uint8Array>>((resolve, reject) => {
        unzip(bytes, {
          filter: (entry) => {
            const ratio = entry.size > 0 ? entry.originalSize / entry.size : 0;
            const allowed = entry.originalSize <= MAX_ENTRY_BYTES
              && extractedBytes + entry.originalSize <= MAX_EXTRACTED_BYTES
              && extractedFiles < 1000
              && !(ratio > 500 && entry.originalSize > 16 * 1024 * 1024);
            if (allowed) { extractedBytes += entry.originalSize; extractedFiles += 1; }
            else skipped += 1;
            return allowed;
          }
        }, (caught, data) => caught ? reject(caught) : resolve(data));
      }).catch(() => ({} as Record<string, Uint8Array>));
      const nextEntries = metadata.map((entry) => ({ ...entry, data: extracted[entry.name] }));
      const firstFile = nextEntries.find((entry) => !entry.name.endsWith("/"));
      setArchive({ name: file.name, size: file.size, kind: inferKind(file.name, metadata), entries: nextEntries, skipped });
      setSelectedName(firstFile?.name ?? "");
      setQuery("");
    } catch (caught) {
      setArchive(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setArchive(null);
    setSelectedName("");
    setQuery("");
    setError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const downloadEntry = () => {
    if (!selected?.data) return;
    const bytes = new Uint8Array(selected.data.length);
    bytes.set(selected.data);
    downloadBlob(selected.name.split("/").pop() || "entry.bin", new Blob([bytes], { type: "application/octet-stream" }));
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
        <input ref={inputRef} type="file" accept=".zip,.apk,.jar,.docx,.xlsx,.pptx,.docm,.xlsm,.pptm" onChange={(event) => void loadFile(event.target.files?.[0])} />
        <div className={`desktop-drop-zone ${dropActive ? "active" : ""}`} role="button" tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }} onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); void loadFile(event.dataTransfer.files?.[0]); }}>
          <strong>{archive?.name || t.dropFileTitle}</strong>
          <span>{archive ? `${archive.kind} · ${fileCount} ${english ? "files" : "个文件"}` : t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!archive && !error} onClick={clear}>{t.clear}</AButton>
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
            [english ? "Not previewed" : "未预览条目", String(archive.skipped)]
          ]} />
        </div>

        <div className="archive-browser-layout wide-panel">
          <div className="tool-panel archive-entry-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Files" : "文件"} />
              <span className="status-pill">{visibleEntries.length}/{entries.length}</span>
            </div>
            <input className="text-input" aria-label={english ? "Search archive paths" : "搜索压缩包路径"} value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={english ? "Search path" : "搜索路径"} />
            <div className="archive-file-list">
              {visibleEntries.map((entry) => (
                <button className={entry.name === selectedName ? "active" : ""} type="button" key={entry.name} onClick={() => setSelectedName(entry.name)}>
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
              <AButton variant="outlined" disabled={!selected?.data} onClick={downloadEntry}>{english ? "Save entry" : "保存条目"}</AButton>
            </div>
            {selected ? <>
              <InfoTable rows={[
                [english ? "Path" : "路径", selected.name],
                [english ? "Size" : "大小", formatBytes(selected.uncompressed)],
                [english ? "Compressed" : "压缩后", formatBytes(selected.compressed)],
                [english ? "Method" : "方式", methodLabel(selected.method)],
                [english ? "Encrypted" : "加密", selected.encrypted ? (english ? "Yes" : "是") : (english ? "No" : "否")]
              ]} />
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

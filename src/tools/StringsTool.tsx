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
import { AButton, AInputNumber, ALinearProgress, ASelect, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { ExtractedStringRow, StringsAnalysis } from "../models";
import { hexPreview, previewText } from "../utils/binary";
import { downloadTextFile, formatBytes } from "../utils/files";
import { useStoredState } from "../utils/storage";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

export type StringsToolServices = {
  extractPrintableStrings: (bytes: Uint8Array, minLength: number) => StringsAnalysis;
  stringRowKey: (row: ExtractedStringRow) => string;
  stringsToCsv: (rows: ExtractedStringRow[]) => string;
};

const PAGE_SIZE = 200;
const MAX_WORKSPACE_PREVIEW_BYTES = 4 * 1024 * 1024;

type StringsWorkspace = {
  sourceName: string;
  sourceSize: number;
  appliedMinLength: number;
  analysis: StringsAnalysis;
  previewBytes: Uint8Array;
};

function isStringsWorkspace(value: unknown): value is StringsWorkspace {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<StringsWorkspace>;
  return typeof candidate.sourceName === "string"
    && typeof candidate.sourceSize === "number"
    && typeof candidate.appliedMinLength === "number"
    && Boolean(candidate.analysis && typeof candidate.analysis === "object")
    && candidate.previewBytes instanceof Uint8Array;
}

export function StringsTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: StringsToolServices; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [text, setText] = useStoredState("strings.text.v2", "");
  const [minLength, setMinLength] = useStoredState("strings.minLength", 4);
  const [appliedMinLength, setAppliedMinLength] = React.useState(minLength);
  const [sourceName, setSourceName] = React.useState("text input");
  const [pendingBytes, setPendingBytes] = React.useState<Uint8Array>(() => new Uint8Array());
  const [bytes, setBytes] = React.useState<Uint8Array>(() => new Uint8Array());
  const [sourceSize, setSourceSize] = React.useState(0);
  const [filter, setFilter] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("");
  const [encodingFilter, setEncodingFilter] = React.useState("");
  const [selectedKey, setSelectedKey] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [dropActive, setDropActive] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [storageNotice, setStorageNotice] = React.useState("");
  const [analyzing, setAnalyzing] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const fileReadRef = React.useRef(0);
  const [analysis, setAnalysis] = React.useState<StringsAnalysis>(() => services.extractPrintableStrings(new Uint8Array(), appliedMinLength));
  const hasInput = bytes.length > 0 || analysis.items.length > 0;
  const workspace = useToolWorkspace<StringsWorkspace>({
    id: "strings.v1",
    version: 1,
    isValid: isStringsWorkspace,
    onRestore: (value) => {
      setStorageNotice(value.sourceSize > value.previewBytes.byteLength
        ? (english ? "Only a preview is restored. Re-open the source file to view byte context." : "当前只恢复了预览数据；如需查看完整字节上下文，请重新选择源文件。")
        : "");
      setSourceName(value.sourceName);
      setSourceSize(value.sourceSize);
      setAppliedMinLength(value.appliedMinLength);
      setPendingBytes(new Uint8Array());
      setBytes(value.previewBytes.slice());
      setAnalysis(value.analysis);
      resetReview();
    }
  });
  const types = React.useMemo(() => analysis.typeRows.map(([type]) => type), [analysis.typeRows]);
  const filteredItems = React.useMemo(() => {
    const query = filter.trim().toLowerCase();
    return analysis.items.filter((item) => {
      if (typeFilter && item.detectedType !== typeFilter) return false;
      if (encodingFilter && item.encoding !== encodingFilter) return false;
      if (!query) return true;
      return [item.value, item.detectedType, item.encoding, String(item.offset), `0x${item.offset.toString(16)}`]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [analysis.items, encodingFilter, filter, typeFilter]);
  const pageCount = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE));
  const visibleItems = filteredItems.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selected = selectedKey ? analysis.items.find((item) => services.stringRowKey(item) === selectedKey) ?? null : null;
  const selectedContext = React.useMemo(() => {
    if (!selected) return null;
    const byteLength = selected.encoding === "UTF-16LE" ? selected.length * 2 : selected.length;
    if (!bytes.length) {
      return {
        start: selected.offset,
        end: selected.offset + byteLength,
        hex: "--",
        text: english ? "Select the source file again to view byte context." : "请重新选择源文件后查看字节上下文。"
      };
    }
    const start = Math.max(0, selected.offset - 64);
    const end = Math.min(bytes.length, selected.offset + byteLength + 64);
    const windowBytes = bytes.slice(start, end);
    return {
      start,
      end,
      hex: hexPreview(windowBytes, 256),
      text: previewText(windowBytes, 400).replace(/\s+/g, " ").trim() || "--"
    };
  }, [bytes, english, selected]);

  React.useEffect(() => {
    if (!text || sourceName !== "text input" || pendingBytes.length || bytes.length) return;
    const next = new TextEncoder().encode(text);
    setSourceSize(next.length);
    setPendingBytes(next);
  }, [bytes.length, pendingBytes.length, sourceName, text]);

  React.useEffect(() => {
    setPage(0);
  }, [encodingFilter, filter, appliedMinLength, typeFilter]);

  React.useEffect(() => {
    if (page >= pageCount) setPage(pageCount - 1);
  }, [page, pageCount]);

  React.useEffect(() => {
    if (selectedKey && !analysis.items.some((item) => services.stringRowKey(item) === selectedKey)) setSelectedKey("");
  }, [analysis.items, selectedKey, services]);

  const resetReview = () => {
    setFilter("");
    setTypeFilter("");
    setEncodingFilter("");
    setSelectedKey("");
    setPage(0);
  };

  const cancelAnalysis = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setAnalyzing(false);
  };

  const handleText = (value: string) => {
    fileReadRef.current += 1;
    cancelAnalysis();
    workspace.clear();
    setLoading(false);
    setError("");
    setStorageNotice("");
    setText(value);
    setSourceName("text input");
    const next = new TextEncoder().encode(value);
    setSourceSize(next.length);
    setPendingBytes(next);
    setBytes(new Uint8Array());
    setAnalysis(services.extractPrintableStrings(new Uint8Array(), minLength));
    resetReview();
  };

  const handleFile = async (file?: File) => {
    if (!file) return;
    cancelAnalysis();
    workspace.clear();
    const requestId = ++fileReadRef.current;
    setLoading(true);
    setError("");
    setDropActive(false);
    setStorageNotice(file.size > MAX_WORKSPACE_PREVIEW_BYTES
      ? (english ? "Only a 4 MiB preview is retained across refreshes; the complete source remains available during this session." : "刷新后仅保留 4 MiB 预览；完整源文件仅在本次打开期间可用。")
      : "");
    try {
      const nextBytes = new Uint8Array(await file.slice(0, 32 * 1024 * 1024).arrayBuffer());
      if (requestId !== fileReadRef.current) return;
      setSourceName(file.name);
      setSourceSize(file.size);
      setPendingBytes(nextBytes);
      setBytes(new Uint8Array());
      setAnalysis(services.extractPrintableStrings(new Uint8Array(), minLength));
      resetReview();
    } catch (caught) {
      if (requestId === fileReadRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (requestId === fileReadRef.current) setLoading(false);
    }
  };

  const clear = () => {
    fileReadRef.current += 1;
    cancelAnalysis();
    setLoading(false);
    setText("");
    setSourceName("text input");
    setSourceSize(0);
    setPendingBytes(new Uint8Array());
    setBytes(new Uint8Array());
    setAnalysis(services.extractPrintableStrings(new Uint8Array(), minLength));
    setError("");
    setStorageNotice("");
    workspace.clear();
    if (inputRef.current) inputRef.current.value = "";
    resetReview();
  };

  const analyze = async () => {
    if (!pendingBytes.length) return;
    cancelAnalysis();
    const controller = new AbortController();
    abortRef.current = controller;
    const nextBytes = pendingBytes.slice();
    const workerBytes = nextBytes.slice();
    const nextMinLength = minLength;
    setAnalyzing(true);
    setError("");
    try {
      const result = await runWorkerTask<{ bytes: Uint8Array; minLength: number }, StringsAnalysis>({
        createWorker: () => new Worker(new URL("../workers/strings.worker.ts", import.meta.url), { type: "module" }),
        request: { bytes: workerBytes, minLength: nextMinLength },
        transfer: [workerBytes.buffer],
        signal: controller.signal,
        timeoutMs: 60_000
      });
      if (controller.signal.aborted) return;
      setAppliedMinLength(nextMinLength);
      setBytes(nextBytes);
      setAnalysis(result);
      workspace.save({
        sourceName,
        sourceSize,
        appliedMinLength: nextMinLength,
        analysis: result,
        previewBytes: nextBytes.slice(0, MAX_WORKSPACE_PREVIEW_BYTES)
      });
      resetReview();
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setAnalyzing(false);
      }
    }
  };

  React.useEffect(() => () => abortRef.current?.abort(), []);
  React.useEffect(() => {
    if (active) return;
    fileReadRef.current += 1;
    cancelAnalysis();
    setLoading(false);
  }, [active]);

  const sourceLabel = sourceName === "text input" ? (english ? "Text input" : "文本输入") : sourceName;

  return (
    <div className={`tool-grid strings-simple-workbench strings-workbench ${hasInput ? "has-strings" : "empty-strings"}`}>
      {(loading || analyzing) && <div className="wide-panel"><ALinearProgress /></div>}
      {error && <pre className="result-box wide-panel">{error}</pre>}
      {storageNotice && <div className="tool-storage-note wide-panel" role="status">{storageNotice}</div>}

      <section className="tool-panel wide-panel strings-simple-source-panel">
        <ToolPanelHeader
          title={english ? "File or text" : "输入文件或文本"}
          actions={<AButton variant="text" disabled={!pendingBytes.length && !hasInput && !error && !loading} onClick={clear}>{t.clear}</AButton>}
        />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
        <div
          className={`desktop-drop-zone text-tool-drop-zone ${dropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); setDropActive(false); void handleFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{sourceName === "text input" ? t.dropFileTitle : sourceName}</strong>
          <span>{sourceName === "text input" ? t.dropFileHint : `${formatBytes(bytes.length)} / ${formatBytes(sourceSize)}`}</span>
        </div>

        <div className="strings-simple-source-controls">
          <label>{t.minLength}<AInputNumber min={3} max={64} value={minLength} onChange={(value) => setMinLength(Math.max(3, Math.min(64, value ?? 4)))} /></label>
          <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="filled" disabled={!pendingBytes.length || analyzing} onClick={analyze}>{analyzing ? (english ? "Extracting..." : "正在提取...") : (english ? "Extract strings" : "提取字符串")}</AButton>
        </div>
        <textarea
          className="single-textarea strings-simple-input"
          aria-label={english ? "File text for string extraction" : "需要提取字符串的文本"}
          value={sourceName === "text input" ? text : `${sourceName}\n${formatBytes(bytes.length)} ${english ? "loaded" : "已读取"}${sourceSize > bytes.length ? ` / ${formatBytes(sourceSize)}` : ""}`}
          readOnly={sourceName !== "text input"}
          placeholder={t.textPlaceholder}
          onChange={(event) => handleText(event.target.value)}
        />
      </section>

      {hasInput && (
        <section className="tool-panel wide-panel strings-simple-results-panel">
          <ToolPanelHeader
            title={t.fileStrings}
            subtitle={`${sourceLabel} · ${filteredItems.length.toLocaleString()} / ${analysis.items.length.toLocaleString()}`}
            actions={<>
              <AButton variant="outlined" disabled={!filteredItems.length} onClick={() => void copyText(filteredItems.map((item) => item.value).join("\n"))}>{t.copyOutput}</AButton>
              <AButton variant="text" disabled={!filteredItems.length} onClick={() => downloadTextFile(`strings-${Date.now()}.csv`, services.stringsToCsv(filteredItems), "text/csv;charset=utf-8")}>{t.exportStringsCsv}</AButton>
            </>}
          />

          <div className="strings-simple-summary" aria-label={english ? "Extraction summary" : "提取摘要"}>
            <span><small>{t.fileSize}</small><strong>{sourceSize > bytes.length ? `${formatBytes(bytes.length)} / ${formatBytes(sourceSize)}` : formatBytes(sourceSize)}</strong></span>
            <span><small>ASCII</small><strong>{analysis.items.filter((item) => item.encoding === "ASCII").length}</strong></span>
            <span><small>UTF-16LE</small><strong>{analysis.items.filter((item) => item.encoding === "UTF-16LE").length}</strong></span>
          </div>

          <div className="strings-simple-filters">
            <input className="text-input" aria-label={t.stringFilter} value={filter} onChange={(event) => setFilter(event.target.value)} placeholder={t.stringFilter} />
            <ASelect aria-label={english ? "String type" : "字符串类型"} value={typeFilter} onChange={(value) => setTypeFilter(String(value))} options={[{ value: "", label: t.regexTypeAll }, ...types.map((type) => ({ value: type, label: type }))]} />
            <ASelect aria-label={english ? "String encoding" : "字符串编码"} value={encodingFilter} onChange={(value) => setEncodingFilter(String(value))} options={[{ value: "", label: english ? "All encodings" : "全部编码" }, { value: "ASCII", label: "ASCII" }, { value: "UTF-16LE", label: "UTF-16LE" }]} />
          </div>

          {visibleItems.length ? (
            <div className="table-scroll strings-simple-table-scroll">
              <table className="data-table strings-simple-table">
                <thead><tr><th>{t.stringOffset}</th><th>{t.stringEncoding}</th><th>{t.stringLength}</th><th>{t.detectedType}</th><th>{t.stringValue}</th><th /></tr></thead>
                <tbody>
                  {visibleItems.map((item) => (
                    <tr className={selected && services.stringRowKey(item) === services.stringRowKey(selected) ? "selected-row" : ""} key={item.id} onClick={() => setSelectedKey(services.stringRowKey(item))}>
                      <td className="mono-cell">0x{item.offset.toString(16).toUpperCase()}</td>
                      <td>{item.encoding}</td>
                      <td>{item.length}</td>
                      <td>{item.detectedType}</td>
                      <td className="strings-simple-value">{item.value}</td>
                      <td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void copyText(item.value); }}>{t.copy}</AButton></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty-state">{english ? "No matching strings" : "没有匹配的字符串"}</div>}

          {filteredItems.length > PAGE_SIZE && (
            <div className="strings-simple-pagination">
              <AButton variant="outlined" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton>
              <span>{page + 1} / {pageCount}</span>
              <AButton variant="outlined" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton>
            </div>
          )}
        </section>
      )}

      {selected && selectedContext && (
        <section className="tool-panel wide-panel strings-simple-detail-panel">
          <ToolPanelHeader
            title={english ? "Selected string" : "当前字符串"}
            actions={<AButton variant="outlined" onClick={() => void copyText(selected.value)}>{t.copy}</AButton>}
          />
          <InfoTable rows={[
            [t.stringOffset, `0x${selected.offset.toString(16).toUpperCase()} / ${selected.offset}`],
            [t.stringEncoding, selected.encoding],
            [t.stringLength, String(selected.length)],
            [t.detectedType, selected.detectedType],
            [english ? "Context window" : "上下文范围", `0x${selectedContext.start.toString(16).toUpperCase()}-0x${selectedContext.end.toString(16).toUpperCase()}`]
          ]} />
          <pre className="result-box strings-simple-selected-value">{selected.value}</pre>
          <div className="strings-simple-context">
            <label>Hex<pre>{selectedContext.hex}</pre></label>
            <label>{english ? "Text" : "文本"}<pre>{selectedContext.text}</pre></label>
          </div>
        </section>
      )}
    </div>
  );
}

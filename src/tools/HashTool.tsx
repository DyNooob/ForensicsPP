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

import { copyText } from "../utils/clipboard";
import React from "react";
import { AButton, ACheckbox, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { BatchHashRow } from "../models";
import type { ExpectedHashTarget } from "../features/hash/matching";
import { downloadTextFile, formatBytes } from "../utils/files";
import { formatHashCase, normalizeHashAlgorithms, SM3_FILE_SIZE_LIMIT } from "../utils/hash";
import { hashBytesInWorker, hashFileInWorker } from "../features/hash/task";
import { useStoredState } from "../utils/storage";
import { useToolWorkspace } from "../utils/useToolWorkspace";

export type HashToolServices = {
  annotateBatchHashMatches: (rows: BatchHashRow[], expectedHash: string) => BatchHashRow[];
  parseExpectedHashSet: (value: string) => ExpectedHashTarget[];
};

const PAGE_SIZE = 100;
const ALGORITHMS = [
  { id: "md5", label: "MD5" },
  { id: "sha1", label: "SHA-1" },
  { id: "sha256", label: "SHA-256" },
  { id: "sha512", label: "SHA-512" },
  { id: "sha3", label: "SHA3-512" },
  { id: "sm3", label: "SM3" }
];

type HashWorkspace = {
  mode: "file" | "text";
  batchRows: BatchHashRow[];
  textHashes: Record<string, string> | null;
  resultAlgorithms: string[];
};

function isHashWorkspace(value: unknown): value is HashWorkspace {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<HashWorkspace>;
  return (candidate.mode === "file" || candidate.mode === "text")
    && Array.isArray(candidate.batchRows)
    && (candidate.textHashes === null || (Boolean(candidate.textHashes) && typeof candidate.textHashes === "object"))
    && Array.isArray(candidate.resultAlgorithms)
    && candidate.resultAlgorithms.every((item) => typeof item === "string");
}

function csvEscape(value: string | number) {
  const text = String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function rowsToCsv(rows: BatchHashRow[], algorithms: string[], hashCase: "lower" | "upper") {
  const headers = ["name", "size", "last_modified", "match", ...algorithms];
  const values = rows.map((row) => [
    row.name,
    row.size,
    row.lastModified ?? "",
    row.matched == null ? "" : row.matched ? "MATCH" : "NO MATCH",
    ...algorithms.map((algorithm) => {
      const digest = row[algorithm as keyof BatchHashRow];
      return typeof digest === "string" ? formatHashCase(digest, hashCase) : "";
    })
  ]);
  return [headers, ...values].map((row) => row.map(csvEscape).join(",")).join("\n");
}

export function HashTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: HashToolServices; active?: boolean }) {
  const { annotateBatchHashMatches, parseExpectedHashSet } = services;
  const english = t.waiting === "Waiting";
  const [text, setText] = useStoredState("hash.text.v2", "");
  const [mode, setMode] = useStoredState<"file" | "text">("hash.mode.v2", "file");
  const [hashCase, setHashCase] = useStoredState<"lower" | "upper">("hash.case", "lower");
  const [selectedAlgorithms, setSelectedAlgorithms] = useStoredState<string[]>("hash.algorithms", ["sha256"]);
  const [expectedHash, setExpectedHash] = useStoredState("hash.expectedHash.v2", "");
  const [batchRows, setBatchRows] = React.useState<BatchHashRow[]>([]);
  const [selectedFiles, setSelectedFiles] = React.useState<File[]>([]);
  const [textHashes, setTextHashes] = React.useState<Record<string, string> | null>(null);
  const [resultAlgorithms, setResultAlgorithms] = React.useState<string[]>([]);
  const [filter, setFilter] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [isHashing, setIsHashing] = React.useState(false);
  const [error, setError] = React.useState("");
  const [progress, setProgress] = React.useState({ done: 0, total: 0, name: "" });
  const [dragActive, setDragActive] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const directoryInputRef = React.useRef<HTMLInputElement | null>(null);
  const lastFilesRef = React.useRef<File[]>([]);
  const abortRef = React.useRef<AbortController | null>(null);
  const textRunRef = React.useRef(0);
  const directoryInputProps = { webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement> & Record<string, string>;
  const algorithms = React.useMemo(() => normalizeHashAlgorithms(selectedAlgorithms), [selectedAlgorithms]);
  const workspace = useToolWorkspace<HashWorkspace>({
    id: "hash.v1",
    version: 1,
    isValid: isHashWorkspace,
    onRestore: (value) => {
      setMode(value.mode);
      setBatchRows(value.batchRows);
      setTextHashes(value.textHashes);
      setResultAlgorithms(value.resultAlgorithms);
      setSelectedFiles([]);
    }
  });
  const expectedTargets = React.useMemo(() => parseExpectedHashSet(expectedHash), [expectedHash, parseExpectedHashSet]);
  const evaluatedRows = React.useMemo(() => annotateBatchHashMatches(batchRows, expectedHash), [annotateBatchHashMatches, batchRows, expectedHash]);
  const filteredRows = React.useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return needle ? evaluatedRows.filter((row) => row.name.toLowerCase().includes(needle)) : evaluatedRows;
  }, [evaluatedRows, filter]);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const visibleRows = React.useMemo(() => filteredRows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), [filteredRows, page]);
  const displayedTextHashes = React.useMemo(() => textHashes
    ? resultAlgorithms.map((algorithm) => [ALGORITHMS.find((item) => item.id === algorithm)?.label ?? algorithm.toUpperCase(), textHashes[algorithm] ? formatHashCase(textHashes[algorithm], hashCase) : "--"] as [string, string])
    : [], [hashCase, resultAlgorithms, textHashes]);
  const textMatched = React.useMemo(() => {
    if (!textHashes || !expectedTargets.length) return null;
    const values = new Set(Object.values(textHashes).map((value) => value.toLowerCase()));
    return expectedTargets.some((target) => values.has(target.hash.toLowerCase()));
  }, [expectedTargets, textHashes]);
  const matchedFiles = evaluatedRows.filter((row) => row.matched).length;
  const selectedFileBytes = React.useMemo(() => selectedFiles.reduce((total, file) => total + file.size, 0), [selectedFiles]);
  const hasInput = Boolean(selectedFiles.length || batchRows.length || text.trim() || textHashes || expectedHash.trim() || isHashing || error);

  React.useEffect(() => {
    setPage(0);
  }, [filter]);

  React.useEffect(() => {
    if (page >= pageCount) setPage(pageCount - 1);
  }, [page, pageCount]);

  React.useEffect(() => () => abortRef.current?.abort(), []);

  React.useEffect(() => {
    if (active) return;
    abortRef.current?.abort();
    abortRef.current = null;
    textRunRef.current += 1;
    setIsHashing(false);
    setProgress({ done: 0, total: 0, name: "" });
  }, [active]);

  const queueFiles = (files: FileList | File[] | null | undefined) => {
    if (!active) return;
    const fileArray = Array.from(files ?? []);
    if (!fileArray.length) return;
    abortRef.current?.abort();
    textRunRef.current += 1;
    lastFilesRef.current = fileArray;
    setSelectedFiles(fileArray);
    setMode("file");
    setBatchRows([]);
    workspace.clear();
    setFilter("");
    setPage(0);
    setError("");
    setProgress({ done: 0, total: fileArray.length, name: "" });
  };

  const hashFiles = async (files: File[] = lastFilesRef.current, selected = algorithms) => {
    if (!active) return;
    const fileArray = Array.from(files);
    if (!fileArray.length) return;
    abortRef.current?.abort();
    const runId = ++textRunRef.current;
    const controller = new AbortController();
    abortRef.current = controller;
    setIsHashing(true);
    setError("");
    setBatchRows([]);
    setFilter("");
    setPage(0);
    const totalBytes = fileArray.reduce((total, file) => total + file.size, 0);
    setProgress({ done: 0, total: totalBytes, name: fileArray[0]?.name ?? "" });
    const rows: BatchHashRow[] = [];
    let completedBytes = 0;
    try {
      for (const [index, file] of fileArray.entries()) {
        const name = file.webkitRelativePath || file.name;
        if (controller.signal.aborted) throw new DOMException("Hash calculation cancelled", "AbortError");
        setProgress({ done: completedBytes, total: totalBytes, name });
        await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
        const digests = await hashFileInWorker(file, selected, { signal: controller.signal, onProgress: ({ loaded }) => {
          if (runId === textRunRef.current) setProgress({ done: completedBytes + loaded, total: totalBytes, name });
        } });
        if (!active || controller.signal.aborted || runId !== textRunRef.current) return;
        rows.push({
          index: index + 1,
          name,
          size: file.size,
          lastModified: Number.isFinite(file.lastModified) ? new Date(file.lastModified).toISOString() : "",
          ...digests
        });
        completedBytes += file.size;
      }
      if (!active || controller.signal.aborted || runId !== textRunRef.current) return;
      setBatchRows(rows);
      setResultAlgorithms(selected);
      workspace.save({ mode: "file", batchRows: rows, textHashes: null, resultAlgorithms: selected });
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      if (!active || runId !== textRunRef.current) return;
      if (caught instanceof RangeError && caught.message.startsWith("SM3_FILE_TOO_LARGE:")) {
        setError(english
          ? `SM3 is limited to files up to ${formatBytes(SM3_FILE_SIZE_LIMIT)}. Deselect SM3 to hash larger files.`
          : `SM3 仅支持不超过 ${formatBytes(SM3_FILE_SIZE_LIMIT)} 的文件。取消勾选 SM3 后可计算更大的文件。`);
      } else {
        setError(caught instanceof Error ? caught.message : String(caught));
      }
      setBatchRows(rows);
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setIsHashing(false);
        setProgress({ done: completedBytes, total: totalBytes, name: "" });
      }
    }
  };

  const hashText = async () => {
    if (!text || !active) return;
    abortRef.current?.abort();
    const runId = ++textRunRef.current;
    const controller = new AbortController();
    abortRef.current = controller;
    setError("");
    setIsHashing(true);
    try {
      const bytes = new TextEncoder().encode(text);
      const values = await hashBytesInWorker(bytes, algorithms, { signal: controller.signal });
      if (!active || controller.signal.aborted || runId !== textRunRef.current) return;
      setTextHashes(Object.fromEntries(Object.entries(values).filter((entry): entry is [string, string] => Boolean(entry[1]))));
      setResultAlgorithms(algorithms);
      workspace.save({
        mode: "text",
        batchRows: [],
        textHashes: Object.fromEntries(Object.entries(values).filter((entry): entry is [string, string] => Boolean(entry[1]))),
        resultAlgorithms: algorithms
      });
    } catch (caught) {
      if (active && runId === textRunRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      if (runId === textRunRef.current) setIsHashing(false);
    }
  };

  const cancelHashing = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    textRunRef.current += 1;
    setIsHashing(false);
    setProgress({ done: 0, total: 0, name: "" });
  };

  const toggleAlgorithm = (algorithm: string) => {
    abortRef.current?.abort();
    abortRef.current = null;
    textRunRef.current += 1;
    setIsHashing(false);
    setProgress({ done: 0, total: 0, name: "" });
    const next = algorithms.includes(algorithm)
      ? algorithms.filter((item) => item !== algorithm)
      : [...algorithms, algorithm];
    if (!next.length) return;
    setSelectedAlgorithms(next);
  };

  const handleTextChange = (value: string) => {
    abortRef.current?.abort();
    abortRef.current = null;
    textRunRef.current += 1;
    setIsHashing(false);
    setProgress({ done: 0, total: 0, name: "" });
    workspace.clear();
    setText(value);
    setTextHashes(null);
    setResultAlgorithms([]);
  };

  const clear = () => {
    cancelHashing();
    if (fileInputRef.current) fileInputRef.current.value = "";
    if (directoryInputRef.current) directoryInputRef.current.value = "";
    lastFilesRef.current = [];
    setSelectedFiles([]);
    setText("");
    setBatchRows([]);
    setTextHashes(null);
    setResultAlgorithms([]);
    setExpectedHash("");
    setFilter("");
    setPage(0);
    setError("");
    setProgress({ done: 0, total: 0, name: "" });
    workspace.clear();
  };

  const rangeStart = filteredRows.length ? page * PAGE_SIZE + 1 : 0;
  const rangeEnd = Math.min((page + 1) * PAGE_SIZE, filteredRows.length);

  return (
    <div className={`tool-grid hash-simple-workbench hash-workbench ${hasInput ? "has-hash" : "empty-hash"}`}>
      <div className="tool-panel wide-panel hash-simple-input-panel">
        <ToolPanelHeader
          title={english ? "Hash input" : "哈希输入"}
          actions={<>
            <ASegmentedGroup className="hash-simple-mode" value={mode} selects="single">
              <ASegmentedButton value="file" onClick={() => setMode("file")}>{english ? "Files" : "文件"}</ASegmentedButton>
              <ASegmentedButton value="text" onClick={() => setMode("text")}>{english ? "Text" : "文本"}</ASegmentedButton>
            </ASegmentedGroup>
            <AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />
        <input className="hidden-file-input" ref={fileInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { queueFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        <input className="hidden-file-input" ref={directoryInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} {...directoryInputProps} onChange={(event) => { queueFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />

        {mode === "file" ? (
          <>
            <div
              className={`desktop-drop-zone hash-simple-drop-zone ${dragActive ? "active" : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => fileInputRef.current?.click()}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  fileInputRef.current?.click();
                }
              }}
              onDragOver={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragActive(false);
                queueFiles(event.dataTransfer.files);
              }}
            >
              <strong>{selectedFiles.length
                ? (english ? `${selectedFiles.length} files selected` : `已选择 ${selectedFiles.length} 个文件`)
                : batchRows.length
                  ? (english ? `${batchRows.length} calculated results restored` : `已恢复 ${batchRows.length} 条计算结果`)
                  : (english ? "Select or drop files" : "选择或拖入文件")}</strong>
              <span>{selectedFiles.length
                ? formatBytes(selectedFileBytes)
                : batchRows.length
                  ? (english ? "Re-select files to calculate again" : "重新选择文件可再次计算")
                  : (english ? "Multiple files are supported" : "支持一次选择多个文件")}</span>
            </div>
            <div className="button-row">
              <AButton variant="outlined" onClick={() => fileInputRef.current?.click()}>{english ? "Select files" : "选择文件"}</AButton>
              <AButton variant="text" onClick={() => directoryInputRef.current?.click()}>{english ? "Select folder" : "选择文件夹"}</AButton>
            </div>
          </>
        ) : (
          <label className="stack-label">
            {english ? "Text" : "文本"}
            <textarea className="single-textarea hash-simple-text-input" value={text} onChange={(event) => handleTextChange(event.currentTarget.value)} placeholder={english ? "Enter text to hash" : "输入要计算哈希的文本"} />
          </label>
        )}

        <div className="hash-simple-options">
          <div className="hash-simple-option-block">
            <span>{t.algorithms}</span>
            <div className="hash-simple-algorithms">
              {ALGORITHMS.map((algorithm) => (
                <ACheckbox className="checkbox-line" key={algorithm.id} checked={algorithms.includes(algorithm.id)} onChange={() => toggleAlgorithm(algorithm.id)}>{algorithm.label}</ACheckbox>
              ))}
            </div>
          </div>
          <div className="hash-simple-case-row">
            <span>{english ? "Output case" : "输出大小写"}</span>
            <ASegmentedGroup value={hashCase} selects="single">
              <ASegmentedButton value="lower" onClick={() => setHashCase("lower")}>{english ? "Lowercase" : "小写"}</ASegmentedButton>
              <ASegmentedButton value="upper" onClick={() => setHashCase("upper")}>{english ? "Uppercase" : "大写"}</ASegmentedButton>
            </ASegmentedGroup>
          </div>
        </div>

        <label className="stack-label">
          {t.expectedHash}
          <textarea className="compact-textarea hash-simple-expected" value={expectedHash} onChange={(event) => setExpectedHash(event.currentTarget.value)} placeholder={t.expectedHashHint} />
        </label>

        <div className="button-row">
          {mode === "text" && <AButton variant="filled" disabled={!text || isHashing} onClick={() => void hashText()}>{english ? "Calculate" : "计算哈希"}</AButton>}
          {mode === "file" && <AButton variant="filled" disabled={!selectedFiles.length || isHashing} onClick={() => void hashFiles()}>{english ? "Calculate hashes" : "计算哈希"}</AButton>}
          {isHashing && <AButton variant="outlined" onClick={cancelHashing}>{english ? "Cancel" : "取消"}</AButton>}
        </div>
        {isHashing && <div className="hash-simple-progress"><progress max={Math.max(1, progress.total)} value={progress.done} /><span>{progress.name || (english ? "Calculating..." : "正在计算...")}{progress.total > 0 ? ` · ${formatBytes(progress.done)} / ${formatBytes(progress.total)}` : ""}</span></div>}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {mode === "text" && textHashes && (
        <div className="tool-panel wide-panel hash-simple-text-result">
          <ToolPanelHeader
            title={english ? "Text hash" : "文本哈希"}
            subtitle={expectedTargets.length ? (textMatched ? "MATCH" : "NO MATCH") : `${text.length.toLocaleString()} ${english ? "characters" : "个字符"}`}
            actions={<AButton variant="text" onClick={() => void copyText(displayedTextHashes.map(([label, value]) => `${label}: ${value}`).join("\n"))}>{t.copy}</AButton>}
          />
          <InfoTable rows={displayedTextHashes} />
        </div>
      )}

      {mode === "file" && evaluatedRows.length > 0 && (
        <div className="tool-panel wide-panel hash-simple-results-panel hash-file-browser-panel">
          <ToolPanelHeader
            title={english ? "File hashes" : "文件哈希"}
            subtitle={`${evaluatedRows.length} ${english ? "files" : "个文件"}${expectedTargets.length ? ` · ${matchedFiles} MATCH` : ""}`}
            actions={<>
              <AButton variant="outlined" onClick={() => downloadTextFile(`hashes-${Date.now()}.csv`, rowsToCsv(filteredRows, resultAlgorithms, hashCase), "text/csv;charset=utf-8")}>{english ? "Export CSV" : "导出 CSV"}</AButton>
              {resultAlgorithms.includes("sha256") && <AButton variant="text" onClick={() => downloadTextFile(`hashes-${Date.now()}.sha256`, filteredRows.map((row) => `${row.sha256 ? formatHashCase(row.sha256, hashCase) : ""}  ${row.name}`).join("\n"), "text/plain;charset=utf-8")}>SHA256SUM</AButton>}
            </>}
          />
          <div className="hash-simple-result-toolbar">
            <input className="text-input" aria-label={english ? "Filter hashed files" : "筛选已计算哈希的文件"} value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter file name" : "过滤文件名"} />
            <span>{filteredRows.length}/{evaluatedRows.length}</span>
          </div>
          <div className="table-scroll hash-simple-scroll">
            <table className="data-table hash-simple-table">
              <thead><tr><th>{english ? "File" : "文件"}</th><th>{t.fileSize}</th><th>{t.lastModified}</th>{expectedTargets.length > 0 && <th>{english ? "Verification" : "核验"}</th>}{resultAlgorithms.map((algorithm) => <th key={algorithm}>{ALGORITHMS.find((item) => item.id === algorithm)?.label ?? algorithm.toUpperCase()}</th>)}</tr></thead>
              <tbody>{visibleRows.map((row) => <tr key={`${row.index}-${row.name}-${row.size}`}><td>{row.name}</td><td>{formatBytes(row.size)}</td><td>{row.lastModified || "--"}</td>{expectedTargets.length > 0 && <td>{row.matched ? "MATCH" : "NO MATCH"}</td>}{resultAlgorithms.map((algorithm) => {
                const digest = row[algorithm as keyof BatchHashRow];
                const displayed = typeof digest === "string" ? formatHashCase(digest, hashCase) : "--";
                return <td key={algorithm}>{displayed === "--" ? displayed : <button className="hash-simple-digest" type="button" title={english ? "Copy digest" : "复制哈希"} onClick={() => void copyText(displayed)}>{displayed}</button>}</td>;
              })}</tr>)}</tbody>
            </table>
          </div>
          {filteredRows.length > PAGE_SIZE && <div className="hash-simple-pagination"><span>{rangeStart}-{rangeEnd} / {filteredRows.length}</span><div className="button-row compact-buttons"><AButton variant="text" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))}>{english ? "Previous" : "上一页"}</AButton><AButton variant="text" disabled={page + 1 >= pageCount} onClick={() => setPage((current) => Math.min(pageCount - 1, current + 1))}>{english ? "Next" : "下一页"}</AButton></div></div>}
        </div>
      )}
    </div>
  );
}

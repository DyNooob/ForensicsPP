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
import { AButton, ALinearProgress, ASelect, InfoTable, ToolPanelHeader } from "../components/ui";
import { analyzeIocs, iocRecordsToStixBundle } from "../features/ioc/analyzer";
import { copy } from "../i18n";
import type { IocAnalysis, IocRecord } from "../models";
import { downloadTextFile, formatBytes } from "../utils/files";

const PAGE_SIZE = 200;

function recordsToCsv(records: IocRecord[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return [
    ["type", "value", "normalized", "defanged", "first_line", "lines", "count", "context"].join(","),
    ...records.map((record) => [
      record.type,
      record.value,
      record.normalized,
      record.defanged,
      record.line,
      record.lines.join(";"),
      record.count,
      record.context
    ].map(escape).join(","))
  ].join("\n");
}

function serializableRecords(records: IocRecord[]) {
  return records.map((record) => ({
    type: record.type,
    value: record.value,
    normalized: record.normalized,
    defanged: record.defanged,
    firstLine: record.line,
    lines: record.lines,
    count: record.count,
    contexts: record.contexts
  }));
}

export function IocTool({ t }: { t: (typeof copy)["zh"] }) {
  const english = t.waiting === "Waiting";
  const [text, setText] = React.useState("");
  const [source, setSource] = React.useState("pasted text");
  const [analyzedText, setAnalyzedText] = React.useState("");
  const [analyzedSource, setAnalyzedSource] = React.useState("pasted text");
  const [filter, setFilter] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("");
  const [selectedId, setSelectedId] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [dropActive, setDropActive] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [analyzing, setAnalyzing] = React.useState(false);
  const [error, setError] = React.useState("");
  const [sourceSize, setSourceSize] = React.useState(() => new TextEncoder().encode(text).length);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const workerRef = React.useRef<Worker | null>(null);
  const requestRef = React.useRef(0);
  const hasInput = analyzedText.trim().length > 0;
  const [analysis, setAnalysis] = React.useState<IocAnalysis>(() => analyzeIocs("", "pasted text"));
  const types = React.useMemo(() => Object.keys(analysis.grouped).sort(), [analysis.grouped]);
  const filteredRecords = React.useMemo(() => {
    const query = filter.trim().toLowerCase();
    return analysis.records.filter((record) => {
      if (typeFilter && record.type !== typeFilter) return false;
      if (!query) return true;
      return [record.type, record.value, record.normalized, record.defanged, record.lines.join(" "), record.context]
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [analysis.records, filter, typeFilter]);
  const pageCount = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const visibleRecords = filteredRecords.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selected = selectedId ? analysis.records.find((record) => record.id === selectedId) ?? null : null;
  const totalSightings = analysis.records.reduce((sum, record) => sum + record.count, 0);

  React.useEffect(() => {
    setPage(0);
  }, [filter, typeFilter]);

  React.useEffect(() => {
    if (page >= pageCount) setPage(pageCount - 1);
  }, [page, pageCount]);

  React.useEffect(() => {
    if (selectedId && !analysis.records.some((record) => record.id === selectedId)) setSelectedId("");
  }, [analysis.records, selectedId]);

  const resetReview = () => {
    setFilter("");
    setTypeFilter("");
    setSelectedId("");
    setPage(0);
  };

  const handleText = (value: string) => {
    setText(value);
    setSource("pasted text");
    setSourceSize(new TextEncoder().encode(value).length);
    setAnalyzedText("");
    resetReview();
  };

  const handleFile = async (file?: File) => {
    if (!file) return;
    setLoading(true);
    setDropActive(false);
    try {
      const value = await file.slice(0, 32 * 1024 * 1024).text();
      setSource(file.name);
      setSourceSize(file.size);
      setText(value);
      setAnalyzedText("");
      resetReview();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setText("");
    setSource("pasted text");
    setSourceSize(0);
    setAnalyzedText("");
    setAnalyzedSource("pasted text");
    setAnalysis(analyzeIocs("", "pasted text"));
    setError("");
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
    resetReview();
  };

  const analyze = () => {
    if (!text.trim() || analyzing) return;
    if (new TextEncoder().encode(text).length > 16 * 1024 * 1024) {
      setError(english ? "IOC text exceeds the 16 MiB analysis limit." : "IOC 文本超过 16 MiB 分析上限。");
      return;
    }
    workerRef.current?.terminate();
    const requestId = ++requestRef.current;
    const worker = new Worker(new URL("../workers/ioc.worker.ts", import.meta.url), { type: "module" });
    workerRef.current = worker;
    setAnalyzing(true);
    setError("");
    worker.onmessage = (event: MessageEvent<{ id: number; analysis?: IocAnalysis; error?: string }>) => {
      if (event.data.id !== requestId) return;
      worker.terminate();
      workerRef.current = null;
      setAnalyzing(false);
      if (event.data.error || !event.data.analysis) {
        setError(event.data.error || (english ? "IOC extraction failed." : "IOC 提取失败。"));
        return;
      }
      setAnalyzedText(text);
      setAnalyzedSource(source);
      setAnalysis(event.data.analysis);
      resetReview();
    };
    worker.onerror = (event) => {
      if (requestId !== requestRef.current) return;
      worker.terminate();
      workerRef.current = null;
      setAnalyzing(false);
      setError(event.message || (english ? "IOC worker failed." : "IOC 提取任务失败。"));
    };
    worker.postMessage({ id: requestId, text, source });
  };

  React.useEffect(() => () => workerRef.current?.terminate(), []);

  const exportJson = () => downloadTextFile(
    `ioc-${Date.now()}.json`,
    JSON.stringify({ source: analyzedSource, generatedAt: new Date().toISOString(), records: serializableRecords(filteredRecords) }, null, 2),
    "application/json;charset=utf-8"
  );

  return (
    <div className={`tool-grid ioc-simple-workbench ioc-workbench ${hasInput ? "has-ioc" : "empty-ioc"}`}>
      {(loading || analyzing) && <div className="wide-panel"><ALinearProgress /></div>}
      {error && <div className="empty-state error-state wide-panel">{error}</div>}

      <section className="tool-panel wide-panel ioc-simple-source-panel">
        <ToolPanelHeader
          title={english ? "Input" : "输入文本"}
          actions={<AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>}
        />
        <input className="hidden-file-input" ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".log,.txt,.csv,.json,text/*,application/json" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
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
          onDrop={(event) => { event.preventDefault(); void handleFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{source === "pasted text" ? t.dropFileTitle : source}</strong>
          <span>{source === "pasted text" ? t.dropFileHint : `${formatBytes(Math.min(sourceSize, 32 * 1024 * 1024))} / ${formatBytes(sourceSize)}`}</span>
        </div>
        <div className="ioc-simple-source-actions">
          <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.uploadIocText}</AButton>
          <AButton variant="filled" disabled={!text.trim() || analyzing} onClick={analyze}>{analyzing ? (english ? "Extracting..." : "正在提取...") : (english ? "Extract indicators" : "提取 IOC")}</AButton>
        </div>
        <textarea className="single-textarea ioc-simple-input" aria-label={english ? "Text to scan for IOCs" : "需要提取 IOC 的文本"} value={text} onChange={(event) => handleText(event.target.value)} placeholder={t.textPlaceholder} />
      </section>

      {hasInput && (
        <section className="tool-panel wide-panel ioc-simple-results-panel">
          <ToolPanelHeader
            title={t.indicators}
            subtitle={`${filteredRecords.length.toLocaleString()} / ${analysis.records.length.toLocaleString()}`}
            actions={<>
              <AButton variant="outlined" disabled={!filteredRecords.length} onClick={() => void navigator.clipboard.writeText(filteredRecords.map((record) => record.normalized).join("\n"))}>{t.iocCopyNormalized}</AButton>
              <AButton variant="text" disabled={!filteredRecords.length} onClick={() => void navigator.clipboard.writeText(filteredRecords.map((record) => record.defanged).join("\n"))}>{t.defangedUrl}</AButton>
            </>}
          />

          <div className="ioc-simple-summary">
            <span><small>{english ? "Unique indicators" : "唯一 IOC"}</small><strong>{analysis.records.length}</strong></span>
            <span><small>{english ? "Sightings" : "出现次数"}</small><strong>{totalSightings}</strong></span>
            <span><small>{english ? "Types" : "类型"}</small><strong>{types.length}</strong></span>
            <span><small>{english ? "Source" : "来源"}</small><strong>{analyzedSource}</strong></span>
          </div>

          <div className="ioc-simple-toolbar">
            <div className="ioc-simple-filters">
              <input className="text-input" aria-label={t.iocFilter} value={filter} onChange={(event) => setFilter(event.target.value)} placeholder={t.iocFilter} />
              <ASelect aria-label={english ? "IOC type" : "IOC 类型"} value={typeFilter} onChange={(value) => setTypeFilter(String(value))} options={[{ value: "", label: t.regexTypeAll }, ...types.map((type) => ({ value: type, label: type }))]} />
            </div>
            <div className="button-row compact-buttons">
              <AButton variant="outlined" disabled={!filteredRecords.length} onClick={() => downloadTextFile(`ioc-${Date.now()}.csv`, recordsToCsv(filteredRecords), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              <AButton variant="text" disabled={!filteredRecords.length} onClick={exportJson}>{t.exportJson}</AButton>
              <AButton variant="text" disabled={!filteredRecords.length} onClick={() => downloadTextFile(`ioc-stix-${Date.now()}.json`, iocRecordsToStixBundle(filteredRecords, analyzedSource), "application/json;charset=utf-8")}>{t.iocExportStix}</AButton>
            </div>
          </div>

          {visibleRecords.length ? (
            <div className="table-scroll ioc-simple-table-scroll">
              <table className="data-table ioc-simple-table">
                <thead><tr><th>{t.detectedType}</th><th>{t.iocNormalized}</th><th>{t.iocCount}</th><th>{t.iocLine}</th><th>Defanged</th><th /></tr></thead>
                <tbody>
                  {visibleRecords.map((record) => (
                    <tr className={selected?.id === record.id ? "selected-row" : ""} key={record.id} onClick={() => setSelectedId(record.id)}>
                      <td>{record.type}</td>
                      <td className="mono-cell ioc-simple-value">{record.normalized}</td>
                      <td>{record.count}</td>
                      <td>{record.lines.join(", ")}</td>
                      <td className="mono-cell ioc-simple-value">{record.defanged}</td>
                      <td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void navigator.clipboard.writeText(record.normalized); }}>{t.copy}</AButton></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty-state">{english ? "No matching indicators" : "没有匹配的 IOC"}</div>}

          {filteredRecords.length > PAGE_SIZE && (
            <div className="ioc-simple-pagination">
              <AButton variant="outlined" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton>
              <span>{page + 1} / {pageCount}</span>
              <AButton variant="outlined" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton>
            </div>
          )}
        </section>
      )}

      {selected && (
        <section className="tool-panel wide-panel ioc-simple-detail-panel">
          <ToolPanelHeader
            title={english ? "Selected indicator" : "当前 IOC"}
            actions={<>
              <AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(selected.normalized)}>{t.copy}</AButton>
              <AButton variant="text" onClick={() => void navigator.clipboard.writeText(selected.defanged)}>{t.defangedUrl}</AButton>
            </>}
          />
          <InfoTable rows={[
            [t.detectedType, selected.type],
            [t.sampleValue, selected.value],
            [t.iocNormalized, selected.normalized],
            [t.defangedUrl, selected.defanged],
            [t.iocCount, String(selected.count)],
            [t.iocLine, selected.lines.join(", ") || "--"]
          ]} />
          <label className="ioc-simple-context">
            <span>{t.iocContext}</span>
            <textarea className="single-textarea compact-textarea" value={selected.contexts.join("\n---\n") || selected.context || selected.value} readOnly />
          </label>
        </section>
      )}
    </div>
  );
}

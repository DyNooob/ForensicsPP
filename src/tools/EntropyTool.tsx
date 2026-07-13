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
import { AButton, AInputNumber, ALinearProgress, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { EntropyAnalysis, EntropyBlock, EntropyRange } from "../models";
import { hexPreview, previewText } from "../utils/binary";
import { downloadTextFile, formatBytes } from "../utils/files";
import { useStoredState } from "../utils/storage";
import { runWorkerTask } from "../utils/workerTask";

export type EntropyToolServices = {
  analyzeEntropy: (bytes: Uint8Array, blockSize?: number) => EntropyAnalysis;
  entropyBlockKey: (block: EntropyBlock) => string;
  entropyBlocksToCsv: (blocks: EntropyBlock[]) => string;
  entropyRangesToCsv: (ranges: EntropyRange[]) => string;
};

const PAGE_SIZE = 200;

export function EntropyTool({ t, services }: { t: (typeof copy)["zh"]; services: EntropyToolServices }) {
  const english = t.waiting === "Waiting";
  const [text, setText] = React.useState("");
  const [sourceName, setSourceName] = React.useState("text input");
  const [bytes, setBytes] = React.useState<Uint8Array>(() => new TextEncoder().encode(text));
  const [sourceSize, setSourceSize] = React.useState(() => new TextEncoder().encode(text).length);
  const [blockSize, setBlockSize] = useStoredState("entropy.blockSize", 1024);
  const [view, setView] = React.useState<"blocks" | "ranges">("ranges");
  const [showDetails, setShowDetails] = React.useState(false);
  const [classFilter, setClassFilter] = React.useState("");
  const [selectedKey, setSelectedKey] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [dropActive, setDropActive] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [analyzing, setAnalyzing] = React.useState(false);
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const effectiveBlockSize = Math.max(64, Number(blockSize) || 1024);
  const hasInput = bytes.length > 0;
  const [analysis, setAnalysis] = React.useState<EntropyAnalysis>(() => services.analyzeEntropy(bytes, effectiveBlockSize));

  React.useEffect(() => {
    if (!bytes.length || bytes.length < 1024 * 1024 || typeof Worker === "undefined") {
      setAnalysis(services.analyzeEntropy(bytes, effectiveBlockSize));
      setAnalyzing(false);
      return;
    }
    const controller = new AbortController();
    setAnalyzing(true);
    setError("");
    const workerBytes = bytes.slice();
    void runWorkerTask<{ bytes: Uint8Array; blockSize: number }, EntropyAnalysis>({
      createWorker: () => new Worker(new URL("../workers/entropy.worker.ts", import.meta.url), { type: "module" }),
      request: { bytes: workerBytes, blockSize: effectiveBlockSize },
      transfer: [workerBytes.buffer],
      signal: controller.signal,
      timeoutMs: 60_000
    }).then((result) => {
      if (!controller.signal.aborted) setAnalysis(result);
    }).catch((caught) => {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    }).finally(() => {
      if (!controller.signal.aborted) setAnalyzing(false);
    });
    return () => controller.abort();
  }, [bytes, effectiveBlockSize, services]);

  const classes = React.useMemo(() => analysis.classRows.map(([label]) => label), [analysis.classRows]);
  const filteredBlocks = React.useMemo(
    () => analysis.blocks.filter((block) => !classFilter || block.classification === classFilter),
    [analysis.blocks, classFilter]
  );
  const itemCount = view === "blocks" ? filteredBlocks.length : analysis.ranges.length;
  const pageCount = Math.max(1, Math.ceil(itemCount / PAGE_SIZE));
  const visibleBlocks = filteredBlocks.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const visibleRanges = analysis.ranges.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selected = selectedKey ? analysis.blocks.find((block) => services.entropyBlockKey(block) === selectedKey) ?? null : null;
  const selectedContext = React.useMemo(() => {
    if (!selected) return null;
    const start = Math.max(0, selected.offset - 96);
    const end = Math.min(bytes.length, selected.endOffset + 96);
    const windowBytes = bytes.slice(start, end);
    return {
      start,
      end,
      hex: hexPreview(windowBytes, 256),
      text: previewText(windowBytes, 400).replace(/\s+/g, " ").trim() || "--"
    };
  }, [bytes, selected]);
  const overallEntropy = analysis.rows.find(([label]) => label === "Entropy")?.[1] ?? "0.0000 / 8";

  React.useEffect(() => {
    setPage(0);
  }, [classFilter, effectiveBlockSize, view]);

  React.useEffect(() => {
    if (page >= pageCount) setPage(pageCount - 1);
  }, [page, pageCount]);

  React.useEffect(() => {
    if (selectedKey && !analysis.blocks.some((block) => services.entropyBlockKey(block) === selectedKey)) setSelectedKey("");
  }, [analysis.blocks, selectedKey, services]);

  const resetReview = () => {
    setClassFilter("");
    setSelectedKey("");
    setPage(0);
    setView("ranges");
    setShowDetails(false);
  };

  const handleText = (value: string) => {
    setText(value);
    setSourceName("text input");
    const next = new TextEncoder().encode(value);
    setSourceSize(next.length);
    setBytes(next);
    resetReview();
  };

  const handleFile = async (file?: File) => {
    if (!file) return;
    setLoading(true);
    setError("");
    setDropActive(false);
    try {
      setSourceName(file.name);
      setSourceSize(file.size);
      setBytes(new Uint8Array(await file.slice(0, 64 * 1024 * 1024).arrayBuffer()));
      resetReview();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setText("");
    setSourceName("text input");
    setSourceSize(0);
    setBytes(new Uint8Array());
    setError("");
    if (inputRef.current) inputRef.current.value = "";
    resetReview();
  };

  return (
    <div className={`tool-grid entropy-simple-workbench entropy-workbench ${hasInput ? "has-entropy" : "empty-entropy"}`}>
      {(loading || analyzing) && <div className="wide-panel"><ALinearProgress /></div>}
      {error && <pre className="result-box wide-panel">{error}</pre>}

      <section className="tool-panel wide-panel entropy-simple-source-panel">
        <ToolPanelHeader
          title={english ? "File or text" : "输入文件或文本"}
          actions={<AButton variant="text" disabled={!hasInput && !loading} onClick={clear}>{t.clear}</AButton>}
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
          onDrop={(event) => { event.preventDefault(); void handleFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{sourceName === "text input" ? t.dropFileTitle : sourceName}</strong>
          <span>{sourceName === "text input" ? t.dropFileHint : `${formatBytes(bytes.length)} / ${formatBytes(sourceSize)}`}</span>
        </div>
        <div className="entropy-simple-source-controls">
          <label>{t.blockSize}<AInputNumber min={64} max={1048576} step={64} value={blockSize} onChange={(value) => setBlockSize(Math.max(64, value ?? 1024))} /></label>
          <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
        </div>
        <textarea
          className="single-textarea entropy-simple-input"
          aria-label={english ? "Text for entropy analysis" : "需要计算熵值的文本"}
          value={sourceName === "text input" ? text : `${sourceName}\n${formatBytes(bytes.length)} ${english ? "loaded" : "已读取"}${sourceSize > bytes.length ? ` / ${formatBytes(sourceSize)}` : ""}`}
          readOnly={sourceName !== "text input"}
          placeholder={t.textPlaceholder}
          onChange={(event) => handleText(event.target.value)}
        />
      </section>

      {hasInput && (
        <section className="tool-panel wide-panel entropy-simple-results-panel">
          <ToolPanelHeader
            title={english ? "Entropy map" : "熵值分布"}
            subtitle={sourceName === "text input" ? (english ? "Text input" : "文本输入") : sourceName}
            actions={<AButton variant="outlined" onClick={() => setShowDetails((value) => !value)}>{showDetails ? (english ? "Hide details" : "收起详细数据") : (english ? "Detailed data" : "查看详细数据")}</AButton>}
          />

          <div className="entropy-simple-summary">
            <span><small>{english ? "Overall entropy" : "整体熵"}</small><strong>{overallEntropy}</strong></span>
            <span><small>{t.fileSize}</small><strong>{sourceSize > bytes.length ? `${formatBytes(bytes.length)} / ${formatBytes(sourceSize)}` : formatBytes(sourceSize)}</strong></span>
            <span><small>{t.entropyBlocks}</small><strong>{analysis.blocks.length}</strong></span>
            <span><small>{t.entropyRanges}</small><strong>{analysis.ranges.length}</strong></span>
          </div>

          {showDetails && <>
          <div className="entropy-simple-toolbar">
            <ASegmentedGroup value={view} selects="single">
              <ASegmentedButton value="blocks" onClick={() => setView("blocks")}>{t.entropyBlocks}</ASegmentedButton>
              <ASegmentedButton value="ranges" onClick={() => setView("ranges")}>{t.entropyRanges}</ASegmentedButton>
            </ASegmentedGroup>
            {view === "blocks" && (
              <ASelect aria-label={english ? "Entropy class" : "熵值分类"} value={classFilter} onChange={(value) => setClassFilter(String(value))} options={[{ value: "", label: english ? "All classifications" : "全部类型" }, ...classes.map((item) => ({ value: item, label: item }))]} />
            )}
            <AButton variant="text" onClick={() => downloadTextFile(`entropy-${view}-${Date.now()}.csv`, view === "blocks" ? services.entropyBlocksToCsv(filteredBlocks) : services.entropyRangesToCsv(analysis.ranges), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
          </div>

          {view === "blocks" ? (
            <div className="table-scroll entropy-simple-table-scroll">
              <table className="data-table entropy-simple-table">
                <thead><tr><th>{english ? "Offset" : "偏移"}</th><th>{english ? "Size" : "大小"}</th><th>{t.entropy}</th><th>{t.asciiRatio}</th><th>{t.zeroRatio}</th><th>{t.entropyClass}</th></tr></thead>
                <tbody>
                  {visibleBlocks.map((block) => (
                    <tr className={selected && services.entropyBlockKey(block) === services.entropyBlockKey(selected) ? "selected-row" : ""} key={services.entropyBlockKey(block)} onClick={() => setSelectedKey(services.entropyBlockKey(block))}>
                      <td className="mono-cell">0x{block.offset.toString(16).toUpperCase()}</td>
                      <td>{formatBytes(block.size)}</td>
                      <td>{block.entropy.toFixed(4)}</td>
                      <td>{(block.asciiRatio * 100).toFixed(1)}%</td>
                      <td>{(block.zeroRatio * 100).toFixed(1)}%</td>
                      <td>{block.classification}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="table-scroll entropy-simple-table-scroll">
              <table className="data-table entropy-simple-ranges-table">
                <thead><tr><th>{english ? "Range" : "范围"}</th><th>{english ? "Size" : "大小"}</th><th>{t.entropyBlocks}</th><th>{english ? "Average entropy" : "平均熵"}</th><th>{t.entropyClass}</th></tr></thead>
                <tbody>
                  {visibleRanges.map((range) => (
                    <tr key={`${range.start}-${range.end}-${range.classification}`}>
                      <td className="mono-cell">0x{range.start.toString(16).toUpperCase()}-0x{range.end.toString(16).toUpperCase()}</td>
                      <td>{formatBytes(range.size)}</td>
                      <td>{range.blockCount}</td>
                      <td>{range.avgEntropy.toFixed(4)}</td>
                      <td>{range.classification}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {itemCount > PAGE_SIZE && (
            <div className="entropy-simple-pagination">
              <AButton variant="outlined" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton>
              <span>{page + 1} / {pageCount}</span>
              <AButton variant="outlined" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton>
            </div>
          )}
          </>}
        </section>
      )}

      {selected && selectedContext && (
        <section className="tool-panel wide-panel entropy-simple-detail-panel">
          <ToolPanelHeader title={english ? "Selected block" : "当前分块"} />
          <InfoTable rows={[
            [english ? "Range" : "范围", `0x${selected.offset.toString(16).toUpperCase()}-0x${selected.endOffset.toString(16).toUpperCase()}`],
            [english ? "Size" : "大小", formatBytes(selected.size)],
            [t.entropy, `${selected.entropy.toFixed(6)} / 8`],
            [t.asciiRatio, `${(selected.asciiRatio * 100).toFixed(2)}%`],
            [t.zeroRatio, `${(selected.zeroRatio * 100).toFixed(2)}%`],
            [t.entropyClass, selected.classification],
            [english ? "Dominant byte" : "主要字节", `0x${selected.dominantByte.toString(16).padStart(2, "0").toUpperCase()} (${(selected.dominantRatio * 100).toFixed(2)}%)`],
            [english ? "Context window" : "上下文范围", `0x${selectedContext.start.toString(16).toUpperCase()}-0x${selectedContext.end.toString(16).toUpperCase()}`]
          ]} />
          <div className="entropy-simple-context">
            <label>Hex<pre>{selectedContext.hex}</pre></label>
            <label>{english ? "Text" : "文本"}<pre>{selectedContext.text}</pre></label>
          </div>
        </section>
      )}
    </div>
  );
}

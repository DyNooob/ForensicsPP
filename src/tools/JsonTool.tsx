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
import { AButton, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { analyzeBasicJson, type JsonBasicPath, type JsonBasicResult } from "../features/json/basic";
import type { JsonBasicWorkerRequest } from "../features/json/basic.worker";
import type { Translation } from "../i18n";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";
import { runWorkerTask } from "../utils/workerTask";

type JsonToolProps = { t: Translation };
type JsonMode = "format" | "minify" | "jsonl" | "escape" | "unescape";

function pathsToCsv(rows: JsonBasicPath[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["path", "type", "length", "value"].join(","),
    ...rows.map((row) => [row.path, row.type, row.length, row.value].map(escape).join(","))
  ].join("\n");
}

const MAX_JSON_BYTES = 16 * 1024 * 1024;

export function JsonTool({ t, active = true }: JsonToolProps & { active?: boolean }) {
  const [input, setInput] = useStoredState("json.input.v2", "");
  const [analyzedInput, setAnalyzedInput] = useStoredState("json.analyzedInput.v2", "");
  const [storedMode, setStoredMode] = useStoredState("json.outputMode", "format");
  const [filter, setFilter] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("");
  const [selectedPath, setSelectedPath] = React.useState("");
  const [error, setError] = React.useState("");
  const [analyzing, setAnalyzing] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  const abortRef = React.useRef<AbortController | null>(null);
  const english = t.waiting === "Waiting";
  const mode = (["format", "minify", "jsonl", "escape", "unescape"] as JsonMode[]).includes(storedMode as JsonMode) ? storedMode as JsonMode : "format";
  const [basicResult, setBasicResult] = React.useState<JsonBasicResult>(() => analyzeBasicJson(analyzedInput));
  const parsed = basicResult.parsed;
  const paths = basicResult.paths;

  React.useEffect(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    if (!active) {
      setAnalyzing(false);
      return;
    }
    if (!analyzedInput.trim()) {
      setBasicResult(analyzeBasicJson(""));
      setAnalyzing(false);
      return;
    }
    if (new TextEncoder().encode(analyzedInput).byteLength > MAX_JSON_BYTES) {
      setBasicResult(analyzeBasicJson(""));
      setError(english ? "JSON input exceeds the 16 MiB processing limit." : "JSON 输入超过 16 MiB 处理上限。");
      setAnalyzing(false);
      return;
    }
    const controller = new AbortController();
    abortRef.current = controller;
    setAnalyzing(true);
    setError("");
    void runWorkerTask<JsonBasicWorkerRequest, JsonBasicResult>({
      createWorker: () => new Worker(new URL("../features/json/basic.worker.ts", import.meta.url), { type: "module" }),
      request: { input: analyzedInput },
      signal: controller.signal,
      timeoutMs: 60_000
    }).then((result) => {
      if (!controller.signal.aborted) setBasicResult(result);
    }).catch((caught) => {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) {
        setBasicResult(analyzeBasicJson(""));
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    }).finally(() => {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setAnalyzing(false);
      }
    });
    return () => controller.abort();
  }, [active, analyzedInput, english]);
  const pathTypes = React.useMemo(() => Array.from(new Set(paths.map((row) => row.type))).sort(), [paths]);
  const visiblePaths = React.useMemo(() => {
    const value = filter.trim().toLowerCase();
    return paths.filter((row) => {
      if (typeFilter && row.type !== typeFilter) return false;
      return !value || [row.path, row.type, row.value].join(" ").toLowerCase().includes(value);
    });
  }, [filter, paths, typeFilter]);
  const selected = React.useMemo(() => paths.find((row) => row.path === selectedPath) ?? visiblePaths[0] ?? null, [paths, selectedPath, visiblePaths]);
  const output = React.useMemo(() => {
    if (mode === "escape") return JSON.stringify(analyzedInput);
    if (mode === "unescape") {
      try {
        const value: unknown = JSON.parse(analyzedInput);
        return typeof value === "string" ? value : JSON.stringify(value, null, 2);
      } catch (error) {
        return error instanceof Error ? error.message : String(error);
      }
    }
    if (!parsed.ok) return "";
    if (mode === "minify") return parsed.minified;
    if (mode === "jsonl") return parsed.jsonl;
    return parsed.normalized;
  }, [analyzedInput, mode, parsed]);
  const hasInput = Boolean(analyzedInput.trim());

  const openFile = async (file?: File) => {
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    setInput("");
    setAnalyzedInput("");
    setFilter("");
    setTypeFilter("");
    setSelectedPath("");
    if (file.size > MAX_JSON_BYTES) {
      setError(english ? "JSON file exceeds the 16 MiB processing limit." : "JSON 文件超过 16 MiB 处理上限。");
      return;
    }
    try {
      const value = await file.text();
      if (!active || requestId !== requestRef.current) return;
      setInput(value);
      setError("");
    } catch (caught) {
      if (active && requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const clear = () => {
    requestRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    setInput("");
    setAnalyzedInput("");
    setFilter("");
    setTypeFilter("");
    setSelectedPath("");
    setError("");
  };
  const analyze = () => {
    if (!active) return;
    if (new TextEncoder().encode(input).byteLength > MAX_JSON_BYTES) {
      setError(english ? "JSON input exceeds the 16 MiB processing limit." : "JSON 输入超过 16 MiB 处理上限。");
      return;
    }
    setAnalyzedInput(input);
    setError("");
    setFilter("");
    setTypeFilter("");
    setSelectedPath("");
  };
  const outputExtension = mode === "jsonl" ? "jsonl" : mode === "escape" || mode === "unescape" ? "txt" : "json";

  return (
    <div className={`tool-grid json-workbench json-simple-workbench ${hasInput ? "has-json" : "empty-json"}`}>
      <div className="tool-panel wide-panel json-simple-editor-panel">
        <ToolPanelHeader
          title={t.json}
          actions={<>
            <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.jsonOpenFile}</AButton>
            <AButton variant="filled" disabled={!input.trim()} onClick={analyze}>{english ? "Process JSON" : "处理 JSON"}</AButton>
            <AButton variant="text" disabled={!input && !hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".json,.jsonl,.ndjson,text/*,application/json" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void openFile(file); }} />
        {error && <div className="empty-state error-state">{error}</div>}
        {analyzing && <div className="empty-state" role="status">{english ? "Processing JSON…" : "正在处理 JSON…"}</div>}
        <ASegmentedGroup className="json-simple-modes" value={mode} selects="single" aria-label={english ? "JSON operation" : "JSON 操作"}>
          <ASegmentedButton value="format" onClick={() => setStoredMode("format")}>{t.formatJson}</ASegmentedButton>
          <ASegmentedButton value="minify" onClick={() => setStoredMode("minify")}>{t.minifyJson}</ASegmentedButton>
          <ASegmentedButton value="jsonl" onClick={() => setStoredMode("jsonl")}>JSONL</ASegmentedButton>
          <ASegmentedButton value="escape" onClick={() => setStoredMode("escape")}>{t.escapeString}</ASegmentedButton>
          <ASegmentedButton value="unescape" onClick={() => setStoredMode("unescape")}>{t.unescapeString}</ASegmentedButton>
        </ASegmentedGroup>
        <div className="text-panel json-simple-text-panel">
          <div className="text-panel-title"><strong>{t.inputText}</strong><AButton variant="text" disabled={!input} onClick={() => void copyText(input)}>{t.copyInput}</AButton></div>
          <textarea className="json-simple-textarea" aria-label={english ? "JSON input" : "JSON 输入"} value={input} onChange={(event) => { requestRef.current += 1; setInput(event.currentTarget.value); setAnalyzedInput(""); setSelectedPath(""); }} placeholder={t.textPlaceholder} />
        </div>
        {hasInput && mode !== "escape" && mode !== "unescape" && !parsed.ok && <div className="empty-state error-state">{parsed.error}</div>}
        <div className="text-panel json-simple-text-panel">
          <div className="text-panel-title">
            <strong>{t.outputText}</strong>
            <div className="mini-actions">
              {parsed.ok && mode !== "escape" && mode !== "unescape" && <span className="status-pill">{parsed.kind} · {paths.length} {english ? "paths" : "路径"}</span>}
              <AButton variant="text" disabled={!output} onClick={() => void copyText(output)}>{t.copyOutput}</AButton>
              <AButton variant="text" disabled={!output} onClick={() => downloadTextFile(`json-output-${Date.now()}.${outputExtension}`, output, "text/plain;charset=utf-8")}>{english ? "Save" : "保存"}</AButton>
            </div>
          </div>
          <textarea className="json-simple-textarea" aria-label={english ? "JSON output" : "JSON 输出"} value={output} readOnly />
        </div>
      </div>

      {parsed.ok && <div className="tool-panel wide-panel json-simple-path-panel">
        <ToolPanelHeader
          title={t.jsonPaths}
          subtitle={paths.length >= 5000 ? (english ? "First 5,000 paths" : "显示前 5,000 条路径") : `${paths.length} ${english ? "paths" : "条路径"}`}
          actions={<AButton variant="outlined" disabled={!visiblePaths.length} onClick={() => downloadTextFile(`json-paths-${Date.now()}.csv`, pathsToCsv(visiblePaths), "text/csv;charset=utf-8")}>{t.exportPathsCsv}</AButton>}
        />
        <div className="json-simple-filter-row">
          <input className="text-input" aria-label={english ? "Filter JSON paths or values" : "筛选 JSON 路径或值"} value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter path or value" : "筛选路径或值"} />
          <ASelect aria-label={english ? "JSON value type" : "JSON 值类型"} value={typeFilter} onChange={(value) => setTypeFilter(String(value))} options={[{ value: "", label: t.jsonTypeAll }, ...pathTypes.map((type) => ({ value: type, label: type }))]} />
        </div>
        <div className="table-scroll json-simple-path-scroll">
          {visiblePaths.length ? <table className="data-table json-simple-path-table">
            <thead><tr><th>{t.jsonPath}</th><th>{t.jsonType}</th><th>{english ? "Length" : "长度"}</th><th>{t.jsonValue}</th><th>{t.copy}</th></tr></thead>
            <tbody>{visiblePaths.slice(0, 1000).map((row) => <tr className={selected?.path === row.path ? "selected-row" : ""} key={row.path} onClick={() => setSelectedPath(row.path)}>
              <td><code>{row.path}</code></td><td>{row.type}</td><td>{row.length}</td><td className="json-path-value">{row.value || "--"}</td><td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void copyText(row.value); }}>{t.copy}</AButton></td>
            </tr>)}</tbody>
          </table> : <div className="empty-state">--</div>}
        </div>
        {selected && <div className="json-simple-selected">
          <InfoTable rows={[[t.jsonPath, selected.path], [t.jsonType, selected.type], [english ? "Length" : "长度", String(selected.length)]]} />
          <div className="result-box"><div className="text-panel-title"><strong>{t.jsonValue}</strong><AButton variant="text" onClick={() => void copyText(selected.value)}>{t.copy}</AButton></div><pre>{selected.value || "--"}</pre></div>
        </div>}
      </div>}
    </div>
  );
}

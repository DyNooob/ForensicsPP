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
import { AButton, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import type { Translation } from "../i18n";
import type { JsonAnalysisServices } from "../features/json/analyzer";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";

type JsonToolProps = JsonAnalysisServices & { t: Translation };
type JsonMode = "format" | "minify" | "jsonl" | "escape" | "unescape";

type JsonPathItem = {
  path: string;
  type: string;
  value: string;
  length: number;
};

function valueType(value: unknown) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function displayValue(value: unknown) {
  if (Array.isArray(value)) return `Array(${value.length})`;
  if (value && typeof value === "object") return `Object(${Object.keys(value).length})`;
  if (typeof value === "string") return value;
  if (value === undefined) return "undefined";
  return JSON.stringify(value);
}

function childPath(parent: string, key: string) {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`;
}

function collectPaths(root: unknown) {
  const rows: JsonPathItem[] = [];
  const visit = (value: unknown, path: string) => {
    if (rows.length >= 5000) return;
    const rendered = displayValue(value);
    rows.push({ path, type: valueType(value), value: rendered, length: rendered.length });
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${path}[${index}]`));
    } else if (value && typeof value === "object") {
      Object.entries(value as Record<string, unknown>).forEach(([key, item]) => visit(item, childPath(path, key)));
    }
  };
  visit(root, "$");
  return rows;
}

function parseJson(input: string) {
  if (!input.trim()) return { ok: false as const, value: null, kind: "", error: "", normalized: "", minified: "", jsonl: "" };
  try {
    const value: unknown = JSON.parse(input);
    return {
      ok: true as const,
      value,
      kind: "JSON",
      error: "",
      normalized: JSON.stringify(value, null, 2),
      minified: JSON.stringify(value),
      jsonl: Array.isArray(value) ? value.map((item) => JSON.stringify(item)).join("\n") : JSON.stringify(value)
    };
  } catch (jsonError) {
    const lines = input.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length > 1) {
      try {
        const value = lines.map((line) => JSON.parse(line) as unknown);
        return {
          ok: true as const,
          value,
          kind: "JSONL",
          error: "",
          normalized: JSON.stringify(value, null, 2),
          minified: JSON.stringify(value),
          jsonl: value.map((item) => JSON.stringify(item)).join("\n")
        };
      } catch {
        // Report the original JSON parser error; it usually has the most useful offset.
      }
    }
    return {
      ok: false as const,
      value: null,
      kind: "",
      error: jsonError instanceof Error ? jsonError.message : String(jsonError),
      normalized: "",
      minified: "",
      jsonl: ""
    };
  }
}

function pathsToCsv(rows: JsonPathItem[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["path", "type", "length", "value"].join(","),
    ...rows.map((row) => [row.path, row.type, row.length, row.value].map(escape).join(","))
  ].join("\n");
}

export function JsonTool({ t, ..._services }: JsonToolProps) {
  const [input, setInput] = React.useState("");
  const [analyzedInput, setAnalyzedInput] = React.useState("");
  const [storedMode, setStoredMode] = useStoredState("json.outputMode", "format");
  const [filter, setFilter] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("");
  const [selectedPath, setSelectedPath] = React.useState("");
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  const english = t.waiting === "Waiting";
  const mode = (["format", "minify", "jsonl", "escape", "unescape"] as JsonMode[]).includes(storedMode as JsonMode) ? storedMode as JsonMode : "format";
  const parsed = React.useMemo(() => parseJson(analyzedInput), [analyzedInput]);
  const paths = React.useMemo(() => parsed.ok ? collectPaths(parsed.value) : [], [parsed]);
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
    if (!file) return;
    const requestId = ++requestRef.current;
    setInput("");
    setAnalyzedInput("");
    setFilter("");
    setTypeFilter("");
    setSelectedPath("");
    if (file.size > 16 * 1024 * 1024) {
      setError(english ? "JSON file exceeds the 16 MiB processing limit." : "JSON 文件超过 16 MiB 处理上限。");
      return;
    }
    try {
      const value = await file.text();
      if (requestId !== requestRef.current) return;
      setInput(value);
      setError("");
    } catch (caught) {
      if (requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const clear = () => {
    requestRef.current += 1;
    setInput("");
    setAnalyzedInput("");
    setFilter("");
    setTypeFilter("");
    setSelectedPath("");
    setError("");
  };
  const analyze = () => {
    if (new TextEncoder().encode(input).length > 16 * 1024 * 1024) {
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
        <ASegmentedGroup className="json-simple-modes" value={mode} selects="single" aria-label={english ? "JSON operation" : "JSON 操作"}>
          <ASegmentedButton value="format" onClick={() => setStoredMode("format")}>{t.formatJson}</ASegmentedButton>
          <ASegmentedButton value="minify" onClick={() => setStoredMode("minify")}>{t.minifyJson}</ASegmentedButton>
          <ASegmentedButton value="jsonl" onClick={() => setStoredMode("jsonl")}>JSONL</ASegmentedButton>
          <ASegmentedButton value="escape" onClick={() => setStoredMode("escape")}>{t.escapeString}</ASegmentedButton>
          <ASegmentedButton value="unescape" onClick={() => setStoredMode("unescape")}>{t.unescapeString}</ASegmentedButton>
        </ASegmentedGroup>
        <div className="text-panel json-simple-text-panel">
          <div className="text-panel-title"><strong>{t.inputText}</strong><AButton variant="text" disabled={!input} onClick={() => void navigator.clipboard.writeText(input)}>{t.copyInput}</AButton></div>
          <textarea className="json-simple-textarea" aria-label={english ? "JSON input" : "JSON 输入"} value={input} onChange={(event) => { requestRef.current += 1; setInput(event.currentTarget.value); setAnalyzedInput(""); setSelectedPath(""); }} placeholder={t.textPlaceholder} />
        </div>
        {hasInput && mode !== "escape" && mode !== "unescape" && !parsed.ok && <div className="empty-state error-state">{parsed.error}</div>}
        <div className="text-panel json-simple-text-panel">
          <div className="text-panel-title">
            <strong>{t.outputText}</strong>
            <div className="mini-actions">
              {parsed.ok && mode !== "escape" && mode !== "unescape" && <span className="status-pill">{parsed.kind} · {paths.length} {english ? "paths" : "路径"}</span>}
              <AButton variant="text" disabled={!output} onClick={() => void navigator.clipboard.writeText(output)}>{t.copyOutput}</AButton>
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
              <td><code>{row.path}</code></td><td>{row.type}</td><td>{row.length}</td><td className="json-path-value">{row.value || "--"}</td><td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void navigator.clipboard.writeText(row.value); }}>{t.copy}</AButton></td>
            </tr>)}</tbody>
          </table> : <div className="empty-state">--</div>}
        </div>
        {selected && <div className="json-simple-selected">
          <InfoTable rows={[[t.jsonPath, selected.path], [t.jsonType, selected.type], [english ? "Length" : "长度", String(selected.length)]]} />
          <div className="result-box"><div className="text-panel-title"><strong>{t.jsonValue}</strong><AButton variant="text" onClick={() => void navigator.clipboard.writeText(selected.value)}>{t.copy}</AButton></div><pre>{selected.value || "--"}</pre></div>
        </div>}
      </div>}
    </div>
  );
}

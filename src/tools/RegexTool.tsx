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
import { AButton, ASelect, InfoTable, PanelTitle, ToolPanelHeader } from "../components/ui";
import type { Translation } from "../i18n";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";

type RegexToolProps = {
  t: Translation;
  classifyIocRisk: (type: string, value: string) => string[];
};

type RegexMatch = {
  order: number;
  index: number;
  end: number;
  line: number;
  length: number;
  value: string;
  groups: string[];
  namedGroups: Record<string, string>;
  context: string;
};

const presets = [
  { label: "Email", pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", flags: "gi" },
  { label: "URL", pattern: "\\bhttps?:\\/\\/[^\\s\"'<>]+", flags: "gi" },
  { label: "IPv4", pattern: "\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b", flags: "g" },
  { label: "Domain", pattern: "\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b", flags: "gi" },
  { label: "Hash", pattern: "\\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\\b", flags: "gi" },
  { label: "CVE", pattern: "\\bCVE-\\d{4}-\\d{4,7}\\b", flags: "gi" },
  { label: "Key=Value", pattern: "(?:^|[&\\s])([^=&\\s]+)=([^&\\s]+)", flags: "g" },
  { label: "Header", pattern: "^([A-Za-z0-9-]+):\\s*(.+)$", flags: "gim" }
];

function normalizeFlags(flags: string) {
  const allowed = new Set(["d", "g", "i", "m", "s", "u", "v", "y"]);
  const normalized: string[] = [];
  for (const flag of flags.trim()) {
    if (!allowed.has(flag)) throw new Error(`Unsupported regex flag: ${flag}`);
    if (!normalized.includes(flag)) normalized.push(flag);
  }
  if (!normalized.includes("g")) normalized.push("g");
  return normalized.join("");
}

function analyze(pattern: string, flags: string, source: string, replacement: string) {
  if (!pattern.trim()) return { matches: [] as RegexMatch[], replaced: source, error: "", flags: "" };
  try {
    const normalizedFlags = normalizeFlags(flags);
    const expression = new RegExp(pattern, normalizedFlags);
    const matches = Array.from(source.matchAll(expression)).slice(0, 1000).map((match, index) => {
      const start = match.index ?? 0;
      const value = match[0];
      const end = start + value.length;
      const line = source.slice(0, start).split(/\r\n|\r|\n/).length;
      return {
        order: index + 1,
        index: start,
        end,
        line,
        length: value.length,
        value,
        groups: match.slice(1).map((item) => item ?? ""),
        namedGroups: Object.fromEntries(Object.entries(match.groups ?? {}).map(([key, item]) => [key, item ?? ""])),
        context: source.slice(Math.max(0, start - 80), Math.min(source.length, end + 80)).replace(/\s+/g, " ").trim()
      };
    });
    return { matches, replaced: source.replace(expression, replacement), error: "", flags: normalizedFlags };
  } catch (error) {
    return { matches: [] as RegexMatch[], replaced: source, error: error instanceof Error ? error.message : String(error), flags: "" };
  }
}

function matchesToCsv(matches: RegexMatch[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["order", "line", "start", "end", "length", "value", "groups", "named_groups", "context"].join(","),
    ...matches.map((match) => [match.order, match.line, match.index, match.end, match.length, match.value, match.groups.join(" | "), JSON.stringify(match.namedGroups), match.context].map(escape).join(","))
  ].join("\n");
}

export function RegexTool({ t, classifyIocRisk: _classifyIocRisk }: RegexToolProps) {
  const [pattern, setPattern] = useStoredState("regex.pattern", "");
  const [flags, setFlags] = useStoredState("regex.flags", "gi");
  const [source, setSource] = useStoredState("regex.text.v2", "");
  const [replacement, setReplacement] = useStoredState("regex.replacement", "[REDACTED]");
  const [filter, setFilter] = React.useState("");
  const [selectedKey, setSelectedKey] = React.useState("");
  const [preset, setPreset] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const english = t.waiting === "Waiting";
  const result = React.useMemo(() => analyze(pattern, flags, source, replacement), [flags, pattern, replacement, source]);
  const hasInput = Boolean(pattern.trim() || source.trim());
  const visibleMatches = React.useMemo(() => {
    const value = filter.trim().toLowerCase();
    if (!value) return result.matches;
    return result.matches.filter((match) => [match.value, match.context, match.groups.join(" "), JSON.stringify(match.namedGroups), match.line, match.index].join(" ").toLowerCase().includes(value));
  }, [filter, result.matches]);
  const selectedMatch = React.useMemo(() => {
    return result.matches.find((match) => `${match.order}:${match.index}` === selectedKey) ?? visibleMatches[0] ?? null;
  }, [result.matches, selectedKey, visibleMatches]);

  const loadFile = async (file?: File) => {
    if (!file) return;
    setSource(await file.text());
    setSelectedKey("");
    setFilter("");
  };
  const applyPreset = (value: string) => {
    setPreset(value);
    const item = presets.find((candidate) => candidate.label === value);
    if (!item) return;
    setPattern(item.pattern);
    setFlags(item.flags);
    setSelectedKey("");
  };
  const clear = () => {
    setPattern("");
    setSource("");
    setFilter("");
    setSelectedKey("");
    setPreset("");
  };

  return (
    <div className={`tool-grid regex-workbench regex-simple-workbench ${hasInput ? "has-regex" : "empty-regex"}`}>
      <div className="tool-panel wide-panel regex-simple-source-panel">
        <ToolPanelHeader
          title={t.regex}
          actions={<>
            <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.uploadRegexText}</AButton>
            <AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".log,.txt,.csv,.json,.xml,.html,text/*,application/json" onChange={(event) => void loadFile(event.currentTarget.files?.[0])} />
        <div className="regex-simple-controls">
          <label className="stack-label regex-pattern-field">{t.pattern}<input className="text-input full-input" value={pattern} onChange={(event) => { setPattern(event.currentTarget.value); setSelectedKey(""); }} placeholder={english ? "Regular expression" : "输入正则表达式"} /></label>
          <label className="stack-label">{t.flags}<input className="text-input full-input" value={flags} onChange={(event) => setFlags(event.currentTarget.value)} placeholder="gim" /></label>
          <label className="stack-label">{t.regexExamples}<ASelect aria-label={t.regexExamples} value={preset} onChange={(value) => applyPreset(String(value))} options={[{ value: "", label: english ? "Choose preset" : "选择常用表达式" }, ...presets.map((item) => ({ value: item.label, label: item.label }))]} /></label>
        </div>
        <label className="stack-label">{english ? "Source text" : "源文本"}<textarea className="single-textarea regex-simple-source" value={source} onChange={(event) => { setSource(event.currentTarget.value); setSelectedKey(""); }} placeholder={t.textPlaceholder} /></label>
        {result.error && <div className="empty-state error-state">{result.error}</div>}
      </div>

      {hasInput && <div className="tool-panel wide-panel regex-simple-results-panel">
        <ToolPanelHeader
          title={t.matches}
          subtitle={result.matches.length >= 1000 ? (english ? "First 1,000 matches" : "显示前 1,000 条") : `${result.matches.length} ${english ? "matches" : "个匹配"}`}
          actions={<>
            <AButton variant="outlined" disabled={!visibleMatches.length} onClick={() => void navigator.clipboard.writeText(visibleMatches.map((match) => match.value).join("\n"))}>{english ? "Copy matches" : "复制匹配"}</AButton>
            <AButton variant="outlined" disabled={!visibleMatches.length} onClick={() => downloadTextFile(`regex-matches-${Date.now()}.csv`, matchesToCsv(visibleMatches), "text/csv;charset=utf-8")}>{t.exportMatchesCsv}</AButton>
          </>}
        />
        <input className="text-input regex-simple-filter" aria-label={english ? "Filter regex matches" : "筛选正则匹配结果"} value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter matches" : "筛选匹配结果"} />
        <div className="table-scroll regex-simple-table-scroll">
          {visibleMatches.length ? <table className="data-table regex-simple-table">
            <thead><tr><th>#</th><th>{english ? "Match" : "匹配内容"}</th><th>{english ? "Line" : "行"}</th><th>{english ? "Range" : "位置"}</th><th>{english ? "Groups" : "分组"}</th><th>{t.copy}</th></tr></thead>
            <tbody>{visibleMatches.map((match) => {
              const key = `${match.order}:${match.index}`;
              return <tr className={selectedMatch && key === `${selectedMatch.order}:${selectedMatch.index}` ? "selected-row" : ""} key={key} onClick={() => setSelectedKey(key)}>
                <td>{match.order}</td><td className="regex-match-value">{match.value || "--"}</td><td>{match.line}</td><td>{match.index}-{match.end}</td><td>{match.groups.length + Object.keys(match.namedGroups).length || "--"}</td><td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void navigator.clipboard.writeText(match.value); }}>{t.copy}</AButton></td>
              </tr>;
            })}</tbody>
          </table> : <div className="empty-state">{result.error || (english ? "No matches" : "没有匹配结果")}</div>}
        </div>
      </div>}

      {selectedMatch && <div className="tool-panel wide-panel regex-simple-detail-panel">
        <ToolPanelHeader title={english ? "Selected match" : "当前匹配"} actions={<AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(selectedMatch.value)}>{t.copy}</AButton>} />
        <InfoTable rows={[
          [english ? "Value" : "内容", selectedMatch.value || "--"],
          [english ? "Line" : "行号", String(selectedMatch.line)],
          [english ? "Range" : "位置", `${selectedMatch.index}-${selectedMatch.end}`],
          [english ? "Length" : "长度", String(selectedMatch.length)],
          [english ? "Groups" : "捕获组", selectedMatch.groups.length ? selectedMatch.groups.map((value, index) => `$${index + 1}=${value}`).join(" | ") : "--"],
          [t.regexNamedGroups, Object.keys(selectedMatch.namedGroups).length ? Object.entries(selectedMatch.namedGroups).map(([key, value]) => `${key}=${value}`).join(" | ") : "--"]
        ]} />
        <div className="result-box regex-simple-context"><strong>{t.regexContext}</strong><span>{selectedMatch.context || "--"}</span></div>
      </div>}

      {hasInput && <div className="tool-panel wide-panel regex-simple-replace-panel">
        <ToolPanelHeader title={t.regexReplaceOutput} actions={<AButton variant="outlined" disabled={!source} onClick={() => void navigator.clipboard.writeText(result.replaced)}>{t.copyOutput}</AButton>} />
        <label className="stack-label">{t.regexReplacement}<input className="text-input full-input" value={replacement} onChange={(event) => setReplacement(event.currentTarget.value)} /></label>
        <textarea aria-label={english ? "Replacement result" : "替换结果"} className="single-textarea regex-simple-output" value={result.replaced} readOnly />
      </div>}
    </div>
  );
}

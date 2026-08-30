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
import { AButton, ASelect, InfoTable, PanelTitle, ToolPanelHeader } from "../components/ui";
import { analyzeRegex, type RegexAnalysis, type RegexMatch } from "../features/regex/analyzer";
import type { Translation } from "../i18n";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";
import { runWorkerTask } from "../utils/workerTask";

type RegexToolProps = {
  t: Translation;
  classifyIocRisk: (type: string, value: string) => string[];
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

const MAX_REGEX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_REGEX_SOURCE_CHARS = 16 * 1024 * 1024;

export function RegexTool({ t, classifyIocRisk: _classifyIocRisk, active = true }: RegexToolProps & { active?: boolean }) {
  const [pattern, setPattern] = useStoredState("regex.pattern.v3", "");
  const [flags, setFlags] = useStoredState("regex.flags.v3", "gi");
  const [source, setSource] = useStoredState("regex.source.v3", "");
  const [replacement, setReplacement] = useStoredState("regex.replacement", "[REDACTED]");
  const [filter, setFilter] = React.useState("");
  const [selectedKey, setSelectedKey] = React.useState("");
  const [preset, setPreset] = React.useState("");
  const [fileError, setFileError] = React.useState("");
  const [analyzing, setAnalyzing] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestRef = React.useRef(0);
  const english = t.waiting === "Waiting";
  const [result, setResult] = React.useState<RegexAnalysis>(() => analyzeRegex("", "", "", replacement));
  const sourceTooLarge = source.length > MAX_REGEX_SOURCE_CHARS;
  React.useEffect(() => {
    const controller = new AbortController();
    if (!active) {
      setAnalyzing(false);
      return () => controller.abort();
    }
    if (sourceTooLarge) {
      setAnalyzing(false);
      setResult({ matches: [], replaced: source, error: t.source_text_is_limited_to_16_mib, flags: "" });
      return () => controller.abort();
    }
    if (!pattern.trim()) {
      setAnalyzing(false);
      setResult(analyzeRegex("", "", source, replacement));
      return () => controller.abort();
    }
    setAnalyzing(true);
    const timer = window.setTimeout(() => {
      void runWorkerTask<{ pattern: string; flags: string; source: string; replacement: string }, RegexAnalysis>({
        createWorker: () => new Worker(new URL("../features/regex/regex.worker.ts", import.meta.url), { type: "module" }),
        request: { pattern, flags, source, replacement },
        signal: controller.signal,
        timeoutMs: 5_000
      }).then((next) => {
        if (!controller.signal.aborted) setResult(next);
      }).catch((caught) => {
        if (!controller.signal.aborted) setResult({ matches: [], replaced: source, error: caught instanceof Error ? caught.message : String(caught), flags: "" });
      }).finally(() => {
        if (!controller.signal.aborted) setAnalyzing(false);
      });
    }, 120);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [active, english, flags, pattern, replacement, source, sourceTooLarge]);
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
    if (!file || !active) return;
    const requestId = ++requestRef.current;
    setSource("");
    setFileError("");
    setSelectedKey("");
    setFilter("");
    if (file.size > MAX_REGEX_FILE_BYTES) {
      setFileError(t.the_file_exceeds_the_16_mib_limit);
      return;
    }
    try {
      const value = await file.text();
      if (active && requestId === requestRef.current) setSource(value);
    } catch (caught) {
      if (active && requestId === requestRef.current) setFileError(caught instanceof Error ? caught.message : String(caught));
    }
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
    requestRef.current += 1;
    setPattern("");
    setSource("");
    setFilter("");
    setSelectedKey("");
    setPreset("");
    setFileError("");
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
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".log,.txt,.csv,.json,.xml,.html,text/*,application/json" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void loadFile(file); }} />
        <div className="regex-simple-controls">
          <label className="stack-label regex-pattern-field">{t.pattern}<input className="text-input full-input" value={pattern} onChange={(event) => { setPattern(event.currentTarget.value); setSelectedKey(""); }} placeholder={t.regular_expression} /></label>
          <label className="stack-label">{t.flags}<input className="text-input full-input" value={flags} onChange={(event) => setFlags(event.currentTarget.value)} placeholder="gim" /></label>
          <label className="stack-label">{t.regexExamples}<ASelect aria-label={t.regexExamples} value={preset} onChange={(value) => applyPreset(String(value))} options={[{ value: "", label: t.choose_preset }, ...presets.map((item) => ({ value: item.label, label: item.label }))]} /></label>
        </div>
        <label className="stack-label">{t.source_text}<textarea className="single-textarea regex-simple-source" value={source} onChange={(event) => { requestRef.current += 1; setSource(event.currentTarget.value); setFileError(""); setSelectedKey(""); }} placeholder={t.textPlaceholder} /></label>
        {fileError && <div className="empty-state error-state">{fileError}</div>}
        {(analyzing || result.error) && <div className={`empty-state ${result.error ? "error-state" : ""}`} role={result.error ? "alert" : "status"}>{analyzing ? (t.matching) : result.error}</div>}
      </div>

      {hasInput && <div className="tool-panel wide-panel regex-simple-results-panel">
        <ToolPanelHeader
          title={t.matches}
          subtitle={result.matches.length >= 1000 ? (t.first_1_000_matches) : `${result.matches.length} ${t.matches_2}`}
          actions={<>
            <AButton variant="outlined" disabled={!visibleMatches.length} onClick={() => void copyText(visibleMatches.map((match) => match.value).join("\n"))}>{t.copy_matches}</AButton>
            <AButton variant="outlined" disabled={!visibleMatches.length} onClick={() => downloadTextFile(`regex-matches-${Date.now()}.csv`, matchesToCsv(visibleMatches), "text/csv;charset=utf-8")}>{t.exportMatchesCsv}</AButton>
          </>}
        />
        <input className="text-input regex-simple-filter" aria-label={t.filter_regex_matches} value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={t.filter_matches} />
        <div className="table-scroll regex-simple-table-scroll">
          {visibleMatches.length ? <table className="data-table regex-simple-table">
            <thead><tr><th>#</th><th>{t.match}</th><th>{t.iocLine}</th><th>{t.range}</th><th>{t.groups}</th><th>{t.copy}</th></tr></thead>
            <tbody>{visibleMatches.map((match) => {
              const key = `${match.order}:${match.index}`;
              return <tr className={selectedMatch && key === `${selectedMatch.order}:${selectedMatch.index}` ? "selected-row" : ""} key={key} onClick={() => setSelectedKey(key)}>
                <td>{match.order}</td><td className="regex-match-value">{match.value || "--"}</td><td>{match.line}</td><td>{match.index}-{match.end}</td><td>{match.groups.length + Object.keys(match.namedGroups).length || "--"}</td><td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void copyText(match.value); }}>{t.copy}</AButton></td>
              </tr>;
            })}</tbody>
          </table> : <div className="empty-state">{result.error || (t.no_matches)}</div>}
        </div>
      </div>}

      {selectedMatch && <div className="tool-panel wide-panel regex-simple-detail-panel">
        <ToolPanelHeader title={t.selected_match} actions={<AButton variant="outlined" onClick={() => void copyText(selectedMatch.value)}>{t.copy}</AButton>} />
        <InfoTable rows={[
          [t.httpHeaderValue, selectedMatch.value || "--"],
          [t.iocLine, String(selectedMatch.line)],
          [t.range, `${selectedMatch.index}-${selectedMatch.end}`],
          [t.stringLength, String(selectedMatch.length)],
          [t.groups, selectedMatch.groups.length ? selectedMatch.groups.map((value, index) => `$${index + 1}=${value}`).join(" | ") : "--"],
          [t.regexNamedGroups, Object.keys(selectedMatch.namedGroups).length ? Object.entries(selectedMatch.namedGroups).map(([key, value]) => `${key}=${value}`).join(" | ") : "--"]
        ]} />
        <div className="result-box regex-simple-context"><strong>{t.regexContext}</strong><span>{selectedMatch.context || "--"}</span></div>
      </div>}

      {hasInput && <div className="tool-panel wide-panel regex-simple-replace-panel">
        <ToolPanelHeader title={t.regexReplaceOutput} actions={<AButton variant="outlined" disabled={!source} onClick={() => void copyText(result.replaced)}>{t.copyOutput}</AButton>} />
        <label className="stack-label">{t.regexReplacement}<input className="text-input full-input" value={replacement} onChange={(event) => setReplacement(event.currentTarget.value)} /></label>
        <textarea aria-label={t.replacement_result} className="single-textarea regex-simple-output" value={result.replaced} readOnly />
      </div>}
    </div>
  );
}

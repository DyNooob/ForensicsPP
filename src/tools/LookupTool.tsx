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

import React from "react";
import { AutoTextarea } from "../components/AutoTextarea";
import { useHomeToolDraft } from "../app/useHomeToolDraft";
import { AButton, ALinearProgress, ASelect, ASegmentedButton, ASegmentedGroup, ToolPanelHeader } from "../components/ui";
import { copyText } from "../utils/clipboard";
import { downloadTextFile, formatBytes } from "../utils/files";
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { buildLookupEnvelope } from "../features/lookup/envelope";
import { lookupDataPackMessage } from "../features/lookup/dataPacks";
import { splitLookupInput } from "../features/lookup/rules";
import type { LookupKind, LookupResult, ResolvedLookupKind } from "../features/lookup/rules";
import type { Translation } from "../i18n";
import type { Lang } from "../models";

const MAX_BATCH = 5000;
const PAGE_SIZE = 100;

type PackState = { state: "idle" | "loading" | "ready" | "error"; detail: string };
type WorkerMessage =
  | { type: "progress"; requestId: number; pack: ResolvedLookupKind; state: PackState["state"]; detail?: string }
  | { type: "batch-progress"; requestId: number; completed: number; total: number }
  | { type: "result"; requestId: number; results: LookupResult[] }
  | { type: "error"; requestId: number; error: string };

function csvCell(value: unknown) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function resultsToCsv(results: LookupResult[]) {
  const fieldNames = Array.from(new Set(results.flatMap((result) => Object.keys(result.fields))));
  const header = ["input", "normalized", "kind", "valid", "matched", "summary", ...fieldNames, "notes", "source", "dataVersion"];
  return [
    header.join(","),
    ...results.map((result) => [
      result.input,
      result.normalized,
      result.kind,
      result.valid,
      result.matched,
      result.summary,
      ...fieldNames.map((name) => result.fields[name] ?? ""),
      result.notes.join(" | "),
      result.source,
      result.dataVersion
    ].map(csvCell).join(","))
  ].join("\n");
}

function displayFields(result: LookupResult, lang: Lang) {
  const names: Record<string, [string, string]> = {
    country: ["国家/地区", "Country"], province: ["省份", "Province"], city: ["城市", "City"], isp: ["运营商", "ISP"],
    carrier: ["运营商", "Carrier"], zipCode: ["邮编", "Postal code"], areaCode: ["区号", "Area code"],
    birthDate: ["出生日期", "Birth date"], gender: ["性别", "Gender"], region: ["行政区划", "Division"],
    regionCode: ["区划代码", "Division code"], regionStatus: ["区划状态", "Division status"], newRegionCode: ["现行代码", "Current code"],
    bank: ["发卡行", "Issuer"], bankCode: ["银行代码", "Bank code"], cardType: ["卡种", "Card type"], bin: ["BIN", "BIN"],
    network: ["卡组织", "Network"], luhn: ["Luhn", "Luhn"], length: ["长度", "Length"], expectedLength: ["预期长度", "Expected length"],
    checkCode: ["校验位", "Check digit"], expectedCheckCode: ["预期校验位", "Expected digit"], reason: ["原因", "Reason"], scope: ["地址范围", "Address scope"]
  };
  return Object.entries(result.fields).filter(([, value]) => value).map(([key, value]) => [names[key]?.[lang === "zh" ? 0 : 1] ?? key, value] as const);
}

export function LookupTool({ lang, active = true }: { t: Translation; lang: Lang; active?: boolean }) {
  const zh = lang === "zh";
  const labels = React.useMemo(() => zh ? {
    title: "归属地与规则核验",
    subtitle: "每行一条，最多 5,000 条。IP、手机号与行政区划数据按类型加载并缓存。",
    placeholder: "例如：\n113.118.113.77\n13800138000\n11010519491231002X\n622202…",
    run: "开始查询",
    running: "正在查询",
    clear: "清空",
    sample: "载入示例",
    results: "查询结果",
    exportCsv: "导出全部 CSV",
    copyJson: "复制全部 JSON",
    searchResults: "搜索查询结果",
    allStatuses: "全部状态",
    failedOnly: "规则未通过",
    unmatchedOnly: "规则有效 / 库无记录",
    filterStatus: "筛选结果状态",
    resetFilter: "重置筛选",
    noMatches: "没有符合筛选条件的结果。",
    previous: "上一页",
    next: "下一页",
    input: "输入",
    type: "类型",
    status: "状态",
    summary: "结果摘要",
    details: "详情与依据",
    valid: "通过",
    invalid: "未通过",
    unmatched: "规则有效 / 库无记录",
    empty: "输入后执行查询。自动模式按行识别 IP、手机号、身份证号和银行卡号。",
    source: "数据源",
    cached: "已加载",
    loadingPack: "正在加载数据包",
    error: "查询失败",
    limit: "超过 5,000 条，请拆分批次后查询。",
    auto: "自动识别",
    ip: "IP 地址",
    phone: "手机号",
    id: "身份证号",
    bank: "银行卡号"
  } : {
    title: "Local Attribution & Rule Checks",
    subtitle: "Enter one or many values, one per line. Processing stays in the browser; large static packs load only when their type is first used and are cached.",
    placeholder: "Examples:\n113.118.113.77\n13800138000\n11010519491231002X\n622202…",
    run: "Run lookup",
    running: "Looking up",
    clear: "Clear",
    sample: "Load samples",
    results: "Results",
    exportCsv: "Export all CSV",
    copyJson: "Copy all JSON",
    searchResults: "Search results",
    allStatuses: "All statuses",
    failedOnly: "Rules failed",
    unmatchedOnly: "Rules pass; no database match",
    filterStatus: "Filter result status",
    resetFilter: "Reset filters",
    noMatches: "No results match the current filters.",
    previous: "Previous",
    next: "Next",
    input: "Input",
    type: "Type",
    status: "Status",
    summary: "Summary",
    details: "Details & basis",
    valid: "Pass",
    invalid: "Failed",
    unmatched: "Rules pass; no database match",
    empty: "Enter values to begin. Auto mode recognizes IPs, mobile numbers, Chinese IDs, and bank cards per line.",
    source: "Source",
    cached: "Loaded",
    loadingPack: "Loading data pack",
    error: "Lookup failed",
    limit: "More than 5,000 values. Split the input into smaller batches.",
    auto: "Auto detect",
    ip: "IP address",
    phone: "Mobile",
    id: "Chinese ID",
    bank: "Bank card"
  }, [zh]);
  const [kind, setKind] = React.useState<LookupKind>("auto");
  const [input, setInput] = React.useState("");
  const [results, setResults] = React.useState<LookupResult[]>([]);
  const [resultQuery, setResultQuery] = React.useState("");
  const [resultStatus, setResultStatus] = React.useState("all");
  const [resultPage, setResultPage] = React.useState(0);
  const deferredQuery = React.useDeferredValue(resultQuery);
  const filteredResults = React.useMemo(() => {
    const query = deferredQuery.trim().toLowerCase();
    return results.filter((result) => {
      if (resultStatus === "failed" && result.valid) return false;
      if (resultStatus === "unmatched" && (!result.valid || result.matched)) return false;
      return !query || [result.input, result.normalized, result.summary, ...Object.values(result.fields)].join(" ").toLowerCase().includes(query);
    });
  }, [results, deferredQuery, resultStatus]);
  const pageCount = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  const currentPage = Math.min(resultPage, pageCount - 1);
  const visibleResults = filteredResults.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const resetResultView = () => { setResultQuery(""); setResultStatus("all"); setResultPage(0); };
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [progress, setProgress] = React.useState(0);
  const [packStates, setPackStates] = React.useState<Partial<Record<ResolvedLookupKind, PackState>>>({});
  const workerRef = React.useRef<Worker | null>(null);
  const requestIdRef = React.useRef(0);
  const runContextRef = React.useRef<{ startedAt: string; kind: LookupKind; lang: Lang }>({ startedAt: "", kind: "auto", lang });

  const stop = React.useCallback(() => {
    requestIdRef.current += 1;
    workerRef.current?.terminate();
    workerRef.current = null;
    setBusy(false);
    setProgress(0);
    setPackStates({});
  }, []);

  const ensureWorker = () => {
    if (workerRef.current) return workerRef.current;
    const worker = new Worker(new URL("../features/lookup/lookup.worker.ts", import.meta.url), { type: "module" });
    workerRef.current = worker;
    worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
      const message = event.data;
      if (message.requestId !== requestIdRef.current) return;
      if (message.type === "progress") {
        setPackStates((current) => ({ ...current, [message.pack]: { state: message.state, detail: message.detail ?? "" } }));
      } else if (message.type === "batch-progress") {
        setProgress(Math.round(message.completed / Math.max(1, message.total) * 100));
      } else if (message.type === "result") {
        resetResultView();
        setResults(message.results);
        setProgress(100);
        setBusy(false);
        publishAnalysisResult("lookup", buildLookupEnvelope(message.results, {
          lang: runContextRef.current.lang,
          kind: runContextRef.current.kind,
          startedAt: runContextRef.current.startedAt || new Date().toISOString()
        }));
      } else if (message.type === "error") {
        setError(message.error);
        setBusy(false);
      }
    };
    worker.onerror = (event) => {
      stop();
      setError(event.message || "Lookup worker failed");
    };
    return worker;
  };

  React.useEffect(() => () => {
    requestIdRef.current += 1;
    workerRef.current?.terminate();
    workerRef.current = null;
  }, []);

  useHomeToolDraft("lookup", active, (draft) => {
    stop();
    resetResultView();
    setResults((current) => current.length ? [] : current);
    setError("");
    clearAnalysisResult("lookup");
    setInput(draft);
    setKind("auto");
  });

  React.useEffect(() => {
    if (active) return;
    stop();
  }, [active, stop]);

  const values = React.useMemo(() => splitLookupInput(input, MAX_BATCH + 1), [input]);
  const overLimit = values.length > MAX_BATCH;
  const run = () => {
    if (!values.length || overLimit) return;
    if (busy) stop();
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setBusy(true);
    setError("");
    resetResultView();
    setResults((current) => current.length ? [] : current);
    clearAnalysisResult("lookup");
    setProgress(0);
    runContextRef.current = { startedAt: new Date().toISOString(), kind, lang };
    try {
      ensureWorker().postMessage({ requestId, kind, values, lang });
    } catch (caught) {
      stop();
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };
  const samples: Record<LookupKind, string> = {
    auto: "113.118.113.77\n13800138000\n11010519491231002X\n6222021001116240533",
    ip: "113.118.113.77\n8.8.8.8\n192.168.1.1",
    phone: "13800138000\n18957509123",
    id: "11010519491231002X\n110103198001010016",
    bank: "6222021001116240533\n4111111111111111"
  };
  const modeLabels: Record<LookupKind, string> = { auto: labels.auto, ip: labels.ip, phone: labels.phone, id: labels.id, bank: labels.bank };
  const kindLabels: Record<ResolvedLookupKind, string> = { ip: labels.ip, phone: labels.phone, id: labels.id, bank: labels.bank };
  const activePacks = Object.entries(packStates).filter(([, state]) => state && state.state !== "idle") as Array<[ResolvedLookupKind, PackState]>;

  return (
    <div className={`tool-grid lookup-workbench ${results.length ? "has-lookup" : "empty-lookup"}`}>
      <section className="tool-panel lookup-intake-panel">
        <ToolPanelHeader title={labels.title} subtitle={labels.subtitle} />
        <ASegmentedGroup className="lookup-mode-tabs" value={kind} selects="single" aria-label={labels.type}>
          {(Object.keys(modeLabels) as LookupKind[]).map((mode) => <ASegmentedButton key={mode} value={mode} onClick={() => { stop(); setKind(mode); resetResultView(); setResults((current) => current.length ? [] : current); setError(""); clearAnalysisResult("lookup"); }}>{modeLabels[mode]}</ASegmentedButton>)}
        </ASegmentedGroup>
        <AutoTextarea
          className="single-textarea lookup-input"
          value={input}
          onChange={(event) => { stop(); setInput(event.currentTarget.value); if (results.length) resetResultView(); setResults((current) => current.length ? [] : current); setError(""); clearAnalysisResult("lookup"); }}
          placeholder={labels.placeholder}
          spellCheck={false}
          aria-label={labels.input}
        />
        <div className="lookup-action-row">
          <div className="button-row">
            <AButton variant="filled" disabled={!values.length || overLimit || busy} loading={busy} onClick={run}>{busy ? labels.running : labels.run}</AButton>
            <AButton variant="outlined" disabled={busy} onClick={() => { stop(); setInput(samples[kind]); resetResultView(); setResults((current) => current.length ? [] : current); setError(""); clearAnalysisResult("lookup"); }}>{labels.sample}</AButton>
            <AButton variant="text" disabled={!input && !results.length && !busy} onClick={() => { stop(); setInput(""); resetResultView(); setResults((current) => current.length ? [] : current); setError(""); clearAnalysisResult("lookup"); }}>{labels.clear}</AButton>
          </div>
          <span>{overLimit ? "> 5,000" : values.length.toLocaleString()} / {MAX_BATCH.toLocaleString()}</span>
        </div>
        {busy && <ALinearProgress />}
        {busy && progress > 0 && <span className="lookup-progress-label">{progress}%</span>}
        {overLimit && <div className="error-banner" role="alert">{labels.limit}</div>}
        {error && <div className="error-banner" role="alert"><strong>{labels.error}</strong><span>{lookupDataPackMessage(error, lang)}</span></div>}
        <div className="lookup-pack-row" aria-live="polite">
          {activePacks.map(([pack, state]) => (
            <span key={pack} className={`lookup-pack lookup-pack--${state.state}`}>
              {kindLabels[pack]} · {state.state === "loading" ? labels.loadingPack : state.state === "ready" ? `${labels.cached}${state.detail ? ` · ${pack === "id" ? `${Number(state.detail).toLocaleString()} codes` : formatBytes(Number(state.detail))}` : ""}` : lookupDataPackMessage(state.detail, lang)}
            </span>
          ))}
        </div>
      </section>

      <section className="tool-panel lookup-results-panel">
        <ToolPanelHeader
          title={`${labels.results}${results.length ? ` · ${results.length.toLocaleString()}` : ""}`}
          actions={
            <>
            <AButton variant="outlined" disabled={!results.length} onClick={() => downloadTextFile(`lookup-${Date.now()}.csv`, resultsToCsv(results), "text/csv;charset=utf-8")}>{labels.exportCsv}</AButton>
            <AButton variant="text" disabled={!results.length} onClick={() => void copyText(JSON.stringify(results, null, 2))}>{labels.copyJson}</AButton>
            </>
          }
        />
        {!results.length ? <div className="empty-state">{labels.empty}</div> : (
          <>
          <div className="lookup-result-controls">
            <input type="search" className="text-input lookup-result-search" aria-label={labels.searchResults} placeholder={labels.searchResults} value={resultQuery} onChange={(event) => { setResultQuery(event.currentTarget.value); setResultPage(0); }} />
            <ASelect aria-label={labels.filterStatus} value={resultStatus} onChange={(value) => { setResultStatus(String(value)); setResultPage(0); }} options={[
              { value: "all", label: labels.allStatuses }, { value: "failed", label: labels.failedOnly }, { value: "unmatched", label: labels.unmatchedOnly }
            ]} />
            {(resultQuery || resultStatus !== "all") && <AButton variant="text" onClick={resetResultView}>{labels.resetFilter}</AButton>}
          </div>
          {!filteredResults.length && <div className="empty-state" role="status">{labels.noMatches}</div>}
          <div className="table-scroll lookup-result-scroll">
            <table className="data-table lookup-result-table">
              <thead><tr><th>{labels.input}</th><th>{labels.type}</th><th>{labels.status}</th><th>{labels.summary}</th><th>{labels.details}</th></tr></thead>
              <tbody>{visibleResults.map((result, index) => (
                <tr key={`${result.kind}-${result.normalized}-${index}`}>
                  <td className="mono-cell">{result.normalized || result.input}</td>
                  <td><span className="lookup-kind-chip">{kindLabels[result.kind]}</span></td>
                  <td><span className={`lookup-status lookup-status--${result.valid ? (result.matched ? "ok" : "partial") : "bad"}`}>{result.valid ? (result.matched ? labels.valid : labels.unmatched) : labels.invalid}</span></td>
                  <td><strong>{result.summary}</strong>{result.notes[0] && <small>{result.notes[0]}</small>}</td>
                  <td>
                    <details className="lookup-row-details">
                      <summary>{labels.details}</summary>
                      <dl>{displayFields(result, lang).map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>
                      {result.notes.slice(1).map((note) => <p key={note}>{note}</p>)}
                      <p><strong>{labels.source}：</strong>{result.source} · {result.dataVersion}</p>
                    </details>
                  </td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="lookup-pagination">
            <span aria-live="polite">{filteredResults.length ? currentPage * PAGE_SIZE + 1 : 0}–{Math.min((currentPage + 1) * PAGE_SIZE, filteredResults.length)} / {filteredResults.length.toLocaleString()}</span>
            <div className="button-row">
              <AButton variant="outlined" disabled={currentPage === 0} onClick={() => setResultPage(currentPage - 1)}>{labels.previous}</AButton>
              <AButton variant="outlined" disabled={currentPage >= pageCount - 1} onClick={() => setResultPage(currentPage + 1)}>{labels.next}</AButton>
            </div>
          </div>
          </>
        )}
      </section>
    </div>
  );
}

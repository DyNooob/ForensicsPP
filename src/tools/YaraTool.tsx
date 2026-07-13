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
import { AButton, ALinearProgress, InfoTable, ToolPanelHeader } from "../components/ui";
import { copy } from "../i18n";
import type { YaraBatchRow, YaraRuleResult, YaraScanResult } from "../models";
import { previewText } from "../utils/binary";
import { downloadTextFile, formatBytes } from "../utils/files";
import { useStoredState } from "../utils/storage";
import { runWorkerTask } from "../utils/workerTask";

type RuleTemplate = { id: string; label: string; rule: string };

export type YaraToolServices = {
  yaraRuleTemplates: RuleTemplate[];
  defaultYaraSample: string;
  yaraHitsToCsv: (results: YaraRuleResult[]) => string;
  yaraBatchRowsToCsv: (rows: YaraBatchRow[]) => string;
};

export function YaraTool({ t, services }: { t: (typeof copy)["zh"]; services: YaraToolServices }) {
  const english = t.waiting === "Waiting";
  const [rules, setRules] = useStoredState("yara.rules.v2", "");
  const [sample, setSample] = React.useState("");
  const [sampleName, setSampleName] = React.useState("text sample");
  const [sampleBytes, setSampleBytes] = React.useState<Uint8Array>(() => new TextEncoder().encode(sample));
  const [result, setResult] = React.useState<YaraScanResult | null>(null);
  const [batchRows, setBatchRows] = React.useState<YaraBatchRow[]>([]);
  const [selectedRule, setSelectedRule] = React.useState("");
  const [hitFilter, setHitFilter] = React.useState("");
  const [dropActive, setDropActive] = React.useState(false);
  const [scanning, setScanning] = React.useState(false);
  const [error, setError] = React.useState("");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);
  const selectedResult = selectedRule && result
    ? result.results.find((item) => item.rule.name === selectedRule) ?? null
    : null;
  const matchedResults = result?.results.filter((item) => item.matched) ?? [];
  const totalStringHits = matchedResults.reduce((sum, item) => sum + item.hits.reduce((inner, hit) => inner + hit.count, 0), 0);
  const visibleHits = React.useMemo(() => {
    if (!result) return [];
    const query = hitFilter.trim().toLowerCase();
    return result.results
      .filter((item) => !selectedResult || item.rule.name === selectedResult.rule.name)
      .flatMap((item) => item.hits.filter((hit) => hit.count > 0).map((hit) => ({ item, hit })))
      .filter(({ item, hit }) => !query || [item.rule.name, hit.id, hit.pattern, hit.preview, hit.contexts.join(" ")].join(" ").toLowerCase().includes(query));
  }, [hitFilter, result, selectedResult]);

  const invalidate = () => {
    setResult(null);
    setBatchRows([]);
    setSelectedRule("");
    setHitFilter("");
    setError("");
  };

  const scanSample = (bytes: Uint8Array, name: string, signal: AbortSignal) => {
    const workerBytes = bytes.slice();
    return runWorkerTask<{ ruleText: string; data: ArrayBuffer; name: string; timeoutMs: number }, YaraScanResult>({
      createWorker: () => new Worker(new URL("../features/yara/yara.worker.ts", import.meta.url), { type: "module" }),
      request: { ruleText: rules, data: workerBytes.buffer, name, timeoutMs: 10_000 },
      transfer: [workerBytes.buffer],
      signal,
      timeoutMs: 20_000
    });
  };

  const runTextScan = async () => {
    const bytes = sampleName === "text sample" ? new TextEncoder().encode(sample) : sampleBytes;
    setSampleBytes(bytes);
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    setScanning(true);
    setError("");
    try {
      const next = await scanSample(bytes, sampleName, controller.signal);
      if (controller.signal.aborted) return;
      setResult(next);
      setSelectedRule(next.results.find((item) => item.matched)?.rule.name ?? "");
      setBatchRows([]);
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setScanning(false);
      }
    }
  };

  const handleFiles = async (files?: FileList | null) => {
    if (!files?.length) return;
    setScanning(true);
    setDropActive(false);
    setError("");
    const rows: YaraBatchRow[] = [];
    const controller = new AbortController();
    abortRef.current?.abort();
    abortRef.current = controller;
    try {
      const selectedFiles = Array.from(files).slice(0, 25);
      let firstResult: YaraScanResult | null = null;
      for (const [index, file] of selectedFiles.entries()) {
        await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
        if (controller.signal.aborted) break;
        const bytes = new Uint8Array(await file.slice(0, 32 * 1024 * 1024).arrayBuffer());
        const scan = await scanSample(bytes, file.name, controller.signal);
        const matchedRules = scan.results.filter((item) => item.matched).map((item) => item.rule.name);
        rows.push({
          name: file.name,
          size: file.size,
          matchedRules,
          matchCount: matchedRules.length,
          stringHits: scan.results.reduce((sum, item) => sum + item.hits.reduce((inner, hit) => inner + hit.count, 0), 0),
          warnings: [
            ...(file.size > bytes.length ? [`Scanned first ${formatBytes(bytes.length)} of ${formatBytes(file.size)}`] : []),
            ...scan.results.flatMap((item) => item.errors)
          ]
        });
        if (index === 0) {
          firstResult = scan;
          setSampleName(file.name);
          setSampleBytes(bytes);
          setSample(previewText(bytes, Math.min(bytes.length, 20000)));
        }
      }
      setBatchRows(rows);
      setResult(firstResult);
      setSelectedRule(firstResult?.results.find((item) => item.matched)?.rule.name ?? "");
      if (files.length > selectedFiles.length) setError(english ? "Only the first 25 files were scanned." : "仅扫描前 25 个文件。");
    } catch (caught) {
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setScanning(false);
      }
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setScanning(false);
  };

  const loadDemo = () => {
    setRules(services.yaraRuleTemplates[0]?.rule ?? "");
    setSampleName("text sample");
    setSample(services.defaultYaraSample);
    setSampleBytes(new TextEncoder().encode(services.defaultYaraSample));
    invalidate();
  };

  const clear = () => {
    cancel();
    setSample("");
    setSampleName("text sample");
    setSampleBytes(new Uint8Array());
    invalidate();
    if (inputRef.current) inputRef.current.value = "";
  };

  React.useEffect(() => () => abortRef.current?.abort(), []);

  return (
    <div className={`tool-grid yara-simple-workbench yara-workbench ${result ? "has-yara" : "empty-yara"}`}>
      {scanning && <div className="wide-panel"><ALinearProgress /></div>}
      {error && <pre className="result-box wide-panel">{error}</pre>}

      <section className="tool-panel wide-panel yara-simple-input-panel">
        <ToolPanelHeader
          title={english ? "YARA scan" : "YARA 扫描"}
          actions={<AButton variant="text" disabled={!sample && !result} onClick={clear}>{t.clear}</AButton>}
        />

        <div className="yara-simple-section-heading">
          <strong>{t.yaraRules}</strong>
          <AButton variant="text" onClick={loadDemo}>{english ? "Load demo" : "载入示例"}</AButton>
        </div>
        <div className="button-row yara-simple-templates">
          {services.yaraRuleTemplates.map((template) => (
            <AButton key={template.id} variant="outlined" onClick={() => { setRules(template.rule); invalidate(); }}>{template.label}</AButton>
          ))}
        </div>
        <textarea className="single-textarea yara-simple-editor" aria-label={english ? "YARA rules" : "YARA 规则"} value={rules} onChange={(event) => { setRules(event.target.value); invalidate(); }} placeholder={english ? "Paste one or more YARA rules" : "粘贴一条或多条 YARA 规则"} />

        <div className="yara-simple-divider" />
        <div className="yara-simple-section-heading"><strong>{t.yaraSample}</strong></div>
        <input ref={inputRef} type="file" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { void handleFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        <div
          className={`desktop-drop-zone yara-drop-zone ${dropActive ? "active" : ""}`}
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
          onDrop={(event) => { event.preventDefault(); void handleFiles(event.dataTransfer.files); }}
        >
          <strong>{sampleName === "text sample" ? (english ? "Text sample" : "文本样本") : sampleName}</strong>
          <span>{sampleBytes.length ? formatBytes(sampleBytes.length) : (english ? "Drop up to 25 files" : "拖入最多 25 个文件")}</span>
        </div>
        <textarea className="single-textarea yara-simple-sample" aria-label={english ? "YARA text sample" : "YARA 文本样本"} value={sample} onChange={(event) => { setSampleName("text sample"); setSample(event.target.value); invalidate(); }} placeholder={t.textPlaceholder} />
        <div className="yara-simple-primary-action">
          <AButton variant="filled" disabled={scanning || !rules.trim() || !sample.trim()} onClick={() => void runTextScan()}>{t.run}</AButton>
          <AButton variant="outlined" disabled={scanning || !rules.trim()} onClick={() => inputRef.current?.click()}>{t.uploadSample}</AButton>
          {scanning && <AButton variant="outlined" onClick={cancel}>{english ? "Cancel" : "取消"}</AButton>}
        </div>
      </section>

      {result && (
        <section className="tool-panel wide-panel yara-simple-results-panel">
          <ToolPanelHeader
            title={t.ruleMatches}
            subtitle={sampleName === "text sample" ? (english ? "Text sample" : "文本样本") : sampleName}
            actions={<>
              <AButton variant="outlined" disabled={!result.results.length} onClick={() => downloadTextFile(`yara-hits-${Date.now()}.csv`, services.yaraHitsToCsv(result.results), "text/csv;charset=utf-8")}>{english ? "Hits CSV" : "命中 CSV"}</AButton>
              <AButton variant="text" disabled={!batchRows.length} onClick={() => downloadTextFile(`yara-batch-${Date.now()}.csv`, services.yaraBatchRowsToCsv(batchRows), "text/csv;charset=utf-8")}>{english ? "Batch CSV" : "批量 CSV"}</AButton>
            </>}
          />

          <div className="yara-simple-summary">
            <span><small>{english ? "Rules" : "规则"}</small><strong>{result.results.length}</strong></span>
            <span><small>{t.matched}</small><strong>{matchedResults.length}</strong></span>
            <span><small>{english ? "String hits" : "字符串命中"}</small><strong>{totalStringHits}</strong></span>
            <span><small>{english ? "Files" : "文件"}</small><strong>{batchRows.length || 1}</strong></span>
          </div>

          <div className="table-scroll yara-simple-rule-scroll">
            <table className="data-table yara-simple-rule-table">
              <thead><tr><th>{english ? "Rule" : "规则"}</th><th>{english ? "Matched" : "命中"}</th><th>{english ? "Tags" : "标签"}</th><th>{english ? "Strings" : "字符串"}</th><th>{english ? "Condition" : "条件"}</th><th>{english ? "Errors" : "错误"}</th></tr></thead>
              <tbody>
                {result.results.map((item) => (
                  <tr className={selectedResult?.rule.name === item.rule.name ? "selected-row" : ""} key={item.rule.name} onClick={() => setSelectedRule(item.rule.name)}>
                    <td>{item.rule.name}</td>
                    <td>{item.matched ? (english ? "Yes" : "是") : (english ? "No" : "否")}</td>
                    <td>{item.rule.tags.join(", ") || "--"}</td>
                    <td>{item.hits.filter((hit) => hit.count).length}/{item.hits.length}</td>
                    <td className="yara-simple-condition">{item.condition}</td>
                    <td>{item.errors.join("; ") || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {result && (
        <section className="tool-panel wide-panel yara-simple-hits-panel">
          <ToolPanelHeader
            title={t.stringMatches}
            subtitle={selectedResult ? selectedResult.rule.name : (english ? "All matched rules" : "全部命中规则")}
          />
          <input className="text-input yara-simple-hit-filter" aria-label={english ? "Filter YARA hits" : "筛选 YARA 命中"} value={hitFilter} onChange={(event) => setHitFilter(event.target.value)} placeholder={english ? "Filter ID, pattern, or context" : "筛选 ID、模式或上下文"} />
          {visibleHits.length ? (
            <div className="table-scroll yara-simple-hit-scroll">
              <table className="data-table yara-simple-hit-table">
                <thead><tr><th>{english ? "Rule" : "规则"}</th><th>ID</th><th>{english ? "Pattern" : "模式"}</th><th>{english ? "Count" : "次数"}</th><th>{t.offsets}</th><th>{t.regexContext}</th></tr></thead>
                <tbody>
                  {visibleHits.map(({ item, hit }) => (
                    <tr key={`${item.rule.name}-${hit.id}`}>
                      <td>{item.rule.name}</td>
                      <td>{hit.id}</td>
                      <td className="mono-cell">{hit.pattern}</td>
                      <td>{hit.count}</td>
                      <td className="mono-cell">{hit.offsets.map((offset) => `0x${offset.toString(16).toUpperCase()}`).join(", ") || "--"}</td>
                      <td className="yara-simple-context-cell">{hit.contexts.join("\n") || hit.preview || "--"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty-state">{english ? "No string hits" : "没有字符串命中"}</div>}
        </section>
      )}

      {selectedResult && (
        <section className="tool-panel wide-panel yara-simple-detail-panel">
          <ToolPanelHeader title={english ? "Selected rule" : "当前规则"} />
          <InfoTable rows={[
            [english ? "Rule" : "规则", selectedResult.rule.name],
            [english ? "Matched" : "命中", selectedResult.matched ? (english ? "Yes" : "是") : (english ? "No" : "否")],
            [english ? "Tags" : "标签", selectedResult.rule.tags.join(", ") || "--"],
            [english ? "Condition" : "条件", selectedResult.condition],
            ["Meta", selectedResult.rule.meta.map(([key, value]) => `${key}=${value}`).join(", ") || "--"],
            [english ? "Errors" : "错误", selectedResult.errors.join("; ") || "--"]
          ]} />
        </section>
      )}

      {batchRows.length > 1 && (
        <section className="tool-panel wide-panel yara-simple-batch-panel">
          <ToolPanelHeader title={t.yaraBatch} subtitle={`${batchRows.length} ${english ? "files" : "个文件"}`} />
          <div className="table-scroll yara-simple-batch-scroll">
            <table className="data-table">
              <thead><tr><th>{english ? "Name" : "名称"}</th><th>{t.fileSize}</th><th>{t.matched}</th><th>{english ? "Rules" : "规则"}</th><th>{english ? "String hits" : "字符串命中"}</th><th>{english ? "Notes" : "说明"}</th></tr></thead>
              <tbody>
                {batchRows.map((row) => (
                  <tr key={`${row.name}-${row.size}`}>
                    <td>{row.name}</td><td>{formatBytes(row.size)}</td><td>{row.matchCount}</td><td>{row.matchedRules.join(", ") || "--"}</td><td>{row.stringHits}</td><td>{row.warnings.join("; ") || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

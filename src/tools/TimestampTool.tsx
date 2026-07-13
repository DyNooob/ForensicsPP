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
import { AButton, ASelect, ASegmentedButton, ASegmentedGroup, ToolPanelHeader } from "../components/ui";
import {
  COCOA_EPOCH_MS,
  dateRows,
  DAY_MS,
  DOTNET_EPOCH_OFFSET_MS,
  generalizedTime,
  GPS_EPOCH_MS,
  HFS_EPOCH_OFFSET_MS,
  parseTimestampCandidates,
  parseTimestampRows,
  timestampCandidateKey,
  timestampCandidateRows,
  timestampRowsToCsv,
  timelineToCsv
} from "../features/timestamp/analyzer";
import { copy } from "../i18n";
import { downloadTextFile } from "../utils/files";
import { FILETIME_EPOCH_OFFSET_MS } from "../utils/forensics";

type TimestampPage = "single" | "batch";

export function TimestampTool({ t }: { t: (typeof copy)["zh"] }) {
  const [input, setInput] = React.useState("");
  const [batchInput, setBatchInput] = React.useState("");
  const [submittedInput, setSubmittedInput] = React.useState("");
  const [submittedBatchInput, setSubmittedBatchInput] = React.useState("");
  const [page, setPage] = React.useState<TimestampPage>(() => input.trim() ? "single" : batchInput.trim() ? "batch" : "single");
  const [selectedCandidateKey, setSelectedCandidateKey] = React.useState("");
  const [batchFilter, setBatchFilter] = React.useState("");
  const [batchFormat, setBatchFormat] = React.useState("");
  const [outputScope, setOutputScope] = React.useState<"common" | "all">("common");
  const english = t.waiting === "Waiting";
  const hasInput = Boolean(submittedInput.trim());

  const rows = React.useMemo<Array<[string, string]>>(() => {
    if (!hasInput) return [];
    try {
      return parseTimestampRows(submittedInput);
    } catch (error) {
      return [[t.timestamp, error instanceof Error ? error.message : String(error)]];
    }
  }, [hasInput, submittedInput, t.timestamp]);
  const candidates = React.useMemo(() => timestampCandidateRows(rows), [rows]);
  const selectedCandidate = React.useMemo(() => {
    if (!candidates.length) return null;
    return candidates.find((candidate, index) => timestampCandidateKey(candidate, index) === selectedCandidateKey) ?? candidates[0];
  }, [candidates, selectedCandidateKey]);
  const conversions = React.useMemo(() => selectedCandidate ? dateRows(new Date(selectedCandidate[1])) : [], [selectedCandidate]);
  const commonConversionLabels = React.useMemo(() => new Set(["ISO", "Local", "UTC", "Unix seconds", "Unix milliseconds", selectedCandidate?.[0] ?? ""]), [selectedCandidate]);
  const visibleConversions = React.useMemo(() => outputScope === "all" ? conversions : conversions.filter(([label]) => commonConversionLabels.has(label)), [commonConversionLabels, conversions, outputScope]);
  const conversionMap = React.useMemo(() => new Map(conversions), [conversions]);

  const batchEvents = React.useMemo(() => parseTimestampCandidates(submittedBatchInput, "timestamp batch"), [submittedBatchInput]);
  const batchFormats = React.useMemo(() => Array.from(new Set(batchEvents.map((event) => event.format))).sort(), [batchEvents]);
  const visibleBatchEvents = React.useMemo(() => {
    const query = batchFilter.trim().toLowerCase();
    return batchEvents.filter((event) => {
      if (batchFormat && event.format !== batchFormat) return false;
      return !query || [event.iso, event.local, event.raw, event.format, event.context].join(" ").toLowerCase().includes(query);
    });
  }, [batchEvents, batchFilter, batchFormat]);

  const setSingleValue = (value: string) => {
    setInput(value);
    setSubmittedInput(value);
    setSelectedCandidateKey("");
    setPage("single");
  };
  const currentTimePresets = React.useMemo(() => {
    const currentMs = Date.now();
    const current = BigInt(currentMs);
    return [
      { id: "unix", label: "Unix seconds", value: Math.floor(currentMs / 1000).toString() },
      { id: "unix-ms", label: "Unix milliseconds", value: currentMs.toString() },
      { id: "filetime", label: "Windows FILETIME", value: ((current + FILETIME_EPOCH_OFFSET_MS) * 10000n).toString() },
      { id: "chrome", label: "Chrome/WebKit", value: ((current + FILETIME_EPOCH_OFFSET_MS) * 1000n).toString() },
      { id: "dotnet", label: ".NET ticks", value: ((current + DOTNET_EPOCH_OFFSET_MS) * 10000n).toString() },
      { id: "ole", label: "OLE / Excel days", value: (currentMs / DAY_MS + 25569).toFixed(8).replace(/0+$/, "").replace(/\.$/, "") },
      { id: "cocoa", label: "Cocoa / CoreData", value: ((currentMs - COCOA_EPOCH_MS) / 1000).toFixed(3).replace(/\.000$/, "") },
      { id: "hfs", label: "HFS+ seconds", value: Math.floor((currentMs + HFS_EPOCH_OFFSET_MS) / 1000).toString() },
      { id: "gps", label: "GPS seconds", value: Math.floor((currentMs - GPS_EPOCH_MS) / 1000).toString() },
      { id: "ldap", label: "LDAP GeneralizedTime", value: generalizedTime(new Date(currentMs)) },
      { id: "iso", label: "ISO 8601", value: new Date(currentMs).toISOString() }
    ];
  }, []);
  const [preset, setPreset] = React.useState("unix");
  const applyPreset = () => {
    const item = currentTimePresets.find((candidate) => candidate.id === preset) ?? currentTimePresets[0];
    setSingleValue(item.value);
  };
  const clearSingle = () => {
    setInput("");
    setSubmittedInput("");
    setSelectedCandidateKey("");
  };

  return (
    <div className={`tool-grid timestamp-workbench timestamp-simple-workbench ${hasInput || submittedBatchInput.trim() ? "has-timestamp" : "empty-timestamp"}`}>
      <ASegmentedGroup className="timestamp-page-tabs wide-panel" value={page} selects="single" aria-label={english ? "Timestamp workspace" : "时间戳工作区"}>
        <ASegmentedButton value="single" onClick={() => setPage("single")}>{english ? "Single value" : "单值转换"}</ASegmentedButton>
        <ASegmentedButton value="batch" onClick={() => setPage("batch")}>{english ? "Batch extract" : "批量提取"}{batchEvents.length ? ` (${batchEvents.length})` : ""}</ASegmentedButton>
      </ASegmentedGroup>

      {page === "single" && <>
        <div className="tool-panel wide-panel timestamp-simple-input-panel">
          <ToolPanelHeader title={english ? "Timestamp input" : "时间戳输入"} actions={<AButton variant="text" disabled={!hasInput} onClick={clearSingle}>{t.clear}</AButton>} />
          <input className="text-input full-input" aria-label={english ? "Timestamp value" : "时间戳数值"} value={input} onChange={(event) => { setInput(event.currentTarget.value); setSelectedCandidateKey(""); }} placeholder="1719705600 / 133638048000000000 / 20260706083045Z" />
          <div className="timestamp-preset-row">
            <ASelect aria-label={english ? "Timestamp format" : "时间戳格式"} value={preset} onChange={(value) => setPreset(String(value))} options={currentTimePresets.map((item) => ({ value: item.id, label: item.label }))} />
            <AButton variant="outlined" onClick={applyPreset}>{english ? "Use current time" : "使用当前时间"}</AButton>
            <AButton variant="filled" disabled={!input.trim()} onClick={() => { setSubmittedInput(input); setSelectedCandidateKey(""); }}>{english ? "Convert" : "转换"}</AButton>
          </div>
        </div>

        {hasInput && <div className="tool-panel wide-panel timestamp-simple-result-panel">
          <ToolPanelHeader
            title={english ? "Conversion result" : "转换结果"}
            subtitle={selectedCandidate?.[0] ?? (english ? "No supported format" : "未匹配支持格式")}
            actions={<>
              <ASegmentedGroup value={outputScope} selects="single" aria-label={english ? "Conversion output scope" : "转换结果范围"}>
                <ASegmentedButton value="common" onClick={() => setOutputScope("common")}>{english ? "Common" : "常用"}</ASegmentedButton>
                <ASegmentedButton value="all" onClick={() => setOutputScope("all")}>{english ? "All" : "全部"}</ASegmentedButton>
              </ASegmentedGroup>
              <AButton variant="outlined" disabled={!selectedCandidate} onClick={() => selectedCandidate && void navigator.clipboard.writeText(selectedCandidate[1])}>{english ? "Copy ISO" : "复制 ISO"}</AButton>
              <AButton variant="outlined" disabled={!conversionMap.get("Unix milliseconds")} onClick={() => void navigator.clipboard.writeText(conversionMap.get("Unix milliseconds") ?? "")}>{english ? "Copy Unix ms" : "复制 Unix ms"}</AButton>
              <AButton variant="text" disabled={!selectedCandidate} onClick={() => downloadTextFile(`timestamp-${Date.now()}.csv`, timestampRowsToCsv(rows, candidates), "text/csv;charset=utf-8")}>{t.exportTimestampCsv}</AButton>
            </>}
          />
          {selectedCandidate ? <div className="table-scroll compact-scroll"><table className="data-table timestamp-conversion-table"><thead><tr><th>{english ? "Format" : "格式"}</th><th>{english ? "Value" : "值"}</th><th>{t.copy}</th></tr></thead><tbody>
            {visibleConversions.map(([label, value]) => <tr key={`${label}-${value}`}><td>{label}</td><td className="mono-cell">{value}</td><td><AButton variant="text" disabled={!value || value === "--"} onClick={() => void navigator.clipboard.writeText(value)}>{t.copy}</AButton></td></tr>)}
          </tbody></table></div> : <div className="empty-state error-state">{rows[0]?.[1] || (english ? "Unsupported timestamp" : "无法识别时间戳")}</div>}
        </div>}

        {candidates.length > 1 && <details className="tool-panel wide-panel timestamp-simple-candidates-panel">
          <summary><span>{t.timestampCandidates}</span><small>{english ? `${candidates.length} possible interpretations` : `${candidates.length} 个可能解释`}</small></summary>
          <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.format}</th><th>ISO</th><th>{t.copy}</th></tr></thead><tbody>{candidates.map((candidate, index) => {
            const key = timestampCandidateKey(candidate, index);
            const active = selectedCandidate?.[0] === candidate[0] && selectedCandidate?.[1] === candidate[1];
            return <tr className={active ? "selected-row" : ""} key={key} onClick={() => setSelectedCandidateKey(key)}><td>{candidate[0]}</td><td>{candidate[1]}</td><td><AButton variant="text" onClick={(event) => { event.stopPropagation(); void navigator.clipboard.writeText(candidate[1]); }}>{t.copy}</AButton></td></tr>;
          })}</tbody></table></div>
        </details>}
      </>}

      {page === "batch" && <div className="tool-panel wide-panel timestamp-simple-batch-panel">
        <ToolPanelHeader
          title={english ? "Extract timestamps from text" : "从文本提取时间戳"}
          subtitle={`${visibleBatchEvents.length}/${batchEvents.length}`}
          actions={<>
            <AButton variant="outlined" disabled={!batchEvents.length} onClick={() => downloadTextFile(`timestamp-batch-${Date.now()}.csv`, timelineToCsv(visibleBatchEvents.length ? visibleBatchEvents : batchEvents), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              <AButton variant="filled" disabled={!batchInput.trim()} onClick={() => { setSubmittedBatchInput(batchInput); setBatchFilter(""); setBatchFormat(""); }}>{english ? "Extract" : "提取"}</AButton>
              <AButton variant="text" disabled={!batchInput && !submittedBatchInput} onClick={() => { setBatchInput(""); setSubmittedBatchInput(""); setBatchFilter(""); setBatchFormat(""); }}>{t.clear}</AButton>
          </>}
        />
        <textarea className="single-textarea timestamp-simple-batch-input" value={batchInput} onChange={(event) => setBatchInput(event.currentTarget.value)} placeholder={t.textPlaceholder} />
        <div className="timestamp-simple-batch-filter">
          <input className="text-input" aria-label={english ? "Filter extracted timestamps" : "筛选提取的时间戳"} value={batchFilter} onChange={(event) => setBatchFilter(event.currentTarget.value)} placeholder={english ? "Filter raw value, ISO, or context" : "筛选原值、ISO 或上下文"} />
          <ASelect aria-label={english ? "Batch result format" : "批量结果格式"} value={batchFormat} onChange={(value) => setBatchFormat(String(value))} options={[{ value: "", label: english ? "All formats" : "全部格式" }, ...batchFormats.map((format) => ({ value: format, label: format }))]} />
        </div>
        <div className="table-scroll timestamp-simple-batch-scroll">
          {visibleBatchEvents.length ? <table className="data-table timestamp-simple-batch-table"><thead><tr><th>ISO</th><th>{t.localTime}</th><th>{t.format}</th><th>{english ? "Raw" : "原值"}</th><th>{english ? "Line" : "行"}</th><th>{english ? "Context" : "上下文"}</th></tr></thead><tbody>{visibleBatchEvents.map((event) => <tr key={event.id}><td>{event.iso}</td><td>{event.local}</td><td>{event.format}</td><td>{event.raw}</td><td>{event.line}</td><td>{event.context}</td></tr>)}</tbody></table> : <div className="empty-state">{submittedBatchInput ? (english ? "No timestamp found" : "未提取到时间戳") : t.waiting}</div>}
        </div>
      </div>}
    </div>
  );
}

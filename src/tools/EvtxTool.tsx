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
import { AButton, ALinearProgress, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { evtxEventsToCsv, persistableEvtxResults, type EvtxEvent, type EvtxFileAnalysis } from "../features/evtx/analyzer";
import { parseSigmaRules, runSigmaRules, type SigmaMatch, type SigmaRule } from "../features/evtx/sigma";
import { copy } from "../i18n";
import { downloadTextFile, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";

const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_SIGMA_FILE_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS_PER_FILE = 50_000;
const PAGE_SIZE = 250;

type View = "overview" | "events" | "sigma" | "files";
type ParsedFile = EvtxFileAnalysis | { source: string; size: number; error: string };

function isAnalysis(file: ParsedFile): file is EvtxFileAnalysis {
  return "events" in file;
}

export function EvtxTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [selectedFiles, setSelectedFiles] = React.useState<File[]>([]);
  const [parsedFiles, setParsedFiles] = React.useState<ParsedFile[]>([]);
  const [view, setView] = React.useState<View>("overview");
  const [loading, setLoading] = React.useState(false);
  const [progress, setProgress] = React.useState("");
  const [error, setError] = React.useState("");
  const [filter, setFilter] = React.useState("");
  const [eventIdFilter, setEventIdFilter] = React.useState("");
  const [levelFilter, setLevelFilter] = React.useState("all");
  const [page, setPage] = React.useState(0);
  const [selectedEventId, setSelectedEventId] = React.useState("");
  const [sigmaText, setSigmaText] = React.useState("");
  const [sigmaRules, setSigmaRules] = React.useState<SigmaRule[]>([]);
  const [sigmaMatches, setSigmaMatches] = React.useState<SigmaMatch[]>([]);
  const [sigmaErrors, setSigmaErrors] = React.useState<string[]>([]);
  const [sigmaLoading, setSigmaLoading] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const sigmaInputRef = React.useRef<HTMLInputElement | null>(null);
  const parseAbortRef = React.useRef<AbortController | null>(null);
  const sigmaAbortRef = React.useRef<AbortController | null>(null);
  const runRef = React.useRef(0);
  const sigmaFileRef = React.useRef(0);
  const workspace = useToolWorkspace<ParsedFile[]>({
    id: "evtx",
    version: 2,
    isValid: (value): value is ParsedFile[] => Array.isArray(value) && value.every((file) => Boolean(file && typeof file === "object" && typeof (file as ParsedFile).source === "string")),
    onRestore: (value) => {
      setParsedFiles(value);
      setView(value.some(isAnalysis) ? "overview" : "files");
      setError("");
    }
  });

  const analyses = parsedFiles.filter(isAnalysis);
  const events = React.useMemo(() => analyses.flatMap((file) => file.events).sort((left, right) => left.timestamp.localeCompare(right.timestamp)), [parsedFiles]);
  const deferredFilter = React.useDeferredValue(filter);
  const filteredEvents = React.useMemo(() => {
    const query = deferredFilter.trim().toLowerCase();
    const wantedEventId = eventIdFilter.trim();
    return events.filter((event) => {
      if (wantedEventId && String(event.eventId ?? "") !== wantedEventId) return false;
      if (levelFilter !== "all" && String(event.level ?? "") !== levelFilter) return false;
      if (!query) return true;
      return [event.timestamp, event.provider, event.channel, event.computer, event.recordId, event.message, ...Object.entries(event.data).flat()].join(" ").toLowerCase().includes(query);
    });
  }, [deferredFilter, eventIdFilter, events, levelFilter]);
  const pageCount = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE));
  const visibleEvents = filteredEvents.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selectedEvent = events.find((event) => event.id === selectedEventId) ?? null;
  const providers = new Set(events.map((event) => event.provider).filter(Boolean));
  const channels = new Set(events.map((event) => event.channel).filter(Boolean));
  const firstEvent = events[0];
  const lastEvent = events[events.length - 1];

  React.useEffect(() => setPage(0), [eventIdFilter, filter, levelFilter]);
  React.useEffect(() => { if (page >= pageCount) setPage(pageCount - 1); }, [page, pageCount]);
  React.useEffect(() => () => { parseAbortRef.current?.abort(); sigmaAbortRef.current?.abort(); }, []);

  const queueFiles = (files?: FileList | null) => {
    workspace.clear();
    const next = Array.from(files ?? []).filter((file) => file.size > 0 && /\.evtx$/i.test(file.name));
    if (!next.length) {
      cancel();
      setSelectedFiles([]);
      setParsedFiles([]);
      setSelectedEventId("");
      setSigmaMatches([]);
      setSigmaErrors([]);
      setView("overview");
      setError(english ? "Select one or more .evtx files." : "请选择一个或多个 .evtx 文件。");
      return;
    }
    const tooLarge = next.find((file) => file.size > MAX_FILE_BYTES);
    const total = next.reduce((sum, file) => sum + file.size, 0);
    if (tooLarge || total > MAX_TOTAL_BYTES) {
      cancel();
      setSelectedFiles([]);
      setParsedFiles([]);
      setSelectedEventId("");
      setSigmaMatches([]);
      setSigmaErrors([]);
      setView("overview");
      setError(tooLarge
        ? (english ? `${tooLarge.name} exceeds 256 MiB.` : `${tooLarge.name} 超过 256 MiB。`)
        : (english ? "Selected files exceed 512 MiB in total." : "所选文件总大小超过 512 MiB。"));
      return;
    }
    setSelectedFiles(next);
    setParsedFiles([]);
    setSigmaMatches([]);
    setSelectedEventId("");
    setView("overview");
    setError("");
  };

  const analyze = async () => {
    if (!selectedFiles.length || loading) return;
    const run = runRef.current + 1;
    runRef.current = run;
    const controller = new AbortController();
    parseAbortRef.current?.abort();
    parseAbortRef.current = controller;
    setLoading(true);
    setParsedFiles([]);
    setError("");
    const results: ParsedFile[] = [];
    for (let index = 0; index < selectedFiles.length; index += 1) {
      if (runRef.current !== run) break;
      const file = selectedFiles[index];
      setProgress(english ? `Parsing ${index + 1}/${selectedFiles.length}: ${file.name}` : `正在解析 ${index + 1}/${selectedFiles.length}：${file.name}`);
      try {
        const bytes = await file.arrayBuffer();
        results.push(await runWorkerTask<{ source: string; bytes: ArrayBuffer; maxRecords: number }, EvtxFileAnalysis>({
          createWorker: () => new Worker(new URL("../features/evtx/evtx.worker.ts", import.meta.url), { type: "module" }),
          request: { source: file.name, bytes, maxRecords: MAX_RECORDS_PER_FILE },
          transfer: [bytes],
          signal: controller.signal,
          timeoutMs: 180_000
        }));
      } catch (caught) {
        if (caught instanceof DOMException && caught.name === "AbortError") break;
        results.push({ source: file.name, size: file.size, error: caught instanceof Error ? caught.message : String(caught) });
      }
      setParsedFiles([...results]);
    }
    if (runRef.current === run) {
      setLoading(false);
      setProgress("");
      setView(results.some(isAnalysis) ? "overview" : "files");
      if (results.length) workspace.save(persistableEvtxResults(results));
    }
    if (parseAbortRef.current === controller) parseAbortRef.current = null;
  };

  const cancel = () => {
    runRef.current += 1;
    parseAbortRef.current?.abort();
    parseAbortRef.current = null;
    sigmaAbortRef.current?.abort();
    sigmaAbortRef.current = null;
    setLoading(false);
    setSigmaLoading(false);
    setProgress("");
  };

  React.useEffect(() => {
    if (active) return;
    cancel();
  }, [active]);

  const clear = () => {
    workspace.clear();
    cancel();
    setSelectedFiles([]);
    setParsedFiles([]);
    setSelectedEventId("");
    setSigmaMatches([]);
    setSigmaErrors([]);
    setFilter("");
    setEventIdFilter("");
    setLevelFilter("all");
    setError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const loadSigma = () => {
    const parsed = parseSigmaRules(sigmaText);
    setSigmaRules(parsed.rules);
    setSigmaErrors(parsed.errors);
    setSigmaMatches([]);
  };

  const openSigmaFile = async (file: File | undefined) => {
    if (!file) return;
    const requestId = ++sigmaFileRef.current;
    setSigmaRules([]);
    setSigmaMatches([]);
    if (file.size > MAX_SIGMA_FILE_BYTES) {
      setSigmaText("");
      setSigmaErrors([english ? "Sigma rule file exceeds 2 MiB." : "Sigma 规则文件超过 2 MiB。"]);
      return;
    }
    try {
      const value = await file.text();
      if (requestId !== sigmaFileRef.current) return;
      setSigmaText(value);
      setSigmaErrors([]);
    } catch (caught) {
      if (requestId === sigmaFileRef.current) setSigmaErrors([caught instanceof Error ? caught.message : String(caught)]);
    }
  };

  const runSigma = async () => {
    const parsed = parseSigmaRules(sigmaText);
    setSigmaRules(parsed.rules);
    setSigmaErrors(parsed.errors);
    setSigmaMatches([]);
    if (!parsed.rules.length) return;
    sigmaAbortRef.current?.abort();
    const controller = new AbortController();
    sigmaAbortRef.current = controller;
    setSigmaLoading(true);
    try {
      const result = await runWorkerTask<{ events: EvtxEvent[]; rules: SigmaRule[] }, ReturnType<typeof runSigmaRules>>({
        createWorker: () => new Worker(new URL("../features/evtx/sigma.worker.ts", import.meta.url), { type: "module" }),
        request: { events, rules: parsed.rules },
        signal: controller.signal,
        timeoutMs: 60_000
      });
      if (controller.signal.aborted) return;
      setSigmaMatches(result.matches);
      setSigmaErrors([...parsed.errors, ...result.errors]);
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) {
        setSigmaErrors([...parsed.errors, caught instanceof Error ? caught.message : String(caught)]);
      }
    } finally {
      if (sigmaAbortRef.current === controller) {
        sigmaAbortRef.current = null;
        setSigmaLoading(false);
      }
    }
  };

  const views: View[] = ["overview", "events", "sigma", "files"];
  const labels: Record<View, [string, string]> = {
    overview: ["概览", "Overview"], events: ["事件", "Events"], sigma: ["Sigma", "Sigma"], files: ["来源文件", "Files"]
  };

  return (
    <div className={`tool-grid evtx-workbench ${parsedFiles.length ? "has-evtx" : "empty-evtx"}`}>
      <section className="tool-panel wide-panel">
        <ToolPanelHeader title={english ? "Windows event logs" : "Windows 事件日志"} actions={<AButton variant="text" disabled={!selectedFiles.length && !parsedFiles.length} onClick={clear}>{t.clear}</AButton>} />
        <input className="hidden-file-input" ref={inputRef} type="file" accept=".evtx" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { queueFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") inputRef.current?.click(); }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); queueFiles(event.dataTransfer.files); }}>
          <strong>{selectedFiles.length ? (english ? `${selectedFiles.length} EVTX file(s)` : `已选择 ${selectedFiles.length} 个 EVTX 文件`) : (english ? "Select EVTX files" : "选择 EVTX 文件")}</strong>
          <span>{selectedFiles.length ? formatBytes(selectedFiles.reduce((sum, file) => sum + file.size, 0)) : ".evtx"}</span>
        </div>
        <div className="button-row">
          <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{english ? "Select files" : "选择文件"}</AButton>
          <AButton variant="filled" disabled={!selectedFiles.length || loading} onClick={() => void analyze()}>{english ? "Parse logs" : "解析日志"}</AButton>
          {loading && <AButton variant="outlined" onClick={cancel}>{english ? "Cancel" : "取消"}</AButton>}
        </div>
        {loading && <><ALinearProgress /><div className="tool-loading-state">{progress}</div></>}
        {error && <div className="empty-state error-state">{error}</div>}
      </section>

      {parsedFiles.length > 0 && <section className="tool-panel wide-panel evtx-results-panel">
        <ToolPanelHeader title={english ? "Event log results" : "事件日志结果"} subtitle={`${events.length.toLocaleString()} ${english ? "events" : "条事件"}`} actions={view === "events" ? <AButton variant="outlined" disabled={!filteredEvents.length} onClick={() => downloadTextFile(`evtx-events-${Date.now()}.csv`, evtxEventsToCsv(filteredEvents), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton> : undefined} />
        <ASegmentedGroup className="evtx-tabs" value={view} selects="single">{views.map((item) => <ASegmentedButton key={item} value={item} onClick={() => setView(item)}>{labels[item][english ? 1 : 0]}{item === "events" ? ` (${events.length})` : item === "sigma" && sigmaMatches.length ? ` (${sigmaMatches.length})` : ""}</ASegmentedButton>)}</ASegmentedGroup>

        {view === "overview" && <InfoTable rows={[
          [english ? "Parsed files" : "已解析文件", `${analyses.length}/${parsedFiles.length}`],
          [english ? "Events" : "事件", events.length.toLocaleString()],
          [english ? "Time range" : "时间范围", firstEvent ? `${firstEvent.timestamp} → ${lastEvent.timestamp}` : "--"],
          [english ? "Providers" : "提供程序", providers.size.toLocaleString()],
          [english ? "Channels" : "通道", channels.size.toLocaleString()],
          [english ? "Skipped records" : "跳过记录", String(analyses.reduce((sum, file) => sum + file.skippedRecords, 0))],
          [english ? "Record limit" : "记录上限", analyses.some((file) => file.truncated) ? (english ? `${MAX_RECORDS_PER_FILE.toLocaleString()} per file (reached)` : `每文件 ${MAX_RECORDS_PER_FILE.toLocaleString()}（已达到）`) : (english ? `${MAX_RECORDS_PER_FILE.toLocaleString()} per file` : `每文件 ${MAX_RECORDS_PER_FILE.toLocaleString()}`)]
        ]} />}

        {view === "files" && <div className="table-scroll"><table className="data-table"><thead><tr><th>{english ? "File" : "文件"}</th><th>{english ? "Size" : "大小"}</th><th>{english ? "Version" : "版本"}</th><th>{english ? "Chunks" : "块"}</th><th>{english ? "Events" : "事件"}</th><th>{english ? "Status" : "状态"}</th></tr></thead><tbody>{parsedFiles.map((file) => <tr key={file.source}><td>{file.source}</td><td>{formatBytes(file.size)}</td>{isAnalysis(file) ? <><td>{file.version}</td><td>{file.chunkCount}</td><td>{file.parsedRecords}{file.truncated ? "+" : ""}</td><td>{file.dirty ? (english ? "Dirty log" : "未正常关闭") : (english ? "Parsed" : "已解析")}</td></> : <><td>--</td><td>--</td><td>0</td><td title={file.error}>{file.error}</td></>}</tr>)}</tbody></table></div>}

        {view === "events" && <>
          <div className="evtx-filter-row">
            <input className="text-input" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={english ? "Filter provider, message, computer, or event data" : "筛选提供程序、内容、计算机或事件数据"} aria-label={english ? "Filter events" : "筛选事件"} />
            <input className="text-input evtx-event-id-filter" value={eventIdFilter} onChange={(event) => setEventIdFilter(event.currentTarget.value.replace(/\D/g, ""))} placeholder="Event ID" aria-label="Event ID" />
            <ASelect value={levelFilter} onChange={(value) => setLevelFilter(String(value))} options={[{ value: "all", label: english ? "All levels" : "全部级别" }, ...[1, 2, 3, 4, 5].map((level) => ({ value: String(level), label: `${level} · ${["", "Critical", "Error", "Warning", "Information", "Verbose"][level]}` }))]} />
            <span>{filteredEvents.length.toLocaleString()}/{events.length.toLocaleString()}</span>
          </div>
          <div className="table-scroll evtx-event-table-scroll"><table className="data-table evtx-event-table"><thead><tr><th>{english ? "Time" : "时间"}</th><th>Event ID</th><th>{english ? "Provider" : "提供程序"}</th><th>{english ? "Level" : "级别"}</th><th>{english ? "Computer" : "计算机"}</th><th>{english ? "Summary" : "摘要"}</th></tr></thead><tbody>{visibleEvents.map((event) => <tr key={event.id} className={selectedEventId === event.id ? "selected-row" : ""} onClick={() => setSelectedEventId(event.id)}><td>{event.timestamp || "--"}</td><td>{event.eventId ?? "--"}</td><td title={event.provider}>{event.provider || "--"}</td><td>{event.levelName}</td><td>{event.computer || "--"}</td><td title={event.message}>{event.message || "--"}</td></tr>)}</tbody></table></div>
          {filteredEvents.length > PAGE_SIZE && <div className="evtx-pagination"><span>{page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, filteredEvents.length)} / {filteredEvents.length}</span><div className="button-row compact-buttons"><AButton variant="text" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{english ? "Previous" : "上一页"}</AButton><AButton variant="text" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{english ? "Next" : "下一页"}</AButton></div></div>}
          {selectedEvent && <div className="evtx-event-detail"><ToolPanelHeader title={`${selectedEvent.provider || "Event"} · ${selectedEvent.eventId ?? "--"}`} subtitle={`#${selectedEvent.recordId} · ${selectedEvent.source}`} actions={<AButton variant="outlined" disabled={!selectedEvent.xml} onClick={() => downloadTextFile(`event-${selectedEvent.recordId || Date.now()}.xml`, selectedEvent.xml, "application/xml;charset=utf-8")}>{selectedEvent.xml ? (english ? "Save XML" : "保存 XML") : (english ? "Re-analyze for XML" : "需重新分析 XML")}</AButton>} /><InfoTable rows={[[english ? "Time" : "时间", selectedEvent.timestamp || "--"], [english ? "Channel" : "通道", selectedEvent.channel || "--"], [english ? "Computer" : "计算机", selectedEvent.computer || "--"], ["User / Process / Thread", `${selectedEvent.userId || "--"} / ${selectedEvent.processId || "--"} / ${selectedEvent.threadId || "--"}`]]} />{Object.keys(selectedEvent.data).length > 0 && <div className="table-scroll evtx-data-table"><table className="data-table"><thead><tr><th>{english ? "Field" : "字段"}</th><th>{english ? "Value" : "值"}</th></tr></thead><tbody>{Object.entries(selectedEvent.data).map(([key, value]) => <tr key={key}><td>{key}</td><td>{value}</td></tr>)}</tbody></table></div>}<details className="evtx-xml-details"><summary>{english ? "Raw XML" : "原始 XML"}</summary>{selectedEvent.xml ? <textarea className="single-textarea mono-textarea evtx-xml" readOnly value={selectedEvent.xml} aria-label="Event XML" /> : <div className="empty-state">{english ? "Raw XML was not kept in the workspace snapshot. Re-analyze the file to retrieve it." : "工作区快照未保留原始 XML，请重新分析文件后查看。"}</div>}</details></div>}
        </>}

        {view === "sigma" && <div className="evtx-sigma-workspace">
          <input className="hidden-file-input" ref={sigmaInputRef} type="file" accept=".yml,.yaml,text/yaml" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void openSigmaFile(file); }} />
          <ToolPanelHeader title={english ? "Local Sigma matcher" : "本地 Sigma 匹配"} subtitle={sigmaRules.length ? `${sigmaRules.length} ${english ? "rule(s) loaded" : "条规则"}` : undefined} actions={<><AButton variant="outlined" onClick={() => sigmaInputRef.current?.click()}>{english ? "Open rules" : "打开规则"}</AButton><AButton variant="outlined" disabled={!sigmaText.trim() || sigmaLoading} onClick={loadSigma}>{english ? "Validate" : "校验"}</AButton><AButton variant="filled" disabled={!sigmaText.trim() || !events.length || sigmaLoading} onClick={runSigma}>{sigmaLoading ? (english ? "Running..." : "正在运行...") : (english ? "Run rules" : "运行规则")}</AButton></>} />
          {sigmaLoading && <ALinearProgress />}
          <textarea className="single-textarea mono-textarea evtx-sigma-editor" value={sigmaText} onChange={(event) => { sigmaFileRef.current += 1; setSigmaText(event.currentTarget.value); }} placeholder={english ? "Paste one or more Sigma YAML rules" : "粘贴一条或多条 Sigma YAML 规则"} />
          {sigmaErrors.length > 0 && <div className="empty-state error-state">{sigmaErrors.join("\n")}</div>}
          {sigmaMatches.length > 0 ? <div className="table-scroll evtx-sigma-matches"><table className="data-table"><thead><tr><th>{english ? "Rule" : "规则"}</th><th>{english ? "Level" : "级别"}</th><th>{english ? "Time" : "时间"}</th><th>Event ID</th><th>{english ? "Provider" : "提供程序"}</th><th>{english ? "Summary" : "摘要"}</th></tr></thead><tbody>{sigmaMatches.slice(0, 10_000).map((match, index) => <tr key={`${match.ruleId}:${match.event.id}:${index}`}><td>{match.ruleTitle}</td><td>{match.level || "--"}</td><td>{match.event.timestamp}</td><td>{match.event.eventId ?? "--"}</td><td>{match.event.provider}</td><td>{match.event.message || "--"}</td></tr>)}</tbody></table></div> : sigmaRules.length > 0 && <div className="empty-state">{english ? "No rule matches." : "没有规则匹配。"}</div>}
        </div>}
      </section>}
    </div>
  );
}

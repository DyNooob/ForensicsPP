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
import { clearAnalysisResult, publishAnalysisResult } from "../features/analysis/resultStore";
import { buildEvtxEnvelope } from "../features/evtx/envelope";
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";

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

  const queueFiles = (files?: FileList | File[] | null) => {
    if (!active) return;
    // Replacing the selection must stop an in-flight parse before its partial
    // results can be committed to the new workspace.
    cancel();
    workspace.clear();
    const next = Array.from(files ?? []).filter((file) => file.size > 0 && /\.evtx$/i.test(file.name));
    if (!next.length) {
      setSelectedFiles([]);
      setParsedFiles([]);
      setSelectedEventId("");
      setSigmaMatches([]);
      setSigmaErrors([]);
      setView("overview");
      setError(t.select_one_or_more_evtx_files);
      return;
    }
    const tooLarge = next.find((file) => file.size > MAX_FILE_BYTES);
    const total = next.reduce((sum, file) => sum + file.size, 0);
    if (tooLarge || total > MAX_TOTAL_BYTES) {
      setSelectedFiles([]);
      setParsedFiles([]);
      setSelectedEventId("");
      setSigmaMatches([]);
      setSigmaErrors([]);
      setView("overview");
      setError(tooLarge
        ? (english ? `${tooLarge.name} exceeds 256 MiB.` : `${tooLarge.name} 超过 256 MiB。`)
        : (t.selected_files_exceed_512_mib_in_total));
      return;
    }
    setSelectedFiles(next);
    setParsedFiles([]);
    setSigmaMatches([]);
    setSelectedEventId("");
    setView("overview");
    setError("");
  };

  const analyze = async (explicitFiles?: File[]) => {
    const files = explicitFiles ?? selectedFiles;
    if (!active || !files.length || loading) return;
    const run = runRef.current + 1;
    runRef.current = run;
    const startedAt = new Date().toISOString();
    const controller = new AbortController();
    parseAbortRef.current?.abort();
    parseAbortRef.current = controller;
    setLoading(true);
    setParsedFiles([]);
    setError("");
    const results: ParsedFile[] = [];
    for (let index = 0; index < files.length; index += 1) {
      if (!active || runRef.current !== run) break;
      const file = files[index];
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
      if (!active || runRef.current !== run) break;
      setParsedFiles([...results]);
    }
    if (active && runRef.current === run) {
      setLoading(false);
      setProgress("");
      setView(results.some(isAnalysis) ? "overview" : "files");
      if (results.length) workspace.save(persistableEvtxResults(results));
      const completedAt = new Date().toISOString();
      for (const file of results) {
        if (!("events" in file)) continue;
        publishAnalysisResult("evtx", buildEvtxEnvelope(file, { startedAt, completedAt }));
      }
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

  const queueFilesRef = React.useRef(queueFiles);
  queueFilesRef.current = queueFiles;
  const analyzeRef = React.useRef(analyze);
  analyzeRef.current = analyze;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("evtx");
      if (handoff) {
        queueFilesRef.current([handoff.file]);
        void analyzeRef.current([handoff.file]);
      }
    };
    consume();
    return subscribeToolHandoff("evtx", consume);
  }, [active]);

  const clear = () => {
    workspace.clear();
    clearAnalysisResult("evtx");
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
    if (!file || !active) return;
    const requestId = ++sigmaFileRef.current;
    setSigmaRules([]);
    setSigmaMatches([]);
    if (file.size > MAX_SIGMA_FILE_BYTES) {
      setSigmaText("");
      setSigmaErrors([t.sigma_rule_file_exceeds_2_mib]);
      return;
    }
    try {
      const value = await file.text();
      if (!active || requestId !== sigmaFileRef.current) return;
      setSigmaText(value);
      setSigmaErrors([]);
    } catch (caught) {
      if (active && requestId === sigmaFileRef.current) setSigmaErrors([caught instanceof Error ? caught.message : String(caught)]);
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
      if (!active || controller.signal.aborted) return;
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
        <ToolPanelHeader title={t.windows_event_logs} actions={<AButton variant="text" disabled={!selectedFiles.length && !parsedFiles.length} onClick={clear}>{t.clear}</AButton>} />
        <input className="hidden-file-input" ref={inputRef} type="file" accept=".evtx" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { queueFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
        <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") inputRef.current?.click(); }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); queueFiles(event.dataTransfer.files); }}>
          <strong>{selectedFiles.length ? (english ? `${selectedFiles.length} EVTX file(s)` : `已选择 ${selectedFiles.length} 个 EVTX 文件`) : (t.select_evtx_files)}</strong>
          <span>{selectedFiles.length ? formatBytes(selectedFiles.reduce((sum, file) => sum + file.size, 0)) : ".evtx"}</span>
        </div>
        <div className="button-row">
          <AButton variant="outlined" onClick={() => inputRef.current?.click()}>{t.select_files}</AButton>
          <AButton variant="filled" disabled={!selectedFiles.length || loading} onClick={() => void analyze()}>{t.parse_logs}</AButton>
          {loading && <AButton variant="outlined" onClick={cancel}>{t.cancelEdit}</AButton>}
        </div>
        {loading && <><ALinearProgress /><div className="tool-loading-state">{progress}</div></>}
        {error && <div className="empty-state error-state">{error}</div>}
      </section>

      {parsedFiles.length > 0 && <section className="tool-panel wide-panel evtx-results-panel">
        <ToolPanelHeader title={t.event_log_results} subtitle={`${events.length.toLocaleString()} ${t.events}`} actions={view === "events" ? <AButton variant="outlined" disabled={!filteredEvents.length} onClick={() => downloadTextFile(`evtx-events-${Date.now()}.csv`, evtxEventsToCsv(filteredEvents), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton> : undefined} />
        <ASegmentedGroup className="evtx-tabs" value={view} selects="single">{views.map((item) => <ASegmentedButton key={item} value={item} onClick={() => setView(item)}>{labels[item][english ? 1 : 0]}{item === "events" ? ` (${events.length})` : item === "sigma" && sigmaMatches.length ? ` (${sigmaMatches.length})` : ""}</ASegmentedButton>)}</ASegmentedGroup>

        {view === "overview" && <InfoTable rows={[
          [t.parsed_files, `${analyses.length}/${parsedFiles.length}`],
          [t.events_2, events.length.toLocaleString()],
          [t.time_range, firstEvent ? `${firstEvent.timestamp} → ${lastEvent.timestamp}` : "--"],
          [t.providers, providers.size.toLocaleString()],
          [t.channels_2, channels.size.toLocaleString()],
          [t.skipped_records, String(analyses.reduce((sum, file) => sum + file.skippedRecords, 0))],
          [t.record_limit, analyses.some((file) => file.truncated) ? (english ? `${MAX_RECORDS_PER_FILE.toLocaleString()} per file (reached)` : `每文件 ${MAX_RECORDS_PER_FILE.toLocaleString()}（已达到）`) : (english ? `${MAX_RECORDS_PER_FILE.toLocaleString()} per file` : `每文件 ${MAX_RECORDS_PER_FILE.toLocaleString()}`)]
        ]} />}

        {view === "files" && <div className="table-scroll"><table className="data-table"><thead><tr><th>{t.sourceFile}</th><th>{t.fileSize}</th><th>{t.version}</th><th>{t.chunks}</th><th>{t.events_2}</th><th>{t.status}</th></tr></thead><tbody>{parsedFiles.map((file) => <tr key={file.source}><td>{file.source}</td><td>{formatBytes(file.size)}</td>{isAnalysis(file) ? <><td>{file.version}</td><td>{file.chunkCount}</td><td>{file.parsedRecords}{file.truncated ? "+" : ""}</td><td>{file.dirty ? (t.dirty_log) : (t.parsed)}</td></> : <><td>--</td><td>--</td><td>0</td><td title={file.error}>{file.error}</td></>}</tr>)}</tbody></table></div>}

        {view === "events" && <>
          <div className="evtx-filter-row">
            <input className="text-input" value={filter} onChange={(event) => setFilter(event.currentTarget.value)} placeholder={t.filter_provider_message_computer_or_event_data} aria-label={t.filter_events} />
            <input className="text-input evtx-event-id-filter" value={eventIdFilter} onChange={(event) => setEventIdFilter(event.currentTarget.value.replace(/\D/g, ""))} placeholder="Event ID" aria-label="Event ID" />
            <ASelect value={levelFilter} onChange={(value) => setLevelFilter(String(value))} options={[{ value: "all", label: t.all_levels }, ...[1, 2, 3, 4, 5].map((level) => ({ value: String(level), label: `${level} · ${["", "Critical", "Error", "Warning", "Information", "Verbose"][level]}` }))]} />
            <span>{filteredEvents.length.toLocaleString()}/{events.length.toLocaleString()}</span>
          </div>
          <div className="table-scroll evtx-event-table-scroll"><table className="data-table evtx-event-table"><thead><tr><th>{t.time}</th><th>Event ID</th><th>{t.provider}</th><th>{t.level}</th><th>{t.computer}</th><th>{t.summary}</th></tr></thead><tbody>{visibleEvents.map((event) => <tr key={event.id} className={selectedEventId === event.id ? "selected-row" : ""} onClick={() => setSelectedEventId(event.id)}><td>{event.timestamp || "--"}</td><td>{event.eventId ?? "--"}</td><td title={event.provider}>{event.provider || "--"}</td><td>{event.levelName}</td><td>{event.computer || "--"}</td><td title={event.message}>{event.message || "--"}</td></tr>)}</tbody></table></div>
          {filteredEvents.length > PAGE_SIZE && <div className="evtx-pagination"><span>{page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, filteredEvents.length)} / {filteredEvents.length}</span><div className="button-row compact-buttons"><AButton variant="text" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>{t.previous}</AButton><AButton variant="text" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>{t.next}</AButton></div></div>}
          {selectedEvent && <div className="evtx-event-detail"><ToolPanelHeader title={`${selectedEvent.provider || "Event"} · ${selectedEvent.eventId ?? "--"}`} subtitle={`#${selectedEvent.recordId} · ${selectedEvent.source}`} actions={<AButton variant="outlined" disabled={!selectedEvent.xml} onClick={() => downloadTextFile(`event-${selectedEvent.recordId || Date.now()}.xml`, selectedEvent.xml, "application/xml;charset=utf-8")}>{selectedEvent.xml ? (t.save_xml) : (t.re_analyze_for_xml)}</AButton>} /><InfoTable rows={[[t.time, selectedEvent.timestamp || "--"], [t.channel, selectedEvent.channel || "--"], [t.computer, selectedEvent.computer || "--"], ["User / Process / Thread", `${selectedEvent.userId || "--"} / ${selectedEvent.processId || "--"} / ${selectedEvent.threadId || "--"}`]]} />{Object.keys(selectedEvent.data).length > 0 && <div className="table-scroll evtx-data-table"><table className="data-table"><thead><tr><th>{t.field}</th><th>{t.httpHeaderValue}</th></tr></thead><tbody>{Object.entries(selectedEvent.data).map(([key, value]) => <tr key={key}><td>{key}</td><td>{value}</td></tr>)}</tbody></table></div>}<details className="evtx-xml-details"><summary>{t.raw_xml}</summary>{selectedEvent.xml ? <textarea className="single-textarea mono-textarea evtx-xml" readOnly value={selectedEvent.xml} aria-label="Event XML" /> : <div className="empty-state">{t.raw_xml_was_not_kept_in_the_workspace_snapshot_re_analyze_the_file_to_retrieve_it}</div>}</details></div>}
        </>}

        {view === "sigma" && <div className="evtx-sigma-workspace">
          <input className="hidden-file-input" ref={sigmaInputRef} type="file" accept=".yml,.yaml,text/yaml" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void openSigmaFile(file); }} />
          <ToolPanelHeader title={t.local_sigma_matcher} subtitle={sigmaRules.length ? `${sigmaRules.length} ${t.rule_s_loaded}` : undefined} actions={<><AButton variant="outlined" onClick={() => sigmaInputRef.current?.click()}>{t.open_rules}</AButton><AButton variant="outlined" disabled={!sigmaText.trim() || sigmaLoading} onClick={loadSigma}>{t.validate}</AButton><AButton variant="filled" disabled={!sigmaText.trim() || !events.length || sigmaLoading} onClick={runSigma}>{sigmaLoading ? (t.running) : (t.run_rules)}</AButton></>} />
          {sigmaLoading && <ALinearProgress />}
          <textarea className="single-textarea mono-textarea evtx-sigma-editor" value={sigmaText} onChange={(event) => { sigmaFileRef.current += 1; setSigmaText(event.currentTarget.value); }} placeholder={t.paste_one_or_more_sigma_yaml_rules} />
          {sigmaErrors.length > 0 && <div className="empty-state error-state">{sigmaErrors.join("\n")}</div>}
          {sigmaMatches.length > 0 ? <div className="table-scroll evtx-sigma-matches"><table className="data-table"><thead><tr><th>{t.rule}</th><th>{t.level}</th><th>{t.time}</th><th>Event ID</th><th>{t.provider}</th><th>{t.summary}</th></tr></thead><tbody>{sigmaMatches.slice(0, 10_000).map((match, index) => <tr key={`${match.ruleId}:${match.event.id}:${index}`}><td>{match.ruleTitle}</td><td>{match.level || "--"}</td><td>{match.event.timestamp}</td><td>{match.event.eventId ?? "--"}</td><td>{match.event.provider}</td><td>{match.event.message || "--"}</td></tr>)}</tbody></table></div> : sigmaRules.length > 0 && <div className="empty-state">{t.no_rule_matches}</div>}
        </div>}
      </section>}
    </div>
  );
}

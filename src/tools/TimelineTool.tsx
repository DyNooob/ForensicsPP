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
import { AButton, ALinearProgress, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, ToolPanelHeader } from "../components/ui";
import { rememberTimelineEvents, timelineBounds } from "../features/reporter/timeline";
import { formatTimelineDuration, timelineToCsv } from "../features/timestamp/analyzer";
import type { TimestampWorkerRequest, TimestampWorkerResult } from "../features/timestamp/timestamp.worker";
import { copy } from "../i18n";
import type { TimelineEvent } from "../models";
import { downloadTextFile } from "../utils/files";
import { useStoredState } from "../utils/storage";
import { runWorkerTask } from "../utils/workerTask";

const PAGE_SIZE = 100;
const MAX_TIMELINE_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TIMELINE_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_TIMELINE_TEXT_BYTES = 32 * 1024 * 1024;

type TimelineSource = {
  name: string;
  text: string;
  size: number;
  lastModified: number;
};

function timelineJson(source: string, events: TimelineEvent[], sources: TimelineSource[]) {
  return JSON.stringify({
    source,
    sources: sources.map((item) => ({ name: item.name, size: item.size, lastModified: item.lastModified })),
    exportedAt: new Date().toISOString(),
    events
  }, null, 2);
}

export function TimelineTool({ t, active = true }: { t: (typeof copy)["zh"]; active?: boolean }) {
  const english = t.waiting === "Waiting";
  const [input, setInput] = useStoredState("timeline.input.v3", "");
  const [source, setSource] = useStoredState("timeline.source.v3", t.pasted_text);
  const [sources, setSources] = React.useState<TimelineSource[]>([]);
  const [query, setQuery] = React.useState("");
  const [format, setFormat] = React.useState("");
  const [sortMode, setSortMode] = React.useState<"time" | "line">("time");
  const [selectedId, setSelectedId] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [dragActive, setDragActive] = React.useState(false);
  const [error, setError] = React.useState("");
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const workbenchRef = React.useRef<HTMLDivElement | null>(null);
  const requestRef = React.useRef(0);
  const deferredInput = React.useDeferredValue(input);
  const hasInput = Boolean(input.trim() || sources.length);
  const sourceLabel = sources.length === 1
    ? sources[0].name
    : sources.length > 1
      ? (english ? `${sources.length} files` : `${sources.length} 个文件`)
      : (/^(?:pasted text|粘贴文本)$/i.test(source) ? (t.pasted_text) : source);
  const parsedSources = React.useMemo(() => sources.length
    ? sources
    : input.trim()
      ? [{ name: sourceLabel, text: deferredInput, size: new TextEncoder().encode(deferredInput).byteLength, lastModified: 0 }]
      : [], [deferredInput, input, sourceLabel, sources]);
  const [events, setEvents] = React.useState<TimelineEvent[]>([]);
  const [parsing, setParsing] = React.useState(false);
  const formats = React.useMemo(() => Array.from(new Set(events.map((event) => event.format))).sort(), [events]);
  const filteredEvents = React.useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events
      .filter((event) => !format || event.format === format)
      .filter((event) => !needle || [event.iso, event.local, event.raw, event.format, event.source, event.context].join(" ").toLowerCase().includes(needle))
      .sort((left, right) => sortMode === "line"
        ? left.line - right.line || left.source.localeCompare(right.source) || (left.epochMs ?? 0) - (right.epochMs ?? 0)
        : (left.epochMs ?? 0) - (right.epochMs ?? 0) || left.source.localeCompare(right.source) || left.line - right.line);
  }, [events, format, query, sortMode]);
  const pageCount = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE));
  const visibleEvents = React.useMemo(() => filteredEvents.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), [filteredEvents, page]);
  const selectedEvent = React.useMemo(() => events.find((event) => event.id === selectedId) ?? null, [events, selectedId]);
  const { first: firstEvent, last: lastEvent } = React.useMemo(() => timelineBounds(events), [events]);
  const span = firstEvent?.epochMs != null && lastEvent?.epochMs != null
    ? formatTimelineDuration(Math.max(0, Math.floor((lastEvent.epochMs - firstEvent.epochMs) / 1000)))
    : "--";

  React.useEffect(() => {
    rememberTimelineEvents(workbenchRef.current, events);
  }, [events]);

  React.useEffect(() => {
    const controller = new AbortController();
    if (!active) {
      setParsing(false);
      return () => controller.abort();
    }
    if (!parsedSources.length) {
      setEvents([]);
      setParsing(false);
      return () => controller.abort();
    }
    if (parsedSources.some((item) => item.size > MAX_TIMELINE_TEXT_BYTES)) {
      setEvents([]);
      setParsing(false);
      setError(t.timeline_text_is_limited_to_32_mib );
      return () => controller.abort();
    }
    setParsing(true);
    setError("");
    void (async () => {
      try {
        const collected: TimelineEvent[] = [];
        for (const item of parsedSources) {
          const result = await runWorkerTask<TimestampWorkerRequest, TimestampWorkerResult>({
            createWorker: () => new Worker(new URL("../features/timestamp/timestamp.worker.ts", import.meta.url), { type: "module" }),
            request: { source: item.text, name: item.name },
            signal: controller.signal,
            timeoutMs: 120_000
          });
          collected.push(...result.events);
          if (collected.length >= 5000) break;
        }
        if (controller.signal.aborted) return;
        setEvents(collected.slice(0, 5000));
      } catch (caught) {
        if (controller.signal.aborted) return;
        setEvents([]);
        setError(caught instanceof Error ? caught.message : String(caught));
      } finally {
        if (!controller.signal.aborted) setParsing(false);
      }
    })();
    return () => controller.abort();
  }, [active, parsedSources]);

  React.useEffect(() => {
    setPage(0);
  }, [format, query, sortMode]);

  React.useEffect(() => {
    if (page >= pageCount) setPage(pageCount - 1);
  }, [page, pageCount]);

  React.useEffect(() => {
    if (selectedId && !events.some((event) => event.id === selectedId)) setSelectedId("");
  }, [events, selectedId]);

  const resetReview = () => {
    setQuery("");
    setFormat("");
    setSortMode("time");
    setSelectedId("");
    setPage(0);
  };

  const clear = () => {
    requestRef.current += 1;
    setInput("");
    setSources([]);
    setSource(t.pasted_text);
    setError("");
    resetReview();
  };

  const loadFiles = async (files: FileList | File[] | null | undefined) => {
    if (!active) return;
    const fileArray = Array.from(files ?? []);
    if (!fileArray.length) return;
    const requestId = ++requestRef.current;
    setDragActive(false);
    setInput("");
    setError("");
    resetReview();
    const oversized = fileArray.find((file) => file.size > MAX_TIMELINE_FILE_BYTES);
    const totalBytes = fileArray.reduce((total, file) => total + file.size, 0);
    if (oversized) {
      setError(english ? `${oversized.name} exceeds the 16 MiB per-file limit.` : `${oversized.name} 超过单文件 16 MiB 限制。`);
      return;
    }
    const currentBytes = sources.reduce((total, item) => total + item.size, 0);
    if (currentBytes + totalBytes > MAX_TIMELINE_TOTAL_BYTES) {
      setError(t.selected_timeline_files_exceed_the_64_mib_total_limit);
      return;
    }
    try {
      const loaded = await Promise.all(fileArray.map(async (file): Promise<TimelineSource> => ({
        name: file.name,
        text: await file.text(),
        size: file.size,
        lastModified: file.lastModified
      })));
      if (!active || requestId !== requestRef.current) return;
      setSources((current) => {
        const byKey = new Map(current.map((item) => [`${item.name}\u0000${item.size}\u0000${item.lastModified}`, item]));
        loaded.forEach((item) => byKey.set(`${item.name}\u0000${item.size}\u0000${item.lastModified}`, item));
        return Array.from(byKey.values());
      });
    } catch (caught) {
      if (active && requestId === requestRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const exportEvents = filteredEvents;
  const rangeStart = filteredEvents.length ? page * PAGE_SIZE + 1 : 0;
  const rangeEnd = Math.min((page + 1) * PAGE_SIZE, filteredEvents.length);

  return (
    <div ref={workbenchRef} className={`tool-grid timeline-simple-workbench ${hasInput ? "has-timeline" : "empty-timeline"}`}>
      <div className="tool-panel wide-panel timeline-simple-input-panel">
        <ToolPanelHeader
          title={t.timeline_input}
          subtitle={sourceLabel}
          actions={<>
            <AButton variant="outlined" onClick={() => fileInputRef.current?.click()}>{t.uploadTimeline}</AButton>
            <AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>
          </>}
        />
        <input ref={fileInputRef} type="file" multiple aria-hidden="true" tabIndex={-1} accept=".log,.txt,.csv,.json,.xml,text/*,application/json" onChange={(event) => { const files = event.currentTarget.files; event.currentTarget.value = ""; void loadFiles(files); }} />
        <div
          className={`desktop-drop-zone timeline-simple-drop-zone ${dragActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              fileInputRef.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(event) => {
            event.preventDefault();
            void loadFiles(event.dataTransfer.files);
          }}
        >
          <strong>{t.open_one_or_more_log_text_csv_or_json_files}</strong>
          <span>{t.or_paste_source_text_below}</span>
        </div>
        <label className="stack-label">
          {t.source_text}
          <textarea
            className="single-textarea timeline-simple-input"
            value={input}
            onChange={(event) => {
              requestRef.current += 1;
              if (new TextEncoder().encode(event.currentTarget.value).byteLength > MAX_TIMELINE_TEXT_BYTES) {
                setError(t.timeline_text_is_limited_to_32_mib );
                return;
              }
              setSources([]);
              setInput(event.currentTarget.value);
              setError("");
              if (!event.currentTarget.value) setSelectedId("");
            }}
            placeholder={t.paste_logs_or_tabular_text_containing_timestamps}
          />
        </label>
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {hasInput && (
        <div className="tool-panel wide-panel timeline-simple-results-panel">
          <ToolPanelHeader
            title={t.timelineEvents}
            subtitle={`${filteredEvents.length}/${events.length} ${t.events}`}
            actions={<>
              <AButton variant="outlined" disabled={!exportEvents.length} onClick={() => downloadTextFile(`timeline-${Date.now()}.csv`, timelineToCsv(exportEvents), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
              <AButton variant="text" disabled={!exportEvents.length} onClick={() => downloadTextFile(`timeline-${Date.now()}.json`, timelineJson(sourceLabel, exportEvents, parsedSources), "application/json;charset=utf-8")}>{t.exportJson}</AButton>
            </>}
          />
          {parsing && <ALinearProgress />}
          <div className="timeline-simple-summary">
            <InfoTable rows={[
              [t.events_2, String(events.length)],
              [t.first, firstEvent?.iso ?? "--"],
              [t.last, lastEvent?.iso ?? "--"],
              [t.span, span]
            ]} />
          </div>
          <div className="timeline-simple-toolbar">
            <input className="text-input" aria-label={t.timelineFilter} value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={t.timelineFilter} />
            <ASelect value={format} onChange={(value) => setFormat(String(value))} aria-label={t.timelineFormats} options={[{ value: "", label: t.timelineFormatAll }, ...formats.map((item) => ({ value: item, label: item }))]} />
            <ASegmentedGroup className="timeline-simple-sort" value={sortMode} selects="single">
              <ASegmentedButton value="time" onClick={() => setSortMode("time")}>{t.timelineSortTime}</ASegmentedButton>
              <ASegmentedButton value="line" onClick={() => setSortMode("line")}>{t.timelineSortLine}</ASegmentedButton>
            </ASegmentedGroup>
          </div>

          {visibleEvents.length ? (
            <div className="table-scroll timeline-simple-scroll">
              <table className="data-table timeline-simple-table">
                <thead><tr><th>ISO</th><th>{t.format}</th><th>{t.iocLine}</th><th>{t.iocSource}</th><th>{t.timelineContext}</th></tr></thead>
                <tbody>
                  {visibleEvents.map((event) => (
                    <tr className={event.id === selectedId ? "selected-row" : ""} key={event.id}>
                      <td><button className="timeline-row-select" type="button" onClick={() => setSelectedId(event.id)}>{event.iso}</button></td>
                      <td>{event.format}</td>
                      <td>{event.line}</td>
                      <td title={event.source}>{event.source}</td>
                      <td>{event.context}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="empty-state">{t.no_timestamps_found}</div>}

          {filteredEvents.length > PAGE_SIZE && (
            <div className="timeline-simple-pagination">
              <span>{rangeStart}-{rangeEnd} / {filteredEvents.length}</span>
              <div className="button-row compact-buttons">
                <AButton variant="text" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))}>{t.previous}</AButton>
                <AButton variant="text" disabled={page + 1 >= pageCount} onClick={() => setPage((current) => Math.min(pageCount - 1, current + 1))}>{t.next}</AButton>
              </div>
            </div>
          )}
        </div>
      )}

      {selectedEvent && (
        <div className="tool-panel wide-panel timeline-simple-detail-panel">
          <ToolPanelHeader
            title={t.event_details}
            subtitle={`${selectedEvent.source} · ${t.line} ${selectedEvent.line}${t.s}`}
            actions={<AButton variant="text" onClick={() => void copyText(selectedEvent.context)}>{t.copy_context}</AButton>}
          />
          <InfoTable rows={[
            ["ISO", selectedEvent.iso],
            [t.local_time, selectedEvent.local],
            [t.raw_value, selectedEvent.raw],
            [t.format, selectedEvent.format],
            [t.iocSource, selectedEvent.source]
          ]} />
          <pre className="result-box timeline-simple-context">{selectedEvent.context}</pre>
        </div>
      )}
    </div>
  );
}

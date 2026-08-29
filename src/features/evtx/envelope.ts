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
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { appVersion } from "../../config/app";
import type { CaseEvidenceFile, CaseTimelineEvent } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisIndicator, AnalysisLimitation } from "../analysis/result";
import type { EvtxEvent, EvtxFileAnalysis } from "./analyzer";

export type EvtxEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const EVTX_TIMELINE_CAP = 5000;
const EVTX_INDICATOR_CAP = 200;

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const ALLOWED_TLDS = new Set([
  "com", "net", "org", "io", "cn", "ru", "info", "biz", "xyz", "top", "cc", "su",
  "de", "fr", "uk", "us", "gov", "mil", "edu", "co", "me", "sh", "to", "tk", "ng",
  "br", "in", "jp", "kr", "tw", "cloud", "app", "dev", "online", "site", "live", "pro"
]);

function isValidIpv4(value: string): boolean {
  const octets = value.split(".").map((part) => Number(part));
  return octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
    && value !== "0.0.0.0"
    && value !== "255.255.255.255";
}

function extractIndicators(events: EvtxEvent[]): AnalysisIndicator[] {
  const seen = new Set<string>();
  const indicators: AnalysisIndicator[] = [];
  const push = (type: string, value: string, event: EvtxEvent) => {
    const normalized = value.toLowerCase().replace(/[.,;:)\]}]*$/, "");
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    indicators.push({
      type,
      value: normalized,
      normalized,
      source: event.provider,
      context: `${event.channel} #${event.recordId}`
    });
  };
  for (const event of events) {
    if (indicators.length >= EVTX_INDICATOR_CAP) break;
    const haystack = `${event.message} ${Object.values(event.data).join(" ")}`;
    for (const match of haystack.match(IPV4_RE) ?? []) {
      if (isValidIpv4(match)) push("ipv4", match, event);
    }
    for (const match of haystack.match(URL_RE) ?? []) {
      push("url", match, event);
    }
    for (const match of haystack.match(DOMAIN_RE) ?? []) {
      const tld = match.slice(match.lastIndexOf(".") + 1).toLowerCase();
      if (ALLOWED_TLDS.has(tld)) push("domain", match, event);
    }
  }
  return indicators.slice(0, EVTX_INDICATOR_CAP);
}

function eventToTimeline(event: EvtxEvent, source: string): CaseTimelineEvent {
  const epochMs = Number.isNaN(Date.parse(event.timestamp)) ? undefined : Date.parse(event.timestamp);
  const context = [event.provider, event.channel, event.eventId != null ? `Event ${event.eventId}` : null]
    .filter(Boolean)
    .join(" / ");
  return {
    iso: event.timestamp,
    local: epochMs == null ? event.timestamp : new Date(epochMs).toLocaleString(),
    raw: event.timestamp,
    format: "evtx",
    line: Number(event.recordId) || 0,
    source,
    context,
    ...(epochMs == null ? {} : { epochMs })
  };
}

/**
 * Map one parsed EVTX file to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * Each source file becomes its own envelope (the result store keys by evidence
 * identity), so a multi-file analysis keeps per-file timelines and indicators.
 */
export function buildEvtxEnvelope(file: EvtxFileAnalysis, meta: EvtxEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const events = file.events ?? [];
  const providers = new Set(events.map((event) => event.provider).filter(Boolean));
  const channels = new Set(events.map((event) => event.channel).filter(Boolean));
  const criticalCount = events.filter((event) => event.level != null && event.level <= 1).length;
  const errorCount = events.filter((event) => event.level === 2).length;
  const timestamps = events.map((event) => event.timestamp).filter(Boolean).sort();
  const timeRange = timestamps.length ? `${timestamps[0]} → ${timestamps[timestamps.length - 1]}` : "--";

  const findings: AnalysisFinding[] = [];
  if (file.truncated) {
    findings.push({
      level: "warn",
      title: "Record limit reached",
      detail: `Parsing stopped at the per-file record cap; some events may be missing from this analysis.`,
      category: "evtx-limit",
      confidence: "high"
    });
  }
  if (file.skippedRecords > 0) {
    findings.push({
      level: "info",
      title: "Skipped records",
      detail: `${file.skippedRecords} record(s) could not be parsed and were skipped.`,
      category: "evtx-skip",
      confidence: "high"
    });
  }
  if (!file.full || file.dirty) {
    findings.push({
      level: "info",
      title: "Log not cleanly closed",
      detail: `File reports ${file.dirty ? "dirty" : "clean"} / ${file.full ? "full" : "not full"} state; the log may have been truncated or copied while active.`,
      category: "evtx-state",
      confidence: "medium"
    });
  }
  if (criticalCount > 0 || errorCount > 0) {
    findings.push({
      level: "warn",
      title: "High-severity events",
      detail: `${criticalCount} critical and ${errorCount} error event(s) detected across ${events.length} parsed record(s).`,
      category: "evtx-severity",
      confidence: "high"
    });
  }

  const artifacts: AnalysisArtifact[] = [{
    id: "evtx-file",
    label: file.source,
    kind: "evtx-file",
    size: file.size,
    confidence: "high"
  }];

  const indicators = extractIndicators(events);

  const limitations: AnalysisLimitation[] = [
    { code: "EVTX_RECORD_LIMIT", detail: `Per-file parsing is capped at 50,000 records; files exceeding the cap are truncated for this analysis.` }
  ];
  if (events.length > EVTX_TIMELINE_CAP) {
    limitations.push({
      code: "EVTX_TIMELINE_TRIM",
      detail: `Timeline trimmed to the first ${EVTX_TIMELINE_CAP.toLocaleString()} events; the full set remains available in the Events view.`
    });
  }

  const source: CaseEvidenceFile = {
    name: file.source,
    size: file.size,
    type: "application/octet-stream",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `evtx-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "evtx", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { truncated: file.truncated } },
    summary: {
      title: "Windows event log analysis",
      text: `${events.length.toLocaleString()} event(s) parsed from ${file.source}; ${providers.size} provider(s), ${channels.size} channel(s).`,
      metrics: [
        { label: "Events", value: events.length.toLocaleString() },
        { label: "Providers", value: String(providers.size) },
        { label: "Channels", value: String(channels.size) },
        { label: "Time range", value: timeRange },
        { label: "Critical", value: String(criticalCount) },
        { label: "Error", value: String(errorCount) },
        { label: "Skipped", value: String(file.skippedRecords) },
        { label: "Truncated", value: file.truncated ? "yes" : "no" }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "evtx.finding" })),
    indicators,
    artifacts,
    timeline: events.slice(0, EVTX_TIMELINE_CAP).map((event) => eventToTimeline(event, file.source)),
    limitations,
    data: {
      source: file.source,
      size: file.size,
      eventCount: events.length,
      providers: Array.from(providers),
      channels: Array.from(channels),
      timeRange,
      truncated: file.truncated,
      skippedRecords: file.skippedRecords,
      criticalCount,
      errorCount,
      indicatorCount: indicators.length
    }
  };
}

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
import type { CaseEvidenceFile, CaseTimelineEvent, ExtractedStringRow, TimelineEvent, WindowsArtifactAnalysis } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisIndicator, AnalysisLimitation } from "../analysis/result";

export type WindowsEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const TIMELINE_CAP = 5000;
const RECORD_CAP = 200;
const INDICATOR_CAP = 200;

const ALLOWED_TLDS = new Set([
  "com", "net", "org", "io", "cn", "ru", "info", "biz", "xyz", "top", "cc", "su",
  "de", "fr", "uk", "us", "gov", "mil", "edu", "co", "me", "sh", "to", "tk", "ng",
  "br", "in", "jp", "kr", "tw", "cloud", "app", "dev", "online", "site", "live", "pro"
]);

function isValidIpv4(value: string): boolean {
  const octets = value.split(".").map((part) => Number(part));
  return octets.length === 4
    && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
    && value !== "0.0.0.0"
    && value !== "255.255.255.255";
}

const ARTIFACT_RELEVANCE: Record<string, string> = {
  "NTFS $MFT": "Filesystem master file table — created / modified / accessed / MFT-write timestamps per file record; the primary filesystem timeline source.",
  "NTFS $UsnJrnl:$J": "Update Sequence Number change journal — file create / rename / delete activity with reason flags.",
  "Windows Shell Link (.lnk)": "Shell shortcut — reveals the accessed target file, local and network paths, and (often) execution context.",
  "Windows Prefetch (.pf)": "Prefetch file — execution evidence: last-run times, run count, and files accessed by an executable.",
  "Zone.Identifier ADS": "Mark-of-the-Web alternate data stream — download source (HostUrl) and trust zone for the file.",
  "Registry Export (.reg)": "Registry hive export — persistence-related keys and risky value data are highlighted."
};

function toCaseTimeline(event: TimelineEvent, fallbackSource: string): CaseTimelineEvent {
  const source = event.source || fallbackSource;
  const base: CaseTimelineEvent = {
    iso: event.iso,
    local: event.local,
    raw: event.raw,
    format: event.format,
    line: event.line,
    source,
    context: event.context
  };
  return event.epochMs == null ? base : { ...base, epochMs: event.epochMs };
}

function extractIndicators(strings: ExtractedStringRow[]): AnalysisIndicator[] {
  const seen = new Set<string>();
  const indicators: AnalysisIndicator[] = [];
  const push = (type: string, value: string) => {
    const normalized = value.toLowerCase().replace(/[.,;:)\]}]*$/, "");
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    indicators.push({ type, value: normalized, normalized, source: "windows-strings", context: "extracted string" });
  };
  for (const item of strings) {
    if (indicators.length >= INDICATOR_CAP) break;
    const value = item.value.trim();
    if (!value) continue;
    if (item.detectedType === "URL") {
      push("url", value);
      const hostMatch = value.match(/^https?:\/\/([^/\s"'<>]+)/i);
      const host = hostMatch?.[1];
      if (host && host.includes(".")) {
        const tld = host.slice(host.lastIndexOf(".") + 1).toLowerCase();
        if (ALLOWED_TLDS.has(tld)) push("domain", host);
      }
    } else if (item.detectedType === "IPv4") {
      if (isValidIpv4(value)) push("ipv4", value);
    } else if (item.detectedType === "Email") {
      push("email", value);
    }
  }
  return indicators.slice(0, INDICATOR_CAP);
}

/**
 * Map a Windows artifact analysis to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * Windows artifacts are the primary Timeline source: $MFT, $UsnJrnl, LNK, and
 * Prefetch all contribute timestamped events. Records become artifacts, and
 * network-typed extracted strings (URL / IPv4 / Email) become indicators.
 */
export function buildWindowsEnvelope(analysis: WindowsArtifactAnalysis, meta: WindowsEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const timeline = (analysis.timeline ?? []).slice(0, TIMELINE_CAP).map((event) => toCaseTimeline(event, analysis.name));
  const records = analysis.records ?? [];
  const strings = analysis.strings ?? [];

  const findings: AnalysisFinding[] = [];
  const relevance = ARTIFACT_RELEVANCE[analysis.artifactType];
  if (relevance) {
    findings.push({ level: "info", title: `Artifact: ${analysis.artifactType}`, detail: relevance, category: "windows-artifact", confidence: "high" });
  } else {
    findings.push({ level: "info", title: "Unrecognized Windows artifact", detail: `No specific parser matched ${analysis.artifactType}; only generic strings and structure were extracted.`, category: "windows-artifact", confidence: "medium" });
  }
  if (timeline.length > 0) {
    findings.push({ level: "info", title: "Timeline parsed", detail: `${timeline.length.toLocaleString()} timestamped event(s) contributed to the case timeline.`, category: "windows-timeline", confidence: "high" });
  }
  if (records.length > 0) {
    findings.push({ level: "info", title: "Structured records parsed", detail: `${records.length.toLocaleString()} record(s) of kind ${Array.from(new Set(records.map((record) => record.kind))).join(", ")}.`, category: "windows-records", confidence: "high" });
  }
  const networkStrings = strings.filter((item) => item.detectedType === "URL" || item.detectedType === "IPv4" || item.detectedType === "Email");
  if (networkStrings.length > 0) {
    findings.push({ level: "warn", title: "Network indicators in strings", detail: `${networkStrings.length} URL / IPv4 / Email string(s) found in the artifact; review for C2 or download endpoints.`, category: "windows-network-strings", confidence: "medium" });
  }

  const indicators = extractIndicators(strings);

  const artifacts: AnalysisArtifact[] = records
    .slice(0, RECORD_CAP)
    .map((record, index) => ({
      id: `record-${index}`,
      label: `${record.kind} · ${record.id}`,
      kind: "windows-record",
      confidence: "high" as const
    }));

  const limitations: AnalysisLimitation[] = [
    { code: "WINDOWS_TRIAGE_SCOPE", detail: "Parsing covers the recognized artifact type only; it does not reconstruct full filesystem state or decode encrypted record content." }
  ];
  if (timeline.length >= TIMELINE_CAP) {
    limitations.push({ code: "WINDOWS_TIMELINE_TRIM", detail: `Timeline capped at ${TIMELINE_CAP.toLocaleString()} events for this analysis; the full set remains in the artifact view.` });
  }

  const source: CaseEvidenceFile = {
    name: analysis.name,
    size: analysis.size,
    type: "application/octet-stream",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `windows-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "windows", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { artifactType: analysis.artifactType } },
    summary: {
      title: "Windows artifact analysis",
      text: `${analysis.artifactType} · ${timeline.length.toLocaleString()} timeline event(s), ${records.length.toLocaleString()} record(s), ${strings.length.toLocaleString()} path string(s).`,
      metrics: [
        { label: "Artifact type", value: analysis.artifactType },
        { label: "Size", value: `${analysis.size.toLocaleString()} B` },
        { label: "Fields", value: String(analysis.rows.length) },
        { label: "Timeline", value: String(timeline.length) },
        { label: "Records", value: String(records.length) },
        { label: "Paths", value: String(strings.length) },
        { label: "Indicators", value: String(indicators.length) }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "windows.finding" })),
    indicators,
    artifacts,
    timeline,
    limitations,
    data: {
      name: analysis.name,
      size: analysis.size,
      artifactType: analysis.artifactType,
      rowCount: analysis.rows.length,
      timelineCount: timeline.length,
      recordCount: records.length,
      stringCount: strings.length,
      textPreviewAvailable: Boolean(analysis.textPreview)
    }
  };
}

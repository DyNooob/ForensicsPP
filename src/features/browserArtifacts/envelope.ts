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

import { appVersion } from "../../config/app";
import type { CaseEvidenceFile, CaseTimelineEvent } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisIndicator, AnalysisLimitation } from "../analysis/result";
import type { BrowserArtifactAnalysis } from "./analyzer";

export type BrowserArtifactEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const TIMELINE_CAP = 5000;
const INDICATOR_CAP = 200;
const ARTIFACT_CAP = 200;

const CATEGORY_LABELS: Record<string, string> = {
  visits: "Visits",
  downloads: "Downloads",
  cookies: "Cookies",
  logins: "Logins",
  autofill: "Autofill",
  extensions: "Extensions"
};

function toCaseTimeline(record: BrowserArtifactAnalysis["records"][number]): CaseTimelineEvent {
  return {
    iso: record.time,
    local: record.time,
    raw: record.time,
    format: "",
    line: 0,
    source: record.source,
    context: `${record.primary}${record.secondary ? ` · ${record.secondary}` : ""}`
  };
}

function extractIndicators(records: BrowserArtifactAnalysis["records"]): AnalysisIndicator[] {
  const seen = new Set<string>();
  const indicators: AnalysisIndicator[] = [];
  for (const record of records) {
    if (indicators.length >= INDICATOR_CAP) break;
    const url = record.url.trim();
    if (!url) continue;
    const normalized = url.toLowerCase();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    indicators.push({ type: "url", value: normalized, normalized, source: "browser-history", context: record.primary });
  }
  return indicators.slice(0, INDICATOR_CAP);
}

/**
 * Map a browser-artifact analysis to a unified AnalysisEnvelope (beta.6 P0-2, C-B4).
 *
 * Browser history/cookies/logins are timeline-grade evidence: each timestamped record
 * becomes a CaseTimelineEvent, visited URLs become indicators, and each parsed source
 * database becomes an artifact. Truncation (50k records/file) is surfaced as a finding
 * and limitation because it means the export is incomplete.
 */
export function buildBrowserArtifactEnvelope(analysis: BrowserArtifactAnalysis, meta: BrowserArtifactEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const timeline = analysis.records
    .filter((record) => record.time)
    .slice(0, TIMELINE_CAP)
    .map(toCaseTimeline);
  const indicators = extractIndicators(analysis.records);
  const parsedFiles = analysis.files.filter((file) => file.status === "parsed");
  const truncated = analysis.files.filter((file) => file.truncated);

  const findings: AnalysisFinding[] = [];
  findings.push({
    level: "info",
    title: "Browser data parsed",
    detail: `Parsed ${parsedFiles.length}/${analysis.files.length} source file(s) into ${analysis.records.length.toLocaleString()} record(s).`,
    category: "browser-parsed",
    confidence: "high"
  });
  if (analysis.firstTime && analysis.lastTime) {
    findings.push({
      level: "info",
      title: "Activity time range",
      detail: `${analysis.firstTime} → ${analysis.lastTime}`,
      category: "browser-timerange",
      confidence: "high"
    });
  }
  const categories = (Object.keys(analysis.counts) as Array<keyof BrowserArtifactAnalysis["counts"]>)
    .filter((category) => analysis.counts[category] > 0)
    .map((category) => CATEGORY_LABELS[category] ?? category);
  if (categories.length) {
    findings.push({
      level: "info",
      title: "Artifact categories present",
      detail: categories.join(", "),
      category: "browser-categories",
      confidence: "high"
    });
  }
  if (truncated.length) {
    findings.push({
      level: "warn",
      title: "Records truncated",
      detail: `${truncated.length} source file(s) reached the 50,000-record limit; the export may be incomplete. Re-open the original database for a complete record set.`,
      category: "browser-records-truncated",
      review: true,
      confidence: "medium"
    });
  }

  const artifacts: AnalysisArtifact[] = parsedFiles
    .slice(0, ARTIFACT_CAP)
    .map((file, index) => ({
      id: `file-${index}`,
      label: `${file.browser} · ${file.profile} · ${file.artifact}`,
      kind: "browser-data-file",
      size: file.size,
      confidence: "high" as const
    }));

  const limitations: AnalysisLimitation[] = [
    { code: "BROWSER_TRIAGE_SCOPE", detail: "Parsing covers recognized browser databases (History, Cookies, Login Data, Web Data, Bookmarks, Preferences); it does not reconstruct full profile state or decode encrypted blob columns." }
  ];
  if (analysis.snapshotLimited || truncated.length) {
    limitations.push({ code: "BROWSER_SNAPSHOT_TRIMMED", detail: "Restored workspace keeps a bounded record snapshot; the full record set remains in the original database." });
  }

  const sources: CaseEvidenceFile[] = analysis.files.map((file) => ({
    name: file.path,
    size: file.size,
    type: "application/octet-stream",
    lastModified: ""
  }));

  const timeRange = analysis.firstTime && analysis.lastTime ? `${analysis.firstTime} → ${analysis.lastTime}` : "--";
  return {
    schemaVersion: "1",
    id: `browser-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "browserartifacts", version: appVersion },
    source: sources,
    run: { startedAt, completedAt, parameters: { browsers: analysis.browsers, profiles: analysis.profiles } },
    summary: {
      title: "Browser artifact analysis",
      text: `${analysis.records.length.toLocaleString()} browser record(s) across ${analysis.files.length} file(s); ${analysis.browsers.join(", ") || "--"}; ${timeRange}.`,
      metrics: [
        { label: "Files", value: `${parsedFiles.length}/${analysis.files.length}` },
        { label: "Records", value: String(analysis.records.length) },
        { label: "Browsers", value: analysis.browsers.join(", ") || "--" },
        { label: "Profiles", value: analysis.profiles.join(", ") || "--" },
        { label: "Time range", value: timeRange },
        { label: "Visits", value: String(analysis.counts.visits) },
        { label: "Downloads", value: String(analysis.counts.downloads) },
        { label: "Cookies", value: String(analysis.counts.cookies) },
        { label: "Logins", value: String(analysis.counts.logins) },
        { label: "Autofill", value: String(analysis.counts.autofill) },
        { label: "Extensions", value: String(analysis.counts.extensions) },
        { label: "Timeline", value: String(timeline.length) },
        { label: "Indicators", value: String(indicators.length) }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "browser.finding" })),
    indicators,
    artifacts,
    timeline,
    limitations,
    data: {
      fileCount: analysis.files.length,
      parsedFileCount: parsedFiles.length,
      recordCount: analysis.records.length,
      browsers: analysis.browsers,
      profiles: analysis.profiles,
      counts: analysis.counts,
      firstTime: analysis.firstTime,
      lastTime: analysis.lastTime,
      truncatedCount: truncated.length,
      timelineCount: timeline.length,
      indicatorCount: indicators.length
    }
  };
}

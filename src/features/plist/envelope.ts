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
import { plistChildren, type PlistValue } from "./analyzer";

export type PlistEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
  sourceName?: string;
  sourceSize?: number;
  format?: string;
};

const TIMELINE_CAP = 2000;
const ARTIFACT_CAP = 200;

type DateHit = { iso: string; path: string };

function walkDates(value: PlistValue, path: string, out: DateHit[]) {
  if (value instanceof Date) {
    out.push({ iso: value.toISOString(), path });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkDates(item, `${path}[${index}]`, out));
    return;
  }
  if (value && typeof value === "object" && !(value instanceof Uint8Array)) {
    for (const key of Object.keys(value)) walkDates((value as Record<string, PlistValue>)[key], `${path}.${key}`, out);
  }
}

/**
 * Map a parsed Apple property list to a unified AnalysisEnvelope (beta.6 B6-B1).
 *
 * The plist analyzer parses both binary (`bplist00`) and XML plists and decodes
 * `NSDate` (Cocoa epoch) timestamps into `Date` values — a first-class Apple
 * forensic artifact class (LaunchAgents, preferences, bookmarks, browser state).
 * Decoded NSDate values become timeline events; top-level entries become
 * artifacts. Provenance is **logical** (key path) — no byte offset is fabricated.
 *
 * The envelope surfaces the parsed structure and timestamps only; it does NOT
 * perform domain-specific forensic interpretation (e.g. LaunchAgent persistence),
 * which is documented as a limitation.
 */
export function buildPlistEnvelope(
  input: { format: string; value: PlistValue; name: string; size: number },
  meta: PlistEnvelopeMeta = {}
): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const sourceName = meta.sourceName ?? input.name ?? "property list";
  const sourceSize = meta.sourceSize ?? input.size ?? 0;
  const format = (input.format ?? meta.format ?? "xml").toLowerCase();

  const topEntries = plistChildren(input.value, "$");
  const dates: DateHit[] = [];
  walkDates(input.value, "$", dates);

  const findings: AnalysisFinding[] = [];
  findings.push({
    level: "info",
    title: "Property list parsed",
    detail: `Parsed a ${format} property list with ${topEntries.length.toLocaleString()} top-level entr(y/ies) from ${sourceName}.`,
    category: "plist-structure",
    confidence: "high"
  });
  if (dates.length) {
    findings.push({
      level: "info",
      title: "Apple timestamps extracted",
      detail: `Extracted ${dates.length.toLocaleString()} NSDate timestamp(s) (Cocoa epoch) as timeline events.`,
      category: "plist-timestamps",
      confidence: "high"
    });
  }

  const timeline: CaseTimelineEvent[] = dates.slice(0, TIMELINE_CAP).map((date) => {
    const epochMs = Date.parse(date.iso);
    return {
      iso: date.iso,
      local: date.iso,
      raw: date.iso,
      format: "apple-nsdate",
      line: 0,
      source: sourceName,
      context: date.path,
      ...(Number.isNaN(epochMs) ? {} : { epochMs })
    };
  });

  const artifacts: AnalysisArtifact[] = topEntries.slice(0, ARTIFACT_CAP).map((entry, index) => ({
    id: `entry-${index}`,
    label: `${entry.key} (${entry.type})`,
    kind: "plist-entry",
    confidence: "medium"
  }));

  const limitations: AnalysisLimitation[] = [
    { code: "PLIST_GENERIC_PARSER", detail: "Generic property-list parser. It surfaces structure and NSDate timestamps but does not perform domain-specific forensic interpretation (e.g. LaunchAgent persistence, bookmark resolution, or preference semantics)." },
    { code: "PLIST_NO_OFFSETS", detail: "Entries are identified by logical key path, not byte offset. No exact byte provenance is fabricated." },
    { code: "PLIST_FORMAT_SUPPORT", detail: "Both binary (bplist00) and XML plist are supported; binary data values are summarized by size only." }
  ];

  const source: CaseEvidenceFile = {
    name: sourceName,
    size: sourceSize,
    type: "application/x-plist",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `plist-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "plist", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { format } },
    summary: {
      title: "Apple Property List analysis",
      text: `${format} plist · ${topEntries.length.toLocaleString()} top-level entries, ${dates.length.toLocaleString()} NSDate timestamp(s).`,
      metrics: [
        { label: "Source", value: sourceName },
        { label: "Size", value: `${sourceSize.toLocaleString()} B` },
        { label: "Format", value: format.toUpperCase() },
        { label: "Top-level entries", value: String(topEntries.length) },
        { label: "Timestamps", value: String(dates.length) }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "plist.finding" })),
    indicators: [],
    artifacts,
    timeline,
    limitations,
    data: {
      format,
      entryCount: topEntries.length,
      dateCount: dates.length
    }
  };
}

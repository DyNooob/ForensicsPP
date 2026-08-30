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
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisEnvelope, AnalysisFinding, AnalysisIndicator, AnalysisLimitation } from "../analysis/result";
import type { IocAnalysis } from "../../models";

export type IocEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
  /** Source label for the analyzed text/file (file name, or "pasted text"). */
  sourceName?: string;
  /** Byte length of the analyzed input. */
  sourceSize?: number;
};

const INDICATOR_CAP = 200;

/**
 * Map an IOC extraction to a unified AnalysisEnvelope (beta.6 P0-2, C-B4).
 *
 * The IOC tool parses pasted text or a dropped log/file in a worker and returns
 * structured `IocRecord[]`. Each record becomes an indicator; the envelope is the
 * structured, case-exportable representation of the extraction (the prior DOM-only
 * output had no provenance). Records carrying a non-empty `risk` array are surfaced
 * as review findings.
 */
export function buildIocEnvelope(analysis: IocAnalysis, meta: IocEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const sourceName = meta.sourceName ?? "pasted text";
  const sourceSize = meta.sourceSize ?? 0;

  const indicators: AnalysisIndicator[] = analysis.records
    .slice(0, INDICATOR_CAP)
    .map((record) => ({
      type: record.type,
      value: record.normalized || record.value,
      normalized: record.normalized || record.value,
      source: "ioc-extraction",
      context: record.context || record.contexts.join("\n---\n")
    }));

  const riskyRecords = analysis.records.filter((record) => record.risk.length > 0);
  const types = Object.keys(analysis.grouped).sort();

  const findings: AnalysisFinding[] = [];
  findings.push({
    level: "info",
    title: "Indicators extracted",
    detail: `Extracted ${analysis.records.length.toLocaleString()} unique indicator(s) across ${types.length} type(s) from ${sourceName}.`,
    category: "ioc-extracted",
    confidence: "high"
  });
  if (riskyRecords.length) {
    findings.push({
      level: "warn",
      title: "Risk-flagged indicators",
      detail: `${riskyRecords.length.toLocaleString()} indicator(s) carry a risk flag (${riskyRecords.slice(0, 6).map((record) => record.normalized).join(", ")}${riskyRecords.length > 6 ? " …" : ""}).`,
      category: "ioc-risk",
      review: true,
      confidence: "medium"
    });
  }

  const limitations: AnalysisLimitation[] = [
    { code: "IOC_TRIAGE_SCOPE", detail: "Extraction is pattern-based (URL / domain / IPv4 / email / hash / CVE etc.); it does not enrich indicators or assess whether a host is malicious." },
    { code: "IOC_INPUT_LIMIT", detail: "Analysis is bounded by the 16 MiB input limit; very large logs should be split before extraction." }
  ];

  const source: CaseEvidenceFile = {
    name: sourceName,
    size: sourceSize,
    type: "text/plain",
    lastModified: ""
  };

  const sights = analysis.records.reduce((sum, record) => sum + record.count, 0);
  return {
    schemaVersion: "1",
    id: `ioc-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "ioc", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { source: sourceName } },
    summary: {
      title: "IOC extraction",
      text: `${analysis.records.length.toLocaleString()} unique indicator(s), ${sights.toLocaleString()} total sighting(s), ${types.length} type(s) from ${sourceName}.`,
      metrics: [
        { label: "Source", value: sourceName },
        { label: "Size", value: `${sourceSize.toLocaleString()} B` },
        { label: "Unique indicators", value: String(analysis.records.length) },
        { label: "Sightings", value: String(sights) },
        { label: "Types", value: String(types.length) },
        { label: "Risk-flagged", value: String(riskyRecords.length) }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "ioc.finding" })),
    indicators,
    artifacts: [],
    timeline: [],
    limitations,
    data: {
      sourceName,
      sourceSize,
      recordCount: analysis.records.length,
      sightingCount: sights,
      types,
      riskyCount: riskyRecords.length
    }
  };
}

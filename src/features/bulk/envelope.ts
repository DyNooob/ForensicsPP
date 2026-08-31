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
import type { BulkScanResult } from "./analyzer";

export type BulkEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
  sourceName?: string;
};

const ARTIFACT_CAP = 500;
const INDICATOR_CAP = 200;

const NETWORK_TYPES = new Set(["URL", "Email", "IPv4", "IPv6", "Domain"]);
const EXACT_TYPES = new Set(["PEM"]);

function confidenceFor(type: string): "low" | "medium" | "high" {
  if (EXACT_TYPES.has(type)) return "high";
  if (NETWORK_TYPES.has(type)) return "medium";
  return "low";
}

/**
 * Map a bulk artifact scan to a unified AnalysisEnvelope (beta.6 B6-B1).
 *
 * The bulk scanner streams a Blob and extracts forensic indicators (URL / Email /
 * IPv4 / IPv6 / MAC / JWT / UUID / Ethereum / Bitcoin / PEM / Windows-Unix-Registry
 * paths / Android packages / User-Agent / Domain). Every artifact carries its real
 * **byte offset** and encoding within the scanned evidence — genuine provenance.
 * Findings are explicitly tagged exact (PEM BEGIN/END markers), pattern-matched
 * (network indicators), or heuristic (package/domain/path patterns) so reviewers
 * can weight false-positive risk. This is a real analyzer, not an orchestrator.
 */
export function buildBulkEnvelope(result: BulkScanResult, meta: BulkEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const sourceName = meta.sourceName ?? result.name ?? "bulk scan";

  const artifacts: AnalysisArtifact[] = result.items.slice(0, ARTIFACT_CAP).map((item, index) => ({
    id: `artifact-${index}`,
    label: `${item.type}: ${item.value.slice(0, 120)}`,
    kind: "bulk-artifact",
    offset: item.offset,
    confidence: confidenceFor(item.type)
  }));

  const indicators: AnalysisIndicator[] = result.items
    .filter((item) => NETWORK_TYPES.has(item.type))
    .slice(0, INDICATOR_CAP)
    .map((item) => ({
      type: item.type.toLowerCase(),
      value: item.value,
      normalized: item.value,
      source: "bulk-scan",
      context: `@0x${item.offset.toString(16).toUpperCase()} (${item.encoding})`
    }));

  const findings: AnalysisFinding[] = [];
  const typeCount = Object.keys(result.counts).length;
  findings.push({
    level: "info",
    title: "Bulk artifact scan complete",
    detail: `Scanned ${result.scannedBytes.toLocaleString()} of ${result.size.toLocaleString()} byte(s); ${result.items.length.toLocaleString()} artifact(s) across ${typeCount} type(s).`,
    category: "bulk-summary",
    confidence: "high"
  });
  if (result.truncated) {
    findings.push({
      level: "warn",
      title: "Scan truncated",
      detail: "The scan hit the item cap or did not finish the full file; lower-signal artifacts may be missing.",
      category: "bulk-truncated",
      review: true,
      confidence: "medium"
    });
  }

  const limitations: AnalysisLimitation[] = [
    { code: "BULK_PATTERN_SCAN", detail: "Detection is pattern-based (regex over ASCII/UTF-16). False positives are possible, especially for Android-package and Domain heuristics. Offsets are byte offsets within the decoded scan window, not original file clusters." },
    { code: "BULK_CONFIDENCE", detail: "PEM/key blocks are flagged high-confidence (exact BEGIN/END markers). Network indicators are pattern-matched (medium). Package/Domain/Path patterns are heuristic (low)." }
  ];

  const source: CaseEvidenceFile = {
    name: sourceName,
    size: result.size,
    type: "application/octet-stream",
    lastModified: ""
  };

  const timeline: CaseTimelineEvent[] = [];

  return {
    schemaVersion: "1",
    id: `bulk-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "bulk", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { scannedBytes: result.scannedBytes } },
    summary: {
      title: "Bulk artifact scan",
      text: `${result.items.length.toLocaleString()} artifact(s) across ${typeCount} type(s) from ${sourceName}.`,
      metrics: [
        { label: "Source", value: sourceName },
        { label: "Size", value: `${result.size.toLocaleString()} B` },
        { label: "Scanned", value: `${result.scannedBytes.toLocaleString()} B` },
        { label: "Artifacts", value: String(result.items.length) },
        { label: "Types", value: String(typeCount) },
        { label: "Truncated", value: result.truncated ? "yes" : "no" }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "bulk.finding" })),
    indicators,
    artifacts,
    timeline,
    limitations,
    data: {
      scannedBytes: result.scannedBytes,
      itemCount: result.items.length,
      counts: result.counts,
      truncated: result.truncated
    }
  };
}

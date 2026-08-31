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
import type { RegistryHive } from "./analyzer";

export type RegistryEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
  /** Source label for the analyzed hive (file name). */
  sourceName?: string;
  /** Byte length of the analyzed hive. */
  sourceSize?: number;
};

const TIMELINE_CAP = 2000;
const ARTIFACT_CAP = 200;

/**
 * Map a parsed Windows Registry hive to a unified AnalysisEnvelope (beta.6 B6-B1).
 *
 * The registry analyzer genuinely parses the `regf` binary format (NK cells,
 * value lists, FILETIME `lastWrite` timestamps) and surfaces forensic warnings
 * (sequence-number mismatch -> transaction-log recovery; header checksum). The
 * envelope carries that as structured findings, a key-last-write timeline, and
 * key-path artifacts. Provenance is **logical** (key path + value name) — the
 * parser does not expose cell byte offsets, so no offset is fabricated.
 */
export function buildRegistryEnvelope(hive: RegistryHive, meta: RegistryEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const sourceName = meta.sourceName ?? "registry hive";
  const sourceSize = meta.sourceSize ?? 0;

  const valueCount = hive.keys.reduce((sum, key) => sum + key.values.length, 0);
  const keysWithValues = hive.keys.filter((key) => key.values.length > 0);

  const findings: AnalysisFinding[] = [];
  findings.push({
    level: "info",
    title: "Registry hive parsed",
    detail: `Parsed ${hive.keys.length.toLocaleString()} key(s) and ${valueCount.toLocaleString()} value(s) from ${sourceName}.`,
    category: "registry-structure",
    confidence: "high"
  });
  if (hive.warnings.length) {
    findings.push({
      level: "warn",
      title: "Registry hive inconsistencies",
      detail: hive.warnings.join(" "),
      category: "registry-integrity",
      review: true,
      confidence: "high"
    });
  }
  if (hive.dirty) {
    findings.push({
      level: "warn",
      title: "Hive sequence numbers differ",
      detail: "Primary and secondary sequence numbers differ; the hive may be incomplete and transaction logs (.LOG) may be required for a complete parse.",
      category: "registry-dirty",
      review: true,
      confidence: "high"
    });
  }

  const timeline: CaseTimelineEvent[] = [];
  for (const key of hive.keys) {
    if (timeline.length >= TIMELINE_CAP) break;
    if (!key.lastWrite || key.lastWrite === "--") continue;
    const epochMs = Date.parse(key.lastWrite);
    if (Number.isNaN(epochMs)) continue;
    timeline.push({
      iso: key.lastWrite,
      local: key.lastWrite,
      raw: key.lastWrite,
      format: "windows-registry-lastWrite",
      line: 0,
      source: sourceName,
      context: key.path,
      epochMs
    });
  }

  const artifacts: AnalysisArtifact[] = keysWithValues.slice(0, ARTIFACT_CAP).map((key, index) => ({
    id: `key-${index}`,
    label: key.path,
    kind: "registry-key",
    confidence: "high"
  }));

  const limitations: AnalysisLimitation[] = [
    { code: "REGISTRY_LOGICAL_LOCATION", detail: "Keys and values are identified by logical path (key path + value name), not byte offset. The parser does not expose cell offsets, so no exact byte provenance is fabricated." },
    { code: "REGISTRY_VALUE_TYPES", detail: "Value data is decoded for common types (REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_LINK); opaque binary values are shown as truncated hex previews." }
  ];
  if (hive.dirty) {
    limitations.push({ code: "REGISTRY_TRANSACTION_LOG", detail: "Sequence-number mismatch indicates the hive may be incomplete; transaction-log recovery was not performed." });
  }

  const source: CaseEvidenceFile = {
    name: sourceName,
    size: sourceSize,
    type: "application/octet-stream",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `registry-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "registry", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { keyCount: hive.keys.length, valueCount } },
    summary: {
      title: "Windows Registry Hive analysis",
      text: `${hive.keys.length.toLocaleString()} key(s), ${valueCount.toLocaleString()} value(s)${hive.warnings.length ? `, ${hive.warnings.length} warning(s)` : ""}.`,
      metrics: [
        { label: "Source", value: sourceName },
        { label: "Size", value: `${sourceSize.toLocaleString()} B` },
        { label: "Keys", value: String(hive.keys.length) },
        { label: "Values", value: String(valueCount) },
        { label: "Warnings", value: String(hive.warnings.length) },
        { label: "Dirty", value: hive.dirty ? "yes" : "no" },
        { label: "Timeline events", value: String(timeline.length) }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "registry.finding" })),
    indicators: [],
    artifacts,
    timeline,
    limitations,
    data: {
      keyCount: hive.keys.length,
      valueCount,
      sequence1: hive.sequence1,
      sequence2: hive.sequence2,
      dirty: hive.dirty,
      warningCount: hive.warnings.length,
      sampleKeys: hive.keys.slice(0, 50).map((key) => ({ path: key.path, lastWrite: key.lastWrite, valueCount: key.values.length }))
    }
  };
}

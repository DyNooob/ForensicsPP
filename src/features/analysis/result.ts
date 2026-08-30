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

import type { CaseEvidenceFile, CaseTimelineEvent } from "../../models";
import type { ToolId } from "../../config/app";
import type { Translation } from "../../i18n";

export type AnalysisFinding = {
  id?: string;
  /**
   * Stable, machine-readable significance code (snake_case, namespaced by analyzer,
   * e.g. `android.debuggable`, `sqlite.deleted_record_recovered`, `windows.network_strings`).
   * The Reporter must match findings by `code` (or `category` fallback), never by parsing
   * the `title`/`detail` text. Assigned by the envelope builder, not by guessing from strings.
   */
  code?: string;
  level: "info" | "warn" | "error" | "critical" | string;
  title: string;
  detail: string;
  /** Human-readable grouping; retained for backward compatibility. Prefer `code` for machine matching. */
  category?: string;
  /** When true, a human examiner must eyeball this finding before it is treated as evidentiary. */
  review?: boolean;
  confidence?: "low" | "medium" | "high";
};

export type AnalysisArtifact = {
  id: string;
  label: string;
  kind: string;
  offset?: number;
  size?: number;
  sha256?: string;
  mime?: string;
  extension?: string;
  parentId?: string;
  depth?: number;
  confidence?: "low" | "medium" | "high";
};

export type AnalysisIndicator = {
  type: string;
  value: string;
  normalized?: string;
  source?: string;
  context?: string;
};

export type AnalysisLimitation = {
  code: string;
  detail: string;
};

export type AnalysisSource = CaseEvidenceFile & {
  id?: string;
};

export type AnalysisEnvelope<T = unknown> = {
  schemaVersion: "1";
  id: string;
  analyzer: {
    id: ToolId | string;
    version: string;
  };
  source: AnalysisSource[];
  run: {
    startedAt: string;
    completedAt: string;
    parameters?: Record<string, unknown>;
    /** Assigned by the result store on publish. Stable id for this run: `<evidenceKey>/<toolId>#<sequence>`. */
    runId?: string;
    /** 1-based sequence number for the same evidenceId + toolId (Run #1, #2, #3...). Assigned on publish. */
    sequence?: number;
  };
  summary: {
    title: string;
    text: string;
    metrics?: Array<{ label: string; value: string }>;
  };
  findings: AnalysisFinding[];
  indicators: AnalysisIndicator[];
  artifacts: AnalysisArtifact[];
  timeline: CaseTimelineEvent[];
  limitations: AnalysisLimitation[];
  data: T;
};

export function analysisResultText(result: AnalysisEnvelope, t?: Translation) {
  const L = {
    findings: t?.findingsSection ?? "Findings",
    artifacts: t?.artifactsSection ?? "Artifacts",
    limitations: t?.limitationsSection ?? "Limitations"
  };
  const lines = [result.summary.title, result.summary.text];
  if (result.summary.metrics?.length) {
    lines.push("", ...result.summary.metrics.map((metric) => `${metric.label}: ${metric.value}`));
  }
  if (result.findings.length) {
    lines.push("", `${L.findings}:`, ...result.findings.map((finding) => `[${finding.level}] ${finding.title}: ${finding.detail}`));
  }
  if (result.artifacts.length) {
    lines.push("", `${L.artifacts}:`, ...result.artifacts.slice(0, 100).map((artifact) => {
      const offset = artifact.offset == null ? "" : ` @ 0x${artifact.offset.toString(16).toUpperCase()}`;
      const size = artifact.size == null ? "" : ` (${artifact.size} bytes)`;
      return `${artifact.label}${offset}${size}`;
    }));
  }
  if (result.limitations.length) {
    lines.push("", `${L.limitations}:`, ...result.limitations.map((item) => `${item.code}: ${item.detail}`));
  }
  return lines.filter((line, index) => line || index > 0).join("\n").trim();
}

function markdownEscapeCell(value: unknown) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function findingLevelLabel(level: AnalysisFinding["level"], t: Translation) {
  if (level === "critical") return t.levelCritical;
  if (level === "error") return t.levelError;
  if (level === "warn") return t.levelWarn;
  return t.levelInfo;
}

/**
 * Render an AnalysisEnvelope as report markdown with its findings/artifacts as
 * tables (instead of a raw ```text block), so structured results are visibly
 * reviewable in the exported report.
 */
export function envelopeReportMarkdown(result: AnalysisEnvelope, t: Translation) {
  const sections: string[] = [
    `## ${result.summary.title}`,
    "",
    result.summary.text
  ];
  if (result.summary.metrics?.length) {
    sections.push(
      "",
      "| Metric | Value |",
      "| --- | --- |",
      ...result.summary.metrics.map((metric) => `| ${markdownEscapeCell(metric.label)} | ${markdownEscapeCell(metric.value)} |`)
    );
  }
  if (result.findings.length) {
    sections.push(
      "",
      `### ${t.findingsSection}`,
      "",
      "| Level | Code | Finding | Detail |",
      "| --- | --- | --- | --- |",
      ...result.findings.map((finding) => `| ${markdownEscapeCell(findingLevelLabel(finding.level, t))} | ${markdownEscapeCell(finding.code ?? finding.category ?? "")} | ${markdownEscapeCell(finding.title)} | ${markdownEscapeCell(finding.detail)} |`)
    );
  }
  if (result.artifacts.length) {
    sections.push(
      "",
      `### ${t.artifactsSection}`,
      "",
      "| Label | Kind | Offset | Size |",
      "| --- | --- | --- | --- |",
      ...result.artifacts.slice(0, 200).map((artifact) => `| ${markdownEscapeCell(artifact.label)} | ${markdownEscapeCell(artifact.kind)} | ${artifact.offset == null ? "--" : `0x${artifact.offset.toString(16).toUpperCase()}`} | ${artifact.size == null ? "--" : `${artifact.size}`} |`)
    );
  }
  if (result.limitations.length) {
    sections.push(
      "",
      `### ${t.limitationsSection}`,
      "",
      "| Code | Detail |",
      "| --- | --- |",
      ...result.limitations.map((item) => `| ${markdownEscapeCell(item.code)} | ${markdownEscapeCell(item.detail)} |`)
    );
  }
  return sections.join("\n");
}

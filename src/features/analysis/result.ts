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

export type AnalysisFinding = {
  id?: string;
  level: "info" | "warn" | "error" | "critical" | string;
  title: string;
  detail: string;
  category?: string;
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

export function analysisResultText(result: AnalysisEnvelope) {
  const lines = [result.summary.title, result.summary.text];
  if (result.summary.metrics?.length) {
    lines.push("", ...result.summary.metrics.map((metric) => `${metric.label}: ${metric.value}`));
  }
  if (result.findings.length) {
    lines.push("", "Findings:", ...result.findings.map((finding) => `[${finding.level}] ${finding.title}: ${finding.detail}`));
  }
  if (result.artifacts.length) {
    lines.push("", "Artifacts:", ...result.artifacts.slice(0, 100).map((artifact) => {
      const offset = artifact.offset == null ? "" : ` @ 0x${artifact.offset.toString(16).toUpperCase()}`;
      const size = artifact.size == null ? "" : ` (${artifact.size} bytes)`;
      return `${artifact.label}${offset}${size}`;
    }));
  }
  if (result.limitations.length) {
    lines.push("", "Limitations:", ...result.limitations.map((item) => `${item.code}: ${item.detail}`));
  }
  return lines.filter((line, index) => line || index > 0).join("\n").trim();
}

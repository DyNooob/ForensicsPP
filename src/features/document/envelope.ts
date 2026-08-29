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
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisIndicator, AnalysisLimitation } from "../analysis/result";
import type { DocumentAnalysis, DocumentFinding } from "./analyzer";

export type DocumentEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const EXTRACT_CAP = 200;
const INDICATOR_CAP = 200;

const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const ALLOWED_TLDS = new Set([
  "com", "net", "org", "io", "cn", "ru", "info", "biz", "xyz", "top", "cc", "su",
  "de", "fr", "uk", "us", "gov", "mil", "edu", "co", "me", "sh", "to", "tk", "ng",
  "br", "in", "jp", "kr", "tw", "cloud", "app", "dev", "online", "site", "live", "pro"
]);

function findingLevel(category: DocumentFinding["category"]): AnalysisFinding["level"] {
  if (category === "external" || category === "macro" || category === "action") return "warn";
  return "info";
}

function extractIndicators(findings: DocumentFinding[]): AnalysisIndicator[] {
  const seen = new Set<string>();
  const indicators: AnalysisIndicator[] = [];
  const push = (type: string, value: string) => {
    const normalized = value.toLowerCase().replace(/[.,;:)\]}]*$/, "");
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    indicators.push({ type, value: normalized, normalized, source: "document-relationships", context: "external relationship" });
  };
  for (const finding of findings) {
    if (indicators.length >= INDICATOR_CAP) break;
    if (finding.category !== "external") continue;
    const haystack = finding.detail ?? "";
    for (const match of haystack.match(URL_RE) ?? []) push("url", match);
    for (const match of haystack.match(DOMAIN_RE) ?? []) {
      const tld = match.slice(match.lastIndexOf(".") + 1).toLowerCase();
      if (ALLOWED_TLDS.has(tld)) push("domain", match);
    }
  }
  return indicators.slice(0, INDICATOR_CAP);
}

/**
 * Map an Office / PDF document analysis to a unified AnalysisEnvelope (beta.6 P0-2).
 *
 * Surfaces structural findings (external relationships, macros, actions),
 * encryption state, embedded-object extracts as artifacts, and external
 * relationship URLs/domains as indicators.
 */
export function buildDocumentForensicsEnvelope(analysis: DocumentAnalysis, meta: DocumentEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const findings: AnalysisFinding[] = [];

  if (analysis.encrypted) {
    findings.push({
      level: "error",
      title: "Document encrypted",
      detail: "An EncryptedPackage part was found; the document body cannot be inspected without decryption.",
      category: "doc-encrypted",
      confidence: "high"
    });
  }

  for (const finding of analysis.findings ?? []) {
    findings.push({
      level: findingLevel(finding.category),
      title: finding.label,
      detail: finding.detail,
      category: `doc-${finding.category}`,
      confidence: "high"
    });
  }

  const indicators = extractIndicators(analysis.findings ?? []);

  const artifacts: AnalysisArtifact[] = (analysis.extracts ?? [])
    .slice(0, EXTRACT_CAP)
    .map((extract, index) => ({
      id: `extract-${index}`,
      label: extract.name,
      kind: "document-extract",
      size: extract.size,
      confidence: "high" as const
    }));

  const limitations: AnalysisLimitation[] = [
    { code: "DOCUMENT_STRUCTURE_ONLY", detail: "Analysis covers container structure, metadata, embedded objects, and relationships; it does not decompile macros or reconstruct document semantics." }
  ];

  const source: CaseEvidenceFile = {
    name: analysis.name,
    size: analysis.size,
    type: analysis.kind === "PDF" ? "application/pdf" : "application/octet-stream",
    lastModified: ""
  };

  const externalCount = (analysis.findings ?? []).filter((item) => item.category === "external").length;
  const embeddedOrMacroCount = (analysis.findings ?? []).filter((item) => item.category === "embedded" || item.category === "macro").length;

  return {
    schemaVersion: "1",
    id: `document-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "documentforensics", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { kind: analysis.kind, subtype: analysis.subtype } },
    summary: {
      title: "Office / PDF document analysis",
      text: `${analysis.kind} · ${analysis.subtype}; ${analysis.findings.length} check(s), ${analysis.extracts.length} extractable embedded item(s).`,
      metrics: [
        { label: "Container", value: `${analysis.kind} · ${analysis.subtype}` },
        { label: "Size", value: `${analysis.size.toLocaleString()} B` },
        { label: "Pages", value: analysis.pages ? String(analysis.pages) : "--" },
        { label: "Revisions", value: analysis.revisions ? String(analysis.revisions) : "--" },
        { label: "Parts / streams", value: String(analysis.entries.length) },
        { label: "Findings", value: String(analysis.findings.length) },
        { label: "Embedded / macro", value: String(embeddedOrMacroCount) },
        { label: "External", value: String(externalCount) },
        { label: "Extracts", value: String(analysis.extracts.length) },
        { label: "Encrypted", value: analysis.encrypted ? "yes" : "no" }
      ]
    },
    findings: findings.map((f) => ({ ...f, code: f.code ?? f.category ?? "document.finding" })),
    indicators,
    artifacts,
    timeline: [],
    limitations,
    data: {
      name: analysis.name,
      size: analysis.size,
      kind: analysis.kind,
      subtype: analysis.subtype,
      pages: analysis.pages,
      revisions: analysis.revisions,
      encrypted: analysis.encrypted,
      metadataCount: analysis.metadata.length,
      findingCount: analysis.findings.length,
      extractCount: analysis.extracts.length,
      entryCount: analysis.entries.length,
      notes: analysis.notes
    }
  };
}

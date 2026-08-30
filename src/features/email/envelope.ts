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
import type { EmailAnalysis } from "../../models";

export type EmailEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
  /** Source file name (or "pasted email" for the text input). */
  sourceName?: string;
  /** Source size in bytes (raw message size when available). */
  sourceSize?: number;
  /** "eml" | "msg". */
  format?: string;
};

const INDICATOR_CAP = 200;
const ARTIFACT_CAP = 200;
const TIMELINE_CAP = 5000;

function toCaseTimeline(hop: EmailAnalysis["receivedHops"][number]): CaseTimelineEvent {
  return {
    iso: hop.date,
    local: hop.date,
    raw: hop.date,
    format: "",
    line: 0,
    source: `Received: ${hop.from} → ${hop.by}`,
    context: hop.ip ? `relay ip ${hop.ip}` : hop.raw
  };
}

function extractIndicators(analysis: EmailAnalysis): AnalysisIndicator[] {
  const seen = new Set<string>();
  const indicators: AnalysisIndicator[] = [];
  for (const hop of analysis.receivedHops) {
    if (indicators.length >= INDICATOR_CAP) break;
    const ip = hop.ip.trim();
    if (!ip || seen.has(ip)) continue;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) continue;
    seen.add(ip);
    indicators.push({ type: "ipv4", value: ip, normalized: ip, source: "email-received", context: `relay ${hop.from} → ${hop.by}` });
  }
  return indicators.slice(0, INDICATOR_CAP);
}

/**
 * Map an email analysis to a unified AnalysisEnvelope (beta.6 P0-2, C-B4).
 *
 * Email is chain-of-custody evidence: the Received hop chain forms a routing
 * timeline, relay IPs become indicators, attachments become artifacts, and
 * authentication failures (SPF/DKIM/DMARC) become review findings.
 */
export function buildEmailEnvelope(analysis: EmailAnalysis, meta: EmailEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const sourceName = meta.sourceName ?? "pasted email";
  const sourceSize = meta.sourceSize ?? analysis.rawSize;
  const format = meta.format ?? "eml";

  const timeline = analysis.receivedHops
    .filter((hop) => hop.date)
    .slice(0, TIMELINE_CAP)
    .map(toCaseTimeline);
  const indicators = extractIndicators(analysis);
  const riskyHops = analysis.receivedHops.filter((hop) => hop.risk.length > 0);
  const failedAuth = analysis.authAssessments.filter((assessment) => /(fail|neutral|none|softfail|temperror|permerror)/i.test(assessment.result) || /(fail|misalign)/i.test(assessment.verdict));

  const findings: AnalysisFinding[] = [];
  findings.push({
    level: "info",
    title: "Email parsed",
    detail: `${analysis.attachments.length} attachment(s), ${analysis.receivedHops.length} Received hop(s), ${analysis.headers.length} header field(s).`,
    category: "email-parsed",
    confidence: "high"
  });
  if (failedAuth.length) {
    findings.push({
      level: "warn",
      title: "Authentication check failed",
      detail: `${failedAuth.length} Authentication-Results assessment(s) did not pass (${failedAuth.map((assessment) => `${assessment.mechanism}=${assessment.result}`).join(", ")}); sender identity may be spoofed.`,
      category: "email-auth-fail",
      review: true,
      confidence: "high"
    });
  }
  if (riskyHops.length) {
    findings.push({
      level: "warn",
      title: "Risky routing hop",
      detail: `${riskyHops.length} Received hop(s) carry a risk flag; review the relay chain for anomalies.`,
      category: "email-route-risk",
      review: true,
      confidence: "medium"
    });
  }

  const artifacts: AnalysisArtifact[] = analysis.attachments
    .slice(0, ARTIFACT_CAP)
    .map((attachment, index) => ({
      id: `attachment-${index}`,
      label: attachment.filename || `attachment-${index + 1}`,
      kind: "email-attachment",
      size: attachment.size,
      extension: attachment.extension,
      mime: attachment.contentType,
      confidence: "high" as const
    }));

  const limitations: AnalysisLimitation[] = [
    { code: "EMAIL_TRIAGE_SCOPE", detail: "Parsing covers headers, authentication results, the Received relay chain, and attachments; it does not decode encrypted message bodies or reassemble multipart beyond what the parser supports." },
    { code: "EMAIL_INPUT_LIMIT", detail: "Analysis is bounded by the 64 MiB message limit; larger mailboxes should be split per message." }
  ];

  const source: CaseEvidenceFile = {
    name: sourceName,
    size: sourceSize,
    type: format === "msg" ? "application/vnd.ms-outlook" : "message/rfc822",
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `email-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "email", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { format } },
    summary: {
      title: "Email analysis",
      text: `${analysis.attachments.length} attachment(s), ${analysis.receivedHops.length} Received hop(s); ${failedAuth.length ? "authentication FAILED" : "authentication passed"}.`,
      metrics: [
        { label: "Format", value: format.toUpperCase() },
        { label: "Size", value: `${sourceSize.toLocaleString()} B` },
        { label: "Attachments", value: String(analysis.attachments.length) },
        { label: "Received hops", value: String(analysis.receivedHops.length) },
        { label: "Headers", value: String(analysis.headers.length) },
        { label: "Auth failed", value: String(failedAuth.length) },
        { label: "Risky hops", value: String(riskyHops.length) },
        { label: "Timeline", value: String(timeline.length) },
        { label: "Indicators", value: String(indicators.length) }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "email.finding" })),
    indicators,
    artifacts,
    timeline,
    limitations,
    data: {
      format,
      rawSize: analysis.rawSize,
      attachmentCount: analysis.attachments.length,
      receivedHopCount: analysis.receivedHops.length,
      headerCount: analysis.headers.length,
      failedAuthCount: failedAuth.length,
      riskyHopCount: riskyHops.length,
      timelineCount: timeline.length,
      indicatorCount: indicators.length
    }
  };
}

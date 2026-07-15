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

import { copyText } from "../../utils/clipboard";
import React from "react";
import { CloseOutlined } from "@ant-design/icons";
import { Modal } from "antd";
import { AButton, InfoTable, PanelTitle } from "../../components/ui";
import { projectLinks } from "../../config/app";
import { fingerprintEvidenceFiles } from "./evidence";
import { readCaseBundleFile } from "./importer";
import { verifyEvidenceRegister, type EvidenceVerificationResult } from "./verification";
import { copy, type Translation } from "../../i18n";
import type { CaseNote, CaseReportMeta, CaseRiskLevel } from "../../models";
import { downloadTextFile, formatBytes, limitReportText, markdownEscapeCell } from "../../utils/files";
import { sha256Bytes } from "../../utils/hash";

function caseReportMetaRows(meta: CaseReportMeta) {
  return [
    ["Case", meta.caseName],
    ["Examiner", meta.examiner],
    ["Organization", meta.organization],
    ["Evidence ID", meta.evidenceId],
    ["Timezone", meta.timezone],
    ["Classification", meta.classification]
  ].filter(([, value]) => value.trim()) as Array<[string, string]>;
}

function caseNoteDigest(note: CaseNote) {
  return note.contentSha256 || sha256Bytes(new TextEncoder().encode(note.markdown || note.content));
}

export function caseNoteRiskLevel(note: CaseNote): CaseRiskLevel {
  const text = [note.title, note.tool, note.summary, note.content, note.markdown].filter(Boolean).join("\n");
  if (/(confirmed malware|confirmed credential leak|已确认恶意|已确认泄露|zip slip|crc mismatch|hash mismatch|signature mismatch|extension\/header mismatch|policy fail|dkim[^.\n]{0,40}fail|dmarc[^.\n]{0,40}fail|spf[^.\n]{0,40}fail|需进一步复核|需要复核|认证失败记录)/i.test(text)) {
    return "review";
  }
  return "normal";
}

function caseRiskLabel(level: CaseRiskLevel, t: Translation) {
  if (level === "critical") return t.riskCritical;
  if (level === "review") return t.riskReview;
  return t.riskNormal;
}

export function reviewLevelLabel(level: string, t: Translation) {
  if (level === "danger" || level === "warn" || level === "review") return t.riskReview;
  if (level === "info" || level === "normal") return t.riskNormal;
  return level;
}

function verificationStatusLabel(status: EvidenceVerificationResult["rows"][number]["status"] | undefined, t: Translation) {
  if (status === "match") return t.evidenceVerified;
  if (status === "mismatch") return t.evidenceMismatch;
  if (status === "missing") return t.evidenceMissing;
  if (status === "unverified") return t.evidenceUnverified;
  return "--";
}

function caseReportToolCount(notes: CaseNote[]) {
  return new Set(notes.map((note) => note.tool).filter(Boolean)).size;
}

function caseReportSourceFiles(notes: CaseNote[]) {
  return notes.flatMap((note) => (note.evidenceFiles ?? []).map((file) => ({ file, note })));
}

function caseReportSourceBytes(notes: CaseNote[]) {
  return caseReportSourceFiles(notes).reduce((total, item) => total + item.file.size, 0);
}

function caseReportTimelineEventCount(notes: CaseNote[]) {
  return notes.reduce((total, note) => total + (note.timelineEvents?.length ?? 0), 0);
}

function caseReportDuplicateDigestCount(notes: CaseNote[]) {
  const seen = new Set<string>();
  let duplicates = 0;
  notes.forEach((note) => {
    const digest = caseNoteDigest(note);
    if (seen.has(digest)) duplicates += 1;
    else seen.add(digest);
  });
  return duplicates;
}

function caseReportEvidenceSetDigest(notes: CaseNote[]) {
  const manifest = notes.map((note, index) => ({
    index: index + 1,
    id: note.id,
    tool: note.tool,
    title: note.title,
    createdAt: note.createdAt,
    digest: caseNoteDigest(note),
    evidenceFiles: note.evidenceFiles ?? []
  }));
  return sha256Bytes(new TextEncoder().encode(JSON.stringify(manifest)));
}

function caseReportSummaryCards(notes: CaseNote[], t: Translation) {
  const reviewCount = notes.filter((note) => caseNoteRiskLevel(note) === "review").length;
  const duplicateCount = caseReportDuplicateDigestCount(notes);
  return [
    { label: t.evidenceItems, value: String(notes.length), detail: t.reportItems, tone: "normal" },
    { label: t.uniqueTools, value: String(caseReportToolCount(notes)), detail: t.tools, tone: "normal" },
    { label: t.sourceFiles, value: String(caseReportSourceFiles(notes).length), detail: formatBytes(caseReportSourceBytes(notes)), tone: "normal" },
    { label: t.timelineEvents, value: String(caseReportTimelineEventCount(notes)), detail: t.parsedTimelineEvents, tone: "normal" },
    { label: t.riskItems, value: String(reviewCount), detail: reviewCount ? t.riskReview : t.riskNormal, tone: reviewCount ? "review" : "normal" },
    { label: t.duplicateDigests, value: String(duplicateCount), detail: duplicateCount ? "Digest collision in notes" : "No duplicate content digest", tone: duplicateCount ? "review" : "normal" }
  ];
}

function caseReportIntegrityRows(notes: CaseNote[], meta: CaseReportMeta, markdown: string, t: Translation): Array<[string, string]> {
  return [
    [t.evidenceItems, String(notes.length)],
    [t.uniqueTools, String(caseReportToolCount(notes))],
    [t.sourceFiles, String(caseReportSourceFiles(notes).length)],
    [t.sourceBytes, formatBytes(caseReportSourceBytes(notes))],
    [t.timelineEvents, String(caseReportTimelineEventCount(notes))],
    [t.duplicateDigests, String(caseReportDuplicateDigestCount(notes))],
    ["Evidence Set SHA256", caseReportEvidenceSetDigest(notes)],
    [t.reportSha256, sha256Bytes(new TextEncoder().encode(markdown))],
    ["Case", meta.caseName || "--"],
    ["Evidence ID", meta.evidenceId || "--"]
  ];
}

function caseReportTimelineRows(notes: CaseNote[]) {
  return notes.flatMap((note, index) => [
    {
      index: index + 1,
      at: note.createdAt,
      tool: note.tool,
      title: note.title,
      detail: "",
      risk: caseNoteRiskLevel(note),
      digest: caseNoteDigest(note)
    },
    ...(note.timelineEvents ?? []).map((event, eventIndex) => ({
      index: index + 1,
      at: event.iso,
      tool: note.tool,
      title: event.context || event.raw || event.iso,
      detail: `${event.format} · ${event.source} · ${event.line}`,
      risk: "normal" as CaseRiskLevel,
      digest: sha256Bytes(new TextEncoder().encode(`${note.id}:${event.iso}:${event.raw}:${event.context}:${eventIndex}`))
    }))
  ])
    .sort((a, b) => a.at.localeCompare(b.at));
}

function caseReportNoteTimelineRows(notes: CaseNote[]) {
  return notes
    .map((note, index) => ({
      index: index + 1,
      at: note.createdAt,
      tool: note.tool,
      title: note.title,
      risk: caseNoteRiskLevel(note),
      digest: caseNoteDigest(note)
    }))
    .sort((a, b) => a.at.localeCompare(b.at));
}

function caseReportBundle(notes: CaseNote[], meta: CaseReportMeta, markdown: string) {
  return {
    generatedAt: new Date().toISOString(),
    project: projectLinks.repo,
    meta,
    integrity: {
      evidenceItems: notes.length,
      uniqueTools: caseReportToolCount(notes),
      sourceFiles: caseReportSourceFiles(notes).length,
      sourceBytes: caseReportSourceBytes(notes),
      timelineEvents: caseReportTimelineEventCount(notes),
      duplicateDigests: caseReportDuplicateDigestCount(notes),
      evidenceSetSha256: caseReportEvidenceSetDigest(notes),
      reportSha256: sha256Bytes(new TextEncoder().encode(markdown))
    },
    timeline: caseReportTimelineRows(notes),
    evidenceFiles: caseReportSourceFiles(notes).map(({ file, note }) => ({ ...file, noteId: note.id, tool: note.tool, noteTitle: note.title })),
    notes: notes.map((note, index) => ({
      ...note,
      index: index + 1,
      riskLevel: caseNoteRiskLevel(note),
      digest: caseNoteDigest(note)
    })),
    markdown
  };
}

function caseNotesToCsv(notes: CaseNote[]) {
  const escape = (value: unknown) => {
    const text = String(value ?? "");
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["index", "id", "tool", "title", "note_level", "created_at", "route", "source_url", "summary", "content_sha256", "source_files", "source_sha256", "timeline_events"].join(","),
    ...notes.map((note, index) => [
      index + 1,
      note.id,
      note.tool,
      note.title,
      caseNoteRiskLevel(note),
      note.createdAt,
      note.route ?? "",
      note.sourceUrl ?? "",
      note.summary || note.content.slice(0, 500),
      caseNoteDigest(note),
      note.evidenceFiles?.length ?? 0,
      (note.evidenceFiles ?? []).map((file) => file.sha256).filter(Boolean).join(";"),
      note.timelineEvents?.length ?? 0
    ].map(escape).join(","))
  ].join("\n");
}

export function buildReportMarkdown(notes: CaseNote[], t: Translation, meta?: CaseReportMeta) {
  const metaRows = meta ? caseReportMetaRows(meta) : [];
  const riskCounts = notes.reduce<Record<CaseRiskLevel, number>>((counts, note) => {
    counts[caseNoteRiskLevel(note)] += 1;
    return counts;
  }, { critical: 0, review: 0, normal: 0 });
  return [
    "# Forensics++ Evidence Report",
    "",
    `- Generated: ${new Date().toISOString()}`,
    `- Project: ${projectLinks.repo}`,
    `- Notes: ${notes.length}`,
    `- Unique Tools: ${caseReportToolCount(notes)}`,
    `- Source Files: ${caseReportSourceFiles(notes).length}`,
    `- Source Bytes: ${formatBytes(caseReportSourceBytes(notes))}`,
    `- Parsed Timeline Events: ${caseReportTimelineEventCount(notes)}`,
    `- Notes: ${riskCounts.review}`,
    `- Evidence Set SHA256: ${caseReportEvidenceSetDigest(notes)}`,
    ...metaRows.map(([label, value]) => `- ${label}: ${value}`),
    "",
    ...(meta?.remarks.trim() ? ["## Examiner Remarks", "", meta.remarks.trim(), ""] : []),
    "## Report Summary",
    "",
    `- ${t.evidenceItems}: ${notes.length}`,
    `- ${t.uniqueTools}: ${caseReportToolCount(notes)}`,
    `- ${t.riskReview}: ${riskCounts.review}`,
    `- ${t.riskNormal}: ${riskCounts.normal}`,
    `- ${t.duplicateDigests}: ${caseReportDuplicateDigestCount(notes)}`,
    "",
    "## Evidence Item Index",
    "",
    notes.length
      ? [
          "| # | Check | Tool | Title | Added | Content SHA256 |",
          "| --- | --- | --- | --- | --- | --- |",
          ...notes.map((note, index) => {
            const digest = caseNoteDigest(note);
            return `| ${index + 1} | ${caseRiskLabel(caseNoteRiskLevel(note), t)} | ${markdownEscapeCell(note.tool)} | ${markdownEscapeCell(note.title)} | ${note.createdAt} | ${digest} |`;
          })
        ].join("\n")
      : "_No evidence items added._",
    "",
    "## Capture Timeline",
    "",
    notes.length
      ? [
          "| Added | Tool | Title | Check |",
          "| --- | --- | --- | --- |",
          ...caseReportNoteTimelineRows(notes).map((row) => `| ${row.at} | ${markdownEscapeCell(row.tool)} | ${markdownEscapeCell(row.title)} | ${caseRiskLabel(row.risk, t)} |`)
        ].join("\n")
      : "_No timeline items._",
    "",
    "## Parsed Timeline Events",
    "",
    caseReportTimelineEventCount(notes)
      ? [
          "| Time | Tool | Format | Source | Line | Context |",
          "| --- | --- | --- | --- | --- | --- |",
          ...notes.flatMap((note) => (note.timelineEvents ?? []).map((event) => `| ${event.iso} | ${markdownEscapeCell(note.tool)} | ${markdownEscapeCell(event.format)} | ${markdownEscapeCell(event.source)} | ${event.line} | ${markdownEscapeCell(event.context || event.raw)} |`))
        ].join("\n")
      : "_No parsed timeline events were registered._",
    "",
    "## Evidence Register",
    "",
    caseReportSourceFiles(notes).length
      ? [
          "| File | Size | Type | SHA256 | Recorded by |",
          "| --- | --- | --- | --- | --- |",
          ...caseReportSourceFiles(notes).map(({ file, note }) => `| ${markdownEscapeCell(file.name)} | ${formatBytes(file.size)} | ${markdownEscapeCell(file.type || "--")} | ${file.sha256 || "--"} | ${markdownEscapeCell(note.tool)} |`)
        ].join("\n")
      : "_No source file was attached to a report item._",
    "",
    ...notes.flatMap((note, index) => [
      `## ${index + 1}. ${note.title}`,
      "",
      `- Tool: ${note.tool}`,
      `- Check: ${caseRiskLabel(caseNoteRiskLevel(note), t)}`,
      `- Added: ${note.createdAt}`,
      ...(note.route ? [`- Route: ${note.route}`] : []),
      ...(note.sourceUrl ? [`- Source URL: ${note.sourceUrl}`] : []),
      `- Content SHA256: ${caseNoteDigest(note)}`,
      ...(note.description ? [`- Tool Description: ${note.description}`] : []),
      ...(note.summary ? ["", "### Snapshot Summary", "", note.summary, ""] : []),
      "",
      note.markdown || ["```text", note.content, "```"].join("\n"),
      ""
    ])
  ].join("\n");
}

function reportHtmlEscape(value: unknown) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function reportHtmlCell(value: unknown) {
  return `<td>${reportHtmlEscape(value == null || value === "" ? "--" : value)}</td>`;
}

export function buildReportHtml(notes: CaseNote[], t: Translation, meta?: CaseReportMeta) {
  const generatedAt = new Date().toISOString();
  const markdown = buildReportMarkdown(notes, t, meta);
  const summaryCards = caseReportSummaryCards(notes, t);
  const integrityRows = caseReportIntegrityRows(notes, meta ?? {
    caseName: "",
    examiner: "",
    organization: "",
    evidenceId: "",
    timezone: "",
    classification: "",
    remarks: ""
  }, markdown, t);
  const metaRows = meta ? caseReportMetaRows(meta) : [];
  const timelineEvents = notes.flatMap((note) => (note.timelineEvents ?? []).map((event) => ({ note, event })));
  const sourceFiles = caseReportSourceFiles(notes);
  const language = t.caseReporter === copy.zh.caseReporter ? "zh-CN" : "en";
  const noteSections = notes.map((note, index) => {
    const content = limitReportText(note.markdown || note.content, 100000);
    return `
      <article class="note">
        <div class="note-heading"><span class="note-index">${index + 1}</span><div><h3>${reportHtmlEscape(note.title)}</h3><p>${reportHtmlEscape(note.tool)} · ${reportHtmlEscape(note.createdAt)} · ${reportHtmlEscape(caseRiskLabel(caseNoteRiskLevel(note), t))}</p></div></div>
        <dl class="detail-list">
          <div><dt>${reportHtmlEscape(t.noteContentHash)}</dt><dd><code>${reportHtmlEscape(caseNoteDigest(note))}</code></dd></div>
          ${note.route ? `<div><dt>Route</dt><dd>${reportHtmlEscape(note.route)}</dd></div>` : ""}
          ${note.sourceUrl ? `<div><dt>Source URL</dt><dd>${reportHtmlEscape(note.sourceUrl)}</dd></div>` : ""}
        </dl>
        ${note.summary ? `<p class="summary">${reportHtmlEscape(note.summary)}</p>` : ""}
        <pre>${reportHtmlEscape(content)}</pre>
      </article>`;
  }).join("\n");
  const html = `<!doctype html>
<html lang="${language}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${reportHtmlEscape(meta?.caseName || t.caseReporter)} - Forensics++</title>
  <style>
    :root { color-scheme: light; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f4f6fa; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 32px 20px 64px; }
    main { width: min(1180px, 100%); margin: 0 auto; }
    header, section, article { background: #fff; border: 1px solid #d9e0eb; border-radius: 10px; box-shadow: 0 6px 24px rgba(28, 42, 66, .06); }
    header { padding: 28px 32px; border-top: 4px solid #4457a6; }
    h1 { margin: 0; font-size: 30px; letter-spacing: -.02em; }
    h2 { margin: 0 0 16px; font-size: 19px; }
    h3 { margin: 0; font-size: 16px; }
    p { color: #58677e; line-height: 1.6; }
    .eyebrow { color: #4457a6; font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
    .generated { margin: 8px 0 0; font-size: 13px; }
    section { margin-top: 18px; padding: 24px 28px; }
    .meta-grid, .metric-grid { display: grid; gap: 10px; }
    .meta-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .metric-grid { grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); }
    .meta-item, .metric { min-width: 0; padding: 12px 14px; background: #f7f9fc; border: 1px solid #e3e8f0; border-radius: 7px; }
    .meta-item span, .metric span { display: block; color: #6a7890; font-size: 12px; }
    .meta-item strong, .metric strong { display: block; margin-top: 5px; overflow-wrap: anywhere; }
    .metric strong { font-size: 21px; }
    .metric.review { border-color: #e0bd78; background: #fffaf0; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #e6eaf1; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: #52627a; background: #f7f9fc; font-weight: 650; white-space: nowrap; }
    code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .note { margin-top: 14px; padding: 22px 24px; box-shadow: none; }
    .note-heading { display: flex; gap: 12px; align-items: flex-start; }
    .note-heading p { margin: 4px 0 0; font-size: 12px; }
    .note-index { display: grid; width: 28px; height: 28px; place-items: center; flex: 0 0 auto; color: #fff; background: #4457a6; border-radius: 50%; font-weight: 700; }
    .detail-list { display: grid; gap: 6px; margin: 18px 0; }
    .detail-list div { display: grid; grid-template-columns: 130px 1fr; gap: 12px; }
    dt { color: #6a7890; font-size: 12px; }
    dd { margin: 0; overflow-wrap: anywhere; }
    .summary { margin: 12px 0; padding: 10px 12px; background: #f7f9fc; border-left: 3px solid #4457a6; }
    pre { margin: 14px 0 0; padding: 14px; overflow: auto; color: #26344a; background: #f7f9fc; border: 1px solid #e3e8f0; border-radius: 6px; font: 12px/1.6 "SFMono-Regular", Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
    .muted { color: #6a7890; }
    footer { padding: 20px 4px; color: #6a7890; font-size: 12px; text-align: center; }
    @media (max-width: 640px) { body { padding: 16px 10px 36px; } header, section { padding: 20px 16px; } h1 { font-size: 24px; } .detail-list div { grid-template-columns: 1fr; gap: 3px; } }
    @media print { body { padding: 0; background: #fff; } header, section, article { box-shadow: none; break-inside: avoid; } section { margin-top: 12px; } }
  </style>
</head>
<body>
  <main>
    <header><div class="eyebrow">Forensics++</div><h1>${reportHtmlEscape(meta?.caseName || t.caseReporter)}</h1><p class="generated">${reportHtmlEscape(t.lastUpdated)}: ${reportHtmlEscape(generatedAt)} · ${reportHtmlEscape(projectLinks.repo)}</p></header>
    ${metaRows.length ? `<section><h2>${reportHtmlEscape(t.reportMeta)}</h2><div class="meta-grid">${metaRows.map(([label, value]) => `<div class="meta-item"><span>${reportHtmlEscape(label)}</span><strong>${reportHtmlEscape(value)}</strong></div>`).join("")}</div>${meta?.remarks.trim() ? `<p>${reportHtmlEscape(meta.remarks)}</p>` : ""}</section>` : ""}
    <section><h2>${reportHtmlEscape(t.reportSummary)}</h2><div class="metric-grid">${summaryCards.map((card) => `<div class="metric ${card.tone === "review" ? "review" : ""}"><span>${reportHtmlEscape(card.label)}</span><strong>${reportHtmlEscape(card.value)}</strong><span>${reportHtmlEscape(card.detail)}</span></div>`).join("")}</div></section>
    <section><h2>${reportHtmlEscape(t.reportIntegrity)}</h2><div class="table-wrap"><table><tbody>${integrityRows.map(([label, value]) => `<tr><th>${reportHtmlEscape(label)}</th>${reportHtmlCell(value)}</tr>`).join("")}</tbody></table></div></section>
    <section><h2>${reportHtmlEscape(t.reportItems)}</h2>${notes.length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>${reportHtmlEscape(t.sourceRole)}</th><th>${reportHtmlEscape(t.noteTitle)}</th><th>${reportHtmlEscape(t.lastUpdated)}</th><th>${reportHtmlEscape(t.noteContentHash)}</th></tr></thead><tbody>${notes.map((note, index) => `<tr>${reportHtmlCell(index + 1)}${reportHtmlCell(note.tool)}${reportHtmlCell(note.title)}${reportHtmlCell(note.createdAt)}${reportHtmlCell(caseNoteDigest(note))}</tr>`).join("")}</tbody></table></div>` : `<p class="muted">${reportHtmlEscape(t.noNotes)}</p>`}</section>
    ${timelineEvents.length ? `<section><h2>${reportHtmlEscape(t.parsedTimelineEvents)}</h2><div class="table-wrap"><table><thead><tr><th>${reportHtmlEscape(t.timestamp)}</th><th>${reportHtmlEscape(t.sourceRole)}</th><th>Format</th><th>Source</th><th>Line</th><th>Context</th></tr></thead><tbody>${timelineEvents.map(({ note, event }) => `<tr>${reportHtmlCell(event.iso)}${reportHtmlCell(note.tool)}${reportHtmlCell(event.format)}${reportHtmlCell(event.source)}${reportHtmlCell(event.line)}${reportHtmlCell(event.context || event.raw)}</tr>`).join("")}</tbody></table></div></section>` : ""}
    ${sourceFiles.length ? `<section><h2>${reportHtmlEscape(t.evidenceRegister)}</h2><div class="table-wrap"><table><thead><tr><th>${reportHtmlEscape(t.sourceFile)}</th><th>${reportHtmlEscape(t.sourceBytes)}</th><th>Type</th><th>SHA256</th><th>${reportHtmlEscape(t.sourceRole)}</th></tr></thead><tbody>${sourceFiles.map(({ file, note }) => `<tr>${reportHtmlCell(file.name)}${reportHtmlCell(formatBytes(file.size))}${reportHtmlCell(file.type)}${reportHtmlCell(file.sha256)}${reportHtmlCell(note.tool)}</tr>`).join("")}</tbody></table></div></section>` : ""}
    <section><h2>${reportHtmlEscape(t.reportItems)}</h2>${noteSections || `<p class="muted">${reportHtmlEscape(t.noNotes)}</p>`}</section>
    <footer>${reportHtmlEscape(projectLinks.repo)} · ${reportHtmlEscape(t.reportSha256)}: ${reportHtmlEscape(sha256Bytes(new TextEncoder().encode(markdown)))}</footer>
  </main>
</body>
</html>`;
  return html;
}

export function CaseReporter({
  notes,
  meta,
  t,
  onClose,
  onMetaChange,
  onUpdateNote,
  onDeleteNote,
  onClear,
  onImport
}: {
  notes: CaseNote[];
  meta: CaseReportMeta;
  t: Translation;
  onClose: () => void;
  onMetaChange: (meta: CaseReportMeta) => void;
  onUpdateNote: (id: string, patch: Partial<CaseNote>) => void;
  onDeleteNote: (id: string) => void;
  onClear: () => void;
  onImport: (bundle: { notes: CaseNote[]; meta: CaseReportMeta }) => void;
}) {
  const [query, setQuery] = React.useState("");
  const [selectedId, setSelectedId] = React.useState(notes[0]?.id ?? "");
  const [importError, setImportError] = React.useState("");
  const [verification, setVerification] = React.useState<EvidenceVerificationResult | null>(null);
  const [verificationBusy, setVerificationBusy] = React.useState(false);
  const [verificationError, setVerificationError] = React.useState("");
  const importInputRef = React.useRef<HTMLInputElement | null>(null);
  const verificationInputRef = React.useRef<HTMLInputElement | null>(null);
  const verificationAbortRef = React.useRef<AbortController | null>(null);
  const markdown = buildReportMarkdown(notes, t, meta);
  const htmlReport = React.useMemo(() => buildReportHtml(notes, t, meta), [meta, notes, t]);
  const summaryCards = React.useMemo(() => caseReportSummaryCards(notes, t), [notes, t]);
  const integrityRows = React.useMemo(() => caseReportIntegrityRows(notes, meta, markdown, t), [notes, meta, markdown, t]);
  const timelineRows = React.useMemo(() => caseReportTimelineRows(notes), [notes]);
  const reportBundle = React.useMemo(() => caseReportBundle(notes, meta, markdown), [notes, meta, markdown]);
  const visibleNotes = React.useMemo(() => {
    const value = query.trim().toLowerCase();
    if (!value) return notes;
    return notes.filter((note) => [note.title, note.tool, note.description, note.route, note.sourceUrl, note.summary, note.content, note.markdown, caseNoteDigest(note)].join(" ").toLowerCase().includes(value));
  }, [notes, query]);
  const selectedNote = notes.find((note) => note.id === selectedId) ?? visibleNotes[0] ?? notes[0] ?? null;
  const selectedDigest = selectedNote ? caseNoteDigest(selectedNote) : "";

  React.useEffect(() => {
    if (!selectedId || !notes.some((note) => note.id === selectedId)) setSelectedId(notes[0]?.id ?? "");
  }, [notes, selectedId]);

  React.useEffect(() => () => {
    verificationAbortRef.current?.abort();
  }, []);

  const updateMetaField = (field: keyof CaseReportMeta, value: string) => {
    onMetaChange({ ...meta, [field]: value });
  };

  const importBundle = async (file: File | undefined) => {
    if (!file) return;
    setImportError("");
    try {
      const bundle = await readCaseBundleFile(file);
      Modal.confirm({
        title: t.importReportConfirmTitle,
        content: `${t.importReportConfirmText} (${bundle.notes.length} ${t.reportItems})`,
        okText: t.importReport,
        cancelText: t.cancelEdit,
        onOk: () => {
          onImport(bundle);
          setQuery("");
          setSelectedId(bundle.notes[0]?.id ?? "");
        }
      });
    } catch (error) {
      setImportError(error instanceof Error ? error.message : String(error));
    } finally {
      if (importInputRef.current) importInputRef.current.value = "";
    }
  };

  const verifySourceFiles = async (files: FileList | File[] | null | undefined) => {
    const selected = Array.from(files ?? []);
    if (!selected.length) return;
    const registered = caseReportSourceFiles(notes).map(({ file }) => file);
    if (!registered.length) return;
    verificationAbortRef.current?.abort();
    const controller = new AbortController();
    verificationAbortRef.current = controller;
    setVerificationBusy(true);
    setVerificationError("");
    try {
      const uploaded = await fingerprintEvidenceFiles(selected, { signal: controller.signal });
      if (controller.signal.aborted) return;
      setVerification(verifyEvidenceRegister(registered, uploaded));
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        setVerificationError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (verificationAbortRef.current === controller) {
        verificationAbortRef.current = null;
        setVerificationBusy(false);
      }
      if (verificationInputRef.current) verificationInputRef.current.value = "";
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div className="modal-panel reporter-panel" role="dialog" aria-modal="true" aria-labelledby="reporter-title" onClick={(event) => event.stopPropagation()}>
        <div className="command-title-row">
          <div>
            <h2 id="reporter-title">{t.caseReporter}</h2>
            <span>{notes.length} {t.tools} · {visibleNotes.length} {t.visibleNotes}</span>
          </div>
          <AButton className="modal-close-button" variant="text" icon={<CloseOutlined aria-hidden="true" />} aria-label={t.close} title={t.close} onClick={onClose} />
        </div>
        <div className="reporter-actions">
          <input ref={importInputRef} className="hidden-file-input" type="file" accept="application/json,.json" aria-hidden="true" tabIndex={-1} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void importBundle(file); }} />
          <AButton variant="outlined" onClick={() => importInputRef.current?.click()}>
            {t.importReport}
          </AButton>
          <AButton variant="filled" disabled={!notes.length} onClick={() => downloadTextFile(`forensicspp-report-${Date.now()}.md`, markdown)}>
            {t.exportReport}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={() => downloadTextFile(`forensicspp-report-${Date.now()}.html`, htmlReport, "text/html;charset=utf-8")}>
            {t.exportReportHtml}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={() => void copyText(markdown)}>
            {t.copyReportMarkdown}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={() => downloadTextFile(`forensicspp-report-${Date.now()}.json`, JSON.stringify(reportBundle, null, 2), "application/json;charset=utf-8")}>
            {t.exportReportJson}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={() => downloadTextFile(`forensicspp-report-bundle-${Date.now()}.json`, JSON.stringify(reportBundle, null, 2), "application/json;charset=utf-8")}>
            {t.exportReportBundle}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={() => downloadTextFile(`forensicspp-notes-index-${Date.now()}.csv`, caseNotesToCsv(notes), "text/csv;charset=utf-8")}>
            {t.exportNotesCsv}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={onClear}>
            {t.clearNotes}
          </AButton>
        </div>
        {importError && <div className="empty-state error-state reporter-import-error">{importError}</div>}
        <div className="reporter-meta-panel">
          <PanelTitle title={t.reportMeta} />
          <div className="reporter-meta-grid">
            <label>{t.caseName}<input value={meta.caseName} onChange={(event) => updateMetaField("caseName", event.target.value)} /></label>
            <label>{t.examiner}<input value={meta.examiner} onChange={(event) => updateMetaField("examiner", event.target.value)} /></label>
            <label>{t.organization}<input value={meta.organization} onChange={(event) => updateMetaField("organization", event.target.value)} /></label>
            <label>{t.evidenceId}<input value={meta.evidenceId} onChange={(event) => updateMetaField("evidenceId", event.target.value)} /></label>
            <label>{t.timezone}<input value={meta.timezone} onChange={(event) => updateMetaField("timezone", event.target.value)} /></label>
            <label>{t.classification}<input value={meta.classification} onChange={(event) => updateMetaField("classification", event.target.value)} /></label>
            <label className="reporter-meta-wide">{t.reportRemarks}<textarea value={meta.remarks} onChange={(event) => updateMetaField("remarks", event.target.value)} /></label>
          </div>
        </div>
        {notes.length ? (
          <div className="reporter-summary-panel">
            <PanelTitle title={t.reportSummary} />
            <div className="reporter-summary-grid">
              {summaryCards.map((card) => (
                <div className={`reporter-summary-card ${card.tone}`} key={card.label}>
                  <span>{card.label}</span>
                  <strong>{card.value}</strong>
                  <small>{card.detail}</small>
                </div>
              ))}
            </div>
          </div>
        ) : null}
        {notes.length ? (
          <div className="reporter-layout">
            <div className="reporter-notes-panel">
              <div className="reporter-section-head">
                <PanelTitle title={t.reportItems} />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t.searchNotes} aria-label={t.searchNotes} />
              </div>
              <div className="reporter-notes">
                {visibleNotes.map((note) => {
                  const risk = caseNoteRiskLevel(note);
                  return (
                  <button
                    className={`reporter-note-card ${risk}${selectedNote?.id === note.id ? " active" : ""}`}
                    key={note.id}
                    type="button"
                    onClick={() => setSelectedId(note.id)}
                  >
                    <div className="reporter-note-card-head">
                      <strong>{note.title}</strong>
                      <em>{caseRiskLabel(risk, t)}</em>
                    </div>
                    <span>{note.tool} · {note.route ?? "--"} · {note.createdAt}</span>
                    <p>{note.summary || note.content}</p>
                  </button>
                  );
                })}
                {!visibleNotes.length && <div className="empty-state">{t.noNotes}</div>}
              </div>
            </div>
            <div className="reporter-detail-panel">
              <div className="reporter-section-head">
                <PanelTitle title={t.selectedNote} />
                <div className="button-row compact-buttons">
                  <AButton variant="outlined" disabled={!selectedNote} onClick={() => selectedNote && void copyText(selectedNote.markdown || selectedNote.content)}>
                    {t.copyNote}
                  </AButton>
                  <AButton variant="outlined" disabled={!selectedNote} onClick={() => selectedNote && onDeleteNote(selectedNote.id)}>
                    {t.deleteNote}
                  </AButton>
                </div>
              </div>
              {selectedNote ? (
                <>
                  <label className="reporter-title-edit">
                    {t.noteTitle}
                    <input value={selectedNote.title} onChange={(event) => onUpdateNote(selectedNote.id, { title: event.target.value })} />
                  </label>
                  <InfoTable rows={[
                    [t.sourceRole, selectedNote.tool],
                    [t.riskLevel, caseRiskLabel(caseNoteRiskLevel(selectedNote), t)],
                    [t.lastUpdated, selectedNote.createdAt],
                    ["Route", selectedNote.route ?? "--"],
                    ["Source URL", selectedNote.sourceUrl ?? "--"],
                    [t.sourceFiles, selectedNote.evidenceFiles?.map((file) => file.name).join(", ") || "--"],
                    [t.timelineEvents, String(selectedNote.timelineEvents?.length ?? 0)],
                    [t.noteContentHash, selectedDigest]
                  ]} />
                  <textarea
                    className="reporter-note-content"
                    value={selectedNote.markdown || selectedNote.content}
                    onChange={(event) => {
                      const value = event.target.value;
                      onUpdateNote(selectedNote.id, {
                        markdown: value,
                        content: value,
                        summary: limitReportText(value.replace(/\s+/g, " "), 420),
                        contentSha256: sha256Bytes(new TextEncoder().encode(value))
                      });
                    }}
                    aria-label={t.selectedNote}
                  />
                </>
              ) : (
                <div className="empty-state">{t.noNotes}</div>
              )}
            </div>
            <div className="reporter-preview-panel">
              <PanelTitle title={t.reportPreview} />
              <div className="reporter-integrity-box">
                <PanelTitle title={t.reportIntegrity} />
                <InfoTable rows={integrityRows} />
              </div>
              <div className="reporter-timeline-box">
                <PanelTitle title={t.reportTimeline} />
                <div className="reporter-timeline-list">
                  {timelineRows.slice(-6).map((row) => (
                    <div className={`reporter-timeline-row ${row.risk}`} key={`${row.at}-${row.digest}`}>
                      <span>{row.at}</span>
                      <strong>{row.title}</strong>
                      <em>{row.detail || row.tool}</em>
                    </div>
                  ))}
                </div>
              </div>
              <div className="reporter-evidence-box">
                <div className="reporter-section-head">
                  <PanelTitle title={t.evidenceRegister} />
                  <>
                    <input ref={verificationInputRef} className="hidden-file-input" type="file" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { const files = event.currentTarget.files; event.currentTarget.value = ""; void verifySourceFiles(files); }} />
                    <AButton variant="outlined" disabled={!caseReportSourceFiles(notes).length || verificationBusy} onClick={() => verificationInputRef.current?.click()} aria-busy={verificationBusy}>
                      {verificationBusy ? t.verifyingEvidence : t.verifyEvidence}
                    </AButton>
                  </>
                </div>
                {caseReportSourceFiles(notes).length ? (
                  <div className="table-scroll reporter-evidence-table">
                    <table className="data-table">
                      <thead><tr><th>{t.sourceFile}</th><th>{t.sourceBytes}</th><th>{t.sourceHash}</th><th>{t.sourceRole}</th><th>{t.evidenceVerification}</th></tr></thead>
                      <tbody>
                        {caseReportSourceFiles(notes).map(({ file, note }, index) => (
                          <tr key={`${file.name}:${file.size}:${file.sha256 ?? index}`}>
                            <td title={file.name}>{file.name}</td>
                            <td>{formatBytes(file.size)}</td>
                            <td><code>{file.sha256 || "--"}</code></td>
                            <td>{note.tool}</td>
                            <td>{verification ? verificationStatusLabel(verification.rows[index]?.status, t) : "--"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <div className="empty-state">{t.noSourceFiles}</div>}
                {verification && <div className="reporter-verification-summary">
                  <span>{t.evidenceVerified}: {verification.matchedCount}</span>
                  <span>{t.evidenceMismatch}: {verification.mismatchCount}</span>
                  <span>{t.evidenceMissing}: {verification.missingCount}</span>
                  {verification.unregisteredCount > 0 && <span>{t.evidenceUnregistered}: {verification.unregisteredCount}</span>}
                </div>}
                {verificationError && <div className="empty-state error-state">{verificationError}</div>}
              </div>
              <textarea className="reporter-markdown" value={markdown} readOnly aria-label="Evidence report markdown" />
            </div>
          </div>
        ) : (
          <div className="empty-state">{t.noNotes}</div>
        )}
      </div>
    </div>
  );
}

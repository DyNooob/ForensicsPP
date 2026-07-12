/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import React from "react";
import { CloseOutlined } from "@ant-design/icons";
import { AButton, InfoTable, PanelTitle } from "../../components/ui";
import { projectLinks } from "../../config/app";
import type { Translation } from "../../i18n";
import type { CaseNote, CaseReportMeta, CaseRiskLevel } from "../../models";
import { downloadTextFile, limitReportText, markdownEscapeCell } from "../../utils/files";
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

function caseNoteRiskLevel(note: CaseNote): CaseRiskLevel {
  const text = [note.title, note.tool, note.summary, note.content, note.markdown].filter(Boolean).join("\n");
  if (/(confirmed malware|confirmed credential leak|已确认恶意|已确认泄露|password\s*[:=]|passwd\s*[:=]|secret\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=]|credential leak|malware|zip slip|crc mismatch|hash mismatch|signature mismatch|extension\/header mismatch|policy fail|dkim[^.\n]{0,40}fail|dmarc[^.\n]{0,40}fail|spf[^.\n]{0,40}fail|需进一步复核|需要复核|认证失败记录|泄露|恶意|凭据泄露|口令泄露)/i.test(text)) {
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

function caseReportToolCount(notes: CaseNote[]) {
  return new Set(notes.map((note) => note.tool).filter(Boolean)).size;
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
    digest: caseNoteDigest(note)
  }));
  return sha256Bytes(new TextEncoder().encode(JSON.stringify(manifest)));
}

function caseReportSummaryCards(notes: CaseNote[], t: Translation) {
  const reviewCount = notes.filter((note) => caseNoteRiskLevel(note) === "review").length;
  const duplicateCount = caseReportDuplicateDigestCount(notes);
  return [
    { label: t.evidenceItems, value: String(notes.length), detail: t.reportItems, tone: "normal" },
    { label: t.uniqueTools, value: String(caseReportToolCount(notes)), detail: t.tools, tone: "normal" },
    { label: t.riskItems, value: String(reviewCount), detail: reviewCount ? t.riskReview : t.riskNormal, tone: reviewCount ? "review" : "normal" },
    { label: t.duplicateDigests, value: String(duplicateCount), detail: duplicateCount ? "Digest collision in notes" : "No duplicate content digest", tone: duplicateCount ? "review" : "normal" }
  ];
}

function caseReportIntegrityRows(notes: CaseNote[], meta: CaseReportMeta, markdown: string, t: Translation): Array<[string, string]> {
  return [
    [t.evidenceItems, String(notes.length)],
    [t.uniqueTools, String(caseReportToolCount(notes))],
    [t.duplicateDigests, String(caseReportDuplicateDigestCount(notes))],
    ["Evidence Set SHA256", caseReportEvidenceSetDigest(notes)],
    [t.reportSha256, sha256Bytes(new TextEncoder().encode(markdown))],
    ["Case", meta.caseName || "--"],
    ["Evidence ID", meta.evidenceId || "--"]
  ];
}

function caseReportTimelineRows(notes: CaseNote[]) {
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
      duplicateDigests: caseReportDuplicateDigestCount(notes),
      evidenceSetSha256: caseReportEvidenceSetDigest(notes),
      reportSha256: sha256Bytes(new TextEncoder().encode(markdown))
    },
    timeline: caseReportTimelineRows(notes),
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
    ["index", "id", "tool", "title", "note_level", "created_at", "route", "source_url", "summary", "content_sha256"].join(","),
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
      caseNoteDigest(note)
    ].map(escape).join(","))
  ].join("\n");
}

function buildReportMarkdown(notes: CaseNote[], t: Translation, meta?: CaseReportMeta) {
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
          ...caseReportTimelineRows(notes).map((row) => `| ${row.at} | ${markdownEscapeCell(row.tool)} | ${markdownEscapeCell(row.title)} | ${caseRiskLabel(row.risk, t)} |`)
        ].join("\n")
      : "_No timeline items._",
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

export function CaseReporter({
  notes,
  meta,
  t,
  onClose,
  onMetaChange,
  onUpdateNote,
  onDeleteNote,
  onClear
}: {
  notes: CaseNote[];
  meta: CaseReportMeta;
  t: Translation;
  onClose: () => void;
  onMetaChange: (meta: CaseReportMeta) => void;
  onUpdateNote: (id: string, patch: Partial<CaseNote>) => void;
  onDeleteNote: (id: string) => void;
  onClear: () => void;
}) {
  const [query, setQuery] = React.useState("");
  const [selectedId, setSelectedId] = React.useState(notes[0]?.id ?? "");
  const markdown = buildReportMarkdown(notes, t, meta);
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

  const updateMetaField = (field: keyof CaseReportMeta, value: string) => {
    onMetaChange({ ...meta, [field]: value });
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
          <AButton variant="filled" disabled={!notes.length} onClick={() => downloadTextFile(`forensicspp-report-${Date.now()}.md`, markdown)}>
            {t.exportReport}
          </AButton>
          <AButton variant="outlined" disabled={!notes.length} onClick={() => void navigator.clipboard.writeText(markdown)}>
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
                  <AButton variant="outlined" disabled={!selectedNote} onClick={() => selectedNote && void navigator.clipboard.writeText(selectedNote.markdown || selectedNote.content)}>
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
                      <em>{row.tool}</em>
                    </div>
                  ))}
                </div>
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

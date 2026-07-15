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

import type { CaseEvidenceFile, CaseNote, CaseReportMeta, CaseTimelineEvent } from "../../models";

const MAX_IMPORTED_NOTES = 40;
const MAX_IMPORTED_NOTE_TEXT = 40_000;
const MAX_IMPORTED_EVENTS = 5_000;
const MAX_IMPORTED_FILES = 500;
const MAX_IMPORTED_BUNDLE_BYTES = 32 * 1024 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{64}$/i;

export type ImportedCaseBundle = {
  notes: CaseNote[];
  meta: CaseReportMeta;
};

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function stringValue(value: unknown, fallback = "", max = 5000) {
  return typeof value === "string" ? value.slice(0, max) : fallback;
}

function requiredString(value: unknown, field: string, index: number, max = 5000) {
  const result = stringValue(value).trim();
  if (!result) throw new Error(`Invalid ${field} in report item ${index + 1}.`);
  return result.slice(0, max);
}

function normalizeEvidenceFiles(value: unknown): CaseEvidenceFile[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, MAX_IMPORTED_FILES).flatMap((item) => {
    const source = record(item);
    if (!source) return [];
    const name = stringValue(source.name).trim();
    const size = typeof source.size === "number" && Number.isFinite(source.size) && source.size >= 0 ? source.size : null;
    if (!name || size == null) return [];
    const sha256 = stringValue(source.sha256).trim();
    return [{
      name: name.slice(0, 1000),
      size,
      type: stringValue(source.type, "application/octet-stream", 300),
      ...(stringValue(source.lastModified).trim() ? { lastModified: stringValue(source.lastModified).trim().slice(0, 80) } : {}),
      ...(SHA256_PATTERN.test(sha256) ? { sha256: sha256.toLowerCase() } : {})
    }];
  });
}

function normalizeTimelineEvents(value: unknown): CaseTimelineEvent[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, MAX_IMPORTED_EVENTS).flatMap((item) => {
    const source = record(item);
    if (!source) return [];
    const iso = stringValue(source.iso).trim();
    if (!iso || Number.isNaN(Date.parse(iso))) return [];
    const line = typeof source.line === "number" && Number.isFinite(source.line) ? Math.max(0, Math.floor(source.line)) : 0;
    const epochMs = typeof source.epochMs === "number" && Number.isFinite(source.epochMs) ? source.epochMs : undefined;
    return [{
      iso: iso.slice(0, 100),
      local: stringValue(source.local, iso, 100),
      raw: stringValue(source.raw, iso, 500),
      format: stringValue(source.format, "Unknown", 100),
      line,
      source: stringValue(source.source, "Imported report", 1000),
      context: stringValue(source.context, iso, 4000),
      ...(epochMs == null ? {} : { epochMs })
    }];
  });
}

function normalizeMeta(value: unknown): CaseReportMeta {
  const source = record(value);
  return {
    caseName: stringValue(source?.caseName).trim(),
    examiner: stringValue(source?.examiner).trim(),
    organization: stringValue(source?.organization).trim(),
    evidenceId: stringValue(source?.evidenceId).trim(),
    timezone: stringValue(source?.timezone).trim(),
    classification: stringValue(source?.classification).trim(),
    remarks: stringValue(source?.remarks, "", 20_000)
  };
}

function normalizeNote(value: unknown, index: number, usedIds: Set<string>): CaseNote {
  const source = record(value);
  if (!source) throw new Error(`Invalid report item ${index + 1}.`);
  const content = stringValue(source.content || source.markdown).trim();
  if (!content) throw new Error(`Report item ${index + 1} has no content.`);
  if (content.length > MAX_IMPORTED_NOTE_TEXT) throw new Error(`Report item ${index + 1} is too large.`);
  const createdAt = requiredString(source.createdAt, "created_at", index, 100);
  if (Number.isNaN(Date.parse(createdAt))) throw new Error(`Invalid created_at in report item ${index + 1}.`);
  const originalId = requiredString(source.id, "id", index, 200);
  let id = originalId;
  let suffix = 2;
  while (usedIds.has(id)) id = `${originalId}-${suffix++}`;
  usedIds.add(id);
  const title = requiredString(source.title, "title", index, 500);
  const tool = requiredString(source.tool, "tool", index, 300);
  const markdown = stringValue(source.markdown, content, MAX_IMPORTED_NOTE_TEXT);
  const summary = stringValue(source.summary, content.replace(/\s+/g, " "), 420);
  return {
    id,
    tool,
    title,
    content,
    ...(summary ? { summary } : {}),
    ...(markdown ? { markdown } : {}),
    ...(stringValue(source.description).trim() ? { description: stringValue(source.description).trim().slice(0, 2000) } : {}),
    ...(stringValue(source.route).trim() ? { route: stringValue(source.route).trim().slice(0, 300) } : {}),
    ...(stringValue(source.sourceUrl).trim() ? { sourceUrl: stringValue(source.sourceUrl).trim().slice(0, 2000) } : {}),
    ...(SHA256_PATTERN.test(stringValue(source.contentSha256).trim()) ? { contentSha256: stringValue(source.contentSha256).trim().toLowerCase() } : {}),
    ...(normalizeEvidenceFiles(source.evidenceFiles).length ? { evidenceFiles: normalizeEvidenceFiles(source.evidenceFiles) } : {}),
    ...(normalizeTimelineEvents(source.timelineEvents).length ? { timelineEvents: normalizeTimelineEvents(source.timelineEvents) } : {}),
    createdAt
  };
}

export function normalizeCaseBundle(value: unknown): ImportedCaseBundle {
  const source = record(value);
  if (!source || !Array.isArray(source.notes)) throw new Error("This file is not a Forensics++ report Bundle JSON.");
  if (source.notes.length > MAX_IMPORTED_NOTES) throw new Error(`A report can contain at most ${MAX_IMPORTED_NOTES} items.`);
  const usedIds = new Set<string>();
  return {
    notes: source.notes.map((item, index) => normalizeNote(item, index, usedIds)),
    meta: normalizeMeta(source.meta)
  };
}

export async function readCaseBundleFile(file: File) {
  if (file.size > MAX_IMPORTED_BUNDLE_BYTES) throw new Error("The report Bundle JSON exceeds the 32 MiB limit.");
  const raw = await file.text();
  try {
    return normalizeCaseBundle(JSON.parse(raw));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("The selected file is not valid JSON.");
    throw error;
  }
}

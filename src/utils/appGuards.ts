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

import { isToolId } from "../config/app";
import type { ToolId } from "../config/app";
import type { CaseNote, CaseReportMeta, Lang, ThemeMode } from "../models";

export const isLangValue = (value: unknown): value is Lang => value === "zh" || value === "en";
export const isThemeModeValue = (value: unknown): value is ThemeMode => value === "light" || value === "dark" || value === "auto";
export const isToolIdValue = (value: unknown): value is ToolId => typeof value === "string" && isToolId(value);
export const isStringValue = (value: unknown): value is string => typeof value === "string";
export const isBooleanValue = (value: unknown): value is boolean => typeof value === "boolean";
export const isToolIdArrayValue = (value: unknown): value is ToolId[] => Array.isArray(value) && value.every((item) => isToolIdValue(item));

export function isCaseNotesValue(value: unknown): value is CaseNote[] {
  if (!Array.isArray(value)) return false;
  return value.every((item) => {
    if (!item || typeof item !== "object") return false;
    const note = item as Partial<CaseNote>;
    return typeof note.id === "string"
      && typeof note.tool === "string"
      && typeof note.content === "string"
      && typeof note.createdAt === "string";
  });
}

export function isCaseReportMetaValue(value: unknown): value is CaseReportMeta {
  if (!value || typeof value !== "object") return false;
  const meta = value as Partial<CaseReportMeta>;
  return ["caseName", "examiner", "organization", "evidenceId", "timezone", "classification", "remarks"]
    .every((key) => typeof meta[key as keyof CaseReportMeta] === "string");
}

export function defaultCaseReportMeta(): CaseReportMeta {
  return {
    caseName: "",
    examiner: "",
    organization: "",
    evidenceId: "",
    timezone: typeof Intl !== "undefined" ? Intl.DateTimeFormat().resolvedOptions().timeZone : "UTC",
    classification: "",
    remarks: ""
  };
}

export function compactReportText(value: string, limit = 24000) {
  const normalized = value.replace(/\n{3,}/g, "\n\n").trim();
  return normalized.length > limit ? `${normalized.slice(0, limit)}\n\n[内容已截断]` : normalized;
}

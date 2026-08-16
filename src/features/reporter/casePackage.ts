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

import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { appVersion, projectLinks } from "../../config/app";
import type { CaseNote, CaseReportMeta } from "../../models";
import { sha256Bytes } from "../../utils/hash";
import { validateZipExpansion } from "../archive/zipDirectory";
import { normalizeCaseBundle, type ImportedCaseBundle } from "./importer";

const CASE_PACKAGE_FORMAT = "Forensics++ Case Package";
const CASE_PACKAGE_SCHEMA = "1.1";
const SUPPORTED_CASE_PACKAGE_SCHEMAS = new Set(["1.0", "1.1"]);
const MAX_CASE_PACKAGE_BYTES = 64 * 1024 * 1024;
const MAX_CASE_PACKAGE_ENTRY = 32 * 1024 * 1024;
const MAX_CASE_PACKAGE_EXPANDED = 96 * 1024 * 1024;

type PackageFileManifest = {
  path: string;
  size: number;
  sha256: string;
};

type CasePackageManifest = {
  format: typeof CASE_PACKAGE_FORMAT;
  schemaVersion: string;
  appVersion: string;
  createdAt: string;
  project: string;
  evidenceEmbedded: false;
  files: PackageFileManifest[];
};

export type CasePackageSource = {
  generatedAt: string;
  project: string;
  meta: CaseReportMeta;
  integrity?: unknown;
  timeline?: unknown[];
  evidenceFiles?: unknown[];
  notes: CaseNote[];
  markdown: string;
  analysisResults?: unknown[];
};

function jsonBytes(value: unknown) {
  return strToU8(`${JSON.stringify(value, null, 2)}\n`);
}

function packageEntries(source: CasePackageSource) {
  return {
    "case.json": jsonBytes({
      generatedAt: source.generatedAt,
      project: source.project || projectLinks.repo,
      meta: source.meta,
      integrity: source.integrity ?? null
    }),
    "notes.json": jsonBytes(source.notes),
    "timeline.json": jsonBytes(source.timeline ?? []),
    "evidence.json": jsonBytes(source.evidenceFiles ?? []),
    "analysis.json": jsonBytes(source.analysisResults ?? []),
    "reports/report.md": strToU8(source.markdown || "")
  } satisfies Record<string, Uint8Array>;
}

export function buildCasePackage(source: CasePackageSource) {
  const entries = packageEntries(source);
  const files = Object.entries(entries).map(([path, bytes]) => ({
    path,
    size: bytes.length,
    sha256: sha256Bytes(bytes)
  }));
  const manifest: CasePackageManifest = {
    format: CASE_PACKAGE_FORMAT,
    schemaVersion: CASE_PACKAGE_SCHEMA,
    appVersion,
    createdAt: new Date().toISOString(),
    project: projectLinks.repo,
    evidenceEmbedded: false,
    files
  };
  return zipSync({
    "manifest.json": jsonBytes(manifest),
    ...entries
  }, { level: 6 });
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function parseJsonEntry(entries: Record<string, Uint8Array>, path: string) {
  const bytes = entries[path];
  if (!bytes) throw new Error(`Case package is missing ${path}.`);
  try {
    return JSON.parse(strFromU8(bytes));
  } catch {
    throw new Error(`Case package ${path} is not valid JSON.`);
  }
}

function readManifest(entries: Record<string, Uint8Array>) {
  const value = object(parseJsonEntry(entries, "manifest.json"));
  if (!value || value.format !== CASE_PACKAGE_FORMAT) throw new Error("This file is not a Forensics++ .fppcase package.");
  if (typeof value.schemaVersion !== "string" || !SUPPORTED_CASE_PACKAGE_SCHEMAS.has(value.schemaVersion)) throw new Error(`Unsupported .fppcase schema version: ${String(value.schemaVersion ?? "unknown")}.`);
  if (value.evidenceEmbedded !== false) throw new Error("This build only accepts reference-only .fppcase packages; embedded evidence is not supported.");
  if (!Array.isArray(value.files) || value.files.length > 32) throw new Error("The .fppcase file manifest is invalid.");
  return value as unknown as CasePackageManifest;
}

function verifyManifest(entries: Record<string, Uint8Array>, manifest: CasePackageManifest) {
  const seen = new Set<string>();
  for (const row of manifest.files) {
    if (!row || typeof row.path !== "string" || typeof row.size !== "number" || typeof row.sha256 !== "string") {
      throw new Error("The .fppcase file manifest contains an invalid entry.");
    }
    if (row.path === "manifest.json" || row.path.includes("..") || row.path.startsWith("/") || seen.has(row.path)) {
      throw new Error("The .fppcase file manifest contains an unsafe or duplicate path.");
    }
    seen.add(row.path);
    const bytes = entries[row.path];
    if (!bytes) throw new Error(`Case package is missing ${row.path}.`);
    if (bytes.length !== row.size) throw new Error(`Case package size mismatch: ${row.path}.`);
    if (sha256Bytes(bytes).toLowerCase() !== row.sha256.toLowerCase()) throw new Error(`Case package integrity check failed: ${row.path}.`);
  }
  for (const required of ["case.json", "notes.json", "timeline.json", "evidence.json", "reports/report.md"]) {
    if (!seen.has(required)) throw new Error(`Case package manifest does not register ${required}.`);
  }
  if (manifest.schemaVersion === "1.1" && !seen.has("analysis.json")) throw new Error("Case package manifest does not register analysis.json.");
}

export function readCasePackageBytes(bytes: Uint8Array): ImportedCaseBundle {
  if (bytes.length > MAX_CASE_PACKAGE_BYTES) throw new Error("The .fppcase package exceeds the 64 MiB limit.");
  validateZipExpansion(bytes, {
    maxEntries: 64,
    maxEntryUncompressed: MAX_CASE_PACKAGE_ENTRY,
    maxTotalUncompressed: MAX_CASE_PACKAGE_EXPANDED,
    maxCompressionRatio: 250,
    ratioGuardMinimum: 1024 * 1024
  });
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(bytes);
  } catch {
    throw new Error("The selected .fppcase file is not a readable ZIP package.");
  }
  const manifest = readManifest(entries);
  verifyManifest(entries, manifest);
  const caseData = object(parseJsonEntry(entries, "case.json"));
  const notes = parseJsonEntry(entries, "notes.json");
  const analysisResults = entries["analysis.json"] ? parseJsonEntry(entries, "analysis.json") : [];
  if (!caseData || !Array.isArray(notes) || !Array.isArray(analysisResults)) throw new Error("The .fppcase case/notes/analysis data is invalid.");
  return normalizeCaseBundle({ notes, meta: caseData.meta, analysisResults });
}

export async function readCasePackageFile(file: File) {
  if (file.size > MAX_CASE_PACKAGE_BYTES) throw new Error("The .fppcase package exceeds the 64 MiB limit.");
  return readCasePackageBytes(new Uint8Array(await file.arrayBuffer()));
}

export function isCasePackageName(name: string) {
  return name.toLowerCase().endsWith(".fppcase");
}

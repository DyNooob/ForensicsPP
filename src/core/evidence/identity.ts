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

import type { CaseEvidenceFile } from "../../models";

/**
 * Forensic verification state for a piece of evidence.
 *
 * Mirrors the four-state model required by the beta.6 plan (P0-3): a metadata
 * match (same name/size/mtime) is NOT a final hash identity.
 */
export type EvidenceVerificationStatus = "match" | "mismatch" | "missing" | "unverified";

/**
 * Where an evidence file entered the workbench. Used to attribute identity
 * provenance and to decide whether a SHA-256 fingerprint can be trusted.
 */
export type EvidenceSource = "upload" | "handoff" | "carve" | "case-import" | "case-package" | "unknown";

const EVID_RE = /^evid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Stable object identity for a piece of evidence, assigned at acquisition.
 *
 * Deliberately NOT derived from the content SHA-256: two logically distinct
 * evidence items can share bytes yet carry different provenance, and a large
 * evidence file must be able to enter analysis before its hash is computed.
 * The caller is responsible for retaining this identity across re-runs so that
 * repeated analysis of the same file groups under one evidence key.
 */
export function deriveEvidenceId(file: { name: string; size: number; sha256?: string }): string {
  return `evid:${crypto.randomUUID()}`;
}

/** True only for a workbench-assigned object identity (`evid:<uuid>`). */
export function isResolvedEvidenceId(id: string | undefined): boolean {
  return typeof id === "string" && EVID_RE.test(id);
}

/**
 * Augment a (possibly metadata-only) evidence record with a proper forensic
 * identity: a SHA-256-derived `id`, an explicit `source`, and a `verification`
 * status. Never mutates the input.
 */
export function buildEvidenceIdentity(
  file: CaseEvidenceFile,
  options: { source?: EvidenceSource; verification?: EvidenceVerificationStatus } = {}
): CaseEvidenceFile {
  return {
    ...file,
    id: deriveEvidenceId(file),
    ...(file.sha256 ? { sha256: file.sha256.toLowerCase() } : {}),
    source: options.source ?? file.source ?? "unknown",
    verification: options.verification ?? file.verification ?? "unverified"
  };
}

/**
 * Stable store key for an analysis result, derived from its evidence sources.
 *
 * Priority: resolved SHA-256 identities → raw sha256 values → the legacy
 * `name:size:lastModified` dedup key (so pre-identity results still group
 * correctly). An empty source list falls back to a single shared key so the
 * behavior of transform-style results is unchanged.
 */
export function evidenceKeyFromSources(sources: CaseEvidenceFile[]): string {
  if (!sources.length) return "__unkeyed__";
  const resolved = sources
    .map((source) => (isResolvedEvidenceId(source.id) ? source.id : null))
    .filter((value): value is string => value !== null);
  if (resolved.length) return resolved.join("|");
  const hashes = sources.map((source) => source.sha256).filter((value): value is string => Boolean(value));
  if (hashes.length) return hashes.map((hash) => `sha256:${hash.toLowerCase()}`).join("|");
  return sources
    .map((source) => `${source.name}:${source.size}:${source.lastModified ?? ""}`)
    .join("|");
}

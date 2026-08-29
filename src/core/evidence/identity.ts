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

const SHA256_RE = /^[a-f0-9]{64}$/i;

/**
 * A resolved evidence identity derives its stable `id` from a SHA-256 digest.
 * An unresolved identity is explicitly marked `pending:<uuid>` so it can never
 * be mistaken for a hash-based identity.
 */
export function deriveEvidenceId(file: { name: string; size: number; sha256?: string }): string {
  if (file.sha256 && SHA256_RE.test(file.sha256)) return `sha256:${file.sha256.toLowerCase()}`;
  return `pending:${crypto.randomUUID()}`;
}

/** True only for SHA-256-derived identities — `pending:`/legacy ids are not resolved. */
export function isResolvedEvidenceId(id: string | undefined): boolean {
  if (!id) return false;
  const [, digest] = id.split(":", 2);
  return id.startsWith("sha256:") && SHA256_RE.test(digest ?? "");
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

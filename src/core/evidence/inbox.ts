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

import type { ToolId } from "../../config/app";
import { fingerprintEvidenceFiles } from "../../features/reporter/evidence";

/**
 * A single piece of evidence acquired this session, tracked centrally so the
 * workbench can present "what did I load, and which tools touched it" instead
 * of 38 isolated file inputs.
 *
 * The `file` reference is kept in memory only (never serialized) so it can be
 * re-dispatched to another tool via handoff. The `key` is a metadata-only
 * stable id (NOT a content hash) so the same logical file re-loaded by
 * different tools groups under one card — matching the existing
 * `evidenceFileKey` semantics used by the reporter.
 */
export type EvidenceInboxItem = {
  key: string;
  id: string;
  name: string;
  size: number;
  type: string;
  sha256?: string;
  acquiredAt: number;
  usedByTools: ToolId[];
  source: "upload" | "drop";
  file: File;
};

/** Stable, hash-independent key for an inbox entry (mirrors `evidenceFileKey`). */
function inboxKey(file: { name: string; size: number; lastModified?: number | string }): string {
  return `${file.name}:${file.size}:${file.lastModified ?? ""}`;
}

let seq = 0;
function nextId(): string {
  seq += 1;
  return `evid-inbox-${Date.now().toString(36)}-${seq.toString(36)}`;
}

const items = new Map<string, EvidenceInboxItem>();
const listeners = new Set<() => void>();
let cachedSnapshot: EvidenceInboxItem[] = [];

function recompute() {
  cachedSnapshot = Array.from(items.values()).sort((a, b) => b.acquiredAt - a.acquiredAt);
}

function notify() {
  recompute();
  listeners.forEach((listener) => listener());
}

/**
 * Record every file a user loads into any tool this session. Files are
 * deduplicated by metadata key; re-loading the same file merges its
 * `usedByTools` rather than creating a duplicate card. SHA-256 is computed
 * asynchronously (fire-and-forget) so the card can show a fingerprint without
 * blocking the load.
 */
export function captureEvidence(files: FileList | File[], source: "upload" | "drop", toolId: ToolId) {
  const list = Array.from(files).filter((file) => typeof file.size === "number" && file.size >= 0);
  if (!list.length) return;
  for (const file of list) {
    const key = inboxKey(file);
    const existing = items.get(key);
    if (existing) {
      existing.file = file;
      if (!existing.usedByTools.includes(toolId)) existing.usedByTools.push(toolId);
      continue;
    }
    items.set(key, {
      key,
      id: nextId(),
      name: file.name,
      size: file.size,
      type: file.type || "application/octet-stream",
      acquiredAt: Date.now(),
      usedByTools: [toolId],
      source,
      file
    });
  }
  notify();
  void fingerprintAndUpdate(list);
}

async function fingerprintAndUpdate(files: File[]) {
  try {
    const records = await fingerprintEvidenceFiles(files);
    let changed = false;
    records.forEach((record, index) => {
      const file = files[index];
      if (!file) return;
      const item = items.get(inboxKey(file));
      if (item && record.sha256 && item.sha256 !== record.sha256) {
        item.sha256 = record.sha256;
        changed = true;
      }
    });
    if (changed) notify();
  } catch {
    // Fingerprinting is best-effort; the card still works without a hash.
  }
}

export function getEvidenceInboxSnapshot(): EvidenceInboxItem[] {
  return cachedSnapshot;
}

export function subscribeEvidenceInbox(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function clearEvidenceInbox() {
  if (!items.size) return;
  items.clear();
  notify();
}

/**
 * Record that an item was handed off to another tool from the inbox (without a
 * fresh file load). Keeps the "used by" trail accurate when the user uses the
 * inbox's "open with" action, which delivers the file via handoff rather than a
 * DOM file input.
 */
export function noteEvidenceUsed(key: string, toolId: ToolId) {
  const item = items.get(key);
  if (!item) return;
  if (item.usedByTools.includes(toolId)) return;
  item.usedByTools.push(toolId);
  notify();
}

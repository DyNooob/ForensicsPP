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

import { isToolId, type ToolId } from "../../config/app";
import type { AnalysisEnvelope } from "./result";
import { evidenceKeyFromSources } from "../../core/evidence/identity";

const MAX_HISTORY_PER_TOOL = 8;

/** Per-(evidence, tool) slot: the current envelope plus the most recent runs. */
type StoredRun = { current: AnalysisEnvelope | null; runs: AnalysisEnvelope[] };

/**
 * Storage index (beta.6, P0-4):
 *   EvidenceKey -> (ToolId -> { current, runs })
 *
 * The public API is unchanged from the previous ToolId-keyed store; the
 * evidence dimension is threaded internally so that repeated runs of the same
 * tool against different evidence are no longer collapsed into a single
 * `history` guess. `currentAnalysisResult(toolId)` keeps returning the latest
 * result for that tool (tracked by `latestByTool`).
 */
const store = new Map<string, Map<ToolId, StoredRun>>();
const latestByTool = new Map<ToolId, { key: string; result: AnalysisEnvelope }>();
type ResultListener = (toolId: ToolId) => void;
const listeners = new Map<ToolId | "*", Set<ResultListener>>();

function notify(toolId: ToolId) {
  listeners.get(toolId)?.forEach((listener) => listener(toolId));
  listeners.get("*")?.forEach((listener) => listener(toolId));
}

function caseSafeValue(value: unknown, depth = 0): unknown {
  if (depth > 10) return "[depth-limit]";
  if (value == null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.length > 200_000 ? `${value.slice(0, 200_000)}…[truncated]` : value;
  if (value instanceof Uint8Array) return { type: "Uint8Array", byteLength: value.byteLength, retained: false };
  if (value instanceof ArrayBuffer) return { type: "ArrayBuffer", byteLength: value.byteLength, retained: false };
  if (Array.isArray(value)) return value.slice(0, 10_000).map((item) => caseSafeValue(item, depth + 1));
  if (typeof value === "object") {
    const output: Record<string, unknown> = {};
    let count = 0;
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (count >= 2_000) { output.__truncated__ = true; break; }
      if (typeof item === "function" || typeof item === "symbol" || typeof item === "undefined") continue;
      output[key] = caseSafeValue(item, depth + 1);
      count += 1;
    }
    return output;
  }
  return String(value);
}

function runsForTool(toolId: ToolId): AnalysisEnvelope[] {
  const merged: AnalysisEnvelope[] = [];
  for (const bucket of store.values()) {
    const stored = bucket.get(toolId);
    if (stored) merged.push(...stored.runs);
  }
  const seen = new Set<string>();
  return merged
    .filter((result) => {
      const id = result.run.runId ?? result.id;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    })
    .sort((a, b) => (b.run.sequence ?? 0) - (a.run.sequence ?? 0))
    .slice(0, MAX_HISTORY_PER_TOOL);
}

export function publishAnalysisResult(toolId: ToolId, result: AnalysisEnvelope) {
  const key = evidenceKeyFromSources(result.source);
  const bucket = store.get(key) ?? new Map<ToolId, StoredRun>();
  const previous = bucket.get(toolId);
  // Preserve an already-stamped run (case import / cross-session restore) so the
  // original runId + sequence survive the round-trip; otherwise stamp fresh.
  // Sequence is monotonic (derived from the highest retained sequence), NOT from
  // `runs.length` — runs are capped at MAX_HISTORY_PER_TOOL, so length-based
  // numbering would repeat a sequence once the cap is hit and collide runIds.
  const incomingRunId = result.run?.runId;
  const incomingSequence = result.run?.sequence;
  const priorSequence = previous
    ? Math.max(0, ...previous.runs.map((r) => r.run.sequence ?? 0))
    : 0;
  const sequence = incomingSequence ?? priorSequence + 1;
  const runId = incomingRunId ?? `${key}/${toolId}#${sequence}`;
  const stamped: AnalysisEnvelope = {
    ...result,
    run: { ...result.run, runId, sequence }
  };
  const runs = [stamped, ...(previous?.runs ?? [])].slice(0, MAX_HISTORY_PER_TOOL);
  // The "current" result is the most recent run for this evidence+tool, derived from
  // sequence so a re-imported history reassembles correctly regardless of order.
  const current = [...runs]
    .sort((a, b) => (b.run.sequence ?? 0) - (a.run.sequence ?? 0))[0] ?? stamped;
  bucket.set(toolId, { current, runs });
  store.set(key, bucket);
  latestByTool.set(toolId, { key, result: current });
  notify(toolId);
}

export function clearAnalysisResult(toolId: ToolId) {
  for (const bucket of store.values()) {
    const stored = bucket.get(toolId);
    if (stored) bucket.set(toolId, { current: null, runs: stored.runs });
  }
  latestByTool.delete(toolId);
  notify(toolId);
}

export function currentAnalysisResult(toolId: ToolId) {
  return latestByTool.get(toolId)?.result ?? null;
}

export function analysisResultHistory(toolId: ToolId) {
  return runsForTool(toolId);
}

export function currentAnalysisResults() {
  return Array.from(latestByTool.entries()).map(([toolId, { result }]) => ({ toolId, result }));
}

/**
 * Full run history (not just the latest per tool) for case export. Iterates every
 * evidence bucket so repeated runs of the same tool against different evidence are
 * all retained. Round-trips back through `restoreAnalysisResultSnapshots`.
 */
export function analysisResultSnapshots() {
  const all: Array<{ toolId: ToolId; result: AnalysisEnvelope }> = [];
  for (const bucket of store.values()) {
    for (const [toolId, stored] of bucket) {
      for (const run of stored.runs) {
        all.push({ toolId, result: caseSafeValue(run) as AnalysisEnvelope });
      }
    }
  }
  return all;
}

export function restoreAnalysisResultSnapshots(value: unknown) {
  if (!Array.isArray(value)) return 0;
  let restored = 0;
  for (const item of value.slice(0, 1000)) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    if (typeof row.toolId !== "string" || !isToolId(row.toolId) || !row.result || typeof row.result !== "object") continue;
    const result = row.result as Partial<AnalysisEnvelope>;
    if (result.schemaVersion !== "1" || typeof result.id !== "string" || !result.summary || !result.analyzer || !result.run) continue;
    publishAnalysisResult(row.toolId, result as AnalysisEnvelope);
    restored += 1;
  }
  return restored;
}

export function subscribeAnalysisResult(toolId: ToolId | "*", listener: ResultListener) {
  const bucket = listeners.get(toolId) ?? new Set<ResultListener>();
  bucket.add(listener);
  listeners.set(toolId, bucket);
  return () => {
    bucket.delete(listener);
    if (!bucket.size) listeners.delete(toolId);
  };
}

export function clearAnalysisResults() {
  const affected = Array.from(latestByTool.keys());
  store.clear();
  latestByTool.clear();
  for (const toolId of affected) notify(toolId);
}

export function clearAnalysisHistory(toolId?: ToolId) {
  if (toolId) {
    for (const bucket of store.values()) {
      const stored = bucket.get(toolId);
      if (stored) bucket.set(toolId, { current: stored.current, runs: [] });
    }
    return;
  }
  for (const bucket of store.values()) {
    for (const [id, stored] of bucket) bucket.set(id, { current: stored.current, runs: [] });
  }
}

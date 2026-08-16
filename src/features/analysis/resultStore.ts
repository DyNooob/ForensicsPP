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

const currentResults = new Map<ToolId, AnalysisEnvelope>();
const histories = new Map<ToolId, AnalysisEnvelope[]>();
const listeners = new Map<ToolId | "*", Set<() => void>>();
const MAX_HISTORY_PER_TOOL = 8;

function notify(toolId: ToolId) {
  listeners.get(toolId)?.forEach((listener) => listener());
  listeners.get("*")?.forEach((listener) => listener());
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

export function publishAnalysisResult(toolId: ToolId, result: AnalysisEnvelope) {
  currentResults.set(toolId, result);
  const history = histories.get(toolId) ?? [];
  histories.set(toolId, [result, ...history.filter((item) => item.id !== result.id)].slice(0, MAX_HISTORY_PER_TOOL));
  notify(toolId);
}

export function clearAnalysisResult(toolId: ToolId) {
  currentResults.delete(toolId);
  notify(toolId);
}

export function currentAnalysisResult(toolId: ToolId) {
  return currentResults.get(toolId) ?? null;
}

export function analysisResultHistory(toolId: ToolId) {
  return (histories.get(toolId) ?? []).slice();
}

export function currentAnalysisResults() {
  return Array.from(currentResults.entries()).map(([toolId, result]) => ({ toolId, result }));
}

export function analysisResultSnapshots() {
  return currentAnalysisResults().map(({ toolId, result }) => ({ toolId, result: caseSafeValue(result) as AnalysisEnvelope }));
}

export function restoreAnalysisResultSnapshots(value: unknown) {
  if (!Array.isArray(value)) return 0;
  let restored = 0;
  for (const item of value.slice(0, 100)) {
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

export function subscribeAnalysisResult(toolId: ToolId | "*", listener: () => void) {
  const bucket = listeners.get(toolId) ?? new Set<() => void>();
  bucket.add(listener);
  listeners.set(toolId, bucket);
  return () => {
    bucket.delete(listener);
    if (!bucket.size) listeners.delete(toolId);
  };
}

export function clearAnalysisResults() {
  const affected = Array.from(currentResults.keys());
  currentResults.clear();
  for (const toolId of affected) notify(toolId);
}

export function clearAnalysisHistory(toolId?: ToolId) {
  if (toolId) histories.delete(toolId);
  else histories.clear();
}

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

import type { ToolId } from "../config/app";

export type ToolHandoff = {
  id: string;
  sourceTool: ToolId;
  targetTool: ToolId;
  file: File;
  label: string;
  createdAt: number;
};

type Listener = () => void;
const MAX_HANDOFF_AGE_MS = 5 * 60 * 1000;
const MAX_PENDING_PER_TOOL = 8;
const pending = new Map<ToolId, ToolHandoff[]>();
const listeners = new Map<ToolId, Set<Listener>>();

function prune(toolId: ToolId) {
  const now = Date.now();
  const queue = (pending.get(toolId) ?? []).filter((item) => now - item.createdAt <= MAX_HANDOFF_AGE_MS);
  if (queue.length) pending.set(toolId, queue.slice(-MAX_PENDING_PER_TOOL));
  else pending.delete(toolId);
  return queue;
}

export function dispatchToolHandoff(input: Omit<ToolHandoff, "id" | "createdAt">) {
  const handoff: ToolHandoff = {
    ...input,
    id: `handoff-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    createdAt: Date.now()
  };
  const queue = prune(input.targetTool);
  queue.push(handoff);
  pending.set(input.targetTool, queue.slice(-MAX_PENDING_PER_TOOL));
  listeners.get(input.targetTool)?.forEach((listener) => listener());
  return handoff;
}

export function takeToolHandoff(toolId: ToolId) {
  const queue = prune(toolId);
  const handoff = queue.shift() ?? null;
  if (queue.length) pending.set(toolId, queue);
  else pending.delete(toolId);
  return handoff;
}

export function pendingToolHandoffCount(toolId: ToolId) {
  return prune(toolId).length;
}

export function subscribeToolHandoff(toolId: ToolId, listener: Listener) {
  const bucket = listeners.get(toolId) ?? new Set<Listener>();
  bucket.add(listener);
  listeners.set(toolId, bucket);
  return () => {
    bucket.delete(listener);
    if (!bucket.size) listeners.delete(toolId);
  };
}

export function clearToolHandoff(toolId: ToolId) {
  pending.delete(toolId);
}

export function clearToolHandoffs() {
  pending.clear();
}

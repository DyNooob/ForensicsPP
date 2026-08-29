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
import { policyOf } from "./resourcePolicy";

/**
 * Resolve which tools should stay mounted (beta.6 P1 heavy-tool governance).
 *
 * Rules:
 * - The active tool is always mounted.
 * - A `dispose-on-switch` tool that is no longer active is evicted immediately so its
 *   parsed caches / large buffers / workers are released; only the active instance stays mounted.
 * - `retain` / `suspendable` tools stay mounted (hidden) and, when over `maxMounted`,
 *   the oldest non-active ones are dropped first. The active tool is never dropped.
 *
 * Pure function — easy to unit test and reused by the application shell.
 */
export function resolveRetainedTools(
  activeTool: ToolId,
  mountedTools: readonly ToolId[],
  maxMounted: number
): ToolId[] {
  const ordered = mountedTools.filter(
    (tool) => tool === activeTool || policyOf(tool) !== "dispose-on-switch"
  );
  if (!ordered.includes(activeTool)) ordered.push(activeTool);

  if (ordered.length <= maxMounted) return ordered;

  const overflow = ordered.length - maxMounted;
  const droppable = ordered.filter((tool) => tool !== activeTool);
  const remove = new Set(droppable.slice(0, overflow));
  return ordered.filter((tool) => !remove.has(tool));
}

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

/**
 * Formal tool lifecycle phases (beta.6 P0-1).
 *
 * Create → Initialize → Ready → Running → Completed → (Reset / Re-run) → Dispose
 *
 * The phase machine documents the contract every tool runtime should follow.
 * React components track the lighter {@link ToolRuntimeStatus} for UI; this
 * phase machine is the canonical reference and is fully pure/testable.
 */
export type ToolLifecyclePhase =
  | "create"
  | "initialize"
  | "ready"
  | "running"
  | "completed"
  | "disposed";

export type ToolLifecycleEvent =
  | "initialize"
  | "ready"
  | "run"
  | "complete"
  | "reset"
  | "dispose";

/**
 * Unified UI status (beta.6 P1 error-handling unification).
 * Every tool reports one of these instead of ad-hoc booleans.
 */
export type ToolRuntimeStatus =
  | "idle"
  | "loading"
  | "running"
  | "success"
  | "warning"
  | "error";

export type ToolErrorRecovery = "retry" | "reset";

/**
 * Structured error every tool must surface (beta.6 P1 error-handling).
 */
export type ToolErrorInfo = {
  tool: ToolId;
  stage: string;
  error: string;
  recovery: ToolErrorRecovery;
};

const LIFECYCLE_TRANSITIONS: Record<ToolLifecyclePhase, Partial<Record<ToolLifecycleEvent, ToolLifecyclePhase>>> = {
  create: { initialize: "initialize" },
  initialize: { ready: "ready" },
  ready: { run: "running", dispose: "disposed" },
  running: { complete: "completed", reset: "ready", dispose: "disposed" },
  completed: { run: "running", reset: "ready", dispose: "disposed" },
  disposed: {}
};

export function nextLifecyclePhase(state: ToolLifecyclePhase, event: ToolLifecycleEvent): ToolLifecyclePhase | null {
  return LIFECYCLE_TRANSITIONS[state]?.[event] ?? null;
}

export function isTerminalPhase(phase: ToolLifecyclePhase): boolean {
  return phase === "disposed";
}

export function isAnalysisPhase(phase: ToolLifecyclePhase): boolean {
  return phase === "running" || phase === "completed";
}

export function describeToolError(
  tool: ToolId,
  stage: string,
  error: unknown,
  recovery: ToolErrorRecovery = "retry"
): ToolErrorInfo {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "Unknown error";
  return { tool, stage, error: message || "Unknown error", recovery };
}

export function isResolvedStatus(status: ToolRuntimeStatus): boolean {
  return status === "success" || status === "warning" || status === "error";
}

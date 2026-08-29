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

import { useCallback, useEffect, useRef, useState } from "react";
import type { ToolId } from "../../config/app";
import { createManagedTask, type ManagedTask } from "./managedTask";
import { createRunGuard, type RunGuard } from "./runGuard";
import { describeToolError, type ToolErrorInfo, type ToolRuntimeStatus } from "./toolLifecycle";

export type ToolRuntimeRunContext = { signal: AbortSignal; requestId: number };
export type ToolRuntimeRunOptions = { stage?: string; recovery?: "retry" | "reset" };
export type ToolRuntimeRunTask<T> = (ctx: ToolRuntimeRunContext) => Promise<T>;

export type ToolRuntime = {
  status: ToolRuntimeStatus;
  error: ToolErrorInfo | null;
  run: <T>(task: ToolRuntimeRunTask<T>, options?: ToolRuntimeRunOptions) => Promise<T>;
  /**
   * Publish a result only if `requestId` still owns the current run and the tool is
   * active. Mirrors the stale-run guard every tool used to hand-roll with a private
   * `reqRef` — now a single shared contract (beta.6 §11). Capture `requestId` from the
   * `run` task context, then call `rt.commit(requestId, () => publish(...))`.
   */
  commit: <T>(requestId: number, fn: () => T) => T | undefined;
  reset: () => void;
  cancel: () => void;
  warn: (message: string, stage?: string) => void;
  registerDispose: (fn: () => void) => () => void;
  managed: ManagedTask;
};

/**
 * Unified tool lifecycle hook (beta.6 P0-1).
 *
 * Encapsulates the request-id guard + AbortController pattern that `BinaryTool` /
 * `FirmwareAnalyzerTool` already implement by hand, and guarantees that every in-flight
 * task is aborted when the tool unmounts (so a Worker can never outlive its host). Tool
 * authors adopt this instead of hand-rolling `requestRef` + `abortRef` and introducing
 * new private lifecycle variants. The active-tool check is supplied by the host via
 * `active` so a superseded run never writes results into a hidden, switched-away tool.
 */
export function useToolRuntime(toolId: ToolId, active: boolean): ToolRuntime {
  const managedRef = useRef<ManagedTask>(createManagedTask());
  const guardRef = useRef<RunGuard>(createRunGuard(() => activeRef.current));
  const statusRef = useRef<ToolRuntimeStatus>("idle");
  const activeRef = useRef(active);
  const disposeFns = useRef(new Set<() => void>());
  const [status, setStatus] = useState<ToolRuntimeStatus>("idle");
  const [error, setError] = useState<ToolErrorInfo | null>(null);

  statusRef.current = status;
  activeRef.current = active;

  useEffect(() => () => {
    managedRef.current.dispose();
    for (const fn of disposeFns.current) {
      try {
        fn();
      } catch {
        // disposal hooks are best-effort
      }
    }
  }, []);

  const run = useCallback(
    async <T,>(task: ToolRuntimeRunTask<T>, options?: ToolRuntimeRunOptions): Promise<T> => {
      const requestId = guardRef.current.next();
      const controller = managedRef.current.register();
      setStatus("running");
      setError(null);
      try {
        const result = await task({ signal: controller.signal, requestId });
        if (guardRef.current.isCurrent(requestId)) setStatus("success");
        return result;
      } catch (caught) {
        const superseded = !guardRef.current.isCurrent(requestId);
        const aborted = caught instanceof DOMException && caught.name === "AbortError";
        if (!superseded) {
          if (aborted) setStatus("idle");
          else {
            setStatus("error");
            setError(describeToolError(toolId, options?.stage ?? "analysis", caught, options?.recovery ?? "retry"));
          }
        }
        throw caught;
      } finally {
        managedRef.current.release(controller);
      }
    },
    [toolId]
  );

  const commit = useCallback(
    <T,>(requestId: number, fn: () => T): T | undefined => guardRef.current.commit(requestId, fn),
    []
  );

  const reset = useCallback(() => {
    guardRef.current.next();
    managedRef.current.abortAll();
    setStatus("idle");
    setError(null);
  }, []);

  const cancel = useCallback(() => {
    managedRef.current.abortAll();
  }, []);

  const warn = useCallback(
    (message: string, stage = "analysis") => {
      setStatus("warning");
      setError(describeToolError(toolId, stage, message, "retry"));
    },
    [toolId]
  );

  const registerDispose = useCallback((fn: () => void) => {
    disposeFns.current.add(fn);
    return () => {
      disposeFns.current.delete(fn);
    };
  }, []);

  return { status, error, run, commit, reset, cancel, warn, registerDispose, managed: managedRef.current };
}

/**
 * Lightweight stale-run guard for tools that do not route their analysis through
 * `useToolRuntime.run` (e.g. they manage their own worker via a private AbortController).
 * Returns the same {@link RunGuard} contract: call `guard.next()` once per analysis, then
 * `guard.commit(id, () => publish(...))` to publish only the current run's result.
 */
export function useStaleRunGuard(active: boolean): RunGuard {
  const activeRef = useRef(active);
  activeRef.current = active;
  const guardRef = useRef<RunGuard>(createRunGuard(() => activeRef.current));
  return guardRef.current;
}

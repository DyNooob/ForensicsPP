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

/**
 * Pure, framework-agnostic run-freshness guard (beta.6 §11 stale-run race).
 *
 * A single monotonic counter identifies the "current" run. `commit` only runs the
 * supplied side-effect when the caller still owns the current run AND the tool is
 * active, so a late-completing superseded run can never publish its result over the
 * current one. `useToolRuntime` and `useStaleRunGuard` are thin React wrappers over
 * the same instance, which keeps the contract in exactly one place.
 *
 * Active-tool awareness is injected via `getActive` so a hidden, switched-away tool
 * (retained but not mounted) never writes results the user can no longer see.
 */
export type RunGuard = {
  /** Advance to and return the next run id. Call once at the start of each analysis. */
  next: () => number;
  /** The id of the run that currently owns the guard (0 before any analysis). */
  current: () => number;
  /** True only if `id` is still the current run and the tool is active. */
  isCurrent: (id: number) => boolean;
  /**
   * Run `fn` only if `id` is still the current run and the tool is active.
   * Returns the value of `fn`, or `undefined` when the run was superseded / hidden.
   */
  commit: <T>(id: number, fn: () => T) => T | undefined;
};

export function createRunGuard(getActive: () => boolean): RunGuard {
  let current = 0;
  return {
    next: () => {
      current += 1;
      return current;
    },
    current: () => current,
    isCurrent: (id) => id === current && getActive(),
    commit: (id, fn) => {
      if (id !== current || !getActive()) return undefined;
      return fn();
    }
  };
}

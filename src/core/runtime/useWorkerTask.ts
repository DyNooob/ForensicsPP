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

import { useCallback, useEffect, useRef } from "react";
import { runWorkerTask, type WorkerTaskOptions } from "../../utils/workerTask";
import { createManagedTask, type ManagedTask } from "./managedTask";

/**
 * Wrap {@link runWorkerTask} with automatic abort on tool unmount (beta.6 P1 worker lifecycle).
 *
 * The host tool owns one instance; when the tool unmounts (switch / dispose-on-switch
 * eviction / page teardown) every in-flight worker task is aborted, so a worker can never
 * keep running after its host left the screen. An externally supplied `signal` is composed
 * so callers keep their own cancellation semantics.
 */
export function useWorkerTask() {
  const managedRef = useRef<ManagedTask>(createManagedTask());
  useEffect(() => () => managedRef.current.dispose(), []);

  const run = useCallback(
    <TRequest, TResult, TProgress = never>(options: WorkerTaskOptions<TRequest, TResult, TProgress>): Promise<TResult> => {
      const controller = managedRef.current.register();
      const external = options.signal;
      if (external) {
        if (external.aborted) controller.abort();
        else external.addEventListener("abort", () => controller.abort(), { once: true });
      }
      const { signal, ...rest } = options;
      void signal;
      return runWorkerTask<TRequest, TResult, TProgress>({ ...rest, signal: controller.signal }).finally(() =>
        managedRef.current.release(controller)
      );
    },
    []
  );

  return { run, managed: managedRef.current };
}

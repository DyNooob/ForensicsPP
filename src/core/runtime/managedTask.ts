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
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

/**
 * Pure, framework-agnostic manager for long-running analysis tasks (beta.6 P1 worker lifecycle).
 *
 * Every tool runtime owns one instance. It tracks the {@link AbortController}s of all
 * in-flight tasks and guarantees that calling {@link ManagedTask.dispose} (on tool unmount /
 * dispose-on-switch eviction) aborts every still-running task so a Worker can never keep
 * running after its host tool has left the screen.
 */
export type ManagedTask = {
  register: () => AbortController;
  release: (controller: AbortController) => void;
  abortAll: () => void;
  dispose: () => void;
  readonly disposed: boolean;
  readonly activeCount: number;
};

export function createManagedTask(): ManagedTask {
  const controllers = new Set<AbortController>();
  let disposed = false;

  const register = (): AbortController => {
    const controller = new AbortController();
    controllers.add(controller);
    return controller;
  };

  const release = (controller: AbortController): void => {
    controllers.delete(controller);
  };

  const abortAll = (): void => {
    for (const controller of controllers) {
      try {
        controller.abort();
      } catch {
        // Aborting is best-effort; ignore controllers already settled.
      }
    }
    controllers.clear();
  };

  const dispose = (): void => {
    disposed = true;
    abortAll();
  };

  return {
    register,
    release,
    abortAll,
    dispose,
    get disposed() {
      return disposed;
    },
    get activeCount() {
      return controllers.size;
    }
  };
}

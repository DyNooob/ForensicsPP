/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

export type WorkerTaskMessage<TResult, TProgress = never> =
  | { type: "result"; result: TResult }
  | { type: "progress"; progress: TProgress }
  | { type: "error"; error: string };

type WorkerTaskOptions<TRequest, TResult, TProgress> = {
  createWorker: () => Worker;
  request: TRequest;
  transfer?: Transferable[];
  signal?: AbortSignal;
  timeoutMs?: number;
  onProgress?: (progress: TProgress) => void;
};

function abortError() {
  return new DOMException("Task cancelled", "AbortError");
}

export function runWorkerTask<TRequest, TResult, TProgress = never>({
  createWorker,
  request,
  transfer = [],
  signal,
  timeoutMs,
  onProgress
}: WorkerTaskOptions<TRequest, TResult, TProgress>) {
  return new Promise<TResult>((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }

    const worker = createWorker();
    let settled = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
      worker.terminate();
    };
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback();
    };
    const onAbort = () => finish(() => reject(abortError()));

    signal?.addEventListener("abort", onAbort, { once: true });
    worker.onmessage = (event: MessageEvent<WorkerTaskMessage<TResult, TProgress>>) => {
      if (settled) return;
      try {
        const message = event.data;
        if (!message || typeof message !== "object" || typeof message.type !== "string") {
          finish(() => reject(new Error("Worker task returned an invalid message")));
          return;
        }
        const messageType = (message as { type: string }).type;
        if (messageType === "progress") {
          onProgress?.((message as Extract<WorkerTaskMessage<TResult, TProgress>, { type: "progress" }>).progress);
          return;
        }
        if (messageType === "result") {
          finish(() => resolve((message as Extract<WorkerTaskMessage<TResult, TProgress>, { type: "result" }>).result));
          return;
        }
        if (messageType === "error") {
          finish(() => reject(new Error((message as Extract<WorkerTaskMessage<TResult, TProgress>, { type: "error" }>).error || "Worker task failed")));
          return;
        }
        finish(() => reject(new Error(`Worker task returned an unknown message type: ${messageType}`)));
      } catch (error) {
        finish(() => reject(error instanceof Error ? error : new Error(String(error))));
      }
    };
    worker.onerror = (event) => finish(() => reject(new Error(event.message || "Worker task failed")));
    worker.onmessageerror = () => finish(() => reject(new Error("Worker task returned unreadable data")));

    if (timeoutMs && timeoutMs > 0) {
      timeout = setTimeout(() => finish(() => reject(new Error(`Worker task timed out after ${timeoutMs} ms`))), timeoutMs);
    }

    try {
      worker.postMessage(request, transfer);
    } catch (error) {
      finish(() => reject(error));
    }
  });
}

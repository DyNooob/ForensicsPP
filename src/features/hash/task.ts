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

import type { HashWorkerRequest, HashWorkerResult } from "./hash.worker";
import type { FileHashProgress } from "../../utils/hash";
import { runWorkerTask } from "../../utils/workerTask";

type HashTaskOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
  onProgress?: (progress: FileHashProgress) => void;
  transfer?: Transferable[];
};

export function runHashTask(request: HashWorkerRequest, options: HashTaskOptions = {}) {
  return runWorkerTask<HashWorkerRequest, HashWorkerResult, FileHashProgress>({
    createWorker: () => new Worker(new URL("./hash.worker.ts", import.meta.url), { type: "module" }),
    request,
    transfer: options.transfer,
    signal: options.signal,
    timeoutMs: options.timeoutMs ?? 180_000,
    onProgress: options.onProgress
  });
}

export function hashFileInWorker(file: Blob, algorithms: string[], options: HashTaskOptions = {}) {
  return runHashTask({ mode: "file", file, algorithms }, options);
}

export function hashBytesInWorker(bytes: Uint8Array, algorithms: string[], options: HashTaskOptions = {}) {
  const copy = bytes.slice();
  return runHashTask({ mode: "bytes", bytes: copy.buffer, algorithms }, { ...options, transfer: [copy.buffer] });
}

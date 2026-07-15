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

import { describe, expect, it, vi } from "vitest";
import { runWorkerTask, type WorkerTaskMessage } from "../src/utils/workerTask";

class MockWorker<TResult, TProgress = never> {
  onmessage: ((event: MessageEvent<WorkerTaskMessage<TResult, TProgress>>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  postMessage = vi.fn();
  terminate = vi.fn();

  send(message: WorkerTaskMessage<TResult, TProgress>) {
    this.onmessage?.({ data: message } as MessageEvent<WorkerTaskMessage<TResult, TProgress>>);
  }
}

describe("worker task runner", () => {
  it("forwards progress and resolves the result", async () => {
    const worker = new MockWorker<number, number>();
    const progress: number[] = [];
    const task = runWorkerTask({
      createWorker: () => worker as unknown as Worker,
      request: { value: 4 },
      onProgress: (value: number) => progress.push(value)
    });

    worker.send({ type: "progress", progress: 50 });
    worker.send({ type: "result", result: 8 });

    await expect(task).resolves.toBe(8);
    expect(progress).toEqual([50]);
    expect(worker.postMessage).toHaveBeenCalledWith({ value: 4 }, []);
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it("terminates the worker when cancelled", async () => {
    const worker = new MockWorker<number>();
    const controller = new AbortController();
    const task = runWorkerTask({
      createWorker: () => worker as unknown as Worker,
      request: null,
      signal: controller.signal
    });

    controller.abort();

    await expect(task).rejects.toMatchObject({ name: "AbortError" });
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it("rejects worker errors and ignores late messages", async () => {
    const worker = new MockWorker<number, number>();
    const progress = vi.fn();
    const task = runWorkerTask({ createWorker: () => worker as unknown as Worker, request: null, onProgress: progress });

    worker.send({ type: "error", error: "broken input" });
    worker.send({ type: "progress", progress: 80 });
    worker.send({ type: "result", result: 10 });

    await expect(task).rejects.toThrow("broken input");
    expect(progress).not.toHaveBeenCalled();
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it("rejects when the worker result cannot be deserialized", async () => {
    const worker = new MockWorker<number>();
    const task = runWorkerTask({ createWorker: () => worker as unknown as Worker, request: null });

    worker.onmessageerror?.();

    await expect(task).rejects.toThrow("returned unreadable data");
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it("rejects malformed worker messages instead of hanging", async () => {
    const worker = new MockWorker<number>();
    const task = runWorkerTask({ createWorker: () => worker as unknown as Worker, request: null });

    worker.onmessage?.({ data: null } as unknown as MessageEvent<WorkerTaskMessage<number>>);

    await expect(task).rejects.toThrow("invalid message");
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it("rejects when a progress callback fails", async () => {
    const worker = new MockWorker<number, number>();
    const task = runWorkerTask({
      createWorker: () => worker as unknown as Worker,
      request: null,
      onProgress: () => { throw new Error("progress handler failed"); }
    });

    worker.send({ type: "progress", progress: 50 });

    await expect(task).rejects.toThrow("progress handler failed");
    expect(worker.terminate).toHaveBeenCalledOnce();
  });

  it("terminates a worker that exceeds its timeout", async () => {
    vi.useFakeTimers();
    try {
      const worker = new MockWorker<number>();
      const task = runWorkerTask({ createWorker: () => worker as unknown as Worker, request: null, timeoutMs: 25 });
      const rejection = expect(task).rejects.toThrow("timed out after 25 ms");

      await vi.advanceTimersByTimeAsync(25);

      await rejection;
      expect(worker.terminate).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });
});

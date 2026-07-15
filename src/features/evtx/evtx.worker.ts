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

self.onmessage = async (event: MessageEvent<{ source: string; bytes: ArrayBuffer; maxRecords: number }>) => {
  try {
    const workerGlobal = globalThis as typeof globalThis & { process?: { env: Record<string, string | undefined> } };
    workerGlobal.process ??= { env: {} };
    const { parseEvtxBytes } = await import("./parser");
    const result = parseEvtxBytes(new Uint8Array(event.data.bytes), event.data.source, event.data.maxRecords);
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

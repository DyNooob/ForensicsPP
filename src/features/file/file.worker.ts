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

import { analyzeFileBytes } from "./analyzer";

export type BinaryWorkerRequest = {
  bytes: ArrayBuffer;
  name: string;
  size: number;
  options?: { includeHash?: boolean; includeSideEvidence?: boolean; includeEmbeddedHashes?: boolean };
};

self.onmessage = (event: MessageEvent<BinaryWorkerRequest>) => {
  try {
    const { bytes, name, size, options } = event.data;
    self.postMessage({ type: "result", result: analyzeFileBytes(new Uint8Array(bytes), name, size, options) });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

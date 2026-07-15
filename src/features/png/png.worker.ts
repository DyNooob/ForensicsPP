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

import { analyzePngEvidence } from "./analyzer";

export type PngWorkerRequest = {
  bytes: ArrayBuffer;
  name: string;
};

self.onmessage = (event: MessageEvent<PngWorkerRequest>) => {
  try {
    const { bytes, name } = event.data;
    self.postMessage({ type: "result", result: analyzePngEvidence(new Uint8Array(bytes), name) });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

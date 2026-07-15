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

import { hashSelectedBytes, hashSelectedFile, type FileHashProgress } from "../../utils/hash";
import type { HashBundle } from "../../models";

export type HashWorkerRequest =
  | { mode: "file"; file: Blob; algorithms: string[] }
  | { mode: "bytes"; bytes: ArrayBuffer; algorithms: string[] };

export type HashWorkerResult = Partial<HashBundle>;

self.onmessage = async (event: MessageEvent<HashWorkerRequest>) => {
  try {
    const request = event.data;
    let result: HashWorkerResult;
    if (request.mode === "file") {
      result = await hashSelectedFile(request.file, request.algorithms, {
        onProgress: (progress: FileHashProgress) => self.postMessage({ type: "progress", progress })
      });
    } else {
      result = await hashSelectedBytes(new Uint8Array(request.bytes), request.algorithms);
    }
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

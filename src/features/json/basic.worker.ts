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

import { analyzeBasicJson, type JsonBasicResult } from "./basic";

export type JsonBasicWorkerRequest = {
  input: string;
};

self.onmessage = (event: MessageEvent<JsonBasicWorkerRequest>) => {
  try {
    const result: JsonBasicResult = analyzeBasicJson(event.data.input);
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

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

import { analyzeRegex, type RegexAnalysis } from "./analyzer";

export type RegexWorkerRequest = {
  pattern: string;
  flags: string;
  source: string;
  replacement: string;
};

self.onmessage = (event: MessageEvent<RegexWorkerRequest>) => {
  try {
    const { pattern, flags, source, replacement } = event.data;
    const result: RegexAnalysis = analyzeRegex(pattern, flags, source, replacement);
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import type { EvtxEvent } from "./analyzer";
import { runSigmaRules, type SigmaRule } from "./sigma";

self.onmessage = (event: MessageEvent<{ events: EvtxEvent[]; rules: SigmaRule[] }>) => {
  try {
    self.postMessage({ type: "result", result: runSigmaRules(event.data.events, event.data.rules) });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

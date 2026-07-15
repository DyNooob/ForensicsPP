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

import { analyzeOle, analyzeOoxml, isOle, isZip } from "./analyzer";

self.onmessage = async (event: MessageEvent<{ name: string; bytes: ArrayBuffer }>) => {
  try {
    const bytes = new Uint8Array(event.data.bytes);
    const result = isOle(bytes)
      ? analyzeOle(bytes, event.data.name)
      : isZip(bytes)
      ? analyzeOoxml(bytes, event.data.name)
      : (() => { throw new Error("Unsupported document container."); })();
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

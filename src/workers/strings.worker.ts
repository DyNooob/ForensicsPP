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

/**
 * Forensics++ - MIT License
 * Copyright (c) 2026 DyNooob. All rights reserved.
 */

import { extractPrintableStrings } from "../features/strings/analyzer";

self.onmessage = (event: MessageEvent<{ id: number; bytes: Uint8Array; minLength: number }>) => {
  const { id, bytes, minLength } = event.data;
  try {
    self.postMessage({ id, analysis: extractPrintableStrings(bytes, minLength) });
  } catch (caught) {
    self.postMessage({ id, error: caught instanceof Error ? caught.message : String(caught) });
  }
};

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

import { analyzeIocs } from "../features/ioc/analyzer";

self.onmessage = (event: MessageEvent<{ id: number; text: string; source: string }>) => {
  const { id, text, source } = event.data;
  try { self.postMessage({ id, analysis: analyzeIocs(text, source) }); }
  catch (caught) { self.postMessage({ id, error: caught instanceof Error ? caught.message : String(caught) }); }
};

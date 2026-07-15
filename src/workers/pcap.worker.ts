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

/**
 * Forensics++ - MIT License
 * Copyright (c) 2026 DyNooob. All rights reserved.
 */

import { parsePcap } from "../features/pcap/analyzer";

self.onmessage = (event: MessageEvent<{ bytes: Uint8Array; name: string; size: number }>) => {
  const { bytes, name, size } = event.data;
  try {
    self.postMessage({ type: "result", result: parsePcap(bytes, name, size, "") });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

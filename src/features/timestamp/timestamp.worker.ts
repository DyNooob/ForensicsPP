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

import { parseTimestampCandidates } from "./analyzer";

export type TimestampWorkerRequest = {
  source: string;
  name: string;
};

export type TimestampWorkerResult = {
  events: ReturnType<typeof parseTimestampCandidates>;
};

self.onmessage = (event: MessageEvent<TimestampWorkerRequest>) => {
  try {
    const { source, name } = event.data;
    const result: TimestampWorkerResult = { events: parseTimestampCandidates(source, name) };
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

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

import { unzip } from "fflate";

export type ArchiveWorkerRequest = {
  bytes: ArrayBuffer;
  entryName: string;
};

self.onmessage = (event: MessageEvent<ArchiveWorkerRequest>) => {
  try {
    const { bytes, entryName } = event.data;
    unzip(new Uint8Array(bytes), { filter: (entry) => entry.name === entryName }, (error, data) => {
      if (error) {
        self.postMessage({ type: "error", error: error instanceof Error ? error.message : String(error) });
        return;
      }
      const output = data[entryName];
      if (!output) {
        self.postMessage({ type: "error", error: "Entry could not be extracted." });
        return;
      }
      const result = output.buffer.slice(output.byteOffset, output.byteOffset + output.byteLength);
      self.postMessage({ type: "result", result });
    });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

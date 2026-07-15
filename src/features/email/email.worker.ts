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

import type { EmailAnalysis } from "../../models";
import { parseMsg } from "./msg";
import { parseEmail } from "./workbench";

type EmailWorkerRequest =
  | { format: "eml"; source: string }
  | { format: "msg"; bytes: ArrayBuffer };

function attachmentTransfers(analysis: EmailAnalysis) {
  return Array.from(new Set(analysis.attachments.map((attachment) => attachment.content.buffer)))
    .filter((buffer): buffer is ArrayBuffer => buffer instanceof ArrayBuffer);
}

self.onmessage = async (event: MessageEvent<EmailWorkerRequest>) => {
  try {
    const result = event.data.format === "msg"
      ? await parseMsg(new Uint8Array(event.data.bytes))
      : { analysis: await parseEmail(event.data.source), source: event.data.source };
    self.postMessage({ type: "result", result }, { transfer: attachmentTransfers(result.analysis) });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

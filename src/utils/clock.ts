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

/** HTTP Date is an estimate, usable only with a fresh and reasonably fast sample. */
export function estimateClockOffset(headers: Pick<Headers, "get">, startedAt: number, endedAt: number, elapsed: number) {
  const date = headers.get("date");
  const serverTime = date ? Date.parse(date) : NaN;
  if (!Number.isFinite(serverTime) || !Number.isFinite(elapsed) || elapsed < 0 || elapsed > 2_000
    || Math.abs(endedAt - startedAt - elapsed) > 1_000 || Number(headers.get("age") || 0) > 0) {
    throw new Error("Server time sample is unavailable or unreliable");
  }
  return serverTime + elapsed / 2 - endedAt;
}

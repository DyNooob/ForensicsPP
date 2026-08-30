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

import React from "react";
import {
  getEvidenceInboxSnapshot,
  subscribeEvidenceInbox,
  type EvidenceInboxItem
} from "../core/evidence/inbox";

export type EvidenceInboxState = {
  items: EvidenceInboxItem[];
  count: number;
};

/**
 * Subscribe a component to the session evidence inbox. Returns a stable array
 * reference that only changes when the inbox mutates, so it is safe to use with
 * `useSyncExternalStore`.
 */
export function useEvidenceInbox(): EvidenceInboxState {
  const items = React.useSyncExternalStore(subscribeEvidenceInbox, getEvidenceInboxSnapshot, getEvidenceInboxSnapshot);
  return React.useMemo(() => ({ items, count: items.length }), [items]);
}

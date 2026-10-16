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
import type { TextLaunchTool } from "../core/launchTarget";

export type HomeDraftTool = TextLaunchTool;
const keyFor = (tool: HomeDraftTool) => `forensicspp:home-draft:${tool}`;
const drafts = new Map<HomeDraftTool, { serialized: string; input: string }>();
let sequence = 0;

function legacyStorage(): Storage | undefined {
  try { return typeof sessionStorage === "undefined" ? undefined : sessionStorage; }
  catch { return undefined; }
}

// Drafts are transient handoffs, including personal identifiers and JWTs.
// Keep new values in memory so browser-storage policy cannot break navigation.
export function saveHomeToolDraft(tool: HomeDraftTool, input: string) {
  if (!input.trim()) return;
  const serialized = JSON.stringify({ input, sequence: ++sequence });
  drafts.set(tool, { serialized, input });
}

export function readHomeToolDraft(tool: HomeDraftTool, storage?: Pick<Storage, "getItem">) {
  const pending = drafts.get(tool);
  if (pending) return pending;
  let serialized: string | null | undefined;
  try { serialized = (storage ?? legacyStorage())?.getItem(keyFor(tool)); }
  catch { return null; }
  if (!serialized) return null;
  try {
    const draft = JSON.parse(serialized) as { input?: unknown } | null;
    return draft && typeof draft.input === "string" && draft.input.trim() ? { serialized, input: draft.input } : null;
  } catch {
    return serialized.trim() ? { serialized, input: serialized } : null;
  }
}

export function consumeHomeToolDraft(tool: HomeDraftTool, serialized: string) {
  if (drafts.get(tool)?.serialized === serialized) drafts.delete(tool);
  try {
    const storage = legacyStorage();
    if (storage?.getItem(keyFor(tool)) === serialized) storage.removeItem(keyFor(tool));
  } catch { /* Legacy storage is optional. */ }
}

export function clearHomeToolDrafts() { drafts.clear(); }

export function useHomeToolDraft(tool: HomeDraftTool, active: boolean, applyDraft: (input: string) => void) {
  const applyDraftRef = React.useRef(applyDraft);
  applyDraftRef.current = applyDraft;
  React.useEffect(() => {
    if (!active) return;
    const draft = readHomeToolDraft(tool);
    if (!draft) return;
    applyDraftRef.current(draft.input);
    // Defer consumption so StrictMode remounts still receive the same payload.
    const timer = window.setTimeout(() => consumeHomeToolDraft(tool, draft.serialized), 0);
    return () => window.clearTimeout(timer);
  }, [active, tool]);
}

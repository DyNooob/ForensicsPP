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
import type { ToolId } from "../config/app";

export type HomeDraftTool = Extract<ToolId, "lookup" | "urltool" | "hash" | "timestamp" | "json" | "ioc">;

type HomeToolDraft = {
  input: string;
  createdAt: number;
};

const keyFor = (tool: HomeDraftTool) => `forensicspp:home-draft:${tool}`;

export function saveHomeToolDraft(tool: HomeDraftTool, input: string) {
  if (typeof sessionStorage === "undefined" || !input.trim()) return;
  const draft: HomeToolDraft = { input, createdAt: Date.now() };
  sessionStorage.setItem(keyFor(tool), JSON.stringify(draft));
}

export function readHomeToolDraft(tool: HomeDraftTool, storage: Pick<Storage, "getItem"> = sessionStorage) {
  const serialized = storage.getItem(keyFor(tool));
  if (!serialized) return null;
  try {
    const draft = JSON.parse(serialized) as Partial<HomeToolDraft>;
    return typeof draft.input === "string" && draft.input.trim() ? { serialized, input: draft.input } : null;
  } catch {
    return serialized.trim() ? { serialized, input: serialized } : null;
  }
}

export function useHomeToolDraft(tool: HomeDraftTool, active: boolean, applyDraft: (input: string) => void) {
  const applyDraftRef = React.useRef(applyDraft);
  applyDraftRef.current = applyDraft;

  React.useEffect(() => {
    if (!active || typeof sessionStorage === "undefined") return;
    const draft = readHomeToolDraft(tool, sessionStorage);
    if (!draft) return;
    applyDraftRef.current(draft.input);

    // Defer consumption so React StrictMode's development remount receives
    // the same payload before the live mount removes it.
    const timer = window.setTimeout(() => {
      if (sessionStorage.getItem(keyFor(tool)) === draft.serialized) {
        sessionStorage.removeItem(keyFor(tool));
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [active, tool]);
}

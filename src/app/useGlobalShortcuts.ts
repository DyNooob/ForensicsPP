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

type SetBool = (value: boolean | ((previous: boolean) => boolean)) => void;

export interface GlobalShortcutsDeps {
  activeTool: ToolId;
  commandOpen: boolean;
  settingsOpen: boolean;
  openCommandPalette: () => void;
  setSidebarCollapsed: SetBool;
  setDetailsExpanded: SetBool;
  setCommandOpen: SetBool;
  setSettingsOpen: SetBool;
}

export function useGlobalShortcuts(deps: GlobalShortcutsDeps) {
  const { activeTool, commandOpen, settingsOpen, openCommandPalette, setSidebarCollapsed, setDetailsExpanded, setCommandOpen, setSettingsOpen } =
    deps;

  React.useEffect(() => {
    const handleKeydown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        openCommandPalette();
        return;
      }
      const target = event.target as HTMLElement | null;
      const isEditableTarget = Boolean(target?.closest("input, textarea, select, [contenteditable='true']"));
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "b" && !isEditableTarget) {
        event.preventDefault();
        setSidebarCollapsed((value) => !value);
        return;
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "." && !isEditableTarget && activeTool !== "home") {
        event.preventDefault();
        setDetailsExpanded((value) => !value);
        return;
      }
      if (event.key === "Escape" && commandOpen) {
        setCommandOpen(false);
        return;
      }
      if (event.key === "Escape" && settingsOpen) {
        setSettingsOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeydown);
    return () => window.removeEventListener("keydown", handleKeydown);
  }, [activeTool, commandOpen, settingsOpen, openCommandPalette, setSidebarCollapsed, setDetailsExpanded, setCommandOpen, setSettingsOpen]);
}

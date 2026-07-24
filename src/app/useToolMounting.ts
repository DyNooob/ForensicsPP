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
import { maxMountedTools } from "../config/app";
import type { ToolId } from "../config/app";

type SetActiveTool = (tool: ToolId, options?: { replaceHash?: boolean }) => void;

export function useToolMounting(activeTool: ToolId, setActiveTool: SetActiveTool) {
  const [mountedTools, setMountedTools] = React.useState<ToolId[]>([activeTool]);
  const [dirtyTools, setDirtyTools] = React.useState<ToolId[]>([]);
  const [pendingToolClose, setPendingToolClose] = React.useState<ToolId[] | null>(null);
  const retainedTools = mountedTools.includes(activeTool) ? mountedTools : [...mountedTools, activeTool];

  React.useEffect(() => {
    setMountedTools((current) => {
      const next = [...current.filter((tool) => tool !== activeTool), activeTool];
      if (next.length <= maxMountedTools) return next;
      const removable = next.filter((tool) => tool !== activeTool && tool !== "home" && !dirtyTools.includes(tool));
      const overflow = next.length - maxMountedTools;
      const remove = new Set(removable.slice(0, overflow));
      return next.filter((tool) => !remove.has(tool));
    });
  }, [activeTool, dirtyTools]);

  const setToolDirty = React.useCallback((tool: ToolId, dirty: boolean) => {
    setDirtyTools((current) =>
      dirty ? (current.includes(tool) ? current : [...current, tool]) : current.filter((item) => item !== tool)
    );
  }, []);

  const closeToolsNow = React.useCallback(
    (closing: ToolId[]) => {
      if (!closing.length) return;
      if (closing.includes(activeTool)) setActiveTool("home");
      setMountedTools((current) => current.filter((item) => !closing.includes(item)));
      setDirtyTools((current) => current.filter((item) => !closing.includes(item)));
    },
    [activeTool, setActiveTool]
  );

  const closeMountedTool = React.useCallback(
    (tool: ToolId) => {
      if (tool === "home") return;
      if (dirtyTools.includes(tool)) {
        setPendingToolClose([tool]);
        return;
      }
      closeToolsNow([tool]);
    },
    [dirtyTools, closeToolsNow]
  );

  const closeAllMountedTools = React.useCallback(() => {
    const closing = retainedTools.filter((tool) => tool !== "home");
    if (closing.some((tool) => dirtyTools.includes(tool))) {
      setPendingToolClose(closing);
      return;
    }
    closeToolsNow(closing);
  }, [retainedTools, dirtyTools, closeToolsNow]);

  React.useEffect(() => {
    if (!dirtyTools.length) return;
    const warnBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warnBeforeUnload);
    return () => window.removeEventListener("beforeunload", warnBeforeUnload);
  }, [dirtyTools.length]);

  return {
    mountedTools,
    retainedTools,
    setToolDirty,
    pendingToolClose,
    setPendingToolClose,
    closeToolsNow,
    closeMountedTool,
    closeAllMountedTools
  };
}

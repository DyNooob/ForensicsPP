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
import { useStoredState } from "../utils/storage";
import { isStringValue, isToolIdArrayValue, isToolIdValue } from "../utils/appGuards";
import { maxRecentTools, tools, toolIdFromHash, writeToolHash } from "../config/app";
import { copy } from "../i18n";
import type { ToolGroup } from "../components/Sidebar";
import type { ToolCategory, ToolId } from "../config/app";

type SetCollapsed = (value: boolean | ((previous: boolean) => boolean)) => void;

export function useToolRouting(isNarrowShell: boolean, setSidebarCollapsed: SetCollapsed) {
  const [storedActiveTool, setStoredActiveTool] = useStoredState<ToolId>("app.activeTool", "home", isToolIdValue);
  const [routeTool, setRouteTool] = React.useState<ToolId | null>(() => toolIdFromHash());
  const [recentTools, setRecentTools] = useStoredState<ToolId[]>("app.recentTools", [], isToolIdArrayValue);
  const [favoriteTools, setFavoriteTools] = useStoredState<ToolId[]>("app.favoriteTools", [], isToolIdArrayValue);
  const [query, setQuery] = useStoredState("app.query", "", isStringValue);

  const rememberToolUse = React.useCallback((tool: ToolId) => {
    if (tool === "home") return;
    setRecentTools((items) =>
      [tool, ...items.filter((item) => item !== tool && tools.some((known) => known.id === item))].slice(0, maxRecentTools)
    );
  }, [setRecentTools]);

  const setActiveTool = React.useCallback(
    (tool: ToolId, options?: { replaceHash?: boolean }) => {
      setRouteTool(tool);
      setStoredActiveTool(tool);
      rememberToolUse(tool);
      writeToolHash(tool, options?.replaceHash);
      if (isNarrowShell) setSidebarCollapsed(true);
    },
    [isNarrowShell, rememberToolUse, setRouteTool, setStoredActiveTool, setSidebarCollapsed]
  );

  const activeTool = routeTool ?? (tools.some((tool) => tool.id === storedActiveTool) ? storedActiveTool : "home");

  const toggleFavoriteTool = React.useCallback((tool: ToolId) => {
    if (tool === "home") return;
    setFavoriteTools((items) => {
      const normalized = items.filter((item) => item !== "home" && tools.some((known) => known.id === item));
      return normalized.includes(tool) ? normalized.filter((item) => item !== tool) : [tool, ...normalized].slice(0, maxRecentTools);
    });
  }, [setFavoriteTools]);

  const favoriteIds = new Set(favoriteTools.filter((id) => id !== "home" && tools.some((tool) => tool.id === id)));

  const filteredTools = tools.filter((tool) => {
    const text = [
      copy.zh[tool.name],
      copy.zh[tool.desc],
      copy.zh[tool.category],
      copy.en[tool.name],
      copy.en[tool.desc],
      copy.en[tool.category]
    ]
      .join(" ")
      .toLowerCase();
    return text.includes(query.toLowerCase());
  });

  const favoriteNavTools = favoriteTools
    .map((id) => filteredTools.find((tool) => tool.id === id))
    .filter((tool): tool is (typeof tools)[number] => Boolean(tool))
    .filter((tool) => tool.id !== "home");

  const groupedTools: ToolGroup[] = (["featured", "analysis", "transform", "network"] as ToolCategory[])
    .map((category) => ({
      category,
      items: filteredTools.filter((tool) => tool.category === category && !favoriteIds.has(tool.id))
    }))
    .filter((group) => group.items.length);

  React.useEffect(() => {
    const hashedTool = toolIdFromHash();
    if (hashedTool) {
      setRouteTool(hashedTool);
      setStoredActiveTool(hashedTool);
      rememberToolUse(hashedTool);
      return;
    }
    writeToolHash(activeTool, true);
    // Intentionally run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    const handleHashChange = () => {
      const nextTool = toolIdFromHash();
      if (!nextTool) return;
      setRouteTool(nextTool);
      setStoredActiveTool(nextTool);
      rememberToolUse(nextTool);
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [rememberToolUse, setRouteTool, setStoredActiveTool]);

  return {
    activeTool,
    setActiveTool,
    query,
    setQuery,
    recentTools,
    favoriteTools,
    toggleFavoriteTool,
    favoriteNavTools,
    groupedTools
  };
}

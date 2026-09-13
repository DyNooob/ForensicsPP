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
  canonicalToolId,
  getToolTitle as resolveToolTitle,
  maxMountedTools,
  maxRecentTools,
  tools,
  visibleTools,
} from "../config/app";
import { resolveCurrentRoute, writeRoute } from "../core/routeAdapter";
import type { ToolCategory, ToolDefinition, ToolId } from "../config/app";
import { resolveRetainedTools } from "../core/runtime";
import { useStoredState } from "../utils/storage";
import { isToolIdValue, isToolIdArrayValue } from "../utils/appGuards";
import { copy } from "../i18n";
import type { Lang } from "../models";
import type { ToolGroup as SidebarToolGroup } from "../components/Sidebar";

export function useToolNavigation({
  isNarrowShell,
  setSidebarCollapsed,
  query,
  lang,
}: {
  isNarrowShell: boolean;
  setSidebarCollapsed: React.Dispatch<React.SetStateAction<boolean>>;
  query: string;
  lang: Lang;
}) {
  const [storedActiveTool, setStoredActiveTool] = useStoredState<ToolId>("app.activeTool", "home", isToolIdValue);
  const initialRoute = resolveCurrentRoute();
  const [routeTool, setRouteTool] = React.useState<ToolId | null>(initialRoute.toolId);
  const [routeUnknown, setRouteUnknown] = React.useState<boolean>(initialRoute.unknown);
  const [recentTools, setRecentTools] = useStoredState<ToolId[]>("app.recentTools", [], isToolIdArrayValue);
  const [favoriteTools, setFavoriteTools] = useStoredState<ToolId[]>("app.favoriteTools", [], isToolIdArrayValue);
  const activeTool = routeTool ?? (tools.some((tool) => tool.id === storedActiveTool) ? canonicalToolId(storedActiveTool) : "home");
  const [mountedTools, setMountedTools] = React.useState<ToolId[]>(() => [activeTool]);
  const [dirtyTools, setDirtyTools] = React.useState<ToolId[]>([]);
  const [pendingToolClose, setPendingToolClose] = React.useState<ToolId[] | null>(null);
  const retainedTools = resolveRetainedTools(activeTool, mountedTools, maxMountedTools);
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
  const rememberToolUse = (tool: ToolId) => {
    if (tool === "home") return;
    const canonical = canonicalToolId(tool);
    setRecentTools((items) => [canonical, ...items.map(canonicalToolId).filter((item) => item !== canonical && visibleTools.some((known) => known.id === item))].slice(0, maxRecentTools));
  };
  const setActiveTool = (tool: ToolId, options?: { replaceHash?: boolean }) => {
    const canonical = canonicalToolId(tool);
    setRouteTool(canonical);
    setRouteUnknown(false);
    setStoredActiveTool(canonical);
    rememberToolUse(canonical);
    writeRoute(canonical, { replace: options?.replaceHash });
    if (isNarrowShell) setSidebarCollapsed(true);
  };
  const setToolDirty = React.useCallback((tool: ToolId, dirty: boolean) => {
    setDirtyTools((current) => dirty
      ? current.includes(tool) ? current : [...current, tool]
      : current.filter((item) => item !== tool));
  }, []);
  const closeToolsNow = (closing: ToolId[]) => {
    if (!closing.length) return;
    if (closing.includes(activeTool)) setActiveTool("home");
    setMountedTools((current) => current.filter((item) => !closing.includes(item)));
    setDirtyTools((current) => current.filter((item) => !closing.includes(item)));
  };
  const closeMountedTool = (tool: ToolId) => {
    if (tool === "home") return;
    if (dirtyTools.includes(tool)) {
      setPendingToolClose([tool]);
      return;
    }
    closeToolsNow([tool]);
  };
  const closeAllMountedTools = () => {
    const closing = retainedTools.filter((tool) => tool !== "home");
    if (closing.some((tool) => dirtyTools.includes(tool))) {
      setPendingToolClose(closing);
      return;
    }
    closeToolsNow(closing);
  };
  React.useEffect(() => {
    if (!dirtyTools.length) return;
    const warnBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warnBeforeUnload);
    return () => window.removeEventListener("beforeunload", warnBeforeUnload);
  }, [dirtyTools.length]);
  const active = tools.find((tool) => tool.id === activeTool) ?? tools[0];
  const toolTitle = React.useCallback((tool: ToolDefinition) => resolveToolTitle(tool, lang, copy[lang]), [lang]);
  const favoriteIds = new Set(favoriteTools.map(canonicalToolId).filter((id) => id !== "home" && visibleTools.some((tool) => tool.id === id)));
  const activeIsFavorite = favoriteIds.has(activeTool);
  const toggleFavoriteTool = (tool: ToolId) => {
    if (tool === "home") return;
    setFavoriteTools((items) => {
      const normalized = Array.from(new Set(items.map(canonicalToolId).filter((item) => item !== "home" && visibleTools.some((known) => known.id === item))));
      return normalized.includes(tool) ? normalized.filter((item) => item !== tool) : [tool, ...normalized].slice(0, maxRecentTools);
    });
  };
  const filteredTools = visibleTools.filter((tool) => {
    const text = [
      copy.zh[tool.name],
      copy.zh[tool.desc],
      copy.zh[tool.category],
      copy.en[tool.name],
      copy.en[tool.desc],
      copy.en[tool.category],
      ...(tool.accepts ?? []),
      ...(tool.capabilities ?? [])
    ].join(" ").toLowerCase();
    return text.includes(query.toLowerCase());
  });
  const favoriteNavTools = favoriteTools
    .map((id) => filteredTools.find((tool) => tool.id === id))
    .filter((tool): tool is (typeof tools)[number] => Boolean(tool))
    .filter((tool) => tool.id !== "home");
  const domainOrder: ToolCategory[] = ["analysis", "transform", "network"];
  const featuredItems = filteredTools.filter((tool) => tool.featured === true && !favoriteIds.has(tool.id));
  const domainGroups: SidebarToolGroup[] = domainOrder
    .map((category) => ({
      category,
      items: filteredTools.filter((tool) => tool.category === category && !tool.featured && !favoriteIds.has(tool.id))
    }))
    .filter((group) => group.items.length);
  const groupedTools: SidebarToolGroup[] = [
    ...(featuredItems.length ? [{ category: "featured" as const, items: featuredItems }] : []),
    ...domainGroups
  ];
  React.useEffect(() => {
    const onNavigate = () => {
      const r = resolveCurrentRoute();
      setRouteUnknown(r.unknown);
      setRouteTool(r.toolId);
      if (r.toolId) {
        setStoredActiveTool(r.toolId);
        rememberToolUse(r.toolId);
      }
    };
    window.addEventListener("popstate", onNavigate);
    window.addEventListener("hashchange", onNavigate);
    return () => {
      window.removeEventListener("popstate", onNavigate);
      window.removeEventListener("hashchange", onNavigate);
    };
  }, []);

  return {
    activeTool,
    active,
    routeUnknown,
    toolTitle,
    recentTools,
    favoriteTools,
    mountedTools,
    retainedTools,
    pendingToolClose,
    setPendingToolClose,
    setActiveTool,
    setToolDirty,
    closeMountedTool,
    closeAllMountedTools,
    closeToolsNow,
    toggleFavoriteTool,
    activeIsFavorite,
    favoriteNavTools,
    groupedTools,
  };
}

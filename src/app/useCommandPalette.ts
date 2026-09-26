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
import { getToolTitle as resolveToolTitle, toolTitleOverrides, visibleTools } from "../config/app";
import type { ToolDefinition, ToolId } from "../config/app";
import { copy } from "../i18n";
import { clearForensicsStorage } from "../utils/storage";
import { writeRoute } from "../core/routeAdapter";
import type { AppCommand, Lang } from "../models";

function getToolTitle(tool: ToolDefinition, lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}

export function useCommandPalette({
  activeTool,
  lang,
  sidebarCollapsed,
  setSidebarCollapsed,
  detailsExpanded,
  setDetailsExpanded,
  caseNotesCount,
  setActiveTool,
  setReporterOpen,
  setThemeMode,
  setCacheClearError,
  settingsOpen,
  setSettingsOpen,
  reopenFirstRun,
}: {
  activeTool: ToolId;
  lang: Lang;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: React.Dispatch<React.SetStateAction<boolean>>;
  detailsExpanded: boolean;
  setDetailsExpanded: React.Dispatch<React.SetStateAction<boolean>>;
  caseNotesCount: number;
  setActiveTool: (id: ToolId) => void;
  setReporterOpen: React.Dispatch<React.SetStateAction<boolean>>;
  setThemeMode: (mode: "dark" | "light" | "auto") => void;
  setCacheClearError: React.Dispatch<React.SetStateAction<boolean>>;
  settingsOpen: boolean;
  setSettingsOpen: React.Dispatch<React.SetStateAction<boolean>>;
  reopenFirstRun: () => void;
}) {
  const t = copy[lang];
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState("");
  const modalOpenGuardRef = React.useRef({ settings: 0, command: 0 });
  const detailsToggleLabel = detailsExpanded ? (lang === "zh" ? "精简" : "Compact") : (lang === "zh" ? "详情" : "Details");

  const openSettingsPanel = React.useCallback(() => {
    modalOpenGuardRef.current.settings = performance.now();
    setSettingsOpen(true);
  }, []);

  const openCommandPalette = React.useCallback(() => {
    modalOpenGuardRef.current.command = performance.now();
    setCommandOpen(true);
  }, []);

  const shouldIgnoreBackdropClick = React.useCallback((modal: "settings" | "command") => (
    performance.now() - modalOpenGuardRef.current[modal] < 220
  ), []);

  const commands = React.useMemo<AppCommand[]>(() => {
    const toolCommands = visibleTools.map((tool) => ({
      id: `tool:${tool.id}`,
      group: t.commandGroupTools,
      label: getToolTitle(tool, lang),
      hint: t[tool.desc],
      meta: t[tool.category],
      keywords: `${tool.id} ${copy.zh[tool.name]} ${copy.en[tool.name]} ${copy.zh[tool.desc]} ${copy.en[tool.desc]} ${toolTitleOverrides[tool.id]?.zh ?? ""} ${toolTitleOverrides[tool.id]?.en ?? ""}`,
      run: () => setActiveTool(tool.id)
    }));
    const actionCommands: AppCommand[] = [
      {
        id: "action:settings",
        group: t.commandGroupActions,
        label: t.openSettings,
        hint: t.settings,
        meta: t.commandGroupActions,
        keywords: "settings preference 设置 主题",
        run: () => openSettingsPanel()
      },
      {
        id: "action:report",
        group: t.commandGroupActions,
        label: t.openReport,
        hint: `${caseNotesCount} ${t.reportItems}`,
        meta: t.commandGroupActions,
        keywords: "report notes evidence case report 报告 笔记 案件",
        run: () => setReporterOpen(true)
      },
      {
        id: "action:sidebar",
        group: t.commandGroupActions,
        label: t.toggleSidebarCommand,
        hint: sidebarCollapsed ? t.expandSidebar : t.collapseSidebar,
        meta: "Ctrl/⌘ B",
        keywords: "sidebar collapse expand navigation nav 侧栏 折叠 展开",
        run: () => setSidebarCollapsed(!sidebarCollapsed)
      },
      {
        id: "action:details",
        group: t.commandGroupActions,
        label: t.toggleDetailsCommand,
        hint: detailsToggleLabel,
        meta: "Ctrl/⌘ .",
        keywords: "details compact advanced detailed 精简 详细",
        run: () => {
          if (activeTool !== "home") setDetailsExpanded(!detailsExpanded);
        }
      },
      {
        id: "action:clear",
        group: t.commandGroupActions,
        label: t.clearWorkspace,
        hint: t.localCache,
        meta: lang === "zh" ? "浏览器存储" : "Browser storage",
        keywords: "clear reset cache localStorage indexedDB 清空 缓存 本地工作区",
        run: () => {
          void clearForensicsStorage().then(() => {
            // Reload so mounted tools cannot write their in-memory state back after the clear.
            writeRoute("home", { replace: true });
            window.location.reload();
          }).catch(() => {
            setCacheClearError(true);
            openSettingsPanel();
          });
        }
      },
      {
        id: "theme:dark",
        group: t.commandGroupActions,
        label: t.themeDarkCommand,
        hint: t.themeMode,
        meta: t.themeMode,
        keywords: "theme dark 黑暗",
        run: () => setThemeMode("dark")
      },
      {
        id: "theme:light",
        group: t.commandGroupActions,
        label: t.themeLightCommand,
        hint: t.themeMode,
        meta: t.themeMode,
        keywords: "theme light 明亮",
        run: () => setThemeMode("light")
      },
      {
        id: "theme:auto",
        group: t.commandGroupActions,
        label: t.themeAutoCommand,
        hint: t.themeMode,
        meta: t.themeMode,
        keywords: "theme auto system follow 系统 自动",
        run: () => setThemeMode("auto")
      },
      {
        id: "action:guide",
        group: t.commandGroupActions,
        label: t.firstRunShowAgain,
        hint: t.firstRunTitle,
        meta: t.commandGroupActions,
        keywords: "guide tour intro welcome first run onboarding 引导 新手 介绍 入门",
        run: () => reopenFirstRun()
      }
    ];
    return [...actionCommands, ...toolCommands];
  }, [activeTool, caseNotesCount, detailsExpanded, detailsToggleLabel, lang, openSettingsPanel, sidebarCollapsed, t, reopenFirstRun]);

  const filteredCommands = React.useMemo(() => {
    const value = commandQuery.trim().toLowerCase();
    if (!value) return commands;
    return commands.filter((command) => [command.label, command.hint, command.keywords].join(" ").toLowerCase().includes(value));
  }, [commandQuery, commands]);

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
  }, [activeTool, commandOpen, openCommandPalette, settingsOpen]);

  return {
    commandOpen,
    setCommandOpen,
    commandQuery,
    setCommandQuery,
    openSettingsPanel,
    openCommandPalette,
    shouldIgnoreBackdropClick,
    filteredCommands,
  };
}

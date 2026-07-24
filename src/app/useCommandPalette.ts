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
import { tools, toolTitleOverrides } from "../config/app";
import { copy } from "../i18n";
import { getToolTitle } from "./toolTitle";
import type { AppCommand, Lang, ThemeMode } from "../models";
import type { Translation } from "../i18n";
import type { ToolId } from "../config/app";

type SetBool = (value: boolean | ((previous: boolean) => boolean)) => void;
type SetActiveTool = (tool: ToolId, options?: { replaceHash?: boolean }) => void;

export interface CommandPaletteDeps {
  t: Translation;
  lang: Lang;
  activeTool: ToolId;
  caseNotesCount: number;
  detailsExpanded: boolean;
  sidebarCollapsed: boolean;
  setActiveTool: SetActiveTool;
  openSettingsPanel: () => void;
  setReporterOpen: SetBool;
  setSidebarCollapsed: SetBool;
  setDetailsExpanded: SetBool;
  setThemeMode: (mode: ThemeMode) => void;
  clearWorkspace: () => void;
  commandQuery: string;
}

export function useCommandPalette(deps: CommandPaletteDeps) {
  const {
    t,
    lang,
    activeTool,
    caseNotesCount,
    detailsExpanded,
    sidebarCollapsed,
    setActiveTool,
    openSettingsPanel,
    setReporterOpen,
    setSidebarCollapsed,
    setDetailsExpanded,
    setThemeMode,
    clearWorkspace,
    commandQuery
  } = deps;

  const detailsToggleLabel = detailsExpanded
    ? lang === "zh"
      ? "精简"
      : "Compact"
    : lang === "zh"
      ? "详情"
      : "Details";

  const commands = React.useMemo<AppCommand[]>(() => {
    const toolCommands = tools.map((tool) => ({
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
          void clearWorkspace();
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
      }
    ];
    return [...actionCommands, ...toolCommands];
  }, [activeTool, caseNotesCount, detailsExpanded, detailsToggleLabel, lang, openSettingsPanel, setActiveTool, setReporterOpen, setSidebarCollapsed, setDetailsExpanded, setThemeMode, sidebarCollapsed, t, clearWorkspace]);

  const filteredCommands = React.useMemo(() => {
    const value = commandQuery.trim().toLowerCase();
    if (!value) return commands;
    return commands.filter((command) => [command.label, command.hint, command.keywords].join(" ").toLowerCase().includes(value));
  }, [commandQuery, commands]);

  return { commands, filteredCommands };
}

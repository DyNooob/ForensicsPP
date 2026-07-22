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

import { copyText, setCopyToastLabel } from "./utils/clipboard";
import React from "react";
import { ConfigProvider, Modal, theme as antdTheme } from "antd";
import { CommandPalette } from "./components/CommandPalette";
import { ToolHost } from "./components/ToolHost";
import { Sidebar } from "./components/Sidebar";
import type { ToolGroup } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { LegalConsentModal } from "./components/LegalConsentModal";
import { getToolTitle as resolveToolTitle, legalVersion, maxMountedTools, maxRecentTools, themePresets, toolTitleOverrides, toolIdFromHash, tools, writeToolHash } from "./config/app";
import type { ToolCategory, ToolDefinition, ToolId } from "./config/app";
import { copy } from "./i18n";
import { clearForensicsStorage, clearLegacyEvidenceStorage, useStoredState } from "./utils/storage";
import { normalizeHexColor, themeDisplayColor, themeSoftColor } from "./utils/themeColors";
import { compactReportText, defaultCaseReportMeta, isBooleanValue, isCaseNotesValue, isCaseReportMetaValue, isLangValue, isStringValue, isThemeModeValue, isToolIdArrayValue, isToolIdValue } from "./utils/appGuards";
import type { AppCommand, CaseNote, CaseReportMeta, Lang, ThemeMode } from "./models";
import { fingerprintEvidenceFiles, rememberedEvidenceFiles, rememberEvidenceFiles } from "./features/reporter/evidence";
import { rememberedTimelineEvents } from "./features/reporter/timeline";

const SettingsModal = React.lazy(() => import("./components/SettingsModal").then((module) => ({ default: module.SettingsModal })));
const CaseReporter = React.lazy(() => import("./features/reporter/CaseReporter").then((module) => ({ default: module.CaseReporter })));

function getToolTitle(tool: (typeof tools)[number], lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}



export function App() {
  const [lang, setLang] = useStoredState<Lang>("app.lang", "zh", isLangValue);
  const [storedActiveTool, setStoredActiveTool] = useStoredState<ToolId>("app.activeTool", "home", isToolIdValue);
  const [routeTool, setRouteTool] = React.useState<ToolId | null>(() => toolIdFromHash());
  const [recentTools, setRecentTools] = useStoredState<ToolId[]>("app.recentTools", [], isToolIdArrayValue);
  const [favoriteTools, setFavoriteTools] = useStoredState<ToolId[]>("app.favoriteTools", [], isToolIdArrayValue);
  const [query, setQuery] = useStoredState("app.query", "", isStringValue);
  const [themeMode, setThemeMode] = useStoredState<ThemeMode>("app.themeMode", "light", isThemeModeValue);
  const [themeColor, setThemeColor] = useStoredState("app.themeColor", themePresets[0].hex, isStringValue);
  const [themeDefaultMigrated, setThemeDefaultMigrated] = useStoredState("app.themeDefaultV070", false, isBooleanValue);
  const [acceptedLegalVersion, setAcceptedLegalVersion] = useStoredState("legal.acceptedVersion", "", isStringValue);
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [cacheClearArmed, setCacheClearArmed] = React.useState(false);
  const [cacheClearError, setCacheClearError] = React.useState(false);
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState("");
  const [reporterOpen, setReporterOpen] = React.useState(false);
  const [reportAddBusy, setReportAddBusy] = React.useState(false);
  const reportAddAbortRef = React.useRef<AbortController | null>(null);
  const [caseNotes, setCaseNotes] = useStoredState<CaseNote[]>("report.notes", [], isCaseNotesValue);
  const [caseReportMeta, setCaseReportMeta] = useStoredState<CaseReportMeta>("report.meta", defaultCaseReportMeta(), isCaseReportMetaValue);
  React.useEffect(() => () => {
    reportAddAbortRef.current?.abort();
  }, []);
  const modalOpenGuardRef = React.useRef({ settings: 0, command: 0 });
  const [toolLinkMessage, setToolLinkMessage] = React.useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useStoredState("app.sidebarCollapsed", false, isBooleanValue);
  const [isNarrowShell, setIsNarrowShell] = React.useState(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia("(max-width: 900px)").matches;
  });
  const [systemTheme, setSystemTheme] = React.useState<"light" | "dark">(() => {
    if (typeof window === "undefined") return "light";
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [detailsExpanded, setDetailsExpanded] = React.useState(false);
  const t = copy[lang];
  const toolTitle = React.useCallback((tool: ToolDefinition) => getToolTitle(tool, lang), [lang]);
  const resolvedThemeColor = React.useMemo(
    () => {
      const normalized = normalizeHexColor(themeColor) ?? themePresets[0].hex;
      return !themeDefaultMigrated && normalized === "#245F73" ? themePresets[0].hex : normalized;
    },
    [themeColor, themeDefaultMigrated]
  );
  const appliedTheme = themeMode === "auto" ? systemTheme : themeMode === "dark" ? "dark" : "light";
  const displayThemeColor = React.useMemo(
    () => themeDisplayColor(resolvedThemeColor, appliedTheme),
    [appliedTheme, resolvedThemeColor]
  );
  const activeTool = routeTool ?? (tools.some((tool) => tool.id === storedActiveTool) ? storedActiveTool : "home");
  const [mountedTools, setMountedTools] = React.useState<ToolId[]>(() => [activeTool]);
  const [dirtyTools, setDirtyTools] = React.useState<ToolId[]>([]);
  const [pendingToolClose, setPendingToolClose] = React.useState<ToolId[] | null>(null);
  const retainedTools = mountedTools.includes(activeTool) ? mountedTools : [...mountedTools, activeTool];
  React.useEffect(() => {
    clearLegacyEvidenceStorage();
  }, []);
  React.useEffect(() => {
    setCopyToastLabel(t.copyDone);
  }, [t]);
  React.useEffect(() => {
    const rememberInputFiles = (event: Event) => {
      const target = event.target;
      if (target instanceof HTMLInputElement && target.type === "file" && target.files?.length) {
        rememberEvidenceFiles(target, target.files);
      }
    };
    const rememberDroppedFiles = (event: DragEvent) => {
      if (event.dataTransfer?.files.length) rememberEvidenceFiles(event.target, event.dataTransfer.files);
    };
    document.addEventListener("change", rememberInputFiles, true);
    document.addEventListener("drop", rememberDroppedFiles, true);
    return () => {
      document.removeEventListener("change", rememberInputFiles, true);
      document.removeEventListener("drop", rememberDroppedFiles, true);
    };
  }, []);
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
    setRecentTools((items) => [tool, ...items.filter((item) => item !== tool && tools.some((known) => known.id === item))].slice(0, maxRecentTools));
  };
  const setActiveTool = (tool: ToolId, options?: { replaceHash?: boolean }) => {
    setRouteTool(tool);
    setStoredActiveTool(tool);
    rememberToolUse(tool);
    writeToolHash(tool, options?.replaceHash);
    if (isNarrowShell) setSidebarCollapsed(true);
  };
  const addCurrentToolToReport = async () => {
    if (reportAddBusy) return;
    if (activeTool === "home") {
      setReporterOpen(true);
      return;
    }
    const toolView = Array.from(document.querySelectorAll<HTMLElement>(".tool-retained-view"))
      .find((element) => element.dataset.toolId === activeTool);
    const content = compactReportText(toolView?.innerText || toolView?.textContent || "");
    const hasFilledControl = Boolean(toolView && Array.from(toolView.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
      'input:not([type="file"]), textarea'
    )).some((control) => control.value.trim()));
    const hasLoadedFile = Boolean(toolView && Array.from(toolView.querySelectorAll<HTMLInputElement>('input[type="file"]'))
      .some((control) => Boolean(control.files?.length)));
    const hasRenderedOutput = Boolean(toolView && Array.from(toolView.querySelectorAll<HTMLElement>(
      "table tbody tr, pre, code, img, .tool-result, .result-panel, [data-report-output]"
    )).some((element) => {
      const rect = element.getBoundingClientRect();
      return !element.hidden && rect.width > 0 && rect.height > 0 && (element.textContent?.trim() || element.tagName === "IMG");
    }));
    if (!content || (!hasFilledControl && !hasLoadedFile && !hasRenderedOutput)) {
      setReporterOpen(true);
      return;
    }
    setReportAddBusy(true);
    reportAddAbortRef.current?.abort();
    const controller = new AbortController();
    reportAddAbortRef.current = controller;
    try {
      const selectedFiles = Array.from(toolView?.querySelectorAll<HTMLInputElement>('input[type="file"]') ?? [])
        .flatMap((input) => Array.from(input.files ?? []));
      const evidenceFiles = await fingerprintEvidenceFiles([
        ...selectedFiles,
        ...(toolView ? rememberedEvidenceFiles(toolView) : [])
      ], { signal: controller.signal });
      if (controller.signal.aborted) return;
      const timelineEvents = toolView ? rememberedTimelineEvents(toolView) : [];
      const createdAt = new Date().toISOString();
      const note: CaseNote = {
        id: `${activeTool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        tool: getToolTitle(active, lang),
        title: `${getToolTitle(active, lang)} · ${createdAt.slice(0, 10)}`,
        content,
        summary: content.replace(/\s+/g, " ").slice(0, 420),
        markdown: ["```text", content, "```"].join("\n"),
        description: t[active.desc],
        route: `#${activeTool}`,
        sourceUrl: window.location.href,
        ...(evidenceFiles.length ? { evidenceFiles } : {}),
        ...(timelineEvents.length ? { timelineEvents } : {}),
        createdAt
      };
      setCaseNotes((current) => [note, ...current].slice(0, 40));
      setReporterOpen(true);
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) {
        setToolLinkMessage(t.reportAddFailed);
      }
    } finally {
      if (reportAddAbortRef.current === controller) {
        reportAddAbortRef.current = null;
        setReportAddBusy(false);
      }
    }
  };
  const updateCaseNote = (id: string, patch: Partial<CaseNote>) => {
    setCaseNotes((current) => current.map((note) => note.id === id ? { ...note, ...patch } : note));
  };
  const deleteCaseNote = (id: string) => {
    setCaseNotes((current) => current.filter((note) => note.id !== id));
  };
  const clearCaseNotes = () => setCaseNotes([]);
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
  const favoriteIds = new Set(favoriteTools.filter((id) => id !== "home" && tools.some((tool) => tool.id === id)));
  const activeIsFavorite = favoriteIds.has(activeTool);
  const toggleFavoriteTool = (tool: ToolId) => {
    if (tool === "home") return;
    setFavoriteTools((items) => {
      const normalized = items.filter((item) => item !== "home" && tools.some((known) => known.id === item));
      return normalized.includes(tool) ? normalized.filter((item) => item !== tool) : [tool, ...normalized].slice(0, maxRecentTools);
    });
  };
  const detailsToggleLabel = detailsExpanded ? (lang === "zh" ? "精简" : "Compact") : (lang === "zh" ? "详情" : "Details");
  const filteredTools = tools.filter((tool) => {
    const text = [
      copy.zh[tool.name],
      copy.zh[tool.desc],
      copy.zh[tool.category],
      copy.en[tool.name],
      copy.en[tool.desc],
      copy.en[tool.category]
    ].join(" ").toLowerCase();
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
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = () => setSystemTheme(media.matches ? "dark" : "light");
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  React.useEffect(() => {
    if (themeDefaultMigrated) return;
    if (themeColor.toUpperCase() === "#245F73") setThemeColor(themePresets[0].hex);
    setThemeDefaultMigrated(true);
  }, [setThemeColor, setThemeDefaultMigrated, themeColor, themeDefaultMigrated]);

  React.useEffect(() => {
    if (themeColor !== resolvedThemeColor) {
      setThemeColor(resolvedThemeColor);
    }
  }, [resolvedThemeColor, setThemeColor, themeColor]);

  React.useLayoutEffect(() => {
    document.documentElement.dataset.themeMode = appliedTheme;
    document.body.dataset.themeMode = appliedTheme;
    document.documentElement.style.colorScheme = appliedTheme;
    document.body.style.colorScheme = appliedTheme;
    document.documentElement.style.backgroundColor = appliedTheme === "dark" ? "#0f1722" : "#f5f7fa";
    document.body.style.backgroundColor = appliedTheme === "dark" ? "#0f1722" : "#f5f7fa";
    document.documentElement.style.setProperty("--app-primary", displayThemeColor);
    document.documentElement.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
    document.documentElement.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    document.body.style.setProperty("--app-primary", displayThemeColor);
    document.body.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
    document.body.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    const rootNode = document.getElementById("root");
    if (rootNode) {
      rootNode.dataset.themeMode = appliedTheme;
      rootNode.style.colorScheme = appliedTheme;
      rootNode.style.setProperty("--app-primary", displayThemeColor);
      rootNode.style.setProperty("--app-primary-soft", themeSoftColor(displayThemeColor, appliedTheme));
      rootNode.style.setProperty("--app-primary-contrast", appliedTheme === "dark" ? "#0F1822" : "#FFFFFF");
    }
    let themeMeta = document.querySelector("meta[name='theme-color']");
    if (!themeMeta) {
      themeMeta = document.createElement("meta");
      themeMeta.setAttribute("name", "theme-color");
      document.head.appendChild(themeMeta);
    }
    themeMeta.setAttribute("content", appliedTheme === "dark" ? "#0f1722" : "#f5f7fa");
  }, [appliedTheme, displayThemeColor]);

  React.useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = activeTool === "home" ? "Forensics++ Workbench | Open-source DFIR tools" : `${getToolTitle(active, lang)} - Forensics++`;
  }, [active.name, activeTool, lang, t]);

  React.useEffect(() => {
    const hashedTool = toolIdFromHash();
    if (hashedTool) {
      setRouteTool(hashedTool);
      setStoredActiveTool(hashedTool);
      rememberToolUse(hashedTool);
      return;
    }
    writeToolHash(activeTool, true);
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
  }, []);

  React.useEffect(() => {
    setDetailsExpanded(false);
  }, [activeTool]);

  React.useEffect(() => {
    const media = window.matchMedia("(max-width: 900px)");
    const handleChange = () => {
      setIsNarrowShell(media.matches);
      if (media.matches) setSidebarCollapsed(true);
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, []);

  React.useEffect(() => {
    if (!toolLinkMessage) return undefined;
    const timer = window.setTimeout(() => setToolLinkMessage(""), 2200);
    return () => window.clearTimeout(timer);
  }, [toolLinkMessage]);

  React.useEffect(() => {
    if (window.isSecureContext && "serviceWorker" in navigator) {
      navigator.serviceWorker.register(new URL("./sw.js", document.baseURI).href).catch(() => undefined);
    }
  }, []);


  React.useEffect(() => {
    if (!settingsOpen) {
      setCacheClearArmed(false);
      setCacheClearError(false);
    }
  }, [settingsOpen]);

  React.useEffect(() => {
    if (!cacheClearArmed) return;
    const timer = window.setTimeout(() => setCacheClearArmed(false), 4000);
    return () => window.clearTimeout(timer);
  }, [cacheClearArmed]);

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
        hint: `${caseNotes.length} ${t.reportItems}`,
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
            window.location.hash = "#home";
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
      }
    ];
    return [...actionCommands, ...toolCommands];
  }, [activeTool, caseNotes.length, detailsExpanded, detailsToggleLabel, lang, openSettingsPanel, sidebarCollapsed, t]);

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

  const applyThemeColor = (hex: string) => {
    const normalized = normalizeHexColor(hex);
    if (!normalized) return;
    setThemeColor(normalized);
  };

  const resetThemeAppearance = () => {
    const fallback = themePresets[0].hex;
    setThemeColor(fallback);
  };

  const clearLocalWorkspace = async () => {
    if (!cacheClearArmed) {
      setCacheClearArmed(true);
      return;
    }
    try {
      await clearForensicsStorage();
      window.location.hash = "#home";
      window.location.reload();
    } catch {
      setCacheClearArmed(false);
      setCacheClearError(true);
    }
  };

  const copyCurrentToolLink = () => {
    const url = `${window.location.origin}${window.location.pathname}${window.location.search}#${activeTool}`;
    void copyText(url, { feedback: false }).then((copied) => setToolLinkMessage(copied ? t.toolLinkCopied : url));
  };

  return (
    <ConfigProvider
      button={{ autoInsertSpace: false }}
      theme={{
        algorithm: appliedTheme === "dark" ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
        cssVar: { key: "forensicspp" },
        token: {
          colorPrimary: displayThemeColor,
          colorTextLightSolid: appliedTheme === "dark" ? "#0f1822" : "#ffffff",
          colorBgElevated: appliedTheme === "dark" ? "#202e3d" : "#ffffff",
          colorBgSpotlight: appliedTheme === "dark" ? "#2a3a4b" : "#ffffff",
          colorBorderSecondary: appliedTheme === "dark" ? "#2e4154" : "#d8e0e8",
          borderRadius: 6,
          fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans SC', sans-serif",
          fontSize: 14,
          controlHeight: 38,
          controlHeightSM: 34,
          colorBgContainer: appliedTheme === "dark" ? "#182330" : "#ffffff",
          colorBgLayout: appliedTheme === "dark" ? "#0f1722" : "#f5f7fa",
          colorBorder: appliedTheme === "dark" ? "#2e4154" : "#d8e0e8",
          colorText: appliedTheme === "dark" ? "#e7edf5" : "#162130",
          colorTextSecondary: appliedTheme === "dark" ? "#a6b8ca" : "#66768a"
        },
        components: {
          Button: {
            borderRadius: 6,
            controlHeight: 38,
            controlHeightSM: 34,
            defaultBorderColor: appliedTheme === "dark" ? "#2e4154" : "#d8e0e8",
            defaultColor: appliedTheme === "dark" ? "#e7edf5" : "#162130",
            defaultBg: appliedTheme === "dark" ? "#182330" : "#ffffff"
          },
          Input: {
            borderRadius: 6,
            activeBorderColor: displayThemeColor,
            hoverBorderColor: displayThemeColor
          },
          Segmented: {
            trackBg: appliedTheme === "dark" ? "#182330" : "#f3f6fa",
            itemColor: appliedTheme === "dark" ? "#a6b8ca" : "#617285",
            itemHoverColor: appliedTheme === "dark" ? "#e7edf5" : "#162130",
            itemHoverBg: appliedTheme === "dark" ? "rgba(255,255,255,0.04)" : "#ffffff",
            itemSelectedBg: appliedTheme === "dark" ? "rgba(255,255,255,0.06)" : "#ffffff",
            itemSelectedColor: appliedTheme === "dark" ? "#e7edf5" : "#162130"
          },
          Card: {
            borderRadiusLG: 8
          },
          Modal: {
            borderRadiusLG: 10
          }
        }
      }}
    >
    <div
      className={[
        "workbench-shell",
        settingsOpen || commandOpen || acceptedLegalVersion !== legalVersion ? "overlay-open" : "",
        sidebarCollapsed ? "sidebar-collapsed" : "",
        isNarrowShell ? "shell-narrow" : ""
      ].filter(Boolean).join(" ")}
    >
      <a className="skip-link" href="#main-content">
        {t.skipToContent}
      </a>
      <aside
        className="tool-sidebar"
        aria-hidden={sidebarCollapsed && !isNarrowShell ? true : undefined}
        inert={sidebarCollapsed && !isNarrowShell ? true : undefined}
      >
        <Sidebar
          t={t}
          query={query}
          onQueryChange={setQuery}
          collapsed={sidebarCollapsed}
          onToggleCollapsed={() => setSidebarCollapsed(!sidebarCollapsed)}
          favoriteNavTools={favoriteNavTools}
          groupedTools={groupedTools}
          activeTool={activeTool}
          onSelectTool={(id) => setActiveTool(id)}
          onOpenCommandPalette={openCommandPalette}
          onOpenSettings={() => openSettingsPanel()}
          toolTitle={toolTitle}
        />
      </aside>

      <main className="tool-main" id="main-content" tabIndex={-1}>
        <Topbar
          t={t}
          lang={lang}
          active={active}
          activeTool={activeTool}
          toolTitle={toolTitle}
          collapsed={sidebarCollapsed}
          onToggleCollapsed={() => setSidebarCollapsed(!sidebarCollapsed)}
          toolLinkMessage={toolLinkMessage}
          onCopyLink={copyCurrentToolLink}
          reportAddBusy={reportAddBusy}
          caseNotesCount={caseNotes.length}
          onAddToReport={addCurrentToolToReport}
          onOpenSettings={() => openSettingsPanel()}
          onOpenCommandPalette={openCommandPalette}
          onSetLang={setLang}
        />

        <section className={detailsExpanded || activeTool === "home" ? "tool-body" : "tool-body compact-results"}>
          {retainedTools.map((mountedTool) => (
            <ToolHost key={mountedTool} toolId={mountedTool} active={mountedTool === activeTool} t={t} lang={lang} recentTools={recentTools} setActiveTool={setActiveTool} setToolDirty={setToolDirty} />
          ))}
        </section>
      </main>

      <LegalConsentModal
        t={t}
        open={acceptedLegalVersion !== legalVersion}
        onAccept={() => setAcceptedLegalVersion(legalVersion)}
      />

      <Modal
        open={Boolean(pendingToolClose)}
        centered
        width={440}
        title={lang === "zh" ? "有修改尚未导出" : "Changes have not been exported"}
        okText={lang === "zh" ? "仍然关闭" : "Close anyway"}
        cancelText={t.cancelEdit}
        okButtonProps={{ danger: true }}
        onCancel={() => setPendingToolClose(null)}
        onOk={() => {
          const closing = pendingToolClose ?? [];
          setPendingToolClose(null);
          closeToolsNow(closing);
        }}
      >
        <p>{lang === "zh" ? "SQLite 中的修改只保存在当前标签页。关闭后将无法恢复。" : "SQLite changes exist only in this tab and cannot be recovered after closing."}</p>
      </Modal>

      {reporterOpen && (
        <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite">{t.loadingTool}</div>}>
          <CaseReporter
            notes={caseNotes}
            meta={caseReportMeta}
            t={t}
            onClose={() => {
              reportAddAbortRef.current?.abort();
              reportAddAbortRef.current = null;
              setReportAddBusy(false);
              setReporterOpen(false);
            }}
            onMetaChange={setCaseReportMeta}
            onUpdateNote={updateCaseNote}
            onDeleteNote={deleteCaseNote}
            onClear={clearCaseNotes}
            onImport={(bundle) => {
              setCaseNotes(bundle.notes);
              setCaseReportMeta(bundle.meta);
            }}
          />
        </React.Suspense>
      )}

      {settingsOpen && (
        <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite">{t.loadingTool}</div>}>
          <SettingsModal
            open
            lang={lang}
            t={t}
            themeMode={themeMode}
            themeColor={resolvedThemeColor}
            cacheClearArmed={cacheClearArmed}
            cacheClearError={cacheClearError}
            onClose={() => setSettingsOpen(false)}
            onThemeModeChange={setThemeMode}
            onThemeColorChange={applyThemeColor}
            onResetAppearance={resetThemeAppearance}
            onClearWorkspace={clearLocalWorkspace}
            openTools={retainedTools
              .filter((tool) => tool !== "home")
              .map((tool) => ({
                id: tool,
                title: getToolTitle(tools.find((item) => item.id === tool) ?? tools[0], lang),
                active: tool === activeTool
              }))}
            onCloseTool={closeMountedTool}
            onCloseAllTools={closeAllMountedTools}
          />
        </React.Suspense>
      )}
      {commandOpen && (
        <CommandPalette
          t={t}
          query={commandQuery}
          commands={filteredCommands}
          onQueryChange={setCommandQuery}
          onClose={() => setCommandOpen(false)}
          shouldIgnoreBackdropClose={() => shouldIgnoreBackdropClick("command")}
          onRun={(command) => {
            command.run();
            setCommandOpen(false);
            setCommandQuery("");
          }}
        />
      )}
    </div>
    </ConfigProvider>
  );
}

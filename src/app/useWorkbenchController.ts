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
import { copyText, setCopyToastLabel } from "../utils/clipboard";
import { useStoredState } from "../utils/storage";
import { clearForensicsStorage, clearLegacyEvidenceStorage } from "../utils/storage";
import { isBooleanValue, isLangValue, isStringValue } from "../utils/appGuards";
import { copy } from "../i18n";
import { legalVersion, tools } from "../config/app";
import { rememberEvidenceFiles } from "../features/reporter/evidence";
import { getToolTitle } from "./toolTitle";
import { useThemeController } from "./useThemeController";
import { useToolRouting } from "./useToolRouting";
import { useToolMounting } from "./useToolMounting";
import { useCaseReport } from "./useCaseReport";
import { useCommandPalette } from "./useCommandPalette";
import { useGlobalShortcuts } from "./useGlobalShortcuts";
import type { Lang, ThemeMode } from "../models";
import type { Translation } from "../i18n";
import type { ToolDefinition, ToolId } from "../config/app";
import type { AppCommand, CaseNote, CaseReportMeta } from "../models";

export interface Workbench {
  t: Translation;
  lang: Lang;
  setLang: (lang: Lang) => void;
  active: ToolDefinition;
  activeTool: ToolId;
  setActiveTool: (tool: ToolId, options?: { replaceHash?: boolean }) => void;
  toolTitle: (tool: ToolDefinition) => string;
  query: string;
  setQuery: (value: string) => void;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (value: boolean | ((previous: boolean) => boolean)) => void;
  isNarrowShell: boolean;
  detailsExpanded: boolean;
  setDetailsExpanded: (value: boolean | ((previous: boolean) => boolean)) => void;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  themeColor: string;
  displayThemeColor: string;
  appliedTheme: "light" | "dark";
  applyThemeColor: (hex: string) => void;
  resetThemeAppearance: () => void;
  toolLinkMessage: string;
  copyCurrentToolLink: () => void;
  reportAddBusy: boolean;
  addCurrentToolToReport: () => void;
  openSettingsPanel: () => void;
  openCommandPalette: () => void;
  settingsOpen: boolean;
  setSettingsOpen: (value: boolean | ((previous: boolean) => boolean)) => void;
  cacheClearArmed: boolean;
  cacheClearError: boolean;
  clearLocalWorkspace: () => void;
  commandOpen: boolean;
  setCommandOpen: (value: boolean | ((previous: boolean) => boolean)) => void;
  commandQuery: string;
  setCommandQuery: (value: string) => void;
  filteredCommands: AppCommand[];
  pendingToolClose: ToolId[] | null;
  setPendingToolClose: (value: ToolId[] | null) => void;
  closeToolsNow: (closing: ToolId[]) => void;
  closeMountedTool: (tool: ToolId) => void;
  closeAllMountedTools: () => void;
  caseNotes: CaseNote[];
  caseReportMeta: CaseReportMeta;
  setCaseReportMeta: (value: CaseReportMeta | ((previous: CaseReportMeta) => CaseReportMeta)) => void;
  updateCaseNote: (id: string, patch: Partial<CaseNote>) => void;
  deleteCaseNote: (id: string) => void;
  clearCaseNotes: () => void;
  importReport: (bundle: { notes: CaseNote[]; meta: CaseReportMeta }) => void;
  onReporterClose: () => void;
  reporterOpen: boolean;
  setReporterOpen: (value: boolean | ((previous: boolean) => boolean)) => void;
  retainedTools: ToolId[];
  setToolDirty: (tool: ToolId, dirty: boolean) => void;
  recentTools: ToolId[];
  favoriteNavTools: ToolDefinition[];
  groupedTools: import("../components/Sidebar").ToolGroup[];
  legalOpen: boolean;
  onAcceptLegal: () => void;
  shouldIgnoreBackdropClick: (modal: "settings" | "command") => boolean;
}

export function useWorkbenchController(): Workbench {
  const [lang, setLang] = useStoredState<Lang>("app.lang", "zh", isLangValue);
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useStoredState("app.sidebarCollapsed", false, isBooleanValue);
  const [isNarrowShell, setIsNarrowShell] = React.useState(() =>
    typeof window === "undefined" ? false : window.matchMedia("(max-width: 900px)").matches
  );
  const [detailsExpanded, setDetailsExpanded] = React.useState(false);
  const [toolLinkMessage, setToolLinkMessage] = React.useState("");
  const [cacheClearArmed, setCacheClearArmed] = React.useState(false);
  const [cacheClearError, setCacheClearError] = React.useState(false);
  const [acceptedLegalVersion, setAcceptedLegalVersion] = useStoredState("legal.acceptedVersion", "", isStringValue);
  const [reporterOpen, setReporterOpen] = React.useState(false);

  const t = copy[lang];
  const theme = useThemeController();
  const routing = useToolRouting(isNarrowShell, setSidebarCollapsed);
  const mounting = useToolMounting(routing.activeTool, routing.setActiveTool);
  const report = useCaseReport(routing.activeTool, lang, t, setReporterOpen, setToolLinkMessage);

  const active = tools.find((tool) => tool.id === routing.activeTool) ?? tools[0];
  const toolTitle = React.useCallback((tool: ToolDefinition) => getToolTitle(tool, lang), [lang]);

  const modalOpenGuardRef = React.useRef({ settings: 0, command: 0 });

  const openSettingsPanel = React.useCallback(() => {
    modalOpenGuardRef.current.settings = performance.now();
    setSettingsOpen(true);
  }, []);

  const openCommandPalette = React.useCallback(() => {
    modalOpenGuardRef.current.command = performance.now();
    setCommandOpen(true);
  }, []);

  const shouldIgnoreBackdropClick = React.useCallback(
    (modal: "settings" | "command") => performance.now() - modalOpenGuardRef.current[modal] < 220,
    []
  );

  const clearLocalWorkspace = React.useCallback(() => {
    if (!cacheClearArmed) {
      setCacheClearArmed(true);
      return;
    }
    void clearForensicsStorage()
      .then(() => {
        window.location.hash = "#home";
        window.location.reload();
      })
      .catch(() => {
        setCacheClearArmed(false);
        setCacheClearError(true);
      });
  }, [cacheClearArmed]);

  const copyCurrentToolLink = React.useCallback(() => {
    const url = `${window.location.origin}${window.location.pathname}${window.location.search}#${routing.activeTool}`;
    void copyText(url, { feedback: false }).then((copied) => setToolLinkMessage(copied ? t.toolLinkCopied : url));
  }, [routing.activeTool, t]);

  const { filteredCommands } = useCommandPalette({
    t,
    lang,
    activeTool: routing.activeTool,
    caseNotesCount: report.caseNotes.length,
    detailsExpanded,
    sidebarCollapsed,
    setActiveTool: routing.setActiveTool,
    openSettingsPanel,
    setReporterOpen,
    setSidebarCollapsed,
    setDetailsExpanded,
    setThemeMode: theme.setThemeMode,
    clearWorkspace: clearLocalWorkspace,
    commandQuery
  });

  useGlobalShortcuts({
    activeTool: routing.activeTool,
    commandOpen,
    settingsOpen,
    openCommandPalette,
    setSidebarCollapsed,
    setDetailsExpanded,
    setCommandOpen,
    setSettingsOpen
  });

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
    if (!routing.activeTool) return;
    setDetailsExpanded(false);
  }, [routing.activeTool]);

  React.useEffect(() => {
    const media = window.matchMedia("(max-width: 900px)");
    const handleChange = () => {
      setIsNarrowShell(media.matches);
      if (media.matches) setSidebarCollapsed(true);
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => media.removeEventListener("change", handleChange);
  }, [setSidebarCollapsed]);

  React.useEffect(() => {
    if (!toolLinkMessage) return undefined;
    const timer = window.setTimeout(() => setToolLinkMessage(""), 2200);
    return () => window.clearTimeout(timer);
  }, [toolLinkMessage]);

  React.useEffect(() => {
    if (window.isSecureContext && "serviceWorker" in navigator) {
      navigator.serviceWorker.register(new URL("../sw.js", document.baseURI).href).catch(() => undefined);
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

  React.useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title =
      routing.activeTool === "home"
        ? "Forensics++ Workbench | Open-source DFIR tools"
        : `${getToolTitle(active, lang)} - Forensics++`;
  }, [active, active.name, routing.activeTool, lang, t]);

  return {
    t,
    lang,
    setLang,
    active,
    activeTool: routing.activeTool,
    setActiveTool: routing.setActiveTool,
    toolTitle,
    query: routing.query,
    setQuery: routing.setQuery,
    sidebarCollapsed,
    setSidebarCollapsed,
    isNarrowShell,
    detailsExpanded,
    setDetailsExpanded,
    themeMode: theme.themeMode,
    setThemeMode: theme.setThemeMode,
    themeColor: theme.themeColor,
    displayThemeColor: theme.displayThemeColor,
    appliedTheme: theme.appliedTheme,
    applyThemeColor: theme.applyThemeColor,
    resetThemeAppearance: theme.resetThemeAppearance,
    toolLinkMessage,
    copyCurrentToolLink,
    reportAddBusy: report.reportAddBusy,
    addCurrentToolToReport: report.addCurrentToolToReport,
    openSettingsPanel,
    openCommandPalette,
    settingsOpen,
    setSettingsOpen,
    cacheClearArmed,
    cacheClearError,
    clearLocalWorkspace,
    commandOpen,
    setCommandOpen,
    commandQuery,
    setCommandQuery,
    filteredCommands,
    pendingToolClose: mounting.pendingToolClose,
    setPendingToolClose: mounting.setPendingToolClose,
    closeToolsNow: mounting.closeToolsNow,
    closeMountedTool: mounting.closeMountedTool,
    closeAllMountedTools: mounting.closeAllMountedTools,
    caseNotes: report.caseNotes,
    caseReportMeta: report.caseReportMeta,
    setCaseReportMeta: report.setCaseReportMeta,
    updateCaseNote: report.updateCaseNote,
    deleteCaseNote: report.deleteCaseNote,
    clearCaseNotes: report.clearCaseNotes,
    importReport: report.importReport,
    onReporterClose: report.onReporterClose,
    reporterOpen,
    setReporterOpen,
    retainedTools: mounting.retainedTools,
    setToolDirty: mounting.setToolDirty,
    recentTools: routing.recentTools,
    favoriteNavTools: routing.favoriteNavTools,
    groupedTools: routing.groupedTools,
    legalOpen: acceptedLegalVersion !== legalVersion,
    onAcceptLegal: () => setAcceptedLegalVersion(legalVersion),
    shouldIgnoreBackdropClick
  };
}

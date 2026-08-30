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
import { Topbar } from "./components/Topbar";
import { LegalConsentModal } from "./components/LegalConsentModal";
import { getToolTitle as resolveToolTitle, legalVersion, toolTitleOverrides, tools, visibleTools, appVersion, appReleaseDate, releaseDownloadUrl } from "./config/app";
import { copy } from "./i18n";
import { clearForensicsStorage, clearLegacyEvidenceStorage, useStoredState } from "./utils/storage";
import { compactReportText, defaultCaseReportMeta, isBooleanValue, isCaseNotesValue, isCaseReportMetaValue, isLangValue, isStringValue, isToolIdArrayValue, isToolIdValue } from "./utils/appGuards";
import type { AppCommand, CaseNote, CaseReportMeta, Lang } from "./models";
import { fingerprintEvidenceFiles, rememberedEvidenceFiles, rememberEvidenceFiles } from "./features/reporter/evidence";
import { rememberedTimelineEvents } from "./features/reporter/timeline";
import { currentAnalysisResult, subscribeAnalysisResult } from "./features/analysis/resultStore";
import { analysisResultText, envelopeReportMarkdown } from "./features/analysis/result";
import { useStaleVersion } from "./app/useStaleVersion";
import { useAppearance } from "./app/useAppearance";
import { useShellLayout } from "./app/useShellLayout";
import { useToolNavigation } from "./app/useToolNavigation";
import { useServiceWorker } from "./app/useServiceWorker";
import { useLegalConsent } from "./app/useLegalConsent";
import { useCacheClear } from "./app/useCacheClear";

const SettingsModal = React.lazy(() => import("./components/SettingsModal").then((module) => ({ default: module.SettingsModal })));
const CaseReporter = React.lazy(() => import("./features/reporter/CaseReporter").then((module) => ({ default: module.CaseReporter })));

function getToolTitle(tool: (typeof tools)[number], lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}



export function App() {
  const [lang, setLang] = useStoredState<Lang>("app.lang", "zh", isLangValue);
  const { query, setQuery, sidebarCollapsed, setSidebarCollapsed, isNarrowShell, detailsExpanded, setDetailsExpanded } = useShellLayout();
  const { activeTool, active, toolTitle, recentTools, retainedTools, pendingToolClose, setPendingToolClose, setActiveTool, setToolDirty, closeMountedTool, closeAllMountedTools, closeToolsNow, toggleFavoriteTool, activeIsFavorite, favoriteNavTools, groupedTools } = useToolNavigation({ isNarrowShell, setSidebarCollapsed, query, lang });
  const { themeMode, setThemeMode, resolvedThemeColor, appliedTheme, displayThemeColor, applyThemeColor, resetThemeAppearance } = useAppearance();
  const { acceptedLegalVersion, setAcceptedLegalVersion } = useLegalConsent();
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const { cacheClearArmed, cacheClearError, setCacheClearError, clearLocalWorkspace } = useCacheClear(settingsOpen);
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState("");
  const [reporterOpen, setReporterOpen] = React.useState(false);
  const [reportAddBusy, setReportAddBusy] = React.useState(false);
  const reportAddAbortRef = React.useRef<AbortController | null>(null);
  const [caseNotes, setCaseNotes] = useStoredState<CaseNote[]>("report.notes", [], isCaseNotesValue);
  const [caseReportMeta, setCaseReportMeta] = useStoredState<CaseReportMeta>("report.meta", defaultCaseReportMeta(), isCaseReportMetaValue);
  const [defaultExportFormat, setDefaultExportFormat] = useStoredState("app.defaultExportFormat", "md", isStringValue);
  const [autoSaveEvidence, setAutoSaveEvidence] = useStoredState("app.autoSaveEvidence", false, isBooleanValue);
  const capturedRunIds = React.useRef<Set<string>>(new Set());
  React.useEffect(() => () => {
    reportAddAbortRef.current?.abort();
  }, []);

  const modalOpenGuardRef = React.useRef({ settings: 0, command: 0 });
  const [toolLinkMessage, setToolLinkMessage] = React.useState("");
  const t = copy[lang];
  const { showStaleBanner, dismissStaleBanner } = useStaleVersion();

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
  const addCurrentToolToReport = async () => {
    if (reportAddBusy) return;
    if (activeTool === "home") {
      setReporterOpen(true);
      return;
    }
    const toolView = Array.from(document.querySelectorAll<HTMLElement>(".tool-retained-view"))
      .find((element) => element.dataset.toolId === activeTool);
    const structuredResult = currentAnalysisResult(activeTool);
    if (structuredResult?.run.runId) capturedRunIds.current.add(structuredResult.run.runId);
    const structuredContent = structuredResult ? compactReportText(analysisResultText(structuredResult)) : "";
    const domContent = compactReportText(toolView?.innerText || toolView?.textContent || "");
    const content = structuredContent || domContent;
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
    if (!content || (!structuredResult && !hasFilledControl && !hasLoadedFile && !hasRenderedOutput)) {
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
      const fingerprintedFiles = await fingerprintEvidenceFiles([
        ...selectedFiles,
        ...(toolView ? rememberedEvidenceFiles(toolView) : [])
      ], { signal: controller.signal });
      if (controller.signal.aborted) return;
      const evidenceFiles = Array.from(new Map([
        ...(structuredResult?.source ?? []).map((file) => [`${file.name}:${file.size}`, {
          name: file.name,
          size: file.size,
          type: file.type,
          ...(file.lastModified ? { lastModified: file.lastModified } : {}),
          ...(file.sha256 ? { sha256: file.sha256 } : {})
        }] as const),
        ...fingerprintedFiles.map((file) => [`${file.name}:${file.size}`, file] as const)
      ]).values());
      const timelineEvents = structuredResult?.timeline.length
        ? structuredResult.timeline
        : toolView ? rememberedTimelineEvents(toolView) : [];
      const createdAt = new Date().toISOString();
      const note: CaseNote = {
        id: `${activeTool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        tool: getToolTitle(active, lang),
        title: structuredResult?.summary.title || `${getToolTitle(active, lang)} · ${createdAt.slice(0, 10)}`,
        content,
        summary: structuredResult?.summary.text || content.replace(/\s+/g, " ").slice(0, 420),
        markdown: structuredResult
          ? envelopeReportMarkdown(structuredResult, t)
          : ["```text", content, "```"].join("\n"),
        description: t[active.desc],
        route: `#${activeTool}`,
        sourceUrl: window.location.href,
        ...(evidenceFiles.length ? { evidenceFiles } : {}),
        ...(timelineEvents.length ? { timelineEvents } : {}),
        ...(structuredResult?.findings.length ? { findings: structuredResult.findings } : {}),
        ...(structuredResult?.indicators.length ? { indicators: structuredResult.indicators } : {}),
        ...(structuredResult?.artifacts.length ? { artifacts: structuredResult.artifacts } : {}),
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
  React.useEffect(() => {
    if (!autoSaveEvidence) return;
    const unsubscribe = subscribeAnalysisResult("*", () => {
      const result = currentAnalysisResult(activeTool);
      const runId = result?.run.runId;
      if (!result || !runId || capturedRunIds.current.has(runId)) return;
      capturedRunIds.current.add(runId);
      const createdAt = new Date().toISOString();
      const note: CaseNote = {
        id: `${activeTool}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        tool: getToolTitle(active, lang),
        title: result.summary.title,
        content: analysisResultText(result, t),
        summary: result.summary.text,
        markdown: envelopeReportMarkdown(result, t),
        description: active ? t[active.desc] : "",
        route: `#${activeTool}`,
        sourceUrl: window.location.href,
        ...(result.source.length ? {
          evidenceFiles: result.source.map((file) => ({
            name: file.name,
            size: file.size,
            type: file.type,
            ...(file.lastModified ? { lastModified: file.lastModified } : {}),
            ...(file.sha256 ? { sha256: file.sha256 } : {})
          }))
        } : {}),
        ...(result.timeline.length ? { timelineEvents: result.timeline } : {}),
        ...(result.findings.length ? { findings: result.findings } : {}),
        ...(result.indicators.length ? { indicators: result.indicators } : {}),
        ...(result.artifacts.length ? { artifacts: result.artifacts } : {}),
        createdAt
      };
      setCaseNotes((current) => [note, ...current].slice(0, 40));
    });
    return unsubscribe;
  }, [autoSaveEvidence, activeTool, lang, t, active, setCaseNotes]);
  const detailsToggleLabel = detailsExpanded ? (lang === "zh" ? "精简" : "Compact") : (lang === "zh" ? "详情" : "Details");
  React.useEffect(() => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = activeTool === "home" ? "Forensics++ Workbench | Open-source DFIR tools" : `${getToolTitle(active, lang)} - Forensics++`;
  }, [active.name, activeTool, lang, t]);

  React.useEffect(() => {
    setDetailsExpanded(false);
  }, [activeTool]);

  React.useEffect(() => {
    if (!toolLinkMessage) return undefined;
    const timer = window.setTimeout(() => setToolLinkMessage(""), 2200);
    return () => window.clearTimeout(timer);
  }, [toolLinkMessage]);

  useServiceWorker();

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
        <div className="app-top-region">
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

        {showStaleBanner && (
          <div
            className="app-stale-banner"
            role="alert"
          >
            <span className="app-stale-banner__icon" aria-hidden="true">⚠</span>
            <span className="app-stale-banner__text">
              <strong>{t.staleVersionTitle}</strong>{" "}
              {t.staleVersionBody.replace("{version}", appVersion).replace("{date}", appReleaseDate)}{" "}
              <a href={releaseDownloadUrl} target="_blank" rel="noreferrer" onClick={dismissStaleBanner}>
                {t.staleVersionDownload}
              </a>
            </span>
            <button
              type="button"
              className="app-stale-banner__close"
              aria-label={t.dismissNotice}
              onClick={dismissStaleBanner}
            >
              ×
            </button>
          </div>
        )}

        </div>

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
            defaultExportFormat={defaultExportFormat}
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
            defaultExportFormat={defaultExportFormat}
            onDefaultExportFormatChange={setDefaultExportFormat}
            autoSaveEvidence={autoSaveEvidence}
            onAutoSaveEvidenceChange={setAutoSaveEvidence}
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

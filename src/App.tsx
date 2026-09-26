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

import { copyText } from "./utils/clipboard";
import React from "react";
import { setUiLang } from "./uiLang";
import { ConfigProvider, Modal, theme as antdTheme } from "antd";
import { CommandPalette } from "./components/CommandPalette";
import { EvidenceInbox } from "./components/EvidenceInbox";
import { ToolHost } from "./components/ToolHost";
import { FirstRunGuide } from "./components/FirstRunGuide";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { LegalConsentModal } from "./components/LegalConsentModal";
import { getToolTitle as resolveToolTitle, legalVersion, tools, appVersion, appReleaseDate, releaseDownloadUrl, buildHash, buildBranch } from "./config/app";
import { copy } from "./i18n";
import { useStoredState } from "./utils/storage";
import { isLangValue } from "./utils/appGuards";
import type { Lang } from "./models";
import { useStaleVersion } from "./app/useStaleVersion";
import { useAppearance } from "./app/useAppearance";
import { useShellLayout } from "./app/useShellLayout";
import { useToolNavigation } from "./app/useToolNavigation";
import { useServiceWorker } from "./app/useServiceWorker";
import { useLegalConsent } from "./app/useLegalConsent";
import { useCacheClear } from "./app/useCacheClear";
import { useCaseReport } from "./app/useCaseReport";
import { useCommandPalette } from "./app/useCommandPalette";
import { useWorkbenchBootstrap } from "./app/useWorkbenchBootstrap";
import { useFirstRun } from "./app/useFirstRun";
import { toolToShareUrl, isPreview } from "./core/routeAdapter";
import { NotFound } from "./components/NotFound";

const SettingsModal = React.lazy(() => import("./components/SettingsModal").then((module) => ({ default: module.SettingsModal })));
const CaseReporter = React.lazy(() => import("./features/reporter/CaseReporter").then((module) => ({ default: module.CaseReporter })));

function getToolTitle(tool: (typeof tools)[number], lang: Lang) {
  return resolveToolTitle(tool, lang, copy[lang]);
}



export function App() {
  const [lang, setLang] = useStoredState<Lang>("app.lang", "zh", isLangValue);
  const { query, setQuery, sidebarCollapsed, setSidebarCollapsed, isNarrowShell, detailsExpanded, setDetailsExpanded } = useShellLayout();
  const { activeTool, active, routeUnknown, toolTitle, recentTools, retainedTools, pendingToolClose, setPendingToolClose, setActiveTool, setToolDirty, closeMountedTool, closeAllMountedTools, closeToolsNow, toggleFavoriteTool, activeIsFavorite, favoriteNavTools, groupedTools } = useToolNavigation({ isNarrowShell, setSidebarCollapsed, query, lang });
  const { themeMode, setThemeMode, resolvedThemeColor, appliedTheme, displayThemeColor, applyThemeColor, resetThemeAppearance } = useAppearance();
  const { acceptedLegalVersion, setAcceptedLegalVersion } = useLegalConsent();
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const { cacheClearArmed, cacheClearError, setCacheClearError, clearLocalWorkspace } = useCacheClear(settingsOpen);
  const [reporterOpen, setReporterOpen] = React.useState(false);
  const [toolLinkMessage, setToolLinkMessage] = React.useState("");
  const [evidenceInboxOpen, setEvidenceInboxOpen] = React.useState(false);
  const { reportAddBusy, reportAddAbortRef, setReportAddBusy, caseNotes, setCaseNotes, caseReportMeta, setCaseReportMeta, defaultExportFormat, setDefaultExportFormat, autoSaveEvidence, setAutoSaveEvidence, addCurrentToolToReport, updateCaseNote, deleteCaseNote, clearCaseNotes } = useCaseReport({ activeTool, active, lang, setReporterOpen, setToolLinkMessage });
  const { firstRunOpen, dismissFirstRun, reopenFirstRun } = useFirstRun();
  const { commandOpen, setCommandOpen, commandQuery, setCommandQuery, openSettingsPanel, openCommandPalette, shouldIgnoreBackdropClick, filteredCommands } = useCommandPalette({ activeTool, lang, sidebarCollapsed, setSidebarCollapsed, detailsExpanded, setDetailsExpanded, caseNotesCount: caseNotes.length, setActiveTool, setReporterOpen, setThemeMode, setCacheClearError, settingsOpen, setSettingsOpen, reopenFirstRun });

  const t = copy[lang];
  React.useEffect(() => { setUiLang(lang); }, [lang]);
  const { showStaleBanner, dismissStaleBanner } = useStaleVersion();

  useWorkbenchBootstrap({
    active,
    activeTool,
    lang,
    detailsExpanded,
    setDetailsExpanded,
    toolLinkMessage,
    setToolLinkMessage,
  });
  useServiceWorker();

  const copyCurrentToolLink = () => {
    const url = toolToShareUrl(activeTool, window.location.origin);
    void copyText(url, { feedback: false }).then((copied) => setToolLinkMessage(copied ? t.toolLinkCopied : url));
  };

  // Preview policy + shareable locale link support.
  React.useEffect(() => {
    if (isPreview()) {
      // Belt-and-suspenders: make sure crawlers never index the preview.
      const existing = document.querySelector('meta[name="robots"]') as HTMLMetaElement | null;
      const content = "noindex,nofollow,noarchive";
      if (existing) existing.content = content;
      else {
        const m = document.createElement("meta");
        m.name = "robots";
        m.content = content;
        document.head.appendChild(m);
      }
    }
    const langParam = new URLSearchParams(window.location.search).get("lang");
    if (langParam === "zh" || langParam === "en") setLang(langParam);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
        aria-hidden={sidebarCollapsed ? true : undefined}
        inert={sidebarCollapsed ? true : undefined}
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
      {isNarrowShell && !sidebarCollapsed && (
        <button
          className="sidebar-scrim"
          type="button"
          aria-label={t.collapseSidebar}
          onClick={() => setSidebarCollapsed(true)}
        />
      )}

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
          onOpenEvidenceInbox={() => setEvidenceInboxOpen(true)}
          onSetLang={setLang}
        />

        {isPreview() && (
          <div
            className="app-stale-banner app-preview-banner"
            role="status"
            aria-label={t.previewBadgeTitle.replace("{version}", appVersion).replace("{hash}", buildHash).replace("{branch}", buildBranch)}
          >
            <span className="app-stale-banner__icon" aria-hidden="true">⚠</span>
            <span className="app-stale-banner__text">
              <strong>{t.previewBadge}</strong>{" "}
              {t.previewBadgeTitle
                .replace("{version}", appVersion)
                .replace("{hash}", buildHash)
                .replace("{branch}", buildBranch)}{" "}
              <a href={releaseDownloadUrl} target="_blank" rel="noreferrer">{t.previewBannerLink}</a>
            </span>
          </div>
        )}

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
          {routeUnknown ? (
            <NotFound onGoHome={() => setActiveTool("home")} t={t} lang={lang} />
          ) : (
            retainedTools.map((mountedTool) => (
              <ToolHost key={mountedTool} toolId={mountedTool} active={mountedTool === activeTool} t={t} lang={lang} recentTools={recentTools} setActiveTool={setActiveTool} setToolDirty={setToolDirty} />
            ))
          )}
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
            onShowGuide={reopenFirstRun}
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

      <EvidenceInbox
        open={evidenceInboxOpen}
        onClose={() => setEvidenceInboxOpen(false)}
        t={t}
        lang={lang}
        onOpenTool={(toolId) => setActiveTool(toolId)}
      />

      <FirstRunGuide
        open={firstRunOpen && acceptedLegalVersion === legalVersion}
        lang={lang}
        t={t}
        onClose={dismissFirstRun}
      />
    </div>
    </ConfigProvider>
  );
}

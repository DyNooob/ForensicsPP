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
import { ConfigProvider, Modal, theme as antdTheme } from "antd";
import { CommandPalette } from "../components/CommandPalette";
import { ToolHost } from "../components/ToolHost";
import { Sidebar } from "../components/Sidebar";
import { Topbar } from "../components/Topbar";
import { LegalConsentModal } from "../components/LegalConsentModal";
import { tools } from "../config/app";
import { getToolTitle } from "./toolTitle";
import { useWorkbench } from "./WorkbenchProvider";

const SettingsModal = React.lazy(() => import("../components/SettingsModal").then((module) => ({ default: module.SettingsModal })));
const CaseReporter = React.lazy(() => import("../features/reporter/CaseReporter").then((module) => ({ default: module.CaseReporter })));

export function WorkbenchShell() {
  const wb = useWorkbench();
  const {
    t,
    lang,
    active,
    activeTool,
    toolTitle,
    query,
    setQuery,
    sidebarCollapsed,
    setSidebarCollapsed,
    isNarrowShell,
    detailsExpanded,
    appliedTheme,
    displayThemeColor,
    toolLinkMessage,
    copyCurrentToolLink,
    reportAddBusy,
    addCurrentToolToReport,
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
    pendingToolClose,
    setPendingToolClose,
    closeToolsNow,
    closeMountedTool,
    closeAllMountedTools,
    caseNotes,
    caseReportMeta,
    setCaseReportMeta,
    updateCaseNote,
    deleteCaseNote,
    clearCaseNotes,
    importReport,
    onReporterClose,
    reporterOpen,
    retainedTools,
    setToolDirty,
    recentTools,
    favoriteNavTools,
    groupedTools,
    legalOpen,
    onAcceptLegal,
    shouldIgnoreBackdropClick
  } = wb;

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
          fontFamily:
            "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans SC', sans-serif",
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
          settingsOpen || commandOpen || legalOpen ? "overlay-open" : "",
          sidebarCollapsed ? "sidebar-collapsed" : "",
          isNarrowShell ? "shell-narrow" : ""
        ]
          .filter(Boolean)
          .join(" ")}
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
            onSelectTool={(id) => wb.setActiveTool(id)}
            onOpenCommandPalette={openCommandPalette}
            onOpenSettings={openSettingsPanel}
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
            onOpenSettings={openSettingsPanel}
            onOpenCommandPalette={openCommandPalette}
            onSetLang={wb.setLang}
          />

          <section className={detailsExpanded || activeTool === "home" ? "tool-body" : "tool-body compact-results"}>
            {retainedTools.map((mountedTool) => (
              <ToolHost
                key={mountedTool}
                toolId={mountedTool}
                active={mountedTool === activeTool}
                t={t}
                lang={lang}
                recentTools={recentTools}
                setActiveTool={wb.setActiveTool}
                setToolDirty={setToolDirty}
              />
            ))}
          </section>
        </main>

        <LegalConsentModal t={t} open={legalOpen} onAccept={onAcceptLegal} />

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
          <p>
            {lang === "zh"
              ? "SQLite 中的修改只保存在当前标签页。关闭后将无法恢复。"
              : "SQLite changes exist only in this tab and cannot be recovered after closing."}
          </p>
        </Modal>

        {reporterOpen && (
          <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite">{t.loadingTool}</div>}>
            <CaseReporter
              notes={caseNotes}
              meta={caseReportMeta}
              t={t}
              onClose={onReporterClose}
              onMetaChange={setCaseReportMeta}
              onUpdateNote={updateCaseNote}
              onDeleteNote={deleteCaseNote}
              onClear={clearCaseNotes}
              onImport={importReport}
            />
          </React.Suspense>
        )}

        {settingsOpen && (
          <React.Suspense fallback={<div className="tool-loading-state" role="status" aria-live="polite">{t.loadingTool}</div>}>
            <SettingsModal
              open
              lang={lang}
              t={t}
              themeMode={wb.themeMode}
              themeColor={wb.themeColor}
              cacheClearArmed={cacheClearArmed}
              cacheClearError={cacheClearError}
              onClose={() => setSettingsOpen(false)}
              onThemeModeChange={wb.setThemeMode}
              onThemeColorChange={wb.applyThemeColor}
              onResetAppearance={wb.resetThemeAppearance}
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

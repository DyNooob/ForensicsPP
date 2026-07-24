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

import { CodeOutlined, FileAddOutlined, LinkOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SettingOutlined } from "@ant-design/icons";
import { ASegmentedButton, ASegmentedGroup } from "./ui";
import { GithubIconButton } from "./GithubIconButton";
import type { ToolDefinition } from "../config/app";
import type { Translation } from "../i18n";
import type { Lang } from "../models";

type TopbarProps = {
  t: Translation;
  lang: Lang;
  active: ToolDefinition;
  activeTool: string;
  toolTitle: (tool: ToolDefinition) => string;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  toolLinkMessage: string;
  onCopyLink: () => void;
  reportAddBusy: boolean;
  caseNotesCount: number;
  onAddToReport: () => void;
  onOpenSettings: () => void;
  onOpenCommandPalette: () => void;
  onSetLang: (lang: Lang) => void;
};

export function Topbar({
  t,
  lang,
  active,
  activeTool,
  toolTitle,
  collapsed,
  onToggleCollapsed,
  toolLinkMessage,
  onCopyLink,
  reportAddBusy,
  caseNotesCount,
  onAddToReport,
  onOpenSettings,
  onOpenCommandPalette,
  onSetLang
}: TopbarProps) {
  return (
    <header className={`tool-topbar ${activeTool === "home" ? "home-topbar" : ""}`}>
      <div className="tool-topbar-frame">
        <button
          className="top-action-icon top-menu-toggle"
          type="button"
          aria-label={collapsed ? t.expandSidebar : t.collapseSidebar}
          title={collapsed ? t.expandSidebar : t.collapseSidebar}
          onClick={onToggleCollapsed}
        >
          {collapsed ? <MenuUnfoldOutlined aria-hidden="true" /> : <MenuFoldOutlined aria-hidden="true" />}
        </button>
        <div className="tool-title-block">
          <span className="tool-kicker">{t[active.category]}</span>
          <strong className="page-title">{toolTitle(active)}</strong>
          <span className="tool-subtitle">{t[active.desc]}</span>
          {toolLinkMessage && <span className="tool-link-feedback">{toolLinkMessage}</span>}
        </div>
        <div className="top-actions">
          <div className="top-action-group">
            <GithubIconButton label={t.repositoryLabel} />
            {activeTool !== "home" && (
              <button
                className="top-action-icon link-toggle"
                type="button"
                aria-label={t.copyToolLink}
                title={t.copyToolLink}
                onClick={onCopyLink}
              >
                <LinkOutlined aria-hidden="true" />
              </button>
            )}
            {activeTool !== "home" && (
              <button
                className="top-action-icon report-add-toggle"
                type="button"
                aria-label={t.addToReport}
                title={reportAddBusy ? t.reportHashingSource : `${t.addToReport}${caseNotesCount ? ` · ${caseNotesCount}` : ""}`}
                aria-busy={reportAddBusy}
                disabled={reportAddBusy}
                onClick={onAddToReport}
              >
                <FileAddOutlined aria-hidden="true" />
              </button>
            )}
            <button
              className="top-action-icon settings-toggle"
              type="button"
              aria-label={t.settings}
              title={t.settings}
              onClick={onOpenSettings}
            >
              <SettingOutlined aria-hidden="true" />
            </button>
            <button
              className="top-action-icon command-toggle"
              type="button"
              aria-label={t.openCommandPalette}
              title={t.openCommandPalette}
              onClick={onOpenCommandPalette}
            >
              <CodeOutlined aria-hidden="true" />
            </button>
          </div>
          <ASegmentedGroup className="language-switch" value={lang} selects="single" aria-label={t.language}>
            <ASegmentedButton value="zh" onClick={() => onSetLang("zh")}>
              中文
            </ASegmentedButton>
            <ASegmentedButton value="en" onClick={() => onSetLang("en")}>
              EN
            </ASegmentedButton>
          </ASegmentedGroup>
        </div>
      </div>
    </header>
  );
}

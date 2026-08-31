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
import { Badge, Drawer } from "antd";
import { CodeOutlined, FileAddOutlined, InboxOutlined, LinkOutlined, MenuFoldOutlined, MenuUnfoldOutlined, QuestionCircleOutlined, SettingOutlined } from "@ant-design/icons";
import { ASegmentedButton, ASegmentedGroup } from "./ui";
import { GithubIconButton } from "./GithubIconButton";
import { useEvidenceInbox } from "../app/useEvidenceInbox";
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
  onOpenEvidenceInbox: () => void;
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
  onOpenEvidenceInbox,
  onSetLang
}: TopbarProps) {
  const [helpOpen, setHelpOpen] = React.useState(false);
  const { count: evidenceCount } = useEvidenceInbox();
  return (
    <>
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
            <button
              className="top-action-icon evidence-toggle"
              type="button"
              aria-label={t.evidenceInbox}
              title={`${t.evidenceInbox}${evidenceCount ? ` · ${evidenceCount}` : ""}`}
              onClick={onOpenEvidenceInbox}
            >
              <Badge count={evidenceCount} size="small" offset={[-2, 2]}>
                <InboxOutlined aria-hidden="true" />
              </Badge>
            </button>
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
            {activeTool !== "home" && active.help && (
              <button
                className="top-action-icon help-toggle"
                type="button"
                aria-label={t.toolHelp}
                title={t.toolHelp}
                onClick={() => setHelpOpen(true)}
              >
                <QuestionCircleOutlined aria-hidden="true" />
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
    <Drawer
      title={toolTitle(active)}
      open={helpOpen}
      onClose={() => setHelpOpen(false)}
      width={420}
      styles={{ body: { whiteSpace: "pre-wrap", lineHeight: 1.7 } }}
    >
      {active.featured && (
        <div className="help-meta">
          <span className="help-meta-label">{t.featured}</span>
          <span className="maturity-chip maturity-featured">★</span>
        </div>
      )}
      {active.maturity && (
        <div className="help-meta">
          <span className="help-meta-label">{t.maturityLabel}</span>
          <span className={`maturity-chip maturity-${active.maturity}`}>
            {active.maturity === "stable" ? t.maturityStable : active.maturity === "triage" ? t.maturityTriage : t.maturityExperimental}
          </span>
        </div>
      )}
      {active.validation && (
        <div className="help-meta">
          <span className="help-meta-label">{t.validationLabel}</span>
          <span className={`validation-chip validation-${active.validation}`}>
            {active.validation === "unvalidated" ? t.validationUnvalidated
              : active.validation === "unit-tested" ? t.validationUnitTested
              : active.validation === "fixture-validated" ? t.validationFixtureValidated
              : t.validationCrossValidated}
          </span>
        </div>
      )}
      {active.help?.[lang]}
    </Drawer>
    </>
  );
}

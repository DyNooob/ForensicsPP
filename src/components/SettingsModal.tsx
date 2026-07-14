/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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
  BgColorsOutlined,
  CodeOutlined,
  CloseOutlined,
  DatabaseOutlined,
  DesktopOutlined,
  GithubOutlined,
  InfoCircleOutlined,
  LinkOutlined,
  MailOutlined,
  MoonOutlined,
  ReloadOutlined,
  SunOutlined
} from "@ant-design/icons";
import { Button, ColorPicker, Menu, Modal, Segmented, Typography } from "antd";
import type { ThemeMode } from "../models";
import type { ToolId } from "../config/app";
import {
  appVersion,
  feedbackEmail,
  lastUpdated,
  projectLicense,
  projectLinks,
  projectRepoName,
  themePresets
} from "../config/app";
import { openSourceProjects } from "../config/openSource";

type SettingsPage = "appearance" | "project" | "storage" | "opensource";

type SettingsModalProps = {
  open: boolean;
  lang: "zh" | "en";
  t: Record<string, string>;
  themeMode: ThemeMode;
  themeColor: string;
  cacheClearArmed: boolean;
  onClose: () => void;
  onThemeModeChange: (mode: ThemeMode) => void;
  onThemeColorChange: (color: string) => void;
  onResetAppearance: () => void;
  onClearWorkspace: () => void;
  openTools: Array<{ id: ToolId; title: string; active: boolean }>;
  onCloseTool: (id: ToolId) => void;
  onCloseAllTools: () => void;
};

function formatStorageMb(bytes: number) {
  return `${(Math.max(0, bytes) / 1024 / 1024).toFixed(2)} MB`;
}

function localStorageBytes() {
  try {
    return Object.keys(window.localStorage).reduce((total, key) => {
      const value = window.localStorage.getItem(key) ?? "";
      return total + (key.length + value.length) * 2;
    }, 0);
  } catch {
    return 0;
  }
}

export function SettingsModal({
  open,
  lang,
  t,
  themeMode,
  themeColor,
  cacheClearArmed,
  onClose,
  onThemeModeChange,
  onThemeColorChange,
  onResetAppearance,
  onClearWorkspace,
  openTools,
  onCloseTool,
  onCloseAllTools
}: SettingsModalProps) {
  const [page, setPage] = React.useState<SettingsPage>("appearance");
  const [storage, setStorage] = React.useState({ local: 0, usage: 0, quota: 0 });

  React.useEffect(() => {
    if (!open || page !== "storage") return;
    let active = true;
    void (async () => {
      const local = localStorageBytes();
      const estimate = await navigator.storage?.estimate?.().catch(() => null);
      if (active) setStorage({ local, usage: Math.max(local, estimate?.usage ?? 0), quota: estimate?.quota ?? 0 });
    })();
    return () => { active = false; };
  }, [open, page]);

  const labels = lang === "zh" ? {
    appearance: "外观",
    appearanceDesc: "调整界面主题与强调色。",
    project: "关于项目",
    storage: "本地数据",
    openSource: "开源项目",
    themeMode: "主题模式",
    themeColor: "强调色",
    system: "跟随系统",
    reset: "恢复默认",
    clearTitle: "清除本地工作区",
    clearDesc: "删除界面设置和已保存的本地工作区。",
    siteUsage: "本站占用",
    localStorageUsage: "localStorage",
    availableQuota: "浏览器配额",
    persistentTitle: "浏览器存储",
    persistentDesc: "这里显示可跨刷新保留的界面数据和工作区。",
    sessionTitle: "当前会话",
    sessionDesc: "关闭工具会释放内存；支持恢复的工作区仍保存在浏览器。",
    closeTool: "关闭工具",
    closeAll: "全部关闭",
    noOpenTools: "当前没有打开的工具",
    activeTool: "正在使用",
    moreOpenTools: "个其他工具已打开",
    relatedLinks: "相关链接",
    projectAccess: "项目入口",
    contact: "联系",
    friendLinks: "友情链接",
    dependenciesTitle: "开源项目",
    dependenciesDesc: `Forensics++ 使用了以下 ${openSourceProjects.length} 个开源项目。`,
    openRepo: "打开仓库"
  } : {
    appearance: "Appearance",
    appearanceDesc: "Adjust the interface theme and accent color.",
    project: "About",
    storage: "Local Data",
    openSource: "Open Source",
    themeMode: "Theme mode",
    themeColor: "Accent color",
    system: "System",
    reset: "Reset",
    clearTitle: "Clear local workspace",
    clearDesc: "Remove interface settings and saved local workspaces.",
    siteUsage: "Site usage",
    localStorageUsage: "localStorage",
    availableQuota: "Browser quota",
    persistentTitle: "Browser storage",
    persistentDesc: "Interface data and workspaces retained across reloads.",
    sessionTitle: "Current session",
    sessionDesc: "Closing a tool releases memory; restorable workspaces remain in browser storage.",
    closeTool: "Close tool",
    closeAll: "Close all",
    noOpenTools: "No tools are currently open",
    activeTool: "Active",
    moreOpenTools: "other tools open",
    relatedLinks: "Links",
    projectAccess: "Project",
    contact: "Contact",
    friendLinks: "Friends",
    dependenciesTitle: "Open-source projects",
    dependenciesDesc: `Forensics++ uses the following ${openSourceProjects.length} open-source projects.`,
    openRepo: "Open Repository"
  };

  const pageHeading = page === "appearance"
    ? [labels.appearance, labels.appearanceDesc]
    : page === "project"
      ? [t.aboutProject, ""]
      : page === "storage"
        ? [labels.storage, t.localCacheDesc]
        : [labels.dependenciesTitle, labels.dependenciesDesc];
  const activeOpenTool = openTools.find((tool) => tool.active);
  const visibleOpenTools = openTools.slice(0, 8);
  if (activeOpenTool && !visibleOpenTools.some((tool) => tool.id === activeOpenTool.id)) {
    visibleOpenTools[visibleOpenTools.length - 1] = activeOpenTool;
  }
  const hiddenOpenToolCount = openTools.length - visibleOpenTools.length;

  return (
    <Modal
      className={`settings-modal settings-page-${page}`}
      open={open}
      centered
      width={920}
      title={t.settings}
      footer={null}
      onCancel={onClose}
      destroyOnHidden
    >
      <div className="settings-shell">
        <aside className="settings-sidebar">
          <Menu
            mode="inline"
            selectedKeys={[page]}
            onClick={({ key }) => setPage(key as SettingsPage)}
            items={[
              { key: "appearance", icon: <BgColorsOutlined />, label: labels.appearance },
              { key: "project", icon: <InfoCircleOutlined />, label: labels.project },
              { key: "storage", icon: <DatabaseOutlined />, label: labels.storage },
              { key: "opensource", icon: <CodeOutlined />, label: labels.openSource }
            ]}
          />
          <div className="settings-sidebar-version">
            <span>Forensics++</span>
            <span>v{appVersion}</span>
          </div>
        </aside>

        <section className="settings-main">
          <header className="settings-heading">
            <Typography.Title level={4}>{pageHeading[0]}</Typography.Title>
            {pageHeading[1] && <Typography.Text type="secondary">{pageHeading[1]}</Typography.Text>}
          </header>

          {page === "appearance" && (
            <div className="settings-form">
              <div className="settings-appearance-preview" aria-hidden="true">
                <div className="settings-preview-sidebar"><span className="settings-preview-logo">F++</span><i /><i /><i /></div>
                <div className="settings-preview-main"><span /><div><b /><b /><b /></div><i /><i /></div>
              </div>
              <div className="settings-form-row">
                <div className="settings-form-label">{labels.themeMode}</div>
                <Segmented
                  block
                  value={themeMode}
                  onChange={(value) => onThemeModeChange(value as ThemeMode)}
                  options={[
                    { label: t.lightMode, value: "light", icon: <SunOutlined /> },
                    { label: t.darkMode, value: "dark", icon: <MoonOutlined /> },
                    { label: labels.system, value: "auto", icon: <DesktopOutlined /> }
                  ]}
                />
              </div>
              <div className="settings-form-row">
                <div className="settings-form-label">{labels.themeColor}</div>
                <div className="settings-color-row">
                  {themePresets.map((preset) => (
                    <button
                      className={`settings-color-swatch${themeColor.toLowerCase() === preset.hex.toLowerCase() ? " is-selected" : ""}`}
                      key={preset.id}
                      type="button"
                      aria-label={preset.name[lang]}
                      aria-pressed={themeColor.toLowerCase() === preset.hex.toLowerCase()}
                      title={preset.name[lang]}
                      style={{ "--settings-swatch": preset.hex } as React.CSSProperties}
                      onClick={() => onThemeColorChange(preset.hex)}
                    ><span className="settings-color-dot" /></button>
                  ))}
                  <ColorPicker
                    value={themeColor}
                    showText
                    onChangeComplete={(color) => onThemeColorChange(color.toHexString())}
                  />
                </div>
              </div>
              <Button className="settings-reset-button" icon={<ReloadOutlined />} onClick={onResetAppearance}>{labels.reset}</Button>
            </div>
          )}

          {page === "project" && (
            <div className="settings-project">
              <div className="settings-project-hero">
                <div className="settings-project-mark">F++</div>
                <div className="settings-project-identity">
                  <div><strong>Forensics++</strong><span>Workbench</span></div>
                  <Typography.Text type="secondary">{t.aboutProjectDesc}</Typography.Text>
                </div>
                <Button type="primary" href={projectLinks.repo} target="_blank" icon={<GithubOutlined />}>{labels.openRepo}</Button>
              </div>
              <div className="settings-project-meta">
                <div><span>{t.projectVersion}</span><strong>{appVersion}</strong></div>
                <div><span>{t.projectLicense}</span><strong>{projectLicense}</strong></div>
                <div><span>{t.lastUpdated}</span><strong>{lastUpdated}</strong></div>
                <div><span>{t.githubRepo}</span><a href={projectLinks.repo} target="_blank" rel="noreferrer">{projectRepoName}</a></div>
              </div>
              <div className="settings-project-resources">
                <section>
                  <strong>{labels.projectAccess}</strong>
                  <div>
                    <Button href={projectLinks.repo} target="_blank" icon={<GithubOutlined />}>GitHub</Button>
                    <Button href={`${projectLinks.repo}#readme`} target="_blank" icon={<LinkOutlined />}>{t.openReadme}</Button>
                  </div>
                </section>
                <section>
                  <strong>{labels.contact}</strong>
                  <a href={`mailto:${feedbackEmail}`}><MailOutlined aria-hidden="true" />{feedbackEmail}</a>
                </section>
              </div>
              <div className="settings-project-links">
                <strong>{labels.friendLinks}</strong>
                <div>
                  <a href="https://www.电子取证.com" target="_blank" rel="noreferrer">电子取证.com</a>
                  <a href="https://www.digiforensics.cn" target="_blank" rel="noreferrer">DigiForensics</a>
                </div>
              </div>
            </div>
          )}

          {page === "storage" && (
            <div className="settings-storage-page">
              <div className="settings-storage-summary">
                <div><span>{labels.siteUsage}</span><strong>{formatStorageMb(storage.usage)}</strong></div>
                <div><span>{labels.localStorageUsage}</span><strong>{formatStorageMb(storage.local)}</strong></div>
                <div><span>{labels.availableQuota}</span><strong>{storage.quota ? formatStorageMb(storage.quota) : "--"}</strong></div>
              </div>
              <div className="settings-storage-meter" aria-hidden="true"><span style={{ width: `${storage.quota ? Math.max(1, Math.min(100, storage.usage / storage.quota * 100)) : 0}%` }} /></div>
              <div className="settings-session-header">
                <div className="settings-section-heading">
                  <strong>{labels.sessionTitle}</strong>
                  <Typography.Text type="secondary">{labels.sessionDesc}</Typography.Text>
                </div>
                {openTools.length > 0 && <Button size="small" onClick={onCloseAllTools}>{labels.closeAll}</Button>}
              </div>
              <div className="settings-session-list">
                {openTools.length === 0 ? (
                  <Typography.Text className="settings-session-empty" type="secondary">{labels.noOpenTools}</Typography.Text>
                ) : visibleOpenTools.map((tool) => (
                  <div className="settings-session-item" key={tool.id}>
                    <span>{tool.title}</span>
                    {tool.active && <span className="settings-session-active">{labels.activeTool}</span>}
                    <Button
                      type="text"
                      size="small"
                      icon={<CloseOutlined />}
                      aria-label={`${labels.closeTool}: ${tool.title}`}
                      title={labels.closeTool}
                      onClick={() => onCloseTool(tool.id)}
                    />
                  </div>
                ))}
                {hiddenOpenToolCount > 0 && <Typography.Text className="settings-session-more" type="secondary">+{hiddenOpenToolCount} {labels.moreOpenTools}</Typography.Text>}
              </div>
              <div className="settings-action-line settings-danger-line">
                <div>
                  <strong>{labels.clearTitle}</strong>
                  <Typography.Text type="secondary">{labels.clearDesc}</Typography.Text>
                </div>
                <Button danger={cacheClearArmed} type={cacheClearArmed ? "primary" : "default"} onClick={onClearWorkspace}>
                  {cacheClearArmed ? t.confirmClearCache : t.clearLocalCache}
                </Button>
              </div>
            </div>
          )}

          {page === "opensource" && (
            <div className="settings-dependencies">
              <div className="settings-dependency-table">
                {openSourceProjects.map((project) => (
                  <a className="settings-dependency-item" href={project.repository} target="_blank" rel="noreferrer" key={`${project.category}-${project.name}`}>
                    <span>{project.name}</span><LinkOutlined aria-hidden="true" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </Modal>
  );
}

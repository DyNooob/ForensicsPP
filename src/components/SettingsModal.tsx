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
  DatabaseOutlined,
  DesktopOutlined,
  GithubOutlined,
  InfoCircleOutlined,
  LinkOutlined,
  MoonOutlined,
  SearchOutlined,
  SunOutlined
} from "@ant-design/icons";
import { Button, ColorPicker, Descriptions, Empty, Input, Menu, Modal, Segmented, Tag, Typography } from "antd";
import type { ThemeMode } from "../models";
import {
  appVersion,
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
};

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
  onClearWorkspace
}: SettingsModalProps) {
  const [page, setPage] = React.useState<SettingsPage>("appearance");
  const [dependencyQuery, setDependencyQuery] = React.useState("");
  const normalizedQuery = dependencyQuery.trim().toLowerCase();
  const visibleProjects = openSourceProjects.filter((project) => (
    !normalizedQuery
    || [project.name, project.license, project.category, project.purpose.zh, project.purpose.en]
      .join(" ")
      .toLowerCase()
      .includes(normalizedQuery)
  ));

  const labels = lang === "zh" ? {
    appearance: "外观",
    appearanceDesc: "调整界面主题与强调色。",
    project: "关于项目",
    storage: "本地数据",
    openSource: "开源依赖",
    themeMode: "主题模式",
    themeColor: "强调色",
    system: "跟随系统",
    reset: "恢复默认",
    clearTitle: "清除本地工作区",
    clearDesc: "删除界面偏好、最近使用、收藏和工具保存的输入。",
    dependenciesTitle: "开源项目与许可证",
    dependenciesDesc: `共 ${openSourceProjects.length} 个直接使用或随项目内置的开源项目。`,
    search: "搜索项目、用途或许可证",
    runtime: "运行时",
    embedded: "内置",
    development: "开发",
    notices: "声明",
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
    clearDesc: "Remove interface preferences, recent tools, favorites, and saved tool inputs.",
    dependenciesTitle: "Open-source projects and licenses",
    dependenciesDesc: `${openSourceProjects.length} open-source projects used directly or embedded in this repository.`,
    search: "Search project, purpose, or license",
    runtime: "Runtime",
    embedded: "Embedded",
    development: "Development",
    notices: "Notices",
    openRepo: "Open Repository"
  };

  const pageHeading = page === "appearance"
    ? [labels.appearance, labels.appearanceDesc]
    : page === "project"
      ? [t.aboutProject, t.aboutProjectDesc]
      : page === "storage"
        ? [labels.storage, t.localCacheDesc]
        : [labels.dependenciesTitle, labels.dependenciesDesc];

  return (
    <Modal
      className="settings-modal"
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
            <Typography.Text type="secondary">{pageHeading[1]}</Typography.Text>
          </header>

          {page === "appearance" && (
            <div className="settings-form">
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
                    />
                  ))}
                  <ColorPicker
                    value={themeColor}
                    showText
                    onChangeComplete={(color) => onThemeColorChange(color.toHexString())}
                  />
                </div>
              </div>
              <Button type="link" className="settings-reset-button" onClick={onResetAppearance}>{labels.reset}</Button>
            </div>
          )}

          {page === "project" && (
            <div className="settings-project">
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label={t.projectLicense}>{projectLicense}</Descriptions.Item>
                <Descriptions.Item label={t.projectVersion}>{appVersion}</Descriptions.Item>
                <Descriptions.Item label={t.githubRepo}><a href={projectLinks.repo} target="_blank" rel="noreferrer">{projectRepoName}</a></Descriptions.Item>
                <Descriptions.Item label={t.lastUpdated}>{lastUpdated}</Descriptions.Item>
              </Descriptions>
              <div className="settings-action-line">
                <div>
                  <strong>{t.usageGuide}</strong>
                  <Typography.Text type="secondary">{t.usageGuideDesc}</Typography.Text>
                </div>
                <Button href={`${projectLinks.repo}#readme`} target="_blank" icon={<LinkOutlined />}>{t.openReadme}</Button>
              </div>
              <div className="settings-action-line">
                <div>
                  <strong>GitHub</strong>
                  <Typography.Text type="secondary">{projectRepoName}</Typography.Text>
                </div>
                <Button href={projectLinks.repo} target="_blank" icon={<GithubOutlined />}>{labels.openRepo}</Button>
              </div>
            </div>
          )}

          {page === "storage" && (
            <div className="settings-action-line settings-danger-line">
              <div>
                <strong>{labels.clearTitle}</strong>
                <Typography.Text type="secondary">{labels.clearDesc}</Typography.Text>
              </div>
              <Button danger={cacheClearArmed} type={cacheClearArmed ? "primary" : "default"} onClick={onClearWorkspace}>
                {cacheClearArmed ? t.confirmClearCache : t.clearLocalCache}
              </Button>
            </div>
          )}

          {page === "opensource" && (
            <div className="settings-dependencies">
              <Input
                allowClear
                prefix={<SearchOutlined />}
                value={dependencyQuery}
                placeholder={labels.search}
                onChange={(event) => setDependencyQuery(event.target.value)}
              />
              <div className="settings-dependency-table">
                {visibleProjects.map((project) => (
                  <div className="settings-dependency-item" key={`${project.category}-${project.name}`}>
                    <div className="settings-dependency-name">
                      <a href={project.repository} target="_blank" rel="noreferrer">{project.name}</a>
                      <Typography.Text type="secondary">{project.purpose[lang]}</Typography.Text>
                    </div>
                    <Tag bordered={false}>{project.category === "runtime" ? labels.runtime : project.category === "embedded" ? labels.embedded : labels.development}</Tag>
                    <span className="settings-license">{project.license}</span>
                    {project.notices
                      ? <a href={project.notices} target="_blank" rel="noreferrer">{labels.notices}</a>
                      : <span className="settings-dependency-version">{project.version ? `v${project.version}` : ""}</span>}
                  </div>
                ))}
                {!visibleProjects.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
              </div>
            </div>
          )}
        </section>
      </div>
    </Modal>
  );
}

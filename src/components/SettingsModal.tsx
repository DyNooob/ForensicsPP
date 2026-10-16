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
import {
  BgColorsOutlined,
  ArrowRightOutlined,
  CodeOutlined,
  CheckOutlined,
  CloseOutlined,
  DatabaseOutlined,
  DesktopOutlined,
  DownloadOutlined,
  FileTextOutlined,
  GithubOutlined,
  InfoCircleOutlined,
  LinkOutlined,
  MoonOutlined,
  ReloadOutlined,
  SunOutlined
} from "@ant-design/icons";
import { Button, ColorPicker, Menu, Modal, Segmented, Switch, Typography } from "antd";
import type { ThemeMode } from "../models";
import type { ToolId } from "../config/app";
import {
  appVersion,
  buildHash,
  projectLinks,
  themePresets
} from "../config/app";
import { openSourceProjects } from "../config/openSource";
import { DataPackError, fetchLookupDataPack, inspectLookupDataPacks, type LookupDataPackId, type LookupDataPackStatus, type PackDownloadProgress } from "../features/lookup/dataPacks";

type SettingsPage = "appearance" | "project" | "storage" | "opensource";

type SettingsModalProps = {
  open: boolean;
  lang: "zh" | "en";
  t: Record<string, string>;
  themeMode: ThemeMode;
  themeColor: string;
  cacheClearArmed: boolean;
  cacheClearError: boolean;
  onClose: () => void;
  onThemeModeChange: (mode: ThemeMode) => void;
  onThemeColorChange: (color: string) => void;
  onResetAppearance: () => void;
  onClearWorkspace: () => void;
  defaultExportFormat: string;
  onDefaultExportFormatChange: (format: string) => void;
  autoSaveEvidence: boolean;
  onAutoSaveEvidenceChange: (value: boolean) => void;
  openTools: Array<{ id: ToolId; title: string; active: boolean }>;
  onCloseTool: (id: ToolId) => void;
  onCloseAllTools: () => void;
};

function formatStorageMb(bytes: number) {
  const mb = Math.max(0, bytes) / 1024 / 1024;
  return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(2)} MB`;
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

type StorageSnapshot = {
  local: number;
  usage: number;
  quota: number;
  estimated: boolean;
};

export function SettingsModal({
  open,
  lang,
  t,
  themeMode,
  themeColor,
  cacheClearArmed,
  cacheClearError,
  onClose,
  onThemeModeChange,
  onThemeColorChange,
  onResetAppearance,
  onClearWorkspace,
  defaultExportFormat,
  onDefaultExportFormatChange,
  autoSaveEvidence,
  onAutoSaveEvidenceChange,
  openTools,
  onCloseTool,
  onCloseAllTools
}: SettingsModalProps) {
  const [page, setPage] = React.useState<SettingsPage>("project");
  const [storage, setStorage] = React.useState<StorageSnapshot>({ local: 0, usage: 0, quota: 0, estimated: false });
  const [dataPacks, setDataPacks] = React.useState<LookupDataPackStatus[]>([]);
  const [storageRefresh, setStorageRefresh] = React.useState(0);
  const [downloads, setDownloads] = React.useState<Partial<Record<LookupDataPackId, PackDownloadProgress & { error?: string; busy: boolean }>>>({});
  const downloadControllers = React.useRef(new Map<LookupDataPackId, AbortController>());

  React.useEffect(() => {
    const controllers = downloadControllers.current;
    // Keep downloads alive when the dialog closes or changes pages.
    // Reopening it shows their current progress; leaving the app cancels them.
    return () => { for (const controller of controllers.values()) controller.abort(); controllers.clear(); };
  }, []);

  React.useEffect(() => {
    if (open) setPage("project");
  }, [open]);

  React.useEffect(() => {
    if (!open || page !== "storage") return;
    let active = true;
    void (async () => {
      const local = localStorageBytes();
      const [estimate, packs] = await Promise.all([
        (navigator.storage?.estimate ? navigator.storage.estimate() : Promise.resolve(null)).catch(() => null),
        inspectLookupDataPacks()
      ]);
      if (active) {
        setStorage({
          local,
          usage: estimate ? Math.max(local, estimate.usage ?? 0) : 0,
          quota: estimate?.quota ?? 0,
          estimated: Boolean(estimate)
        });
        setDataPacks(packs);
      }
    })();
    return () => { active = false; };
  }, [open, page, storageRefresh]);

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
    clearDesc: "删除界面设置、已保存的工作区和本地化数据包。",
    siteUsage: "本站占用",
    localStorageUsage: "localStorage",
    availableQuota: "浏览器配额",
    persistentTitle: "浏览器存储",
    persistentDesc: "管理保存在此浏览器中的工作区与参考数据。",
    sessionTitle: "当前会话",
    sessionDesc: "关闭工具会释放内存；支持恢复的工作区仍保存在浏览器。",
    dataPacks: "静态数据包",
    checkDataPacks: "检查状态",
    cachedPack: "已本地化",
    localizePack: "本地化",
    downloadingPack: "下载中",
    cancelDownload: "取消",
    retryDownload: "重试",
    packHint: "点击本地化，将数据包保存到此浏览器；之后查询直接读取本地数据，无需重复下载。",
    packRetention: "浏览器或清理操作可能移除数据包；更新数据版本后需重新本地化。",
    downloadUnavailable: "当前环境不支持本地缓存，请使用 HTTPS 或 localhost 打开。",
    downloadNetwork: "下载失败，请检查网络后重试。",
    downloadInvalid: "数据包不完整或格式无效，请重试。",
    downloadStorage: "保存失败，请检查浏览器存储权限和剩余空间。",
    downloadTimeout: "下载超时，请重试。",
    cacheUnavailable: "缓存不可用",
    closeTool: "关闭工具",
    closeAll: "全部关闭",
    noOpenTools: "当前没有打开的工具",
    activeTool: "正在使用",
    moreOpenTools: "个其他工具已打开",
    relatedLinks: "相关链接",
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
    clearDesc: "Remove interface settings, saved workspaces, and localized data packs.",
    siteUsage: "Site usage",
    localStorageUsage: "localStorage",
    availableQuota: "Browser quota",
    persistentTitle: "Browser storage",
    persistentDesc: "Manage workspaces and reference data stored in this browser.",
    sessionTitle: "Current session",
    sessionDesc: "Closing a tool releases memory; restorable workspaces remain in browser storage.",
    dataPacks: "Static data packs",
    checkDataPacks: "Check status",
    cachedPack: "Localized",
    localizePack: "Localize",
    downloadingPack: "Downloading",
    cancelDownload: "Cancel",
    retryDownload: "Retry",
    packHint: "Localize a pack to save it in this browser. Later lookups read local data without downloading it again.",
    packRetention: "Browser eviction or clearing data can remove packs. New pack versions need localization again.",
    downloadUnavailable: "Local cache is unavailable. Open over HTTPS or localhost.",
    downloadNetwork: "Download failed. Check your connection and retry.",
    downloadInvalid: "The pack is incomplete or invalid. Please retry.",
    downloadStorage: "Could not save. Check storage permissions and available space.",
    downloadTimeout: "Download timed out. Please retry.",
    cacheUnavailable: "Cache unavailable",
    closeTool: "Close tool",
    closeAll: "Close all",
    noOpenTools: "No tools are currently open",
    activeTool: "Active",
    moreOpenTools: "other tools open",
    relatedLinks: "Related links",
    dependenciesTitle: "Open-source projects",
    dependenciesDesc: `Forensics++ uses the following ${openSourceProjects.length} open-source projects.`,
    openRepo: "Open Repository"
  };

  const pageHeading = page === "appearance"
    ? [labels.appearance, labels.appearanceDesc]
    : page === "project"
      ? [t.aboutProject, ""]
      : page === "storage"
        ? [labels.storage, labels.persistentDesc]
        : [labels.dependenciesTitle, labels.dependenciesDesc];
  const activeOpenTool = openTools.find((tool) => tool.active);
  const visibleOpenTools = openTools.slice(0, 8);
  if (activeOpenTool && !visibleOpenTools.some((tool) => tool.id === activeOpenTool.id)) {
    visibleOpenTools[visibleOpenTools.length - 1] = activeOpenTool;
  }
  const hiddenOpenToolCount = openTools.length - visibleOpenTools.length;
  const legalUrl = window.location.protocol === "file:" ? "./legal.html" : "/legal.html";
  const dataPackNames: Record<LookupDataPackStatus["id"], string> = lang === "zh"
    ? { ip: "IP 地址库", phone: "手机号段库", id: "行政区划库" }
    : { ip: "IP database", phone: "Mobile prefix database", id: "Administrative divisions" };

  const localize = async (id: LookupDataPackId) => {
    if (downloadControllers.current.has(id)) return;
    const controller = new AbortController();
    downloadControllers.current.set(id, controller);
    setDownloads((current) => ({ ...current, [id]: { received: 0, total: 0, busy: true } }));
    try {
      await fetchLookupDataPack(id, { requireCache: true, signal: controller.signal, onProgress: (progress) => {
        if (downloadControllers.current.get(id) === controller) setDownloads((current) => ({ ...current, [id]: { ...progress, busy: true } }));
      } });
      if (downloadControllers.current.get(id) !== controller) return;
      setDataPacks((current) => current.map((pack) => pack.id === id ? { ...pack, cached: true } : pack));
      setDownloads((current) => ({ ...current, [id]: undefined }));
    } catch (caught) {
      if (downloadControllers.current.get(id) !== controller) return;
      const messages = { unavailable: labels.downloadUnavailable, network: labels.downloadNetwork, invalid: labels.downloadInvalid, storage: labels.downloadStorage, timeout: labels.downloadTimeout };
      setDownloads((current) => ({ ...current, [id]: controller.signal.aborted ? undefined : { received: 0, total: 0, busy: false, error: caught instanceof DataPackError ? messages[caught.code] : labels.downloadNetwork } }));
    } finally {
      if (downloadControllers.current.get(id) === controller) { downloadControllers.current.delete(id); setStorageRefresh((value) => value + 1); }
    }
  };

  return (
    <Modal
      className={`settings-modal settings-page-${page}`}
      open={open}
      centered
      width={920}
      title={<div className="settings-dialog-title"><BgColorsOutlined aria-hidden="true" /><span>{t.settings}</span><small>Forensics++</small></div>}
      footer={null}
      onCancel={onClose}
      destroyOnHidden
    >
      <div className="settings-shell">
        <aside className="settings-sidebar">
          <div className="settings-nav-caption">{lang === "zh" ? "工作台偏好" : "WORKSPACE"}</div>
          <Menu
            mode="inline"
            selectedKeys={[page]}
            onClick={({ key }) => setPage(key as SettingsPage)}
            items={[
              { key: "appearance", icon: <BgColorsOutlined />, label: labels.appearance },
              { key: "storage", icon: <DatabaseOutlined />, label: labels.storage },
              { key: "project", icon: <InfoCircleOutlined />, label: labels.project },
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
                <div className="settings-preview-main"><strong>Forensics++</strong><span>{lang === "zh" ? "你的本地分析工作台" : "Your local analysis workspace"}</span><div><b /><b /><b /></div></div>
                <span className="settings-preview-label">{lang === "zh" ? "实时预览" : "Live preview"}</span>
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
                    showText={false}
                    aria-label={labels.themeColor}
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
                  <div><strong>Forensics++</strong><span className="settings-release-badge">1.0 RC</span></div>
                  <Typography.Text type="secondary">{t.aboutProjectDesc}</Typography.Text>
                </div>
              </div>
              <div className="settings-project-details">
                <section className="settings-project-build">
                  <strong>{lang === "zh" ? "版本信息" : "Build information"}</strong>
                  <div className="settings-project-meta">
                    <div><span>{t.projectVersion}</span><code>{appVersion}</code></div>
                    <div><span>Hash</span><code title={buildHash}>{buildHash.slice(0, 7)}</code></div>
                  </div>
                </section>
                <section className="settings-project-related">
                  <strong>{labels.relatedLinks}</strong>
                  <div>
                    <a href="https://www.forensicspp.com" target="_blank" rel="noreferrer">ForensicsPP.com<ArrowRightOutlined aria-hidden="true" /></a>
                    <a href="https://www.digiforensics.cn" target="_blank" rel="noreferrer">DigiForensics<ArrowRightOutlined aria-hidden="true" /></a>
                  </div>
                </section>
              </div>
              <div className="settings-project-actions">
                <Button type="primary" href={projectLinks.repo} target="_blank" rel="noreferrer" icon={<GithubOutlined />}>{labels.openRepo}</Button>
                <Button href={legalUrl} target="_blank" rel="noreferrer" icon={<FileTextOutlined />}>{t.viewFullTerms}</Button>
              </div>
            </div>
          )}

          {page === "storage" && (
            <div className="settings-storage-page">
              <div className="settings-storage-summary">
                <div><span>{labels.siteUsage}</span><strong>{storage.estimated ? formatStorageMb(storage.usage) : "--"}</strong></div>
                <div><span>{labels.localStorageUsage}</span><strong>{formatStorageMb(storage.local)}</strong></div>
                <div><span>{labels.availableQuota}</span><strong>{storage.quota ? formatStorageMb(storage.quota) : "--"}</strong></div>
              </div>
              <div className="settings-storage-meter" aria-hidden="true"><span style={{ width: `${storage.estimated && storage.quota ? Math.max(1, Math.min(100, storage.usage / storage.quota * 100)) : 0}%` }} /></div>
              <section className="settings-data-packs">
                <div className="settings-session-header">
                  <div className="settings-section-heading"><strong>{labels.dataPacks}</strong><Typography.Text type="secondary">{labels.packHint}</Typography.Text></div>
                  <Button size="small" icon={<ReloadOutlined />} onClick={() => setStorageRefresh((value) => value + 1)}>{labels.checkDataPacks}</Button>
                </div>
                <div className="settings-data-pack-list">
                  {dataPacks.map((pack) => (
                    <div className="settings-data-pack-row" key={pack.id} data-pack={pack.id}>
                      <span className="settings-pack-icon" aria-hidden="true"><DatabaseOutlined /></span>
                      <div className="settings-pack-info"><strong>{dataPackNames[pack.id]}</strong><span>{pack.source}</span><code>{pack.version}</code></div>
                      <div className="settings-pack-action">
                        {pack.cached ? <span className="settings-pack-cached"><CheckOutlined />{labels.cachedPack}</span> : <Button size="small" icon={<DownloadOutlined />} loading={downloads[pack.id]?.busy} disabled={!pack.cacheSupported} title={!pack.cacheSupported ? labels.downloadUnavailable : undefined} aria-label={`${labels.localizePack}: ${dataPackNames[pack.id]}`} onClick={() => void localize(pack.id)}>{downloads[pack.id]?.busy ? labels.downloadingPack : downloads[pack.id]?.error ? labels.retryDownload : labels.localizePack}</Button>}
                        {downloads[pack.id]?.busy && <><span role="status">{formatStorageMb(downloads[pack.id]!.received)}{downloads[pack.id]!.total > 0 && ` / ${formatStorageMb(downloads[pack.id]!.total)}`}</span><Button type="text" size="small" onClick={() => downloadControllers.current.get(pack.id)?.abort()}>{labels.cancelDownload}</Button></>}
                        {!pack.cacheSupported && <span>{labels.cacheUnavailable}</span>}
                      </div>
                      {downloads[pack.id]?.error && <div className="settings-pack-error" role="alert">{downloads[pack.id]!.error}</div>}
                    </div>
                  ))}
                </div>
                <Typography.Text className="settings-pack-retention" type="secondary">{labels.packRetention}</Typography.Text>
              </section>
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
              <div className="settings-action-line">
                <div>
                  <strong>{t.defaultExportFormat}</strong>
                  <Typography.Text type="secondary">{t.defaultExportFormatDesc}</Typography.Text>
                </div>
                <Segmented
                  value={defaultExportFormat}
                  onChange={(value) => onDefaultExportFormatChange(String(value))}
                  options={[
                    { label: t.exportFormatMd, value: "md" },
                    { label: t.exportFormatHtml, value: "html" },
                    { label: t.exportFormatJson, value: "json" },
                    { label: t.exportFormatCsv, value: "csv" }
                  ]}
                />
              </div>
              <div className="settings-action-line">
                <div>
                  <strong>{t.autoSaveEvidence}</strong>
                  <Typography.Text type="secondary">{t.autoSaveEvidenceDesc}</Typography.Text>
                </div>
                <Switch checked={autoSaveEvidence} onChange={onAutoSaveEvidenceChange} aria-label={t.autoSaveEvidence} />
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
              {cacheClearError && <div className="empty-state error-state settings-cache-error" role="alert">{t.cacheClearFailed}</div>}
            </div>
          )}

          {page === "opensource" && (
            <div className="settings-dependencies">
              <div className="settings-dependency-table">
                {openSourceProjects.map((project) => (
                  <a className="settings-dependency-item" href={project.repository} target="_blank" rel="noreferrer" key={`${project.category}-${project.name}`}>
                    <div><strong>{project.name}</strong><span>{project.purpose[lang]}</span><code>{[project.version, project.license].filter(Boolean).join(" · ")}</code></div><LinkOutlined aria-hidden="true" />
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

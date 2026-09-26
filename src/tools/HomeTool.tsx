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
import { ArrowRightOutlined, ClockCircleOutlined, FileSearchOutlined, FolderOpenOutlined, PictureOutlined, SearchOutlined } from "@ant-design/icons";
import { saveHomeToolDraft, type HomeDraftTool } from "../app/useHomeToolDraft";
import { AButton, ASegmentedButton, ASegmentedGroup, ATextField } from "../components/ui";
import { analyzerForArtifact } from "../core/analyzerRouting";
import { dispatchToolHandoff } from "../core/toolHandoff";
import {
  appVersion,
  getToolTitle,
  lastUpdated,
  maxRecentTools,
  projectLicense,
  visibleTools,
  type ToolId
} from "../config/app";
import type { Translation } from "../i18n";
import type { Lang } from "../models";

type HomeToolProps = {
  t: Translation;
  lang: Lang;
  recentTools: ToolId[];
  setActiveTool: (tool: ToolId) => void;
};

function launchTarget(value: string): ToolId {
  const input = value.trim();
  if (!input) return "lookup";
  const lines = input.split(/[\r\n,;，；\t]+/).map((item) => item.trim()).filter(Boolean);
  const lookupLike = lines.length > 0 && lines.every((item) =>
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(item) ||
    /^(?:\+?86)?1[3-9]\d{9}$/.test(item.replace(/[\s-]/g, "")) ||
    /^\d{15}$/.test(item) ||
    /^\d{17}[\dXx]$/.test(item) ||
    /^\d{12,19}$/.test(item.replace(/[\s-]/g, ""))
  );
  if (lookupLike) return "lookup";
  if (/^https?:\/\//i.test(input) || /^[\w.-]+\.[a-z]{2,}(?:[/:?#]|$)/i.test(input)) return "urltool";
  if (/^[a-f\d]{32,128}$/i.test(input.replace(/\s/g, ""))) return "hash";
  if (/^[\d.]{9,19}$/.test(input)) return "timestamp";
  try { JSON.parse(input); return "json"; } catch { return "ioc"; }
}

export function HomeTool({ t, lang, recentTools, setActiveTool }: HomeToolProps) {
  const [query, setQuery] = React.useState("");
  const [launchInput, setLaunchInput] = React.useState("");
  const [dragActive, setDragActive] = React.useState(false);
  const [category, setCategory] = React.useState<"all" | "featured" | "analysis" | "transform" | "network">("all");
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const directoryRef = React.useRef<HTMLElement | null>(null);
  const categories = ["all", "featured", "analysis", "transform", "network"] as const;
  const searchableTools = visibleTools.filter((tool) => tool.id !== "home");
  const titleFor = (tool: (typeof visibleTools)[number]) => getToolTitle(tool, lang, t);

  const recentValidTools = recentTools
    .map((id) => searchableTools.find((tool) => tool.id === id))
    .filter((tool): tool is (typeof visibleTools)[number] => Boolean(tool))
    .slice(0, maxRecentTools);

  const filteredDirectoryTools = searchableTools.filter((tool) => {
    const normalizedQuery = query.trim().toLowerCase();
    if (category !== "all") {
      const matches = category === "featured" ? tool.featured === true : tool.category === category;
      if (!matches) return false;
    }
    if (!normalizedQuery) return true;
    return [titleFor(tool), t[tool.desc], t[tool.category], ...(tool.capabilities ?? []), ...(tool.accepts ?? [])].join(" ").toLowerCase().includes(normalizedQuery);
  });

  const directoryTools = filteredDirectoryTools;
  const categoryLabel = (item: (typeof categories)[number]) => item === "all" ? (lang === "zh" ? "全部" : "All") : t[item];
  const openTool = (target: ToolId) => {
    if (["lookup", "urltool", "hash", "timestamp", "json", "ioc"].includes(target) && launchInput.trim()) {
      saveHomeToolDraft(target as HomeDraftTool, launchInput);
    }
    setActiveTool(target);
  };

  const openLaunchTarget = () => openTool(launchTarget(launchInput));
  const detectedTool = searchableTools.find((tool) => tool.id === launchTarget(launchInput));

  const openEvidenceFile = async (file: File | undefined) => {
    if (!file) return;
    const extension = file.name.includes(".") ? file.name.split(".").pop() : undefined;
    let bytes: Uint8Array | undefined;
    try {
      bytes = new Uint8Array(await file.slice(0, 64 * 1024).arrayBuffer());
    } catch {
      bytes = undefined;
    }
    const target = analyzerForArtifact({ label: file.name, extension, mime: file.type, bytes });
    dispatchToolHandoff({ sourceTool: "home", targetTool: target, file, label: file.name });
    setActiveTool(target);
  };

const launchShortcuts: Array<{ id: ToolId; icon: React.ReactNode; zh: string; en: string; hintZh: string; hintEn: string }> = [
    { id: "lookup", icon: <SearchOutlined />, zh: "归属地查询", en: "Attribution", hintZh: "IP、手机号、身份证、银行卡", hintEn: "IP, mobile, ID, bank card" },
    { id: "image", icon: <PictureOutlined />, zh: "图片取证", en: "Image forensics", hintZh: "隐写、尾部数据、容器修复", hintEn: "Stego, trailer, container repair" },
    { id: "timestamp", icon: <ClockCircleOutlined />, zh: "时间转换", en: "Time conversion", hintZh: "取证时间戳与时区", hintEn: "Forensic timestamps and zones" },
    { id: "ioc", icon: <FileSearchOutlined />, zh: "IOC 提取", en: "IOC extraction", hintZh: "日志、文本与批量指标", hintEn: "Logs, text, and bulk indicators" }
  ];
  const continueTools = (recentValidTools.length
    ? recentValidTools
    : ["image", "sqlite", "evtx"].map((id) => searchableTools.find((tool) => tool.id === id)).filter((tool): tool is (typeof visibleTools)[number] => Boolean(tool)))
    .slice(0, 3);

  return (
    <div className="home-grid">
      <section className="home-hero">
        <div className="home-hero-main">
          <div className="home-hero-copy">
            <div>
              <h2>{lang === "zh" ? "本地分析工作台" : "Local Analysis Workbench"}</h2>
              <p>{lang === "zh" ? "输入内容或文件，选择操作并查看结果。" : "Add text or a file, choose an operation, and inspect the result."}</p>
            </div>
            <button type="button" className="home-open-evidence" onClick={() => fileInputRef.current?.click()}>
              <FolderOpenOutlined aria-hidden="true" />
              <span>{lang === "zh" ? "打开文件" : "Open file"}</span>
            </button>
          </div>
          <div className="home-command-box">
            <div className="home-command-head">
              <strong>{lang === "zh" ? "快速分析" : "Quick analysis"}</strong>
              <kbd>Ctrl / ⌘ + Enter</kbd>
            </div>
            <textarea
              value={launchInput}
              onChange={(event) => setLaunchInput(event.currentTarget.value)}
              onKeyDown={(event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") openLaunchTarget(); }}
              placeholder={lang === "zh" ? "IP、手机号、身份证号、银行卡号、URL、哈希、时间戳、日志" : "IP, mobile, ID, bank card, URL, hash, timestamp, logs"}
              aria-label={lang === "zh" ? "工作台输入" : "Workbench input"}
              spellCheck={false}
            />
            <div className="home-command-actions">
              <span>{launchInput.trim() && detectedTool ? `${lang === "zh" ? "自动选择" : "Auto"} · ${titleFor(detectedTool)}` : (lang === "zh" ? "自动识别内容类型" : "Detect input type automatically")}</span>
              <AButton variant="filled" onClick={openLaunchTarget}>{lang === "zh" ? "运行" : "Run"}</AButton>
            </div>
          </div>
          <div className="home-launch-shortcuts">
            {launchShortcuts.map((shortcut) => (
              <button type="button" key={shortcut.id} onClick={() => openTool(shortcut.id)}>
                <span className="home-shortcut-icon" aria-hidden="true">{shortcut.icon}</span>
                <span className="home-shortcut-copy">
                  <strong>{lang === "zh" ? shortcut.zh : shortcut.en}</strong>
                  <small>{lang === "zh" ? shortcut.hintZh : shortcut.hintEn}</small>
                </span>
                <ArrowRightOutlined className="home-shortcut-arrow" aria-hidden="true" />
              </button>
            ))}
          </div>
          <div className="home-meta-bar">
            <span><strong>v{appVersion}</strong></span>
            <span>{projectLicense}</span>
            <span>{lang === "zh" ? "更新" : "Updated"} {lastUpdated}</span>
          </div>
        </div>
        <aside className="home-evidence-panel" aria-label={lang === "zh" ? "文件输入" : "File input"}>
          <div className="home-panel-heading">
            <div><span>INPUT</span><h2>{lang === "zh" ? "文件" : "File"}</h2></div>
            <strong>FILE</strong>
          </div>
          <input
            ref={fileInputRef}
            className="hidden-file-input"
            type="file"
            aria-hidden="true"
            tabIndex={-1}
            onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void openEvidenceFile(file); }}
          />
          <div
            className={`home-file-drop ${dragActive ? "active" : ""}`}
            role="button"
            tabIndex={0}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInputRef.current?.click(); } }}
            onDragOver={(event) => { event.preventDefault(); setDragActive(true); }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(event) => { event.preventDefault(); setDragActive(false); void openEvidenceFile(event.dataTransfer.files?.[0]); }}
          >
            <FileSearchOutlined aria-hidden="true" />
            <strong>{lang === "zh" ? "拖入文件" : "Drop a file"}</strong>
            <span>{lang === "zh" ? "自动选择分析器" : "Analyzer selected automatically"}</span>
          </div>
          <div className="home-continue-tools">
            <div className="home-session-heading"><span>{lang === "zh" ? "最近操作" : "Recent operations"}</span></div>
            {continueTools.map((tool) => (
              <button type="button" key={tool.id} onClick={() => openTool(tool.id)}>
                <span><strong>{titleFor(tool)}</strong><small>{t[tool.category]}</small></span>
                <ArrowRightOutlined aria-hidden="true" />
              </button>
            ))}
          </div>
        </aside>
      </section>

      <section className="home-directory" ref={directoryRef}>
        <div className="directory-title">
          <h2>{lang === "zh" ? "操作" : "Operations"}</h2>
        </div>
        <div className="home-directory-toolbar">
          <ATextField
            className="home-tool-search"
            variant="outlined"
            type="search"
            clearable
            placeholder={t.search}
            aria-label={t.search}
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
          />
          <ASegmentedGroup className="home-category-tabs" value={category} selects="single" aria-label={t.category}>
            {categories.map((item) => (
              <ASegmentedButton key={item} value={item} onClick={() => setCategory(item)}>{categoryLabel(item)}</ASegmentedButton>
            ))}
          </ASegmentedGroup>
        </div>
        <div className="directory-list home-launcher-list expanded">
          {directoryTools.map((tool) => (
            <button className="directory-item" type="button" key={tool.id} onClick={() => openTool(tool.id)}>
              <strong>{titleFor(tool)}</strong>
              <span className="directory-meta">{t[tool.category]}</span>
              <em>{t[tool.desc]}</em>
            </button>
          ))}
          {!directoryTools.length && <div className="empty-state">{t.noToolMatches}</div>}
        </div>
      </section>
    </div>
  );
}

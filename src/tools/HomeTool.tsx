/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import React from "react";
import { AButton, ASegmentedButton, ASegmentedGroup, ATextField } from "../components/ui";
import { GithubIconButton } from "../components/GithubIconButton";
import {
  appVersion,
  getToolTitle,
  lastUpdated,
  maxRecentTools,
  projectLicense,
  projectLinks,
  projectRepoName,
  tools,
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

const defaultQuickToolIds: ToolId[] = ["hash", "image", "sqlite", "email"];
export function HomeTool({ t, lang, recentTools, setActiveTool }: HomeToolProps) {
  const [query, setQuery] = React.useState("");
  const [category, setCategory] = React.useState<"all" | "featured" | "analysis" | "transform" | "network">("all");
  const directoryRef = React.useRef<HTMLElement | null>(null);
  const categories = ["all", "featured", "analysis", "transform", "network"] as const;
  const searchableTools = tools.filter((tool) => tool.id !== "home");
  const titleFor = (tool: (typeof tools)[number]) => getToolTitle(tool, lang, t);

  const recentValidTools = recentTools
    .map((id) => searchableTools.find((tool) => tool.id === id))
    .filter((tool): tool is (typeof tools)[number] => Boolean(tool))
    .slice(0, maxRecentTools);
  const quickTools = (recentValidTools.length ? recentValidTools.map((tool) => tool.id) : defaultQuickToolIds)
    .map((id) => searchableTools.find((tool) => tool.id === id))
    .filter((tool): tool is (typeof tools)[number] => Boolean(tool))
    .slice(0, 4);

  const visibleTools = searchableTools.filter((tool) => {
    const normalizedQuery = query.trim().toLowerCase();
    if (category !== "all" && tool.category !== category) return false;
    if (!normalizedQuery) return true;
    return [titleFor(tool), t[tool.desc], t[tool.category]].join(" ").toLowerCase().includes(normalizedQuery);
  });

  const directoryTools = visibleTools;
  const directoryCount = `${directoryTools.length}/${searchableTools.length}`;
  const categoryLabel = (item: (typeof categories)[number]) => item === "all" ? (lang === "zh" ? "全部" : "All") : t[item];
  const quickLabel = recentValidTools.length ? t.recentTools : t.recommendedTools;

  return (
    <div className="home-grid">
      <section className="home-hero">
        <div className="home-hero-main">
          <div className="home-hero-copy">
            <span className="home-kicker">{lang === "zh" ? "启动台" : "Launcher"}</span>
            <h2>{t.heroTitle}</h2>
            <p>{t.heroTagline}</p>
            <div className="hero-tags" aria-label={t.product}>
              <span>{t.heroTagOpenSource}</span>
              <span>{t.heroTagEvidence}</span>
            </div>
            <div className="hero-links">
              <GithubIconButton label={t.repositoryLabel} />
              <AButton variant="text" onClick={() => directoryRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}>
                {lang === "zh" ? "浏览工具目录" : "Browse Tools"}
              </AButton>
            </div>
          </div>
          <dl className="project-meta">
            <div><dt>{t.projectLicense}</dt><dd>{projectLicense}</dd></div>
            <div><dt>{t.githubRepo}</dt><dd><a href={projectLinks.repo} target="_blank" rel="noreferrer">{projectRepoName}</a></dd></div>
            <div><dt>{t.projectVersion}</dt><dd>{appVersion}</dd></div>
            <div><dt>{t.lastUpdated}</dt><dd>{lastUpdated}</dd></div>
          </dl>
        </div>
        <aside className="home-quick-panel" aria-label={quickLabel}>
          <div className="directory-title compact"><h2>{quickLabel}</h2><span>{t.startWorkbench}</span></div>
          <div className="home-quick-list">
            {quickTools.map((tool) => (
              <button className="directory-item home-quick-item" type="button" key={tool.id} onClick={() => setActiveTool(tool.id)}>
                <strong>{titleFor(tool)}</strong>
                <span className="directory-meta">{t[tool.category]}</span>
                <em>{t[tool.desc]}</em>
              </button>
            ))}
          </div>
        </aside>
      </section>

      <section className="home-directory" ref={directoryRef}>
        <div className="directory-title">
          <h2>{t.toolDirectory}</h2>
          <span>{lang === "zh" ? "显示" : "Showing"} {directoryCount}</span>
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
            <button className="directory-item" type="button" key={tool.id} onClick={() => setActiveTool(tool.id)}>
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

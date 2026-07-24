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

import { MenuFoldOutlined, MenuUnfoldOutlined, CodeOutlined, SettingOutlined } from "@ant-design/icons";
import { AButton, AList, AListItem, AListSubheader, ATextField } from "./ui";
import type { ToolCategory, ToolDefinition } from "../config/app";
import type { Translation } from "../i18n";

export type ToolGroup = { category: ToolCategory; items: ToolDefinition[] };

type SidebarProps = {
  t: Translation;
  query: string;
  onQueryChange: (value: string) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  favoriteNavTools: ToolDefinition[];
  groupedTools: ToolGroup[];
  activeTool: string;
  onSelectTool: (id: ToolDefinition["id"]) => void;
  onOpenCommandPalette: () => void;
  onOpenSettings: () => void;
  toolTitle: (tool: ToolDefinition) => string;
};

export function Sidebar({
  t,
  query,
  onQueryChange,
  collapsed,
  onToggleCollapsed,
  favoriteNavTools,
  groupedTools,
  activeTool,
  onSelectTool,
  onOpenCommandPalette,
  onOpenSettings,
  toolTitle
}: SidebarProps) {
  return (
    <div className="sidebar-inner">
      <div className="sidebar-head">
        <a className="brand" href="#home" title="Forensics++">
          <span>F++</span>
          <strong>{t.product}</strong>
          <small>{t.subtitle}</small>
        </a>
        <button
          className="sidebar-toggle"
          type="button"
          aria-label={collapsed ? t.expandSidebar : t.collapseSidebar}
          title={collapsed ? t.expandSidebar : t.collapseSidebar}
          onClick={onToggleCollapsed}
        >
          {collapsed ? <MenuUnfoldOutlined aria-hidden="true" /> : <MenuFoldOutlined aria-hidden="true" />}
        </button>
      </div>
      {!collapsed && (
        <>
          <ATextField
            className="tool-search"
            variant="outlined"
            type="search"
            clearable
            placeholder={t.search}
            value={query}
            aria-label={t.search}
            onChange={(event) => onQueryChange(event.currentTarget.value)}
          />
          <nav className="tool-nav" aria-label={t.toolDirectory}>
            {favoriteNavTools.length ? (
              <AList className="favorite-tool-section tool-nav-list">
                <AListSubheader>{t.favoriteTools}</AListSubheader>
                {favoriteNavTools.map((tool) => (
                  <AListItem
                    className={tool.id === activeTool ? "active favorite-tool-item" : "favorite-tool-item"}
                    key={`favorite-${tool.id}`}
                    rounded
                    active={tool.id === activeTool}
                    description={t[tool.category]}
                    description-line={1}
                    title={`${toolTitle(tool)} - ${t[tool.desc]}`}
                    aria-current={tool.id === activeTool ? "page" : undefined}
                    onClick={() => onSelectTool(tool.id)}
                  >
                    {toolTitle(tool)}
                  </AListItem>
                ))}
              </AList>
            ) : null}
            {groupedTools.map((group) => (
              <AList className="tool-nav-list" key={group.category}>
                <AListSubheader>{t[group.category]}</AListSubheader>
                {group.items.map((tool) => (
                  <AListItem
                    className={tool.id === activeTool ? "active" : ""}
                    key={tool.id}
                    rounded
                    active={tool.id === activeTool}
                    description={t[tool.category]}
                    description-line={1}
                    title={`${t[tool.name]} - ${t[tool.desc]}`}
                    aria-current={tool.id === activeTool ? "page" : undefined}
                    onClick={() => onSelectTool(tool.id)}
                  >
                    {t[tool.name]}
                  </AListItem>
                ))}
              </AList>
            ))}
            {!groupedTools.length && <div className="nav-empty">{t.noToolMatches}</div>}
          </nav>
        </>
      )}
      <div className="sidebar-footer">
        <AButton variant="outlined" aria-label={t.openCommandPalette} title={t.openCommandPalette} onClick={onOpenCommandPalette}>
          <CodeOutlined className="sidebar-action-icon" aria-hidden="true" />
          <strong>{t.openCommandPalette}</strong>
        </AButton>
        <AButton variant="outlined" aria-label={t.settings} onClick={onOpenSettings}>
          <SettingOutlined className="sidebar-action-icon" aria-hidden="true" />
          <strong>{t.settings}</strong>
        </AButton>
      </div>
    </div>
  );
}

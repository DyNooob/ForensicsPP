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
import { Badge, Button, Card, Drawer, Empty, Popconfirm, Select, Space, Tag, Tooltip } from "antd";
import { CopyOutlined, DeleteOutlined, InboxOutlined, SendOutlined } from "@ant-design/icons";
import { useEvidenceInbox } from "../app/useEvidenceInbox";
import { clearEvidenceInbox, noteEvidenceUsed, type EvidenceInboxItem } from "../core/evidence/inbox";
import { dispatchToolHandoff } from "../core/toolHandoff";
import { copy, type Translation } from "../i18n";
import { getToolTitle, tools, type ToolId, type ToolDefinition } from "../config/app";
import type { Lang } from "../models";
import { copyText } from "../utils/clipboard";

/**
 * Every tool that can actually receive a handoff. Derived from `config/app.ts`
 * (`supportsHandoff: true`, excluding hidden/merged aliases) so the dropdown
 * can never drift out of sync with the tools that subscribe to
 * `takeToolHandoff`. The two sets are kept in lockstep by a contract test
 * (`tests/handoff-targets.test.ts`).
 */
const HANDOFF_TARGETS: ToolId[] = tools
  .filter((tool: ToolDefinition) => tool.supportsHandoff && !tool.hidden)
  .map((tool) => tool.id);

function formatBytes(n: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value < 10 ? 2 : 1)} ${units[i]}`;
}

function formatLoadedAt(ts: number, lang: Lang): string {
  try {
    return new Date(ts).toLocaleString(lang === "zh" ? "zh-CN" : "en-US");
  } catch {
    return String(ts);
  }
}

type EvidenceCardProps = {
  item: EvidenceInboxItem;
  t: Translation;
  lang: Lang;
  titleMap: Map<ToolId, string>;
  onOpenTool: (toolId: ToolId) => void;
};

function EvidenceCard({ item, t, lang, titleMap, onOpenTool }: EvidenceCardProps) {
  const [openWith, setOpenWith] = React.useState<ToolId | undefined>(undefined);
  const [copied, setCopied] = React.useState(false);

  const handleOpenWith = (target: ToolId) => {
    dispatchToolHandoff({
      sourceTool: "evidence-inbox",
      targetTool: target,
      file: item.file,
      label: item.name
    });
    noteEvidenceUsed(item.key, target);
    onOpenTool(target);
    setOpenWith(undefined);
  };

  const handleCopyHash = () => {
    if (!item.sha256) return;
    void copyText(item.sha256, { feedback: false }).then((ok) => {
      if (!ok) return;
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    });
  };

  return (
    <Card size="small" className="evidence-inbox-card" styles={{ body: { padding: 12 } }}>
      <div className="evidence-inbox-card__name" title={item.name}>
        {item.name}
      </div>
      <div className="evidence-inbox-card__meta">
        <span>{formatBytes(item.size)}</span>
        <span className="evidence-inbox-card__dot">·</span>
        <span>{item.source === "drop" ? t.evidenceSourceDrop : t.evidenceSourceUpload}</span>
        <span className="evidence-inbox-card__dot">·</span>
        <span>{formatLoadedAt(item.acquiredAt, lang)}</span>
      </div>

      <div className="evidence-inbox-card__hash">
        <span className="evidence-inbox-card__hash-label">{t.evidenceSha256}</span>
        <code className="evidence-inbox-card__hash-value">
          {item.sha256 ? item.sha256 : t.evidenceHashing}
        </code>
        <Tooltip title={t.evidenceCopyHash}>
          <Button
            type="text"
            size="small"
            aria-label={t.evidenceCopyHash}
            disabled={!item.sha256}
            icon={<CopyOutlined />}
            onClick={handleCopyHash}
          >
            {copied ? t.evidenceHashCopied : null}
          </Button>
        </Tooltip>
      </div>

      {item.usedByTools.length > 0 && (
        <div className="evidence-inbox-card__used">
          <span className="evidence-inbox-card__used-label">{t.evidenceUsedBy}</span>
          <Space size={[4, 4]} wrap>
            {item.usedByTools.map((toolId) => (
              <Tag
                key={toolId}
                className="evidence-inbox-card__chip"
                color="blue"
                onClick={() => onOpenTool(toolId)}
                style={{ cursor: "pointer" }}
              >
                {titleMap.get(toolId) ?? toolId}
              </Tag>
            ))}
          </Space>
        </div>
      )}

      <div className="evidence-inbox-card__open">
        <Select<ToolId>
          size="small"
          value={openWith}
          placeholder={t.evidenceOpenWith}
          onChange={handleOpenWith}
          className="evidence-inbox-card__select"
          popupMatchSelectWidth={false}
          options={HANDOFF_TARGETS.map((id) => ({ value: id, label: titleMap.get(id) ?? id }))}
        />
        <Tooltip title={t.evidenceOpenWithHint}>
          <SendOutlined className="evidence-inbox-card__open-hint" aria-hidden="true" />
        </Tooltip>
      </div>
    </Card>
  );
}

type EvidenceInboxProps = {
  open: boolean;
  onClose: () => void;
  t: Translation;
  lang: Lang;
  onOpenTool: (toolId: ToolId) => void;
};

export function EvidenceInbox({ open, onClose, t, lang, onOpenTool }: EvidenceInboxProps) {
  const { items, count } = useEvidenceInbox();

  const titleMap = React.useMemo(() => {
    const map = new Map<ToolId, string>();
    for (const tool of tools) map.set(tool.id, getToolTitle(tool, lang, copy[lang]));
    return map;
  }, [lang]);

  return (
    <Drawer
      title={
        <span className="evidence-inbox-title">
          <InboxOutlined aria-hidden="true" />
          <span>{t.evidenceInbox}</span>
          {count > 0 && <Badge count={count} size="small" offset={[4, -2]} />}
        </span>
      }
      open={open}
      onClose={onClose}
      width={440}
      extra={
        <Popconfirm
          title={t.evidenceClearInboxConfirm}
          okText={t.evidenceClearInbox}
          cancelText={t.cancelEdit}
          okButtonProps={{ danger: true }}
          disabled={!count}
          onConfirm={() => clearEvidenceInbox()}
        >
          <Button type="text" size="small" danger disabled={!count} icon={<DeleteOutlined />}>
            {t.evidenceClearInbox}
          </Button>
        </Popconfirm>
      }
    >
      {items.length === 0 ? (
        <Empty description={t.evidenceInboxEmpty} image={Empty.PRESENTED_IMAGE_SIMPLE} />
      ) : (
        <div className="evidence-inbox-list">
          {items.map((item) => (
            <EvidenceCard
              key={item.key}
              item={item}
              t={t}
              lang={lang}
              titleMap={titleMap}
              onOpenTool={onOpenTool}
            />
          ))}
        </div>
      )}
    </Drawer>
  );
}

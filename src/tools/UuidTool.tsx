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
import { AButton, ACheckbox, ASelect, InfoTable, ToolPanelHeader } from "../components/ui";
import type { Translation } from "../i18n";
import type { UuidAnalysis } from "../models";
import { downloadTextFile } from "../utils/files";
import { isUsableDate } from "../utils/forensics";
import { useStoredState } from "../utils/storage";

function uuidVersionName(version: string) {
  return ({
    "1": "v1 time/node",
    "2": "v2 DCE security",
    "3": "v3 MD5 namespace",
    "4": "v4 random",
    "5": "v5 SHA1 namespace",
    "6": "v6 reordered time",
    "7": "v7 Unix epoch time",
    "8": "v8 custom"
  } as Record<string, string>)[version] ?? `v${version}`;
}

function uuidTimestampToIso(timestamp100ns: bigint) {
  const unixMs = Number(timestamp100ns / 10000n - 12219292800000n);
  const date = new Date(unixMs);
  return Number.isFinite(unixMs) && isUsableDate(date) ? date.toISOString() : "--";
}

function guidMixedEndianBytes(match: RegExpMatchArray) {
  const hex = `${match[1].match(/../g)?.reverse().join("")}${match[2].match(/../g)?.reverse().join("")}${match[3].match(/../g)?.reverse().join("")}${match[4]}${match[5]}`;
  return hex.match(/.{2}/g)?.join(" ").toUpperCase() ?? "--";
}

function analyzeUuid(value: string): UuidAnalysis {
  const clean = value.trim().toLowerCase();
  const invalid = (): UuidAnalysis => ({
    input: value,
    valid: false,
    normalized: "--",
    rows: [["UUID", clean ? "Invalid" : "--"]],
    findings: clean ? [{ level: "warn", title: "Invalid UUID", detail: "Expected 32 hexadecimal characters with optional hyphens." }] : [],
    bytes: "--",
    guidBytes: "--",
    version: "--",
    variant: "--",
    timestamp: "--",
    node: "--"
  });
  if (!clean) return invalid();
  const match = clean.match(/^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})$/);
  if (!match) return invalid();

  const normalized = `${match[1]}-${match[2]}-${match[3]}-${match[4]}-${match[5]}`;
  const hex = normalized.replace(/-/g, "");
  const versionDigit = match[3][0];
  const version = uuidVersionName(versionDigit);
  const variantByte = parseInt(match[4].slice(0, 2), 16);
  const variant = (variantByte & 0x80) === 0x00 ? "NCS" : (variantByte & 0xc0) === 0x80 ? "RFC 4122 / Leach-Salz" : (variantByte & 0xe0) === 0xc0 ? "Microsoft" : "Future";
  const bytes = hex.match(/.{2}/g)?.join(" ").toUpperCase() ?? "--";
  const guidBytes = guidMixedEndianBytes(match);
  let timestamp = "--";
  let node = "--";
  const rows: Array<[string, string]> = [
    ["UUID", normalized],
    ["Version", version],
    ["Variant", variant]
  ];

  if (versionDigit === "1" || versionDigit === "6") {
    const timestampHex = versionDigit === "1" ? `${match[3].slice(1)}${match[2]}${match[1]}` : `${match[1]}${match[2]}${match[3].slice(1)}`;
    timestamp = uuidTimestampToIso(BigInt(`0x${timestampHex}`));
    node = match[5].match(/../g)?.join(":") ?? match[5];
    const clockSeq = ((parseInt(match[4].slice(0, 2), 16) & 0x3f) << 8) | parseInt(match[4].slice(2, 4), 16);
    rows.push(["Timestamp", timestamp], ["Clock sequence", String(clockSeq)], ["Node", node]);
  } else if (versionDigit === "7") {
    const unixMs = Number(BigInt(`0x${hex.slice(0, 12)}`));
    const date = new Date(unixMs);
    timestamp = Number.isFinite(unixMs) && isUsableDate(date) ? date.toISOString() : "--";
    rows.push(["Unix ms timestamp", timestamp]);
  }
  rows.push(["Standard bytes", bytes], ["Windows GUID bytes", guidBytes]);
  return { input: value, valid: true, normalized, rows, findings: [], bytes, guidBytes, version, variant, timestamp, node };
}

function randomUuid(version: 4 | 7) {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  if (version === 7) {
    let ms = BigInt(Date.now());
    for (let index = 5; index >= 0; index -= 1) {
      bytes[index] = Number(ms & 0xffn);
      ms >>= 8n;
    }
  }
  bytes[6] = (bytes[6] & 0x0f) | (version << 4);
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uuidAnalysesToCsv(items: UuidAnalysis[]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["input", "valid", "normalized", "version", "variant", "timestamp", "node", "bytes", "guid_bytes"].join(","),
    ...items.map((item) => [item.input, String(item.valid), item.normalized, item.version, item.variant, item.timestamp, item.node, item.bytes, item.guidBytes].map(escape).join(","))
  ].join("\n");
}

export function UuidTool({ t }: { t: Translation }) {
  const [value, setValue] = useStoredState("uuid.value", "");
  const [query, setQuery] = React.useState("");
  const [sortMode, setSortMode] = React.useState<"input" | "time" | "version">("input");
  const [timeOnly, setTimeOnly] = React.useState(false);
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const english = t.waiting === "Waiting";
  const hasInput = Boolean(value.trim());
  const analyses = React.useMemo(() => {
    const matches = value.match(/[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}/g);
    return (matches?.length ? matches : [value]).map(analyzeUuid);
  }, [value]);
  const selected = analyses[Math.min(selectedIndex, Math.max(0, analyses.length - 1))] ?? analyzeUuid("");
  const selectedRows = React.useMemo<Array<[string, string]>>(() => {
    if (english) return selected.rows;
    const labels: Record<string, string> = {
      UUID: "UUID",
      Version: "版本",
      Variant: "变体",
      Timestamp: "时间",
      "Clock sequence": "时钟序列",
      Node: "节点",
      "Unix ms timestamp": "Unix 毫秒时间",
      "Standard bytes": "标准字节序",
      "Windows GUID bytes": "Windows GUID 字节序"
    };
    return selected.rows.map(([label, itemValue]) => [labels[label] ?? label, itemValue]);
  }, [english, selected]);
  const visible = React.useMemo(() => {
    const search = query.trim().toLowerCase();
    const rows = analyses.map((item, index) => ({ item, index })).filter(({ item }) => {
      if (timeOnly && item.timestamp === "--") return false;
      return !search || [item.input, item.normalized, item.version, item.variant, item.timestamp, item.node].join(" ").toLowerCase().includes(search);
    });
    return rows.sort((left, right) => {
      if (sortMode === "version") return left.item.version.localeCompare(right.item.version);
      if (sortMode === "time") return (left.item.timestamp === "--" ? Infinity : Date.parse(left.item.timestamp)) - (right.item.timestamp === "--" ? Infinity : Date.parse(right.item.timestamp));
      return left.index - right.index;
    });
  }, [analyses, query, sortMode, timeOnly]);

  const replaceWithGenerated = (version: 4 | 7) => {
    setValue(randomUuid(version));
    setSelectedIndex(0);
    setQuery("");
  };
  const clear = () => {
    setValue("");
    setQuery("");
    setTimeOnly(false);
    setSelectedIndex(0);
  };

  return (
    <div className={`tool-grid uuid-workbench uuid-simple-workbench ${hasInput ? "has-uuid" : "empty-uuid"}`}>
      <div className="tool-panel wide-panel uuid-simple-input-panel">
        <ToolPanelHeader title={english ? "UUID input" : "UUID 输入"} actions={<AButton variant="text" disabled={!hasInput} onClick={clear}>{t.clear}</AButton>} />
        <textarea className="single-textarea uuid-simple-input" aria-label={english ? "UUID input" : "UUID 输入"} value={value} placeholder={english ? "Paste one or more UUID values" : "粘贴一个或多个 UUID"} onChange={(event) => { setValue(event.currentTarget.value); setSelectedIndex(0); }} />
        <div className="action-row">
          <AButton variant="filled" onClick={() => replaceWithGenerated(4)}>{t.generate} v4</AButton>
          <AButton variant="outlined" onClick={() => replaceWithGenerated(7)}>{english ? "Generate v7" : "生成 v7"}</AButton>
          <AButton variant="outlined" disabled={!selected.valid} onClick={() => void navigator.clipboard.writeText(selected.normalized)}>{t.copyOutput}</AButton>
        </div>
      </div>

      {hasInput && <div className="tool-panel wide-panel uuid-simple-result-panel">
        <ToolPanelHeader
          title={english ? "Parsed UUID" : "解析结果"}
          subtitle={analyses.length > 1 ? `${selectedIndex + 1}/${analyses.length}` : undefined}
          actions={<>
            <AButton variant="outlined" disabled={!selected.valid} onClick={() => void navigator.clipboard.writeText(selected.bytes)}>{t.standardBytes}</AButton>
            <AButton variant="outlined" disabled={!selected.valid} onClick={() => void navigator.clipboard.writeText(selected.guidBytes)}>{t.guidBytes}</AButton>
          </>}
        />
        {selected.valid ? <InfoTable rows={selectedRows} /> : <div className="empty-state error-state">{english ? "Invalid UUID" : "UUID 格式无效"}</div>}
      </div>}

      {hasInput && analyses.length > 1 && <div className="tool-panel wide-panel uuid-simple-batch-panel">
        <ToolPanelHeader
          title={t.uuidBatch}
          subtitle={`${analyses.filter((item) => item.valid).length}/${analyses.length} ${english ? "valid" : "有效"}`}
          actions={<>
            <AButton variant="outlined" onClick={() => downloadTextFile(`uuid-${Date.now()}.csv`, uuidAnalysesToCsv(analyses), "text/csv;charset=utf-8")}>{t.exportUuidCsv}</AButton>
            <AButton variant="text" onClick={() => void navigator.clipboard.writeText(analyses.filter((item) => item.valid).map((item) => item.normalized).join("\n"))}>{t.copy}</AButton>
          </>}
        />
        <div className="uuid-simple-filter-row">
          <input className="text-input" value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={t.uuidSearch} />
          <ASelect aria-label={english ? "Sort UUIDs" : "UUID 排序"} value={sortMode} onChange={(value) => setSortMode(String(value) as typeof sortMode)} options={[{ value: "input", label: t.uuidSortInput }, { value: "time", label: t.uuidSortTime }, { value: "version", label: t.uuidSortVersion }]} />
          <ACheckbox className="checkbox-label" checked={timeOnly} onChange={(event) => setTimeOnly(event.target.checked)}>{t.uuidTimeOnly}</ACheckbox>
        </div>
        <div className="table-scroll uuid-simple-scroll">
          {visible.length ? <table className="data-table uuid-simple-table"><thead><tr><th>#</th><th>UUID</th><th>{english ? "Valid" : "有效"}</th><th>{english ? "Version" : "版本"}</th><th>{english ? "Timestamp" : "时间"}</th><th>{english ? "Node" : "节点"}</th></tr></thead><tbody>{visible.map(({ item, index }) => <tr className={index === selectedIndex ? "selected-row" : ""} key={`${index}-${item.input}`} onClick={() => setSelectedIndex(index)}><td>{index + 1}</td><td><code>{item.normalized}</code></td><td>{item.valid ? (english ? "yes" : "是") : (english ? "no" : "否")}</td><td>{item.version}</td><td>{item.timestamp}</td><td>{item.node}</td></tr>)}</tbody></table> : <div className="empty-state">--</div>}
        </div>
      </div>}
    </div>
  );
}

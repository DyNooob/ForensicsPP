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
import { AButton, ATextField, PanelTitle } from "../ui";
import { exifFieldLabel, exifValueLabel } from "../../features/image/exifLocalize";
import { downloadBlob } from "../../utils/files";
import { hasMetadataValue, metadataHighlights, sortedMetadataEntries } from "../../features/image/metadata";

export function ImageMetadataHighlights({ metadata, english }: { metadata: Record<string, unknown>; english: boolean }) {
  const highlights = metadataHighlights(metadata, english);
  if (!highlights.length) return null;
  return <div className="image-metadata-highlights">{highlights.map((item) => <div key={item.label}><span>{item.label}</span><strong>{item.value}</strong><small>{item.note}</small></div>)}</div>;
}

export function ImageMetadata({ metadata, name, english, formatValue, showHighlights = true }: {
  metadata: Record<string, unknown>; name: string; english: boolean; formatValue: (value: unknown) => string; showHighlights?: boolean;
}) {
  const [query, setQuery] = React.useState("");
  const [showEmpty, setShowEmpty] = React.useState(false);
  const [limit, setLimit] = React.useState(100);
  React.useEffect(() => { setQuery(""); setLimit(100); setShowEmpty(false); }, [metadata]);
  const entries = sortedMetadataEntries(metadata);
  const populated = entries.filter(([, value]) => hasMetadataValue(value));
  const filtered = entries.filter(([key, value]) => (showEmpty || hasMetadataValue(value)) && (!query.trim() || `${key} ${exifFieldLabel(key, english)} ${exifValueLabel(key, value, english) ?? ""} ${formatValue(value)}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())));
  const exportMetadata = () => {
    const json = JSON.stringify(metadata, (_key, value) => typeof value === "bigint" ? String(value) : ArrayBuffer.isView(value) ? Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) : value, 2);
    downloadBlob(`${name.replace(/\.[^.]+$/, "")}-metadata.json`, new Blob([json], { type: "application/json" }));
  };
  return <section className="image-metadata">
    <div className="panel-heading-row image-exif-heading"><PanelTitle title={english ? "Metadata / EXIF" : "元数据 / EXIF"} /><AButton disabled={!entries.length} onClick={exportMetadata}>{english ? "Export all metadata" : "导出全部元数据"}</AButton></div>
    <p className="inline-note">{english ? `${populated.length} populated fields. Capture details appear first; all extracted fields are available below.` : `已提取 ${populated.length} 个有内容的字段。拍摄信息优先显示，全部字段在下方直接展开。`}</p>
    {showHighlights && <ImageMetadataHighlights metadata={metadata} english={english} />}
    {entries.length ? <>
      <div className="image-metadata-controls"><ATextField value={query} onChange={(event) => { setQuery(event.currentTarget.value); setLimit(100); }} placeholder={english ? "Search fields or values" : "搜索字段或内容"} aria-label={english ? "Search image metadata" : "搜索图片元数据"} /><span role="status">{Math.min(limit, filtered.length)} / {filtered.length}</span>{populated.length < entries.length && <label><input type="checkbox" checked={showEmpty} onChange={(event) => setShowEmpty(event.currentTarget.checked)} /> {english ? "Include empty fields" : "显示空字段"}</label>}</div>
      {filtered.length ? <div className="image-exif-scroll"><table className="image-exif-table"><colgroup><col className="image-exif-field-col" /><col /></colgroup><thead><tr><th>{english ? "Field" : "字段"}</th><th>{english ? "Value" : "值"}</th></tr></thead><tbody>
        {filtered.slice(0, limit).map(([key, value]) => { const label = exifFieldLabel(key, english); return <tr key={key}><th scope="row"><span className="exif-field-label">{label}</span>{!english && label !== key && <code className="exif-tag-sub">{key}</code>}</th><td><pre>{exifValueLabel(key, value, english) ?? formatValue(value)}</pre></td></tr>; })}
      </tbody></table></div> : <div className="empty-state">{english ? "No matching metadata. Try another search." : "没有匹配的元数据，请调整搜索内容。"}</div>}
      {filtered.length > limit && <AButton onClick={() => setLimit((value) => value + 100)}>{english ? "Show 100 more fields" : "再显示 100 个字段"}</AButton>}
    </> : <div className="empty-state">{english ? "No metadata was extracted. Screenshots and shared photos may have no EXIF; this does not mean analysis failed." : "未提取到元数据。截图、社交平台转存图片可能没有 EXIF，这不代表分析失败。"}</div>}
  </section>;
}

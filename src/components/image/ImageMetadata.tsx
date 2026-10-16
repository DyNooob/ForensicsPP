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

export function ImageMetadata({ metadata, name, english, formatValue }: {
  metadata: Record<string, unknown>; name: string; english: boolean; formatValue: (value: unknown) => string;
}) {
  const [query, setQuery] = React.useState("");
  React.useEffect(() => setQuery(""), [metadata]);
  const entries = Object.entries(metadata);
  const filtered = entries.filter(([key, value]) => !query.trim() || `${key} ${exifFieldLabel(key, english)} ${formatValue(value)}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));
  const exportMetadata = () => {
    const json = JSON.stringify(metadata, (_key, value) => typeof value === "bigint" ? String(value) : ArrayBuffer.isView(value) ? Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) : value, 2);
    downloadBlob(`${name.replace(/\.[^.]+$/, "")}-metadata.json`, new Blob([json], { type: "application/json" }));
  };
  return <section className="image-metadata">
    <div className="panel-heading-row image-exif-heading"><PanelTitle title={english ? "Metadata / EXIF" : "元数据 / EXIF"} /><AButton disabled={!entries.length} onClick={exportMetadata}>{english ? "Export all metadata" : "导出全部元数据"}</AButton></div>
    {entries.length ? <>
      <div className="image-metadata-controls"><ATextField value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={english ? "Search fields or values" : "搜索字段或内容"} aria-label={english ? "Search image metadata" : "搜索图片元数据"} /><span role="status">{Math.min(100, filtered.length)} / {filtered.length}{query ? ` (${entries.length})` : ""}</span></div>
      {filtered.length ? <div className="image-exif-scroll"><table className="image-exif-table"><colgroup><col className="image-exif-field-col" /><col /></colgroup><thead><tr><th>{english ? "Field" : "字段"}</th><th>{english ? "Value" : "值"}</th></tr></thead><tbody>
        {filtered.slice(0, 100).map(([key, value]) => { const label = exifFieldLabel(key, english); return <tr key={key}><th scope="row"><span className="exif-field-label">{label}</span>{!english && label !== key && <code className="exif-tag-sub">{key}</code>}</th><td><pre>{exifValueLabel(key, value, english) ?? formatValue(value)}</pre></td></tr>; })}
      </tbody></table></div> : <div className="empty-state">{english ? "No matching metadata. Try another search." : "没有匹配的元数据，请调整搜索内容。"}</div>}
      {filtered.length > 100 && <div className="inline-note">{english ? "Showing the first 100 matches. Search covers all fields; export includes every field." : "显示前 100 个匹配项；搜索覆盖全部字段，导出保留完整元数据。"}</div>}
    </> : <div className="empty-state">{english ? "No metadata fields were found in this file." : "当前文件未解析到元数据字段。"}</div>}
  </section>;
}

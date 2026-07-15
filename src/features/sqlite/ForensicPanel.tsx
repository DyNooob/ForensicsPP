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

import { copyText } from "../../utils/clipboard";
import React from "react";
import { ASelect, InfoTable, PanelTitle } from "../../components/ui";
import { formatBytes } from "../../utils/files";
import type { SqliteForensicAnalysis, SqlitePageKind } from "./forensic";

function pageKindLabel(kind: SqlitePageKind, english: boolean) {
  if (english) return kind.replace(/-/g, " ");
  const labels: Record<SqlitePageKind, string> = {
    "database-header": "数据库首页",
    "table-interior": "表内部页",
    "table-leaf": "表叶子页",
    "index-interior": "索引内部页",
    "index-leaf": "索引叶子页",
    "freelist-trunk": "空闲链表主干页",
    "freelist-leaf": "空闲页",
    empty: "空页",
    unknown: "未识别页"
  };
  return labels[kind];
}
export function SqliteForensicPanel({ analysis, english }: { analysis: SqliteForensicAnalysis; english: boolean }) {
  const [pageFilter, setPageFilter] = React.useState<SqlitePageKind | "all">("all");
  const [selectedPage, setSelectedPage] = React.useState<number | null>(1);
  const visiblePages = React.useMemo(
    () => pageFilter === "all" ? analysis.pages : analysis.pages.filter((page) => page.kind === pageFilter),
    [analysis.pages, pageFilter]
  );
  const selectedPageInfo = React.useMemo(
    () => analysis.pages.find((page) => page.pageNumber === selectedPage) ?? null,
    [analysis.pages, selectedPage]
  );

  React.useEffect(() => {
    setPageFilter("all");
    setSelectedPage(analysis.pages[0]?.pageNumber ?? null);
  }, [analysis]);

  return <div className="sqlite-forensic-workspace">
    <div className="tool-panel wide-panel sqlite-forensic-summary-panel">
      <div className="panel-heading-row"><PanelTitle title={english ? "Database pages" : "数据库页面"} /><span className="status-pill">{analysis.pages.length} {english ? "pages" : "页"}</span></div>
      <InfoTable rows={[
        [english ? "Page size" : "页大小", formatBytes(analysis.header.pageSize)],
        [english ? "Pages in file" : "文件页数", String(analysis.header.filePages)],
        [english ? "Pages in header" : "头部记录页数", String(analysis.header.headerPages)],
        [english ? "Freelist pages" : "空闲页数", String(analysis.header.freelistPages)],
        [english ? "Encoding" : "编码", analysis.header.encoding],
        [english ? "Change counter" : "修改计数", String(analysis.header.changeCounter)],
        [english ? "Schema cookie" : "Schema Cookie", String(analysis.header.schemaCookie)],
        [english ? "User version" : "User Version", String(analysis.header.userVersion)],
        [english ? "Application ID" : "Application ID", `0x${analysis.header.applicationId.toString(16).padStart(8, "0").toUpperCase()}`]
      ]} />
    </div>

    {analysis.walError && <div className="tool-panel wide-panel sqlite-forensic-wal-panel">
      <div className="panel-heading-row"><PanelTitle title={english ? "WAL" : "WAL 文件"} /><span className="status-pill danger">{english ? "Unavailable" : "不可用"}</span></div>
      <div className="empty-state error-state">{analysis.walError}</div>
    </div>}

    <div className="tool-panel wide-panel sqlite-forensic-pages-panel">
      <div className="panel-heading-row">
        <PanelTitle title={english ? "Page map" : "页面分布"} />
        <ASelect
          className="sqlite-forensic-page-filter"
          aria-label={english ? "Filter page type" : "筛选页面类型"}
          value={pageFilter}
          onChange={(value) => setPageFilter(value as SqlitePageKind | "all")}
          options={[
            { value: "all", label: english ? "All page types" : "全部页面" },
            ...Array.from(new Set(analysis.pages.map((page) => page.kind))).map((kind) => ({ value: kind, label: pageKindLabel(kind, english) }))
          ]}
        />
      </div>
      <div className="sqlite-forensic-page-layout">
        <div className="table-scroll sqlite-forensic-page-scroll">
          <table className="data-table sqlite-forensic-table">
            <thead><tr><th>{english ? "Page" : "页号"}</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Type" : "类型"}</th><th>{english ? "Cells" : "单元格"}</th><th>{english ? "Free" : "空闲空间"}</th><th>WAL</th><th>Offset</th></tr></thead>
            <tbody>{visiblePages.map((page) => <tr className={selectedPage === page.pageNumber ? "is-selected" : ""} key={page.pageNumber} onClick={() => setSelectedPage(page.pageNumber)}>
              <td>{page.pageNumber}</td><td><span className={`sqlite-source-badge ${page.source}`}>{page.source === "wal" ? "WAL" : english ? "Main" : "主库"}</span></td><td>{pageKindLabel(page.kind, english)}</td><td>{page.cellCount ?? "--"}</td><td>{page.freeBytes ? formatBytes(page.freeBytes) : "--"}</td><td>{page.walFrame ?? "--"}</td><td><code>0x{page.offset.toString(16).toUpperCase()}</code></td>
            </tr>)}</tbody>
          </table>
        </div>
        {selectedPageInfo && <div className="sqlite-forensic-page-detail">
          <strong>{english ? `Page ${selectedPageInfo.pageNumber}` : `第 ${selectedPageInfo.pageNumber} 页`}</strong>
          <InfoTable rows={[
            [english ? "Type" : "类型", pageKindLabel(selectedPageInfo.kind, english)],
            [english ? "Source" : "来源", selectedPageInfo.source === "wal" ? `WAL frame ${selectedPageInfo.walFrame}` : (english ? "Main database" : "主数据库")],
            ["Offset", `0x${selectedPageInfo.offset.toString(16).toUpperCase()}`],
            [english ? "Cells" : "单元格", String(selectedPageInfo.cellCount ?? "--")],
            [english ? "Free space" : "空闲空间", selectedPageInfo.freeBytes ? formatBytes(selectedPageInfo.freeBytes) : "--"],
            [english ? "First freeblock" : "首个 Freeblock", selectedPageInfo.firstFreeblock == null ? "--" : String(selectedPageInfo.firstFreeblock)],
            [english ? "Content offset" : "内容区偏移", selectedPageInfo.contentOffset == null ? "--" : String(selectedPageInfo.contentOffset)]
          ]} />
        </div>}
      </div>
    </div>

    {analysis.wal && <div className="tool-panel wide-panel sqlite-forensic-wal-panel">
      <div className="panel-heading-row"><PanelTitle title={english ? "WAL frames" : "WAL 帧"} /><span className="status-pill">{analysis.wal.info.committedFrames}/{analysis.wal.info.frames}</span></div>
      <div className="table-scroll sqlite-forensic-wal-scroll"><table className="data-table sqlite-forensic-table"><thead><tr><th>{english ? "Frame" : "帧"}</th><th>{english ? "Page" : "页号"}</th><th>{english ? "State" : "状态"}</th><th>{english ? "Database pages" : "提交页数"}</th><th>Offset</th></tr></thead><tbody>{analysis.wal.frames.map((frame) => <tr key={frame.index}><td>{frame.index}</td><td>{frame.pageNumber || "--"}</td><td>{!frame.valid ? (english ? `Invalid: ${frame.reason}` : `无效：${frame.reason}`) : frame.committed ? `${english ? "Committed" : "已提交"}${frame.latestForPage ? (english ? " · active" : " · 当前生效") : ""}` : (english ? "Not committed" : "未提交")}</td><td>{frame.commitPages || "--"}</td><td><code>0x{frame.offset.toString(16).toUpperCase()}</code></td></tr>)}</tbody></table></div>
    </div>}

    <div className="tool-panel wide-panel sqlite-forensic-fragment-panel">
      <div className="panel-heading-row"><PanelTitle title={english ? "Free-space text fragments" : "空闲区文本片段"} /><span className="status-pill">{analysis.fragments.length}</span></div>
      {analysis.fragments.length ? <div className="table-scroll sqlite-forensic-fragment-scroll"><table className="data-table sqlite-forensic-table"><thead><tr><th>{english ? "Page" : "页号"}</th><th>Offset</th><th>{english ? "Source" : "来源"}</th><th>{english ? "Area" : "区域"}</th><th>{english ? "Encoding" : "编码"}</th><th>{english ? "Fragment" : "片段"}</th></tr></thead><tbody>{analysis.fragments.map((fragment, index) => <tr key={`${fragment.pageNumber}-${fragment.offset}-${fragment.encoding}-${index}`}><td>{fragment.pageNumber}</td><td><code>0x{fragment.offset.toString(16).toUpperCase()}</code></td><td>{fragment.source === "wal" ? "WAL" : english ? "Main" : "主库"}</td><td>{fragment.area}</td><td>{fragment.encoding}</td><td><button className="sqlite-fragment-copy" type="button" title={fragment.text} onClick={() => void copyText(fragment.text)}>{fragment.text}</button></td></tr>)}</tbody></table></div> : <div className="empty-state">{english ? "No printable fragments found in the scanned free space." : "扫描的空闲区域中未发现可打印文本片段。"}</div>}
    </div>
  </div>;
}

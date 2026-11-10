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
import type { ImageInfo } from "../../models";
import { formatBytes } from "../../utils/files";
import { AnalysisNotice, FindingCard } from "../AnalysisNotice";
import { sortFindings, type NoticeLevel } from "../../core/analysisPresentation";
import { dimensionRecoveryMessage } from "../../features/png/presentation";

type Page = "structure" | "hidden" | "channels" | "repair";
export function ImageReviewSummary({ image, english, onNavigate }: { image: ImageInfo; english: boolean; onNavigate: (page: Page) => void }) {
  const findings = sortFindings([...(image.containerFindings ?? []), ...image.formatLayers.flatMap(layer => layer.findings)]);
  const errors = findings.filter(item => item.level === "danger");
  const warnings = findings.filter(item => item.level === "warn");
  const badCrc = image.pngChunks.filter(chunk => !chunk.ok);
  const recovery = image.dimensionRecovery;
  const repairNeeded = !image.decoded || badCrc.length > 0;
  const items: Array<{ page: Page; title: string; value: string; detail: string; level: NoticeLevel }> = [
    { page: "structure", title: english ? "1 · Container evidence" : "1 · 结构与校验", value: english ? `${errors.length} errors · ${warnings.length} review items` : `${errors.length} 项异常 · ${warnings.length} 项需关注`, detail: english ? "Inspect chunks, offsets and metadata" : "查看数据块、偏移与原始字段", level: errors.length ? "danger" : warnings.length ? "warn" : "info" },
    { page: "repair", title: english ? "2 · Recovery" : "2 · 宽高与容器修复", value: recovery?.status === "recovered" ? (english ? "Dimensions recovered" : "已匹配恢复尺寸") : repairNeeded ? (english ? "Recovery recommended" : "建议检查修复") : (english ? "Dimensions not checked" : "宽高尚未验证"), detail: english ? "CRC + scanlines, compare recovery copies" : "联合 CRC 与扫描行验证，比较修复副本", level: recovery?.status === "recovered" ? "success" : recovery?.status === "ambiguous" || repairNeeded ? "warn" : "pending" },
    { page: "hidden", title: english ? "3 · Extra content" : "3 · 附加与隐藏内容", value: english ? `${formatBytes(image.trailerBytes.length)} trailer · ${image.hiddenPayloads.length} extracted` : `尾部 ${formatBytes(image.trailerBytes.length)} · ${image.hiddenPayloads.length} 个提取项`, detail: english ? "Review signatures and extracted bytes" : "核对文件特征，查看或导出提取内容", level: image.trailerBytes.length || image.hiddenPayloads.length ? "warn" : "info" },
    { page: "channels", title: english ? "4 · Pixel inspection" : "4 · 像素与位平面", value: !image.decoded ? (english ? "Requires recovery first" : "需先恢复可解码图片") : image.autoRevealPreviews.length ? (english ? "Previews generated" : "预览已生成") : (english ? "Not generated" : "尚未生成"), detail: english ? "Inspect channels and bit planes on demand" : "按需生成通道与位平面，交叉验证隐写线索", level: "pending" },
  ];
  return <section className="image-review-section" aria-label={english ? "Inspection conclusion and next steps" : "检查结论与下一步"}>
    <AnalysisNotice level={!image.decoded || errors.length ? "danger" : warnings.length || image.trailerBytes.length ? "warn" : "info"} title={!image.decoded ? (english ? "Pixel decoding failed" : "像素解码未成功") : errors.length ? (english ? "Structural errors found" : "发现结构或校验异常") : (english ? "Initial inspection completed" : "基础检查已完成")} english={english}>
      {!image.decoded ? (english ? "Pixel decoding failed; container and metadata analysis remain available. Start with recovery, then inspect pixel content." : "像素暂时无法解码，仍已检查容器并提取可读取的元数据。先恢复宽高或容器，再查看像素内容。") : errors.length ? (english ? "The image opens, but structural errors were detected. Review evidence before treating the preview as complete." : "图片能够显示，但发现结构或校验异常；预览可打开不代表内容完整，请先核对异常证据。") : (english ? "Container and readable metadata have been checked. Pixel steganography requires further inspection." : "已检查容器结构和可读取的元数据；像素隐写仍需进一步检查。")}
    </AnalysisNotice>
    {findings.filter(item => item.level === "danger" || item.level === "warn").slice(0, 3).map((finding,index) => <FindingCard key={index} finding={finding} english={english} />)}
    {recovery && <AnalysisNotice level={recovery.status === "recovered" || recovery.status === "consistent" ? "success" : "warn"} title={english ? "Dimension recovery result" : "宽高恢复结果"} english={english}>{dimensionRecoveryMessage(recovery, english)}</AnalysisNotice>}
    <div className="image-review-summary">{items.map(item => <button key={item.page} type="button" data-severity={item.level} onClick={() => onNavigate(item.page)}><span>{item.title}</span><strong>{item.value}</strong><small>{item.detail}<span aria-hidden="true"> →</span></small></button>)}</div>
  </section>;
}

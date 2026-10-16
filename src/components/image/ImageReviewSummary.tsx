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

export function ImageReviewSummary({ image, english, onNavigate }: { image: ImageInfo; english: boolean; onNavigate: (page: "structure" | "hidden" | "channels" | "repair") => void }) {
  const findings = image.formatLayers.flatMap((layer) => layer.findings);
  const warnings = findings.filter((finding) => finding.level !== "info").length;
  const items = [
    { page: "structure" as const, title: english ? "Container checks" : "容器检查", value: english ? `${findings.length} notes · ${warnings} warnings` : `${findings.length} 项记录 · ${warnings} 项异常`, detail: english ? "Inspect structure and metadata" : "查看结构与元数据", warning: warnings > 0 },
    { page: "hidden" as const, title: english ? "Appended data" : "尾部数据", value: formatBytes(image.trailerBytes.length), detail: english ? `${image.hiddenPayloads.length} extracted items` : `${image.hiddenPayloads.length} 个提取项`, warning: image.trailerBytes.length > 0 },
    { page: "channels" as const, title: english ? "Pixel inspection" : "像素检查", value: english ? "Channels / bit planes" : "颜色通道 / 位平面", detail: english ? "Generate when needed" : "按需生成，查看隐写线索", warning: false },
    ...(!image.decoded ? [{ page: "repair" as const, title: english ? "Image repair" : "图片修复", value: english ? "Decode failed" : "像素解码失败", detail: english ? "Try container recovery" : "尝试修复容器与预览", warning: true }] : [])
  ];
  return <div className="image-review-summary">{items.map((item) => <button key={item.page} type="button" className={item.warning ? "has-attention" : ""} onClick={() => onNavigate(item.page)}><span>{item.title}</span><strong>{item.value}</strong><small>{item.detail}<span aria-hidden="true"> →</span></small></button>)}</div>;
}

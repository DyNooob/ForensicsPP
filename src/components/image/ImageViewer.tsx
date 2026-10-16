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
import { AButton } from "../ui";

export function ImageViewer({ src, label, english, onExpand, large = false }: {
  src: string; label: string; english: boolean; onExpand?: () => void; large?: boolean;
}) {
  const [zoom, setZoom] = React.useState(0);
  const [background, setBackground] = React.useState(0);
  const [dimensions, setDimensions] = React.useState({ width: 0, height: 0 });
  React.useEffect(() => { setZoom(0); }, [src]);
  const step = (direction: number) => setZoom((value) => Math.max(0.125, Math.min(8, (value || 1) * (direction > 0 ? 1.5 : 1 / 1.5))));
  return <div className={`image-viewer ${large ? "image-viewer-large" : ""}`}>
    <div className="image-viewer-toolbar">
      <div className="button-row">
        <AButton size="small" variant={zoom === 0 ? "filled" : "text"} onClick={() => setZoom(0)}>{english ? "Fit" : "适应窗口"}</AButton>
        <AButton size="small" variant={zoom === 1 ? "filled" : "text"} onClick={() => setZoom(1)}>100%</AButton>
        <AButton size="small" aria-label={english ? "Zoom out" : "缩小"} onClick={() => step(-1)}>−</AButton>
        <span className="image-zoom-label" role="status">{zoom ? `${Math.round(zoom * 100)}%` : (english ? "Fit" : "适应")}</span>
        <AButton size="small" aria-label={english ? "Zoom in" : "放大"} onClick={() => step(1)}>+</AButton>
      </div>
      <div className="button-row">
        <AButton size="small" onClick={() => setBackground((value) => (value + 1) % 3)} title={english ? "Change preview background" : "切换预览背景"}>
          {english ? ["Checkerboard", "Dark", "Light"][background] : ["透明棋盘", "深色背景", "浅色背景"][background]}
        </AButton>
        {onExpand && <AButton size="small" onClick={onExpand}>{english ? "Expand" : "大图查看"}</AButton>}
      </div>
    </div>
    <div className={`image-viewer-viewport image-background-${background}`} tabIndex={0} role="region" aria-label={english ? "Image preview; use plus, minus or zero to zoom" : "图片预览，可用加减号缩放，0 恢复适应窗口"}
      onKeyDown={(event) => { if (["+", "=", "-", "0"].includes(event.key)) { event.preventDefault(); if (event.key === "0") setZoom(0); else step(event.key === "-" ? -1 : 1); } }}>
      <div className={`image-viewer-canvas ${zoom ? "is-zoomed" : ""}`}>
        <img src={src} alt={label} className="image-viewer-img" draggable={false} onLoad={(event) => setDimensions({ width: event.currentTarget.naturalWidth, height: event.currentTarget.naturalHeight })}
          style={zoom && dimensions.width ? { width: dimensions.width * zoom, height: dimensions.height * zoom, maxWidth: "none", maxHeight: "none" } : undefined} />
      </div>
    </div>
    <div className="image-viewer-caption"><span>{dimensions.width} × {dimensions.height} px</span><span>{english ? "Preview only · original bytes unchanged" : "仅调整显示 · 原始数据不变"}</span></div>
  </div>;
}

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
import { AButton, ALinearProgress, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import { downloadTextFile, formatBytes } from "../utils/files";

type QrPoint = [string, string];
type CompactQrAnalysis = {
  name: string;
  size: number;
  mime: string;
  format: string;
  width: number;
  height: number;
  scanWidth: number;
  scanHeight: number;
  previewUrl: string;
  payload: string;
  payloadType: string;
  decodedBytes: number;
  payloadRows: QrPoint[];
  cornerRows: QrPoint[];
  geometryRows: QrPoint[];
};

export type QrToolServices = {
  classifyQrPayload: (payload: string) => string;
  detectImageFormat: (bytes: Uint8Array, mime: string) => string;
  parseQrPayloadDetails: (payload: string, payloadType: string) => QrPoint[];
  qrPointRow: (label: string, point: unknown) => QrPoint | null;
  qrGeometryRows: (location: Record<string, unknown>, imageWidth: number, imageHeight: number) => QrPoint[];
};

const MAX_QR_FILE_BYTES = 96 * 1024 * 1024;
const MAX_QR_SOURCE_PIXELS = 40_000_000;
const MAX_QR_SCAN_PIXELS = 4_000_000;
const MAX_QR_SCAN_EDGE = 2048;

function scaledQrLocation(location: Record<string, unknown>, scaleX: number, scaleY: number) {
  return Object.fromEntries(Object.entries(location).map(([key, value]) => {
    if (!value || typeof value !== "object") return [key, value];
    const point = value as { x?: number; y?: number };
    if (typeof point.x !== "number" || typeof point.y !== "number") return [key, value];
    return [key, { ...point, x: point.x * scaleX, y: point.y * scaleY }];
  }));
}

export function QrTool({ t, services }: { t: (typeof copy)["zh"]; services: QrToolServices }) {
  const { classifyQrPayload, detectImageFormat, parseQrPayloadDetails, qrGeometryRows, qrPointRow } = services;
  const english = t.waiting === "Waiting";
  const [analysis, setAnalysis] = React.useState<CompactQrAnalysis | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [isDropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const requestIdRef = React.useRef(0);
  const previewUrlRef = React.useRef("");

  React.useEffect(() => () => {
    requestIdRef.current += 1;
    if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
  }, []);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    const requestId = ++requestIdRef.current;
    let pendingPreviewUrl = "";
    setDropActive(false);
    setLoading(true);
    setError("");
    try {
      if (file.size > MAX_QR_FILE_BYTES) throw new Error(english ? "Image is too large (96 MiB maximum)." : "图片过大，最大支持 96 MiB。");
      const sampleBytes = new Uint8Array(await file.slice(0, 1024 * 1024).arrayBuffer());
      const previewUrl = URL.createObjectURL(file);
      pendingPreviewUrl = previewUrl;
      const image = await new Promise<HTMLImageElement>((resolve, reject) => {
        const next = new Image();
        next.onload = () => resolve(next);
        next.onerror = () => reject(new Error(english ? "The image could not be decoded." : "图片无法解码。"));
        next.src = previewUrl;
      });
      if (requestId !== requestIdRef.current) {
        URL.revokeObjectURL(previewUrl);
        return;
      }
      const sourcePixels = image.naturalWidth * image.naturalHeight;
      if (!sourcePixels || sourcePixels > MAX_QR_SOURCE_PIXELS) throw new Error(english ? "Image dimensions are too large (40 megapixels maximum)." : "图片尺寸过大，最大支持 4000 万像素。");
      const scale = Math.min(1, MAX_QR_SCAN_EDGE / Math.max(image.naturalWidth, image.naturalHeight), Math.sqrt(MAX_QR_SCAN_PIXELS / sourcePixels));
      const scanWidth = Math.max(1, Math.round(image.naturalWidth * scale));
      const scanHeight = Math.max(1, Math.round(image.naturalHeight * scale));
      const canvas = document.createElement("canvas");
      canvas.width = scanWidth;
      canvas.height = scanHeight;
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) throw new Error("Canvas is not available");
      context.drawImage(image, 0, 0, scanWidth, scanHeight);
      const imageData = context.getImageData(0, 0, scanWidth, scanHeight);
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
      const { default: jsQR } = await import("jsqr");
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      canvas.width = 1;
      canvas.height = 1;
      if (requestId !== requestIdRef.current) {
        URL.revokeObjectURL(previewUrl);
        return;
      }
      const payload = code?.data ?? "";
      const payloadType = classifyQrPayload(payload);
      const scanLocation = (code as unknown as { location?: Record<string, unknown> } | null)?.location ?? {};
      const location = scaledQrLocation(scanLocation, image.naturalWidth / scanWidth, image.naturalHeight / scanHeight);
      const cornerRows = [
        qrPointRow("Top-left", location.topLeftCorner),
        qrPointRow("Top-right", location.topRightCorner),
        qrPointRow("Bottom-left", location.bottomLeftCorner),
        qrPointRow("Bottom-right", location.bottomRightCorner)
      ].filter(Boolean) as QrPoint[];
      const decodedBytes = Array.isArray((code as unknown as { binaryData?: number[] } | null)?.binaryData)
        ? (code as unknown as { binaryData: number[] }).binaryData.length
        : new Blob([payload]).size;
      setAnalysis({
        name: file.name,
        size: file.size,
        mime: file.type || "unknown",
        format: detectImageFormat(sampleBytes, file.type),
        width: image.naturalWidth,
        height: image.naturalHeight,
        scanWidth,
        scanHeight,
        previewUrl,
        payload,
        payloadType,
        decodedBytes,
        payloadRows: parseQrPayloadDetails(payload, payloadType),
        cornerRows,
        geometryRows: qrGeometryRows(location, image.naturalWidth, image.naturalHeight)
      });
      if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
      previewUrlRef.current = previewUrl;
      pendingPreviewUrl = "";
    } catch (caught) {
      if (pendingPreviewUrl) URL.revokeObjectURL(pendingPreviewUrl);
      if (requestId === requestIdRef.current) {
        setAnalysis(null);
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (requestId === requestIdRef.current) setLoading(false);
    }
  };

  const clear = () => {
    requestIdRef.current += 1;
    if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    previewUrlRef.current = "";
    setAnalysis(null);
    setError("");
    setLoading(false);
    setDropActive(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const infoRows: QrPoint[] = analysis ? [
    [english ? "Name" : "名称", analysis.name],
    [t.fileSize, formatBytes(analysis.size)],
    [t.fileType, `${analysis.mime} / ${analysis.format}`],
    [t.dimensions, `${analysis.width} x ${analysis.height}`],
    [english ? "Scan size" : "扫描尺寸", `${analysis.scanWidth} x ${analysis.scanHeight}`]
  ] : [];

  return (
    <div className={`tool-grid qr-workbench ${analysis ? "has-qr" : "empty-qr"}`}>
      <div className="tool-panel wide-panel qr-preview-panel">
        <PanelTitle title={english ? "QR image" : "二维码图片"} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept="image/*" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleFile(file); }} />
        <div
          className={`desktop-drop-zone ${isDropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDropActive(true);
          }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDropActive(false);
            void handleFile(event.dataTransfer.files?.[0]);
          }}
        >
          <strong>{analysis?.name || t.dropFileTitle}</strong>
          <span>{analysis ? `${analysis.payload ? analysis.payloadType : (english ? "No QR code" : "未识别二维码")} · ${analysis.width} x ${analysis.height}` : t.dropFileHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!analysis && !error && !loading} onClick={clear}>{t.clear}</AButton>
        </div>
        {loading && <ALinearProgress />}
        {error && <pre className="result-box">{error}</pre>}
        {analysis && <img className="image-preview" src={analysis.previewUrl} alt={analysis.name} />}
      </div>

      {analysis && (
        <>
          <div className="tool-panel wide-panel qr-result-panel">
            <div className="panel-heading-row">
              <PanelTitle title={english ? "Decoded content" : "识别结果"} />
              <AButton variant="text" disabled={!analysis.payload} onClick={() => void navigator.clipboard.writeText(analysis.payload)}>{t.copy}</AButton>
            </div>
            <div className="qr-primary-grid">
              <div className="result-copy-card"><span>{t.qrPayloadType}</span><strong>{analysis.payload ? analysis.payloadType : "--"}</strong></div>
              <div className="result-copy-card"><span>{t.qrDecodedBytes}</span><strong>{analysis.decodedBytes}</strong></div>
              <div className="result-copy-card"><span>{t.dimensions}</span><strong>{analysis.width} x {analysis.height}</strong></div>
            </div>
            <textarea aria-label={english ? "QR code payload" : "二维码内容"} className="single-textarea qr-payload-box" value={analysis.payload || t.qrNoCode} readOnly />
          </div>

          {analysis.payload && (
            <div className="tool-panel wide-panel qr-fields-panel">
              <div className="panel-heading-row">
                <PanelTitle title={t.qrPayloadDetails} />
                <AButton variant="text" onClick={() => downloadTextFile(`qr-payload-${Date.now()}.txt`, analysis.payload, "text/plain;charset=utf-8")}>TXT</AButton>
              </div>
              <InfoTable rows={analysis.payloadRows} />
            </div>
          )}

          <details className="image-advanced-shell qr-advanced-shell wide-panel">
            <summary>{english ? "Image and geometry" : "图片与几何信息"}</summary>
            <div className="qr-advanced-stack">
              <div className="tool-panel wide-panel"><PanelTitle title={t.qrImageInfo} /><InfoTable rows={infoRows} /></div>
              {analysis.cornerRows.length ? <div className="tool-panel wide-panel"><PanelTitle title={t.qrCorners} /><InfoTable rows={analysis.cornerRows} /></div> : null}
              {analysis.geometryRows.length ? <div className="tool-panel wide-panel"><PanelTitle title={english ? "Geometry" : "几何信息"} /><InfoTable rows={analysis.geometryRows} /></div> : null}
            </div>
          </details>
        </>
      )}
    </div>
  );
}

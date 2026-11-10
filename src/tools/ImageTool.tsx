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

import { AnalysisNotice, FindingCard, ErrorNotice } from "../components/AnalysisNotice";
import { copyText } from "../utils/clipboard";
import { localizeAnalysisText, sortFindings } from "../core/analysisPresentation";
import { pngChunkSeverity } from "../features/png/parser";
import { dimensionRecoveryMessage } from "../features/png/presentation";
import React from "react";
import { PasteButton } from "../components/ClipboardImport";
import { AutoTextarea } from "../components/AutoTextarea";
import { Modal } from "antd";
import { ImageViewer } from "../components/image/ImageViewer";
import { ImageMetadata, ImageMetadataHighlights } from "../components/image/ImageMetadata";
import { ImageReviewSummary } from "../components/image/ImageReviewSummary";
import { subscribeToolHandoff, takeToolHandoff } from "../core/toolHandoff";
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { ImageInfo } from "../models";
import { buildImageEnvelope } from "../features/image/envelope";
import { scanQrRobust } from "../features/qr/scan";
import { useStaleRunGuard } from "../core/runtime";
import { publishAnalysisResult } from "../features/analysis/resultStore";
import { downloadBlob, formatBytes } from "../utils/files";
import { useToolWorkspace } from "../utils/useToolWorkspace";
import { runWorkerTask } from "../utils/workerTask";
import type { ImageAnalysisResult, ImageBasicsWorkerResult, ImageRepairWorkerResult, ImageWorkerRequest } from "../features/image/image.worker";

type ImageService = (...args: any[]) => any;
type ImageRepairCandidate = { label: string; note: string; bytes: Uint8Array; mime: string };
type ImageWorkspace = { name: string; type: string; lastModified: number; bytes: Uint8Array };
type QrPoint = [string, string];
type ImageQrResult = {
  payload: string;
  payloadType: string;
  decodedBytes: number;
  scanWidth: number;
  scanHeight: number;
  scanStrategy: string;
  payloadRows: QrPoint[];
  cornerRows: QrPoint[];
  geometryRows: QrPoint[];
};
const MAX_IMAGE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PERSISTED_IMAGE_BYTES = 8 * 1024 * 1024;

function scaledQrLocation(location: Record<string, unknown>, scaleX: number, scaleY: number) {
  return Object.fromEntries(Object.entries(location).map(([key, value]) => {
    if (!value || typeof value !== "object") return [key, value];
    const point = value as { x?: number; y?: number };
    if (typeof point.x !== "number" || typeof point.y !== "number") return [key, value];
    return [key, { ...point, x: point.x * scaleX, y: point.y * scaleY }];
  }));
}

function formatExifValue(value: unknown) {
  if (value == null) return "--";
  if (typeof value === "string") return value || "--";
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? String(value) : value.toISOString();
  if (typeof value !== "object") return String(value);
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(value, (_key, item: unknown) => {
      if (typeof item === "bigint") return item.toString();
      if (item instanceof Date) return Number.isNaN(item.getTime()) ? String(item) : item.toISOString();
      if (ArrayBuffer.isView(item)) {
        const bytes = new Uint8Array(item.buffer, item.byteOffset, item.byteLength);
        const preview = Array.from(bytes.subarray(0, 256), (byte) => byte.toString(16).padStart(2, "0")).join(" ");
        return bytes.byteLength > 256 ? `${preview} ... (${bytes.byteLength} bytes)` : preview;
      }
      if (item && typeof item === "object") {
        if (seen.has(item)) return "[Circular]";
        seen.add(item);
      }
      return item;
    }, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

function dataUrlToBytes(dataUrl: string): { bytes: Uint8Array; mime: string } | null {
  const comma = dataUrl.indexOf(",");
  if (comma < 0) return null;
  const meta = dataUrl.slice(0, comma);
  const isBase64 = /;base64/i.test(meta);
  const mimeMatch = /data:([^;,]*)/.exec(meta);
  const mime = mimeMatch?.[1] || "image/png";
  const raw = dataUrl.slice(comma + 1);
  let bytes: Uint8Array;
  if (isBase64) {
    const binary = atob(raw);
    bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  } else {
    bytes = new TextEncoder().encode(decodeURIComponent(raw));
  }
  return { bytes, mime };
}

function sanitizeChannelLabel(label: string) {
  const slug = label.replace(/[^\w.-]+/g, "-").replace(/^-+|-+$/g, "") || "channel";
  return slug;
}

function downloadChannelImage(name: string, label: string, dataUrl: string) {
  const parsed = dataUrlToBytes(dataUrl);
  if (!parsed) return;
  const base = (name || "image").replace(/\.[^.]+$/, "");
  downloadBlob(`${base}-${sanitizeChannelLabel(label)}.png`, new Blob([parsed.bytes.slice()], { type: parsed.mime }));
}

export type ImageToolServices = {
  buildAutoRevealPreviews: ImageService;
  bytesToDataUrl: ImageService;
  createChannelPreviews: ImageService;
  createImageAnalysisPixels: ImageService;
  detectImageFormat: ImageService;
  emptyImageChannels: ImageService;
  guessImageDimensions: ImageService;
  imageExtensionForMime: ImageService;
  imageMimeForFormat: ImageService;
  imagePlaceholderDataUrl: ImageService;
  loadBrowserImage: ImageService;
  revokeImageObjectUrls: ImageService;
  revokeImagePreviewUrl: ImageService;
  revokeImagePreviewUrls: ImageService;
  classifyQrPayload: (payload: string) => string;
  parseQrPayloadDetails: (payload: string, payloadType: string) => QrPoint[];
  qrPointRow: (label: string, point: unknown) => QrPoint | null;
  qrGeometryRows: (location: Record<string, unknown>, imageWidth: number, imageHeight: number) => QrPoint[];
};

export function ImageTool({ t, services, active = true }: { t: (typeof copy)["zh"]; services: ImageToolServices; active?: boolean }) {
  const {
    buildAutoRevealPreviews, bytesToDataUrl, createChannelPreviews, createImageAnalysisPixels,
    detectImageFormat, emptyImageChannels, guessImageDimensions,
    imageExtensionForMime, imageMimeForFormat, imagePlaceholderDataUrl,
    loadBrowserImage, revokeImagePreviewUrl, revokeImageObjectUrls
  } = services;
  const isEnglish = t.waiting === "Waiting";
  const [imageInfo, setImageInfo] = React.useState<ImageInfo | null>(null);
  const [previewVersion, setPreviewVersion] = React.useState<"original" | "recovered">("original");
  const [loading, setLoading] = React.useState(false);
  const [advancedTask, setAdvancedTask] = React.useState<"hidden" | "channels" | "repair" | "">("");
  const advancedTaskRef = React.useRef<typeof advancedTask>("");
  const updateAdvancedTask = (task: typeof advancedTask) => {
    advancedTaskRef.current = task;
    setAdvancedTask(task);
  };
  const [error, setError] = React.useState("");
  const [storageNotice, setStorageNotice] = React.useState("");
  const [isImageDropActive, setIsImageDropActive] = React.useState(false);
  const [imagePage, setImagePage] = React.useState<"overview" | "structure" | "hidden" | "channels" | "qr" | "repair">(() => {
    if (typeof window === "undefined") return "overview";
    const legacy = window.location.hash.replace(/^#/, "").toLowerCase();
    if (["png", "gif", "jpeg", "webp", "bmp", "tiff", "heif"].includes(legacy)) return "structure";
    return legacy === "qr" ? "qr" : "overview";
  });
  const [imageFormatLayer, setImageFormatLayer] = React.useState<"container" | "exif" | "PNG" | "GIF" | "JPEG" | "WEBP" | "BMP" | "TIFF" | "HEIF/AVIF">("container");
  const [qrResult, setQrResult] = React.useState<ImageQrResult | null>(null);
  const [qrScanning, setQrScanning] = React.useState(false);
  const [lightbox, setLightbox] = React.useState<{ src: string; label: string; open?: boolean } | null>(null);
  const [restoredSource, setRestoredSource] = React.useState<ImageWorkspace | null>(null);
  React.useEffect(() => {
    if (!active || typeof window === "undefined") return;
    const legacy = window.location.hash.replace(/^#/, "").toLowerCase();
    if (legacy === "png") { setImagePage("structure"); setImageFormatLayer("PNG"); }
    else if (["gif", "jpeg", "webp", "bmp", "tiff", "heif"].includes(legacy)) { setImagePage("structure"); setImageFormatLayer(legacy === "heif" ? "HEIF/AVIF" : legacy.toUpperCase() as "GIF" | "JPEG" | "WEBP" | "BMP" | "TIFF"); }
    else if (legacy === "qr") setImagePage("qr");
  }, [active]);

  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const analysisIdRef = React.useRef(0);
  const abortRef = React.useRef<AbortController | null>(null);
  const guard = useStaleRunGuard(active);
  const channelTimerRef = React.useRef<number | null>(null);
  const autoHiddenAnalysisRef = React.useRef<number | null>(null);
  const restoreStartedRef = React.useRef(false);
  const sourceRef = React.useRef<{ file: File; bytes: Uint8Array; image: HTMLImageElement | null; exif: Record<string, unknown>; rawDataUrl: string; format: string } | null>(null);
  const workspace = useToolWorkspace<ImageWorkspace>({
    id: "image",
    version: 2,
    isValid: (value): value is ImageWorkspace => Boolean(value && typeof value === "object" && typeof (value as ImageWorkspace).name === "string" && (value as ImageWorkspace).bytes instanceof Uint8Array),
    onRestore: setRestoredSource
  });

  React.useEffect(() => () => {
    analysisIdRef.current += 1;
    abortRef.current?.abort();
    if (channelTimerRef.current !== null) window.clearTimeout(channelTimerRef.current);
    revokeImageObjectUrls();
  }, [revokeImageObjectUrls]);

  React.useEffect(() => {
    if (active) return;
    setLightbox(null);
    analysisIdRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    if (channelTimerRef.current !== null) {
      window.clearTimeout(channelTimerRef.current);
      channelTimerRef.current = null;
    }
    setLoading(false);
    updateAdvancedTask("");
    setIsImageDropActive(false);
  }, [active]);

  const runImageWorker = <T,>(request: ImageWorkerRequest, transfer: Transferable[], signal: AbortSignal) => runWorkerTask<ImageWorkerRequest, T>({
    createWorker: () => new Worker(new URL("../features/image/image.worker.ts", import.meta.url), { type: "module" }),
    request,
    transfer,
    signal,
    timeoutMs: 120_000
  });

  const handleImage = async (file: File | undefined, persist = true) => {
    if (!file || !active) return;
    setLightbox(null);
    if (persist) {
      restoreStartedRef.current = true;
      setRestoredSource(null);
      workspace.clear();
    }
    if (persist) setStorageNotice("");
    analysisIdRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    if (channelTimerRef.current !== null) {
      window.clearTimeout(channelTimerRef.current);
      channelTimerRef.current = null;
    }
    services.revokeImageObjectUrls();
    sourceRef.current = null;
    setImageInfo(null);
    updateAdvancedTask("");
    setQrResult(null);
    setQrScanning(false);
    setImagePage("overview");
    setLoading(false);
    autoHiddenAnalysisRef.current = null;
    if (file.size > MAX_IMAGE_FILE_BYTES) {
      setError(isEnglish ? "This image exceeds the 64 MiB browser analysis limit." : "图片超过 64 MiB，无法在浏览器中直接分析。");
      return;
    }
    const analysisId = analysisIdRef.current + 1;
    analysisIdRef.current = analysisId;
    const requestId = guard.next();
    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(true);
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      const detectedFormat = detectImageFormat(bytes, file.type);
      const guessedDimensions = guessImageDimensions(bytes, detectedFormat);
      const oversizedHeader = guessedDimensions.width * guessedDimensions.height > 50_000_000 || guessedDimensions.width > 65535 || guessedDimensions.height > 65535;
      const sourceMime = /^image\//i.test(file.type) ? file.type : imageMimeForFormat(detectedFormat, file.type || "application/octet-stream");
      const rawDataUrl = await bytesToDataUrl(bytes, sourceMime);
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      let image: HTMLImageElement | null = null;
      let displayDataUrl = rawDataUrl;
      let heicPreview = false;
      let heicError = "";
      if (!oversizedHeader) { try { image = await loadBrowserImage(rawDataUrl); } catch { image = null; } }
      if (!image && !oversizedHeader && detectedFormat === "HEIF/AVIF") {
        try {
          const png = await runWorkerTask<{ file: Blob }, ArrayBuffer>({
            createWorker: () => new Worker(new URL("../features/image/heic.worker.ts", import.meta.url), { type: "module" }),
            request: { file }, signal: controller.signal, timeoutMs: 120_000
          });
          if (controller.signal.aborted || analysisId !== analysisIdRef.current) return;
          displayDataUrl = await bytesToDataUrl(new Uint8Array(png), "image/png");
          if (controller.signal.aborted || analysisId !== analysisIdRef.current) { revokeImagePreviewUrl(displayDataUrl); return; }
          image = await loadBrowserImage(displayDataUrl);
          heicPreview = true;
        } catch (caught) {
          if (controller.signal.aborted) return;
          heicError = caught instanceof Error ? caught.message : String(caught);
        }
      }
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      if (image && image.naturalWidth * image.naturalHeight > 50_000_000) {
        throw new Error(isEnglish ? "Decoded image dimensions exceed the 50 megapixel analysis limit." : "解码后的图片尺寸超过 5000 万像素分析上限。");
      }
      if (analysisId !== analysisIdRef.current) return;
      const decoded = Boolean(image);
      const dimensions = image ? { width: image.naturalWidth, height: image.naturalHeight } : guessImageDimensions(bytes, detectedFormat);
      const placeholderDataUrl = imagePlaceholderDataUrl(
        isEnglish ? "Image pixels could not be decoded" : "图片像素暂时无法解码",
        isEnglish ? "Open Repair to recover dimensions and container." : "原始数据已保留，请进入修复页检查宽高与容器。",
        "warn"
      );
      const effectiveDisplayDataUrl = image ? displayDataUrl : placeholderDataUrl;
      const workerBytes = bytes.slice();
      const workerResult = await runImageWorker<ImageBasicsWorkerResult>({
        action: "basics",
        bytes: workerBytes.buffer,
        fileType: file.type
      }, [workerBytes.buffer], controller.signal);
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      const { analysis, exif } = workerResult;
      sourceRef.current = { file, bytes, image, exif, rawDataUrl, format: detectedFormat };
      if (analysisId !== analysisIdRef.current) return;
      const nextImageInfo: ImageInfo = {
        name: file.name,
        size: file.size,
        type: `${file.type || "unknown"} / ${detectedFormat}`,
        decoded,
        width: dimensions.width,
        height: dimensions.height,
        dataUrl: effectiveDisplayDataUrl,
        repairedDataUrl: "",
        repairedContainerBytes: null,
        repairStatus: heicPreview ? (isEnglish ? "HEIC/HEIF decoded locally for preview; metadata comes from the original file." : "已在本地解码 HEIC/HEIF 预览；元数据读取自原文件。") : heicError ? `${isEnglish ? "HEIC/HEIF preview unavailable; original metadata is still analyzed" : "HEIC/HEIF 预览解码未成功，仍分析原文件元数据"} (${heicError})` : decoded ? (isEnglish ? "Image opened successfully." : "图片可正常打开。") : (isEnglish ? "Open Repair to try recovery." : "可进入修复页尝试恢复。"),
        recoveryRows: [],
        exif,
        containerFindings: analysis.findings,
        hiddenFindings: [],
        structureRows: analysis.rows,
        hiddenRows: analysis.hiddenRows,
        trailerBytes: analysis.trailerBytes,
        trailerPreview: analysis.trailerPreview,
        trailerText: analysis.trailerText,
        lsbCandidates: analysis.lsbCandidates,
        hiddenPayloads: analysis.hiddenPayloads,
        repairDownloads: [],
        pngTextEntries: analysis.pngTextEntries,
        pngChunks: analysis.pngChunks,
        repairPreviewItems: [],
        autoRevealPreviews: [],
        formatLayers: analysis.formatLayer ? [analysis.formatLayer] : [],
        channelDataUrls: emptyImageChannels(placeholderDataUrl)
      };
      guard.commit(requestId, () => {
        setImageInfo(nextImageInfo);
        publishAnalysisResult("image", buildImageEnvelope(nextImageInfo));
      });
      if (persist) {
        if (file.size <= MAX_PERSISTED_IMAGE_BYTES) {
          workspace.save({ name: file.name, type: file.type, lastModified: file.lastModified, bytes });
        } else {
          setStorageNotice(isEnglish
            ? "This image is available for the current session only; images over 8 MiB are not restored automatically."
            : "当前图片仅在本次打开期间保留；超过 8 MiB 的图片不会自动恢复。");
        }
      }
      setPreviewVersion("original");
      setImagePage("overview");
    } catch (caught) {
      if (analysisId !== analysisIdRef.current) return;
      if (caught instanceof DOMException && caught.name === "AbortError") return;
      services.revokeImageObjectUrls();
      sourceRef.current = null;
      setImageInfo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      if (analysisId === analysisIdRef.current) setLoading(false);
    }
  };
  const handleImageRef = React.useRef(handleImage);
  handleImageRef.current = handleImage;
  React.useEffect(() => {
    if (!active) return;
    const consume = () => {
      const handoff = takeToolHandoff("image");
      if (handoff) void handleImageRef.current(handoff.file);
    };
    consume();
    return subscribeToolHandoff("image", consume);
  }, [active]);

  React.useEffect(() => {
    if (!active || !restoredSource || restoreStartedRef.current) return;
    restoreStartedRef.current = true;
    setRestoredSource(null);
    const bytes = restoredSource.bytes.slice();
    const file = new File([bytes.buffer], restoredSource.name, { type: restoredSource.type, lastModified: restoredSource.lastModified });
    void handleImage(file, false);
  }, [active, restoredSource]);
  const runHiddenAnalysis = async () => {
    const source = sourceRef.current;
    if (!active || !source || !imageInfo || advancedTaskRef.current) return;
    const analysisId = analysisIdRef.current;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    updateAdvancedTask("hidden");
    setError("");
    try {
      const workerBytes = source.bytes.slice();
      let analysis: ImageAnalysisResult;
      if (source.image) {
        const pixels = createImageAnalysisPixels(source.image) as { data: Uint8ClampedArray; width: number; height: number };
        analysis = await runImageWorker<ImageAnalysisResult>({
          action: "hidden-pixels",
          bytes: workerBytes.buffer,
          fileType: source.file.type,
          metadataFields: Object.keys(source.exif).length,
          pixels: pixels.data.buffer as ArrayBuffer,
          width: pixels.width,
          height: pixels.height
        }, [workerBytes.buffer, pixels.data.buffer as ArrayBuffer], controller.signal);
      } else {
        analysis = await runImageWorker<ImageAnalysisResult>({
          action: "hidden-undecoded",
          bytes: workerBytes.buffer,
          fileType: source.file.type,
          metadataFields: Object.keys(source.exif).length,
          recoveryRows: [["Original container", "failed"]]
        }, [workerBytes.buffer], controller.signal);
      }
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      setImageInfo((current) => {
        if (!current) return current;
        const next = { ...current, hiddenFindings: analysis.findings, hiddenRows: analysis.hiddenRows, trailerBytes: analysis.trailerBytes, trailerPreview: analysis.trailerPreview, trailerText: analysis.trailerText, lsbCandidates: analysis.lsbCandidates, hiddenPayloads: analysis.hiddenPayloads, pngTextEntries: analysis.pngTextEntries, pngChunks: analysis.pngChunks };
        publishAnalysisResult("image", buildImageEnvelope(next));
        return next;
      });
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      if (analysisId === analysisIdRef.current) updateAdvancedTask("");
    }
  };
  React.useEffect(() => {
    if (!active || !imageInfo || loading || advancedTask || !sourceRef.current) return;
    if (autoHiddenAnalysisRef.current === analysisIdRef.current) return;
    const scheduledId = analysisIdRef.current;
    const timer = window.setTimeout(() => {
      if (advancedTaskRef.current || scheduledId !== analysisIdRef.current) return;
      autoHiddenAnalysisRef.current = scheduledId;
      void runHiddenAnalysis();
    }, 120);
    return () => window.clearTimeout(timer);
    // Run once for each newly loaded image; subsequent page changes must not repeat the scan.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, imageInfo?.name, loading, advancedTask]);
  const runChannelAnalysis = () => {
    const source = sourceRef.current;
    if (!active || !source?.image || !imageInfo || advancedTaskRef.current) return;
    const analysisId = analysisIdRef.current;
    updateAdvancedTask("channels");
    setError("");
    if (channelTimerRef.current !== null) window.clearTimeout(channelTimerRef.current);
    channelTimerRef.current = window.setTimeout(() => {
      channelTimerRef.current = null;
      void (async () => {
        try {
          if (!active || analysisId !== analysisIdRef.current) return;
          const channels = await createChannelPreviews(source.image!, () => analysisId !== analysisIdRef.current);
          if (!active || !channels || analysisId !== analysisIdRef.current) return;
          setImageInfo((current) => {
            if (!current) return current;
            services.revokeImagePreviewUrls(current.channelDataUrls);
            return { ...current, channelDataUrls: channels, autoRevealPreviews: buildAutoRevealPreviews(channels, false) };
          });
        } catch (caught) {
          setError(caught instanceof Error ? caught.message : String(caught));
        } finally {
          if (analysisId === analysisIdRef.current) updateAdvancedTask("");
        }
      })();
    }, 0);
  };
  const runRepairAnalysis = async () => {
    const source = sourceRef.current;
    if (!active || !source || !imageInfo || advancedTaskRef.current) return;
    const analysisId = analysisIdRef.current;
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    updateAdvancedTask("repair");
    setError("");
    const previewUrls: string[] = [];
    let committed = false;
    try {
      const workerBytes = source.bytes.slice();
      const repair = await runImageWorker<ImageRepairWorkerResult>({ action: "repair", bytes: workerBytes.buffer, format: source.format }, [workerBytes.buffer], controller.signal);
      const dimensionResult = repair.dimensions;
      const dimensionCandidates: ImageRepairCandidate[] = (dimensionResult?.candidates ?? []).map(candidate => ({
        label: isEnglish ? `PNG dimensions ${candidate.width} × ${candidate.height}` : `PNG 宽高恢复 ${candidate.width} × ${candidate.height}`,
        note: candidate.crcMatch ? (isEnglish ? "Original IHDR CRC and full filtered scanlines match. Only dimensions and IHDR CRC are written; other bytes are preserved." : "原 IHDR CRC 与完整扫描行同时匹配；仅写入宽高与 IHDR CRC，其余字节保留。") : (isEnglish ? "Scanline candidate only; original CRC does not confirm it. Compare the preview before choosing." : "仅根据扫描行推导的候选，原 CRC 无法确认。请比较预览后选择，不代表已确定原始尺寸。"),
        bytes: candidate.bytes, mime: "image/png"
      }));
      const candidates: ImageRepairCandidate[] = [...dimensionCandidates, ...repair.candidates.map(candidate => ({ ...candidate, label: localizeAnalysisText(candidate.label, isEnglish), note: localizeAnalysisText(candidate.note, isEnglish) }))];
      const rebuiltPng = repair.rebuiltPng;
      if (rebuiltPng) candidates.push({ label: localizeAnalysisText("Rebuilt PNG critical chunks", isEnglish), note: rebuiltPng.notes.map(note => localizeAnalysisText(note, isEnglish)).join(" "), bytes: rebuiltPng.bytes, mime: "image/png" });
      const previews: ImageInfo["repairPreviewItems"] = [];
      const rows: Array<[string, string]> = dimensionResult?.status !== "not-png" && dimensionResult ? [
        [isEnglish ? "Declared dimensions" : "文件头声明尺寸", `${dimensionResult.declaredWidth} × ${dimensionResult.declaredHeight}`],
        [isEnglish ? "Dimension recovery" : "宽高恢复结论", dimensionRecoveryMessage(dimensionResult, isEnglish)],
        [isEnglish ? "Inflated scanline bytes" : "解压扫描行字节", formatBytes(dimensionResult.inflatedBytes)],
        [isEnglish ? "Search width range" : "宽度搜索范围", dimensionResult.searchedWidth ? `1–${dimensionResult.searchedWidth}` : "—"],
        [isEnglish ? "Candidate count" : "尺寸候选数", `${dimensionResult.candidateCount}${dimensionResult.candidateCount > dimensionResult.candidates.length ? (isEnglish ? ` (first ${dimensionResult.candidates.length} shown)` : `（展示前 ${dimensionResult.candidates.length} 个）`) : ""}`]
      ] : [];
      for (const candidate of candidates) {
        if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
        const guessed = guessImageDimensions(candidate.bytes, candidate.mime === "image/png" ? "PNG" : source.format);
        if (guessed.width * guessed.height > 50_000_000 || guessed.width > 65535 || guessed.height > 65535) {
          rows.push([candidate.label, isEnglish ? "Preview skipped: declared dimensions exceed limits" : "声明尺寸超限，跳过像素预览；容器候选仍可下载核对"]);
          continue;
        }
        const src = await bytesToDataUrl(candidate.bytes, candidate.mime);
        previewUrls.push(src);
        try {
          const decoded = await loadBrowserImage(src);
          if (decoded.naturalWidth * decoded.naturalHeight > 50_000_000) throw new Error("pixel-limit");
          previews.push({ label: candidate.label, src, detail: `${decoded.naturalWidth} × ${decoded.naturalHeight} · ${candidate.note}` });
          rows.push([candidate.label, isEnglish ? "Decoded" : "预览解码通过"]);
        }
        catch { rows.push([candidate.label, isEnglish ? "Decode failed" : "预览解码失败（保留候选供核对）"]); }
      }
      if (!active || controller.signal.aborted || analysisId !== analysisIdRef.current) return;
      const retained = new Set(previews.map((item) => item.src));
      previewUrls.filter((url) => !retained.has(url)).forEach(revokeImagePreviewUrl);
      setImageInfo((current) => {
        if (!current) return current;
        if (current.repairedDataUrl) revokeImagePreviewUrl(current.repairedDataUrl);
        current.repairPreviewItems.forEach((item) => revokeImagePreviewUrl(item.src));
        return {
          ...current,
        repairedDataUrl: previews[0]?.src || "",
        repairedContainerBytes: dimensionResult?.status === "recovered" && previews.some(item => item.label === dimensionCandidates[0]?.label) ? dimensionCandidates[0].bytes : rebuiltPng?.bytes ?? null,
        dimensionRecovery: dimensionResult?.status === "not-png" ? undefined : dimensionResult ? { ...dimensionResult, candidates: dimensionResult.candidates.map(({ bytes: _bytes, ...item }) => item) } : undefined,
        repairStatus: previews.length
          ? (isEnglish ? "A displayable repair result is available." : "已找到可显示的修复结果。")
          : source.image
            ? (isEnglish ? "The image already opens; no repair result was generated." : "图片当前可正常打开，未生成修复结果。")
            : (isEnglish ? "No displayable repair result was found." : "没有找到可显示的修复结果。"),
        recoveryRows: rows,
        repairPreviewItems: previews,
        repairDownloads: candidates.map((candidate) => ({ label: candidate.label, note: candidate.note, size: candidate.bytes.length, extension: imageExtensionForMime(candidate.mime), mime: candidate.mime, bytes: candidate.bytes }))
        };
      });
      if (previews.length) setPreviewVersion("recovered");
      committed = true;
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (!committed) previewUrls.forEach(revokeImagePreviewUrl);
      if (abortRef.current === controller) abortRef.current = null;
      if (analysisId === analysisIdRef.current) updateAdvancedTask("");
    }
  };
  const handleImageDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsImageDropActive(false);
    void handleImage(event.dataTransfer.files?.[0]);
  };
  const runQrAnalysis = async () => {
    const source = sourceRef.current;
    if (!active || !source?.image || qrScanning) return;
    const analysisId = analysisIdRef.current;
    setQrScanning(true);
    setError("");
    try {
      const image = source.image;
      const result = await scanQrRobust(image);
      if (!active || analysisId !== analysisIdRef.current) return;
      const code = result?.code ?? null;
      const scanWidth = result?.scanWidth ?? image.naturalWidth;
      const scanHeight = result?.scanHeight ?? image.naturalHeight;
      const scanStrategy = result?.strategy ?? "original";
      const payload = code?.data ?? "";
      const payloadType = services.classifyQrPayload(payload);
      const rawLocation = (code as unknown as { location?: Record<string, unknown> } | null)?.location ?? {};
      const location = scaledQrLocation(rawLocation, image.naturalWidth / scanWidth, image.naturalHeight / scanHeight);
      const cornerRows = [
        services.qrPointRow("Top-left", location.topLeftCorner),
        services.qrPointRow("Top-right", location.topRightCorner),
        services.qrPointRow("Bottom-left", location.bottomLeftCorner),
        services.qrPointRow("Bottom-right", location.bottomRightCorner)
      ].filter(Boolean) as QrPoint[];
      const decodedBytes = Array.isArray((code as unknown as { binaryData?: number[] } | null)?.binaryData)
        ? (code as unknown as { binaryData: number[] }).binaryData.length
        : new Blob([payload]).size;
      setQrResult({
        payload,
        payloadType,
        decodedBytes,
        scanWidth,
        scanHeight,
        scanStrategy,
        payloadRows: services.parseQrPayloadDetails(payload, payloadType),
        cornerRows,
        geometryRows: services.qrGeometryRows(location, image.naturalWidth, image.naturalHeight)
      });
    } catch (caught) {
      if (analysisId === analysisIdRef.current) setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (analysisId === analysisIdRef.current) setQrScanning(false);
    }
  };
  const clearImage = () => {
    setLightbox(null);
    restoreStartedRef.current = true;
    guard.next();
    setRestoredSource(null);
    workspace.clear();
    analysisIdRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    if (channelTimerRef.current !== null) {
      window.clearTimeout(channelTimerRef.current);
      channelTimerRef.current = null;
    }
    services.revokeImageObjectUrls();
    sourceRef.current = null;
    setImageInfo(null);
    setStorageNotice("");
    setError("");
    setLoading(false);
    updateAdvancedTask("");
    setQrResult(null);
    setQrScanning(false);
    setIsImageDropActive(false);
    setImagePage("overview");
    if (inputRef.current) inputRef.current.value = "";
  };
  const downloadTrailer = () => {
    if (!imageInfo?.trailerBytes.length) return;
    const copy = new Uint8Array(imageInfo.trailerBytes.byteLength);
    copy.set(imageInfo.trailerBytes);
    downloadBlob(`${imageInfo.name}-trailer.bin`, new Blob([copy.buffer], { type: "application/octet-stream" }));
  };
  const downloadContainerRepair = () => {
    if (!imageInfo?.repairedContainerBytes) return;
    const copy = new Uint8Array(imageInfo.repairedContainerBytes.byteLength);
    copy.set(imageInfo.repairedContainerBytes);
    downloadBlob(`${imageInfo.name.replace(/\.[^.]+$/, "") || "image"}-container-repair.png`, new Blob([copy.buffer], { type: "image/png" }));
  };
  const downloadRepairCandidate = (candidate: ImageInfo["repairDownloads"][number], index: number) => {
    const copy = new Uint8Array(candidate.bytes.byteLength);
    copy.set(candidate.bytes);
    const base = imageInfo?.name.replace(/\.[^.]+$/, "") || "image";
    downloadBlob(`${base}-repair-${index + 1}.${candidate.extension}`, new Blob([copy.buffer], { type: candidate.mime }));
  };
  const downloadHiddenPayload = (payload: ImageInfo["hiddenPayloads"][number], index: number) => {
    const copy = new Uint8Array(payload.bytes.byteLength);
    copy.set(payload.bytes);
    const base = imageInfo?.name.replace(/\.[^.]+$/, "") || "image";
    downloadBlob(`${base}-payload-${index + 1}-${payload.offset}.${payload.extension}`, new Blob([copy.buffer], { type: payload.mime }));
  };
  const copyHiddenText = () => {
    if (!imageInfo) return;
    const content = [
      ...imageInfo.lsbCandidates.map((candidate) => `[${candidate.mode}]\n${candidate.text}`),
      ...imageInfo.pngTextEntries.map((entry) => `[PNG ${entry.chunk} ${entry.keyword} @ ${entry.offset}]\n${entry.text}`),
      imageInfo.trailerText ? `[Trailer]\n${imageInfo.trailerText}` : ""
    ].filter(Boolean).join("\n\n");
    void copyText(content || "");
  };
  const pngBadCrc = imageInfo?.pngChunks.filter((chunk) => !chunk.ok) ?? [];
  const pngRiskChunks = imageInfo?.pngChunks.filter((chunk) => chunk.risk.length) ?? [];
  const pngIdatBytes = imageInfo?.pngChunks.filter((chunk) => chunk.type === "IDAT").reduce((sum, chunk) => sum + chunk.length, 0) ?? 0;
  const pngHasIend = imageInfo?.pngChunks.some((chunk) => chunk.type === "IEND") ?? false;
  const channelItems: Array<[string, string]> = imageInfo ? [
    [t.red, imageInfo.channelDataUrls.red],
    [t.green, imageInfo.channelDataUrls.green],
    [t.blue, imageInfo.channelDataUrls.blue],
    [t.alpha, imageInfo.channelDataUrls.alpha],
    [isEnglish ? "Noise" : "噪声", imageInfo.channelDataUrls.noiseMap],
    [isEnglish ? "Low-bit heatmap" : "低位热图", imageInfo.channelDataUrls.lowBitHeatmap],
    [t.lsb, imageInfo.channelDataUrls.lsb],
    ["LSB R", imageInfo.channelDataUrls.lsbRed],
    ["LSB G", imageInfo.channelDataUrls.lsbGreen],
    ["LSB B", imageInfo.channelDataUrls.lsbBlue]
  ] : [];

  return (
    <div className={`tool-grid image-workbench image-workbench-simple ${imageInfo ? "has-image" : "empty-image"}`}>
      <div
        className="tool-panel wide-panel image-source-panel"
        onDragOver={(event) => { event.preventDefault(); setIsImageDropActive(true); }}
        onDragLeave={() => setIsImageDropActive(false)}
        onDrop={handleImageDrop}
      >
        <PanelTitle title={t.uploadImage} />
        {imageInfo && <div className="image-source-file"><strong>{imageInfo.name}</strong><span>{formatBytes(imageInfo.size)} · {imageInfo.width} × {imageInfo.height}</span></div>}
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept="image/*,.png,.jpg,.jpeg,.gif,.webp,.bmp,.tif,.tiff,.heic,.heif,.bin" onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; void handleImage(file); }} />
        <div className={`desktop-drop-zone ${isImageDropActive ? "active" : ""}`} role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}>
          <strong>{imageInfo?.name || t.dropFileTitle}</strong>
          <span>{imageInfo ? `${imageInfo.type} · ${formatBytes(imageInfo.size)}` : (isEnglish ? "PNG, JPEG, GIF, WebP, BMP, TIFF, HEIC, or image-like data" : "支持 PNG、JPEG、GIF、WebP、BMP、TIFF、HEIC 和疑似图片数据")}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <PasteButton english={isEnglish} />
          <AButton variant="text" disabled={!imageInfo && !error && !loading} onClick={clearImage}>{t.clear}</AButton>
        </div>
        {storageNotice && <div className="tool-storage-note" role="status">{storageNotice}</div>}
        {(loading || advancedTask) && <ALinearProgress />}
        {error && <ErrorNotice message={error} />}
      </div>

      {imageInfo && <>
        <ASegmentedGroup className="image-page-tabs wide-panel" value={imagePage} selects="single" aria-label={isEnglish ? "Image result pages" : "图片结果分页"}>
          <ASegmentedButton value="overview" onClick={() => setImagePage("overview")}>{isEnglish ? "Overview" : "概览"}</ASegmentedButton>
          <ASegmentedButton value="structure" onClick={() => setImagePage("structure")}>{isEnglish ? "Structure" : "结构"}</ASegmentedButton>
          <ASegmentedButton value="hidden" onClick={() => setImagePage("hidden")}>{isEnglish ? "Hidden data" : "隐藏数据"}</ASegmentedButton>
          <ASegmentedButton value="channels" onClick={() => setImagePage("channels")}>{isEnglish ? "Channels" : "通道"}</ASegmentedButton>
          <ASegmentedButton value="qr" onClick={() => setImagePage("qr")}>{isEnglish ? "QR" : "二维码"}</ASegmentedButton>
          <ASegmentedButton value="repair" onClick={() => setImagePage("repair")}>{isEnglish ? "Repair" : "修复"}</ASegmentedButton>
        </ASegmentedGroup>

        {imagePage === "overview" && <div className="tool-panel wide-panel image-simple-overview-panel">
          <ImageReviewSummary image={imageInfo} english={isEnglish} onNavigate={setImagePage} />
          <div className="image-simple-overview">
            <div className="image-simple-preview">
              {imageInfo.repairedDataUrl && <ASegmentedGroup value={previewVersion} selects="single" aria-label={isEnglish ? "Compare original and recovery" : "原图与修复副本对照"}><ASegmentedButton value="original" onClick={() => setPreviewVersion("original")}>{isEnglish ? "Original" : "原始图片"}</ASegmentedButton><ASegmentedButton value="recovered" onClick={() => setPreviewVersion("recovered")}>{isEnglish ? "Recovered copy" : "修复副本"}</ASegmentedButton></ASegmentedGroup>}
              <ImageViewer src={previewVersion === "recovered" && imageInfo.repairedDataUrl ? imageInfo.repairedDataUrl : imageInfo.dataUrl} label={imageInfo.name} english={isEnglish} onExpand={() => setLightbox({ src: previewVersion === "recovered" && imageInfo.repairedDataUrl ? imageInfo.repairedDataUrl : imageInfo.dataUrl, label: imageInfo.name })} />
            </div>
            <div className="image-simple-facts">
              <PanelTitle title={t.imageOverview} />
              <InfoTable rows={[
                [isEnglish ? "Name" : "名称", imageInfo.name],
                [t.fileType, imageInfo.type],
                [t.fileSize, formatBytes(imageInfo.size)],
                [imageInfo.decoded ? t.dimensions : (isEnglish ? "Declared dimensions (unverified)" : "声明尺寸（未验证）"), imageInfo.width && imageInfo.height ? `${imageInfo.width} × ${imageInfo.height}` : "--"],
                [isEnglish ? "Display" : "显示状态", imageInfo.decoded ? (isEnglish ? "Opened" : "可打开") : (isEnglish ? "Not decoded" : "无法解码")],
                [t.repairStatus, imageInfo.repairStatus],
                [t.exif, String(Object.keys(imageInfo.exif).length)],
                [isEnglish ? "Extracted items" : "提取项", String(imageInfo.hiddenPayloads.length)],
                [isEnglish ? "Trailer" : "尾部数据", formatBytes(imageInfo.trailerBytes.length)]
              ]} />
              <div className="action-row">
                {imageInfo.decoded && imageInfo.type.includes("HEIF/AVIF") && <AButton variant="outlined" onClick={async () => {
                  const image = sourceRef.current?.image;
                  if (!image) return;
                  const canvas = document.createElement("canvas");
                  try {
                    canvas.width = image.naturalWidth; canvas.height = image.naturalHeight;
                    canvas.getContext("2d")!.drawImage(image, 0, 0);
                    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
                    if (blob) downloadBlob(`${imageInfo.name.replace(/\.[^.]+$/, "")}-preview.png`, blob);
                  } finally { canvas.width = 1; canvas.height = 1; }
                }}>{isEnglish ? "Export PNG preview" : "导出 PNG 预览"}</AButton>}
                {imageInfo.decoded && imageInfo.repairedDataUrl && <AButton variant="outlined" href={imageInfo.repairedDataUrl} download={`${imageInfo.name.replace(/\.[^.]+$/, "") || "image"}-normalized.png`}>{t.downloadRepaired}</AButton>}
                <AButton variant="outlined" disabled={!imageInfo.hiddenPayloads.length} onClick={() => setImagePage("hidden")}>{isEnglish ? "View extracted" : "查看提取项"}</AButton>
              </div>
            </div>
          </div>
          <ImageMetadataHighlights metadata={imageInfo.exif} english={isEnglish} />
          <ImageMetadata metadata={imageInfo.exif} name={imageInfo.name} english={isEnglish} formatValue={formatExifValue} showHighlights={false} />
        </div>}

        {imagePage === "structure" && <div className="tool-panel wide-panel image-simple-structure-panel">
          <PanelTitle title={t.imageStructure} />
          <ASegmentedGroup className="image-format-layer-tabs" value={imageFormatLayer} selects="single" aria-label={isEnglish ? "Format analysis layers" : "格式分析层"}>
            <ASegmentedButton value="container" onClick={() => setImageFormatLayer("container")}>{isEnglish ? "Container" : "容器"}</ASegmentedButton>
            {imageInfo.formatLayers.map((layer) => (
              <ASegmentedButton key={layer.format} value={layer.format} onClick={() => setImageFormatLayer(layer.format)}>{layer.format}</ASegmentedButton>
            ))}
          </ASegmentedGroup>

          {imageFormatLayer === "container" && <>
            <div className="finding-list">{sortFindings([...(imageInfo.containerFindings ?? []), ...imageInfo.formatLayers.flatMap(layer => layer.findings)]).map((finding, index) => <FindingCard key={index} finding={finding} english={isEnglish} />)}</div>
            <InfoTable rows={imageInfo.structureRows.map(([key,value]) => [key, localizeAnalysisText(value, isEnglish)] as [string,string])} />
            <ImageMetadata metadata={imageInfo.exif} name={imageInfo.name} english={isEnglish} formatValue={formatExifValue} />
          </>}

          {imageInfo.formatLayers.filter((layer) => layer.format === imageFormatLayer).map((layer) => (
            <React.Fragment key={layer.format}>
              <InfoTable rows={layer.rows.map(([key,value]) => [key, localizeAnalysisText(value, isEnglish)] as [string,string])} />
              {layer.findings.length > 0 && <>
                <PanelTitle title={isEnglish ? "Format findings" : "格式检查记录"} />
                <div className="finding-list">{sortFindings(layer.findings).map((finding, index) => <FindingCard finding={finding} english={isEnglish} key={`fl-${index}`} />)}</div>
              </>}

              {layer.format === "PNG" && imageInfo.pngChunks.length > 0 && <>
                <PanelTitle title={isEnglish ? "PNG forensic structure" : "PNG 取证结构"} />
                <InfoTable rows={[
                  ["Chunks", String(imageInfo.pngChunks.length)],
                  ["IDAT", formatBytes(pngIdatBytes)],
                  ["CRC", pngBadCrc.length ? (isEnglish ? `${pngBadCrc.length} mismatch` : `${pngBadCrc.length} 个块校验失败`) : (isEnglish ? "Passed" : "校验通过")],
                  ["IEND", pngHasIend ? (isEnglish ? "Present" : "存在") : (isEnglish ? "Missing" : "缺失")],
                  [isEnglish ? "Text chunks" : "文本块", String(imageInfo.pngTextEntries.length)],
                  [isEnglish ? "Risk / private chunks" : "风险 / 私有块", String(pngRiskChunks.length)],
                  [isEnglish ? "Trailer" : "尾部数据", formatBytes(imageInfo.trailerBytes.length)]
                ]} />
                {pngRiskChunks.length > 0 && <div className="finding-list">{pngRiskChunks.slice(0, 32).map((chunk) => <FindingCard key={`png-risk-${chunk.offset}-${chunk.type}`} english={isEnglish} finding={{ level: pngChunkSeverity(chunk), title: `${chunk.type} @ 0x${chunk.offset.toString(16).toUpperCase()}`, detail: chunk.risk.map(risk => localizeAnalysisText(risk, isEnglish)).join("；") }} />)}</div>}
                <div className="table-scroll image-chunk-scroll"><table className="data-table"><thead><tr><th>#</th><th>Chunk</th><th>{isEnglish ? "Offset" : "偏移"}</th><th>{isEnglish ? "Length" : "长度"}</th><th>CRC</th><th>{isEnglish ? "Flags" : "属性"}</th></tr></thead><tbody>{imageInfo.pngChunks.map((chunk, index) => <tr className={chunk.ok ? "" : "analysis-row-danger"} key={`${chunk.offset}-${chunk.type}`}><td>{index + 1}</td><td>{chunk.type}</td><td>0x{chunk.offset.toString(16).toUpperCase()}</td><td>{formatBytes(chunk.length)}</td><td>{chunk.ok ? (isEnglish ? "Passed" : "通过") : <><strong className="analysis-text-danger">{isEnglish ? "CRC mismatch" : "校验失败"}</strong><br/>{isEnglish ? "Stored" : "保存值"} {chunk.crc}<br/>{isEnglish ? "Computed" : "计算值"} {chunk.computed}</>}</td><td>{[chunk.ancillary ? (isEnglish ? "ancillary" : "辅助块") : (isEnglish ? "critical" : "关键块"), chunk.privateUse ? (isEnglish ? "private" : "私有") : (isEnglish ? "public" : "公开"), chunk.safeToCopy ? (isEnglish ? "safe-copy" : "可安全复制") : (isEnglish ? "unsafe-copy" : "不可随意复制")].join(" · ")}</td></tr>)}</tbody></table></div>
              </>}

              {layer.format === "GIF" && <>
                <PanelTitle title={isEnglish ? "GIF summary" : "GIF 概要"} />
                <InfoTable rows={[
                  ["Version", layer.gif.version],
                  ["Screen", `${layer.gif.screenWidth} × ${layer.gif.screenHeight}`],
                  [isEnglish ? "Global color table" : "全局色表", layer.gif.globalColorTable ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  [isEnglish ? "Loop count" : "循环次数", layer.gif.loopCount === null ? (isEnglish ? "not set / infinite" : "未设置 / 无限") : String(layer.gif.loopCount)],
                  [isEnglish ? "Frame count" : "帧数", String(layer.gif.frameCount)],
                  [isEnglish ? "Comment count" : "注释数", String(layer.gif.commentCount)],
                  [isEnglish ? "Trailing bytes" : "尾部残留", formatBytes(layer.gif.trailingBytes)]
                ]} />
                {layer.gif.frames.length > 0 && <>
                  <PanelTitle title={isEnglish ? "GIF frames" : "GIF 帧"} />
                  <div className="table-scroll"><table className="data-table"><thead><tr><th>#</th><th>{isEnglish ? "Dimensions" : "尺寸"}</th><th>{isEnglish ? "Delay (cs)" : "延迟(厘秒)"}</th><th>{isEnglish ? "Disposal" : "处置"}</th><th>{isEnglish ? "Transparent" : "透明"}</th><th>{isEnglish ? "Local CT" : "局部色表"}</th></tr></thead><tbody>{layer.gif.frames.map((frame) => <tr key={frame.index}><td>{frame.index + 1}</td><td>{frame.width} × {frame.height}{frame.left || frame.top ? ` @${frame.left},${frame.top}` : ""}</td><td>{frame.delayCentiseconds}</td><td>{frame.disposalMethod}</td><td>{frame.transparentFlag ? (isEnglish ? `yes (${frame.transparentColorIndex})` : `是 (${frame.transparentColorIndex})`) : (isEnglish ? "no" : "否")}</td><td>{frame.localColorTable ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")}</td></tr>)}</tbody></table></div>
                </>}
                {layer.gif.comments.length > 0 && <>
                  <PanelTitle title={isEnglish ? "GIF comments" : "GIF 注释"} />
                  <div className="image-text-result-list">{layer.gif.comments.map((comment, index) => <label key={`gif-comment-${index}`}>{`${isEnglish ? "Comment" : "注释"} #${index + 1}`}<AutoTextarea className="single-textarea compact-textarea" value={comment} readOnly /></label>)}</div>
                </>}
                {layer.gif.applicationExtensions.length > 0 && <>
                  <PanelTitle title={isEnglish ? "GIF application extensions" : "GIF 应用扩展"} />
                  <div className="image-text-result-list">{layer.gif.applicationExtensions.map((ext, index) => <label key={`gif-appext-${index}`}>{`${isEnglish ? "App extension" : "应用扩展"} #${index + 1}`}<AutoTextarea className="single-textarea compact-textarea" value={ext} readOnly /></label>)}</div>
                </>}
              </>}

              {layer.format === "JPEG" && <>
                <PanelTitle title={isEnglish ? "JPEG summary" : "JPEG 概要"} />
                <InfoTable rows={[
                  [isEnglish ? "Marker count" : "标记数", String(layer.jpeg.markerCount)],
                  [isEnglish ? "Dimensions" : "尺寸", layer.jpeg.sof ? `${layer.jpeg.sof.width} × ${layer.jpeg.sof.height}` : "--"],
                  ["APP0 / JFIF", layer.jpeg.app0 ? `${layer.jpeg.app0.version} (${layer.jpeg.app0.density})` : (isEnglish ? "not present" : "不存在")],
                  ["EXIF", layer.jpeg.hasExif ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  ["XMP", layer.jpeg.hasXmp ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  ["Adobe APP14", layer.jpeg.hasAdobe === null ? (isEnglish ? "n/a" : "不适用") : (layer.jpeg.hasAdobe ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否"))],
                  [isEnglish ? "Comments" : "注释", String(layer.jpeg.commentCount)],
                  [isEnglish ? "Thumbnail" : "缩略图", layer.jpeg.hasThumbnail ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")]
                ]} />
                {layer.jpeg.markers.length > 0 && <>
                  <PanelTitle title={isEnglish ? "JPEG markers" : "JPEG 标记"} />
                  <div className="table-scroll"><table className="data-table"><thead><tr><th>{isEnglish ? "Marker" : "标记"}</th><th>{isEnglish ? "Offset" : "偏移"}</th><th>{isEnglish ? "Label" : "标签"}</th></tr></thead><tbody>{layer.jpeg.markers.map((marker, index) => <tr key={`jpeg-marker-${index}`}><td>{marker.marker}</td><td>0x{marker.offset.toString(16).toUpperCase()}</td><td>{marker.label}</td></tr>)}</tbody></table></div>
                </>}
              </>}

              {layer.format === "WEBP" && <>
                <PanelTitle title={isEnglish ? "WEBP summary" : "WEBP 概要"} />
                <InfoTable rows={[
                  [isEnglish ? "Chunk count" : "块数", String(layer.webp.chunkCount)],
                  ["VP8X", layer.webp.hasVp8x ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  [isEnglish ? "Canvas" : "画布", layer.webp.hasVp8x ? `${layer.webp.canvasWidth} × ${layer.webp.canvasHeight}` : "--"],
                  [isEnglish ? "Alpha" : "透明", layer.webp.hasAlpha ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  [isEnglish ? "Animation" : "动画", layer.webp.isAnimation ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  ["EXIF", layer.webp.hasExif ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  ["XMP", layer.webp.hasXmp ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  ["ICC", layer.webp.hasIcc ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")]
                ]} />
                {layer.webp.chunks.length > 0 && <>
                  <PanelTitle title={isEnglish ? "WEBP chunks" : "WEBP 块"} />
                  <div className="table-scroll"><table className="data-table"><thead><tr><th>FourCC</th><th>{isEnglish ? "Size" : "大小"}</th><th>{isEnglish ? "Offset" : "偏移"}</th></tr></thead><tbody>{layer.webp.chunks.map((chunk, index) => <tr key={`webp-chunk-${index}`}><td>{chunk.fourcc}</td><td>{formatBytes(chunk.size)}</td><td>0x{chunk.offset.toString(16).toUpperCase()}</td></tr>)}</tbody></table></div>
                </>}
              </>}

              {layer.format === "BMP" && <>
                <PanelTitle title={isEnglish ? "BMP header" : "BMP 文件头"} />
                <InfoTable rows={[
                  [isEnglish ? "DIB header" : "DIB 头", layer.bmp.dibHeaderType],
                  [isEnglish ? "Dimensions" : "尺寸", `${layer.bmp.width} × ${layer.bmp.height}`],
                  [isEnglish ? "Planes" : "面数", String(layer.bmp.planes)],
                  ["BPP", String(layer.bmp.bpp)],
                  [isEnglish ? "Compression" : "压缩", `${layer.bmp.compression} (${layer.bmp.compressionName})`],
                  [isEnglish ? "Important colors" : "重要颜色", String(layer.bmp.importantColors)],
                  [isEnglish ? "Color masks" : "颜色掩码", layer.bmp.colorMasks ? `R:0x${layer.bmp.colorMasks.red.toString(16)} G:0x${layer.bmp.colorMasks.green.toString(16)} B:0x${layer.bmp.colorMasks.blue.toString(16)} A:0x${layer.bmp.colorMasks.alpha.toString(16)}` : (isEnglish ? "not present" : "不存在")]
                ]} />
              </>}

              {layer.format === "TIFF" && <>
                <PanelTitle title={isEnglish ? "TIFF summary" : "TIFF 概要"} />
                <InfoTable rows={[
                  [isEnglish ? "Endian" : "字节序", layer.tiff.endian],
                  ["Magic", String(layer.tiff.magic)],
                  [isEnglish ? "IFD0 offset" : "IFD0 偏移", String(layer.tiff.ifd0Offset)],
                  [isEnglish ? "Entry count" : "条目数", String(layer.tiff.entryCount)],
                  [isEnglish ? "Dimensions" : "尺寸", layer.tiff.width && layer.tiff.height ? `${layer.tiff.width} × ${layer.tiff.height}` : "--"]
                ]} />
                {layer.tiff.entries.length > 0 && <>
                  <PanelTitle title={isEnglish ? "TIFF IFD entries" : "TIFF IFD 条目"} />
                  <div className="table-scroll"><table className="data-table"><thead><tr><th>{isEnglish ? "Tag" : "标签"}</th><th>{isEnglish ? "Name" : "名称"}</th><th>{isEnglish ? "Type" : "类型"}</th><th>{isEnglish ? "Count" : "数量"}</th><th>{isEnglish ? "Value" : "值"}</th></tr></thead><tbody>{layer.tiff.entries.map((entry, index) => <tr key={`tiff-entry-${index}`}><td>0x{entry.tag.toString(16).toUpperCase()}</td><td>{entry.tagName}</td><td>{entry.type}</td><td>{String(entry.count)}</td><td>{entry.value}</td></tr>)}</tbody></table></div>
                </>}
              </>}

              {layer.format === "HEIF/AVIF" && <>
                <PanelTitle title={isEnglish ? "HEIF/AVIF summary" : "HEIF/AVIF 概要"} />
                <InfoTable rows={[
                  [isEnglish ? "Major brand" : "主品牌", layer.heif.majorBrand],
                  [isEnglish ? "Minor version" : "次版本", String(layer.heif.minorVersion)],
                  [isEnglish ? "Dimensions" : "尺寸", layer.heif.width && layer.heif.height ? `${layer.heif.width} × ${layer.heif.height}` : "--"],
                  ["meta", layer.heif.hasMeta ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")],
                  ["mdia", layer.heif.hasMdia ? (isEnglish ? "yes" : "是") : (isEnglish ? "no" : "否")]
                ]} />
                {layer.heif.compatibleBrands.length > 0 && <>
                  <PanelTitle title={isEnglish ? "Compatible brands" : "兼容品牌"} />
                  <InfoTable rows={layer.heif.compatibleBrands.map((brand, index) => [`${isEnglish ? "Brand" : "品牌"} #${index + 1}`, brand])} />
                </>}
              </>}
            </React.Fragment>
          ))}

          {imageFormatLayer !== "container" && !imageInfo.formatLayers.some((layer) => layer.format === imageFormatLayer) && <div className="empty-state">{isEnglish ? "This file was not detected as that format, so no dedicated structure layer is shown." : "该图片未被识别为此格式，无独立结构层。"}</div>}
        </div>}

        {imagePage === "hidden" && <div className="tool-panel wide-panel image-simple-hidden-panel">
          <div className="panel-heading-row"><PanelTitle title={t.hiddenData} /><div className="button-row compact-buttons"><AButton variant="filled" disabled={Boolean(advancedTask)} onClick={() => void runHiddenAnalysis()}>{advancedTask === "hidden" ? (isEnglish ? "Scanning..." : "正在扫描...") : (isEnglish ? "Reveal common steganography" : "一键还原常见隐写")}</AButton><AButton variant="outlined" disabled={!imageInfo.trailerBytes.length} onClick={downloadTrailer}>{t.downloadHiddenData}</AButton><AButton variant="text" disabled={!imageInfo.lsbCandidates.length && !imageInfo.pngTextEntries.length && !imageInfo.trailerText} onClick={copyHiddenText}>{t.copyHiddenText}</AButton></div></div>
          <div className="finding-list">{sortFindings(imageInfo.hiddenFindings ?? []).map((finding, index) => <FindingCard key={index} finding={finding} english={isEnglish} />)}</div>
          <InfoTable rows={imageInfo.hiddenRows.map(([key,value]) => [key, localizeAnalysisText(value, isEnglish)] as [string,string])} />
          {imageInfo.hiddenPayloads.length > 0 && <><PanelTitle title={t.extractedPayloads} /><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{isEnglish ? "Source" : "来源"}</th><th>{isEnglish ? "Offset" : "偏移"}</th><th>{isEnglish ? "Type" : "类型"}</th><th>{t.fileSize}</th><th>{t.preview}</th><th></th></tr></thead><tbody>{imageInfo.hiddenPayloads.map((payload, index) => <tr key={`${payload.offset}-${index}`}><td>{payload.source}</td><td>{payload.offset}</td><td>{payload.label}</td><td>{formatBytes(payload.size)}</td><td>{payload.preview.slice(0, 160) || "--"}</td><td><AButton variant="outlined" onClick={() => downloadHiddenPayload(payload, index)}>{t.download}</AButton></td></tr>)}</tbody></table></div></>}
          {imageInfo.pngTextEntries.length > 0 && <><PanelTitle title={t.pngTextMetadata} /><div className="image-text-result-list">{imageInfo.pngTextEntries.map((entry) => <label key={`${entry.offset}-${entry.keyword}`}>{entry.keyword || entry.chunk}<AutoTextarea className="single-textarea compact-textarea" value={entry.text} readOnly /></label>)}</div></>}
          {imageInfo.lsbCandidates.length > 0 && <><PanelTitle title={t.lsbCandidates} /><div className="image-text-result-list">{imageInfo.lsbCandidates.map((candidate) => <label key={`${candidate.mode}-${candidate.text.slice(0, 20)}`}>{candidate.mode}<AutoTextarea className="single-textarea compact-textarea" value={candidate.text} readOnly /></label>)}</div></>}
          {imageInfo.trailerBytes.length > 0 && <><PanelTitle title={t.trailerData} /><AutoTextarea className="single-textarea image-trailer-preview" value={`${imageInfo.trailerPreview || "--"}\n\n${imageInfo.trailerText || ""}`} readOnly /></>}
          {!imageInfo.hiddenPayloads.length && !imageInfo.pngTextEntries.length && !imageInfo.lsbCandidates.length && !imageInfo.trailerBytes.length && <div className="empty-state">{t.noHiddenCandidate}</div>}
        </div>}

        {imagePage === "channels" && <div className="tool-panel wide-panel image-simple-channels-panel">
          <div className="panel-heading-row"><PanelTitle title={t.channels} /><AButton variant="filled" disabled={!imageInfo.decoded || Boolean(advancedTask)} onClick={runChannelAnalysis}>{advancedTask === "channels" ? (isEnglish ? "Generating..." : "正在生成...") : (isEnglish ? "Generate channels" : "生成通道图")}</AButton></div>
          <div className="image-channel-grid">{channelItems.map(([label, src]) => <figure key={label} role="button" tabIndex={0} onClick={() => setLightbox({ src, label })} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setLightbox({ src, label }); } }}><img src={src} alt={label} /><figcaption>{label}</figcaption></figure>)}</div>
          {imageInfo.autoRevealPreviews.length > 0 && <><PanelTitle title={t.autoReveal} /><div className="image-channel-grid">{imageInfo.autoRevealPreviews.map((item) => <figure key={item.label} role="button" tabIndex={0} onClick={() => setLightbox({ src: item.src, label: item.label })} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setLightbox({ src: item.src, label: item.label }); } }}><img src={item.src} alt={item.label} /><figcaption>{item.label}</figcaption></figure>)}</div></>}
        </div>}


        {imagePage === "qr" && <div className="tool-panel wide-panel image-simple-qr-panel">
          <div className="panel-heading-row"><PanelTitle title={isEnglish ? "QR code" : "二维码分析"} /><AButton variant="filled" disabled={!imageInfo.decoded || qrScanning} onClick={() => void runQrAnalysis()}>{qrScanning ? (isEnglish ? "Scanning..." : "正在识别...") : (isEnglish ? "Scan QR" : "识别二维码")}</AButton></div>
          {!imageInfo.decoded && <div className="empty-state">{isEnglish ? "Pixel decode is required before QR recognition." : "二维码识别需要先成功解码图片像素。"}</div>}
          {imageInfo.decoded && !qrResult && !qrScanning && <div className="empty-state">{isEnglish ? "Run QR recognition on the currently opened image; no second upload is required." : "直接识别当前图片，无需再次上传。"}</div>}
          {qrResult && <>
            <InfoTable rows={[
              [isEnglish ? "Result" : "识别结果", qrResult.payload ? (isEnglish ? "Decoded" : "已识别") : (isEnglish ? "No QR code found" : "未发现二维码")],
              [isEnglish ? "Payload type" : "内容类型", qrResult.payloadType || "--"],
              [isEnglish ? "Decoded bytes" : "解码字节", String(qrResult.decodedBytes)],
              [isEnglish ? "Scan resolution" : "扫描分辨率", `${qrResult.scanWidth} × ${qrResult.scanHeight}`],
              [isEnglish ? "Scan strategy" : "识别策略", isEnglish ? qrResult.scanStrategy : ({ original: "原图", mirror: "镜像", binary: "二值化", "binary-invert": "反相二值化" } as Record<string, string>)[qrResult.scanStrategy] ?? qrResult.scanStrategy]
            ]} />
            {!qrResult.payload && <div className="tool-storage-note" role="status">{isEnglish ? "No QR code detected. Multiple resolutions and binarization strategies were tried. Common causes: low resolution, QR too small in the frame, oversized center logo, or a non-standard code (e.g. a WeChat mini-program circular code)." : "未识别到二维码。已按多分辨率与二值化策略重试。常见原因：图片分辨率过低、二维码占比过小、中央 logo 过大，或为非标准码（如微信小程序圆形码）。"}</div>}
            {qrResult.payload && <><PanelTitle title={isEnglish ? "Payload" : "二维码内容"} /><AutoTextarea className="single-textarea compact-textarea" value={qrResult.payload} readOnly /><div className="action-row"><AButton variant="outlined" onClick={() => void copyText(qrResult.payload)}>{t.copy}</AButton></div></>}
            {qrResult.payloadRows.length > 0 && <><PanelTitle title={isEnglish ? "Parsed payload" : "内容解析"} /><InfoTable rows={qrResult.payloadRows} /></>}
            {qrResult.cornerRows.length > 0 && <><PanelTitle title={isEnglish ? "Corners" : "定位点"} /><InfoTable rows={qrResult.cornerRows} /></>}
            {qrResult.geometryRows.length > 0 && <><PanelTitle title={isEnglish ? "Geometry" : "几何信息"} /><InfoTable rows={qrResult.geometryRows} /></>}
          </>}
        </div>}

        {imagePage === "repair" && <div className="tool-panel wide-panel image-simple-repair-panel">
          <div className="panel-heading-row"><PanelTitle title={t.recoveryPlan} /><div className="button-row compact-buttons"><AButton variant="filled" disabled={Boolean(advancedTask)} onClick={() => void runRepairAnalysis()}>{advancedTask === "repair" ? (isEnglish ? "Checking..." : "正在检查...") : (isEnglish ? "Recover dimensions / check repair" : "恢复宽高 / 检查修复")}</AButton><AButton variant="outlined" disabled={!imageInfo.repairedContainerBytes} onClick={downloadContainerRepair}>{t.downloadContainerRepair}</AButton>{imageInfo.repairedDataUrl && <AButton variant="outlined" href={imageInfo.repairedDataUrl} download={`${imageInfo.name.replace(/\.[^.]+$/, "") || "image"}-recovered.png`}>{t.downloadRepaired}</AButton>}</div></div>
          <AnalysisNotice level={imageInfo.dimensionRecovery?.status === "recovered" ? "success" : imageInfo.dimensionRecovery?.status === "ambiguous" ? "warn" : "info"} title={isEnglish ? "Recovery conclusion" : "恢复结论"} english={isEnglish}>
            {imageInfo.dimensionRecovery ? dimensionRecoveryMessage(imageInfo.dimensionRecovery, isEnglish) : (isEnglish ? "Run recovery to search dimensions using IHDR CRC and IDAT scanlines. Container normalization alone does not restore dimensions." : "点击上方按钮，联合 IHDR CRC 与 IDAT 扫描行恢复宽高。仅重算 CRC 不代表恢复真实尺寸。")}
            <p>{isEnglish ? "Recovery creates copies. The original bytes, metadata and appended evidence remain available." : "修复结果均为副本；原文件、元数据和尾部证据不会被覆盖。"}</p>
          </AnalysisNotice>
          <InfoTable rows={imageInfo.recoveryRows.map(([key,value]) => [key, localizeAnalysisText(value, isEnglish)] as [string,string])} />
          <div className="image-repair-preview-grid">{imageInfo.repairPreviewItems.map((item) => <figure key={`${item.label}-${item.detail}`} role="button" tabIndex={0} onClick={() => setLightbox({ src: item.src, label: item.label })} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setLightbox({ src: item.src, label: item.label }); } }}><img src={item.src} alt={item.label} /><figcaption><strong>{item.label}</strong><span>{item.detail}</span></figcaption></figure>)}</div>
          {imageInfo.repairDownloads.length > 0 && <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{isEnglish ? "Result" : "结果"}</th><th>{t.fileSize}</th><th>{isEnglish ? "Notes" : "说明"}</th><th></th></tr></thead><tbody>{imageInfo.repairDownloads.map((candidate, index) => <tr key={`${candidate.label}-${index}`}><td>{localizeAnalysisText(candidate.label, isEnglish)}</td><td>{formatBytes(candidate.size)}</td><td>{localizeAnalysisText(candidate.note, isEnglish)}</td><td><div className="button-row"><AButton variant="outlined" onClick={() => downloadRepairCandidate(candidate, index)}>{t.download}</AButton><AButton variant="text" onClick={() => void handleImage(new File([candidate.bytes.slice().buffer as ArrayBuffer], `${imageInfo.name.replace(/\.[^.]+$/, "")}-recovered-${index + 1}.${candidate.extension}`, { type: candidate.mime }))}>{isEnglish ? "Analyze this copy" : "分析此副本"}</AButton></div></td></tr>)}</tbody></table></div>}
        </div>}
      </>}
      {lightbox && <ImageLightbox open={lightbox.open !== false} src={lightbox.src} label={lightbox.label} name={imageInfo?.name ?? ""} english={isEnglish} t={t} onClose={() => setLightbox((current) => current ? { ...current, open: false } : null)} />}
    </div>
  );
}

function ImageLightbox({ open, src, label, name, english, t, onClose }: { open: boolean; src: string; label: string; name: string; english: boolean; t: (typeof copy)["zh"]; onClose: () => void }) {
  return <Modal open={open} title={label} onCancel={onClose} footer={null} width="min(1200px, calc(100vw - 32px))" centered className="image-lightbox-modal" destroyOnHidden>
    <div className="image-lightbox-download"><AButton onClick={() => downloadChannelImage(name, label, src)}>{t.download}</AButton></div>
    <ImageViewer src={src} label={label} english={english} large />
  </Modal>;
}

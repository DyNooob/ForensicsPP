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
import { AButton, ALinearProgress, ASegmentedButton, ASegmentedGroup, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type { ImageDecodedSignal, ImageInfo } from "../models";
import { downloadBlob, formatBytes } from "../utils/files";

type ImageService = (...args: any[]) => any;
type ImageRepairCandidate = { label: string; note: string; bytes: Uint8Array; mime: string };
type ImageFinding = { level: string; title: string; detail: string };

export type ImageToolServices = {
  analyzeImageBasics: ImageService;
  analyzeImageBytes: ImageService;
  analyzeUndecodedImageBytes: ImageService;
  buildAutoRevealPreviews: ImageService;
  buildHiddenPayloadPreviews: ImageService;
  buildImageDecodedSignals: ImageService;
  buildImageRepairCandidates: ImageService;
  bytesToDataUrl: ImageService;
  createChannelPreviews: ImageService;
  createNormalizedImageDataUrl: ImageService;
  detectImageFormat: ImageService;
  emptyImageChannels: ImageService;
  guessImageDimensions: ImageService;
  imageExtensionForMime: ImageService;
  imageMimeForFormat: ImageService;
  imagePlaceholderDataUrl: ImageService;
  loadBrowserImage: ImageService;
  revokeImageObjectUrls: ImageService;
  tryRebuildPngContainer: ImageService;
};

export function ImageTool({ t, services }: { t: (typeof copy)["zh"]; services: ImageToolServices }) {
  const {
    analyzeImageBytes, analyzeUndecodedImageBytes, buildAutoRevealPreviews, buildHiddenPayloadPreviews,
    buildImageDecodedSignals, buildImageRepairCandidates, bytesToDataUrl, createChannelPreviews,
    createNormalizedImageDataUrl, detectImageFormat, emptyImageChannels, guessImageDimensions,
    imageExtensionForMime, imageMimeForFormat, imagePlaceholderDataUrl,
    loadBrowserImage, tryRebuildPngContainer
  } = services;
  const isEnglish = t.waiting === "Waiting";
  const [imageInfo, setImageInfo] = React.useState<ImageInfo | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [advancedTask, setAdvancedTask] = React.useState<"hidden" | "channels" | "repair" | "">("");
  const [error, setError] = React.useState("");
  const [isImageDropActive, setIsImageDropActive] = React.useState(false);
  const [imagePage, setImagePage] = React.useState<"overview" | "structure" | "hidden" | "channels" | "repair">("overview");
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const analysisIdRef = React.useRef(0);
  const sourceRef = React.useRef<{ file: File; bytes: Uint8Array; image: HTMLImageElement | null; exif: Record<string, unknown>; rawDataUrl: string; format: string } | null>(null);

  React.useEffect(() => () => {
    analysisIdRef.current += 1;
    services.revokeImageObjectUrls();
  }, [services]);

  const handleImage = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > 128 * 1024 * 1024) {
      setImageInfo(null);
      setError(isEnglish ? "This image exceeds the 128 MiB browser analysis limit." : "图片超过 128 MiB，无法在浏览器中直接分析。");
      return;
    }
    const analysisId = analysisIdRef.current + 1;
    analysisIdRef.current = analysisId;
    services.revokeImageObjectUrls();
    setLoading(true);
    setError("");
    try {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const bytes = new Uint8Array(await file.arrayBuffer());
      const detectedFormat = detectImageFormat(bytes, file.type);
      const guessedDimensions = guessImageDimensions(bytes, detectedFormat);
      if (guessedDimensions.width * guessedDimensions.height > 50_000_000) {
        throw new Error(isEnglish ? "Image dimensions exceed the 50 megapixel analysis limit." : "图片尺寸超过 5000 万像素分析上限。");
      }
      const sourceMime = /^image\//i.test(file.type) ? file.type : imageMimeForFormat(detectedFormat, file.type || "application/octet-stream");
      const rawDataUrl = await bytesToDataUrl(bytes, sourceMime);
      let image: HTMLImageElement | null = null;
      try { image = await loadBrowserImage(rawDataUrl); } catch { image = null; }
      if (image && image.naturalWidth * image.naturalHeight > 50_000_000) {
        throw new Error(isEnglish ? "Decoded image dimensions exceed the 50 megapixel analysis limit." : "解码后的图片尺寸超过 5000 万像素分析上限。");
      }
      if (analysisId !== analysisIdRef.current) return;
      const exifrModule = await import("exifr");
      const exif =
        ((await exifrModule
          .parse(file, { tiff: true, xmp: true, iptc: true, icc: true, jfif: true, ihdr: true, gps: true })
          .catch(() => null)) ?? {}) as Record<string, unknown>;
      const decoded = Boolean(image);
      const dimensions = image ? { width: image.naturalWidth, height: image.naturalHeight } : guessImageDimensions(bytes, detectedFormat);
      const placeholderDataUrl = imagePlaceholderDataUrl(
        "Image pixels could not be decoded",
        "Open the Repair page to try container recovery.",
        "warn"
      );
      const effectiveDisplayDataUrl = image ? rawDataUrl : placeholderDataUrl;
      const analysis = services.analyzeImageBasics(bytes, file.type, exif);
      sourceRef.current = { file, bytes, image, exif, rawDataUrl, format: detectedFormat };
      if (analysisId !== analysisIdRef.current) return;
      setImageInfo({
        name: file.name,
        size: file.size,
        type: `${file.type || "unknown"} / ${detectedFormat}`,
        decoded,
        width: dimensions.width,
        height: dimensions.height,
        sha256: "",
        dataUrl: effectiveDisplayDataUrl,
        repairedDataUrl: "",
        repairedContainerBytes: null,
        repairNotes: [],
        repairStatus: decoded ? (isEnglish ? "Image opened successfully." : "图片可正常打开。") : (isEnglish ? "Open Repair to try recovery." : "可进入修复页尝试恢复。"),
        recoveryRows: [],
        autoAssessment: { level: "info", title: "", subtitle: "", primaryAction: "", items: [] },
        scanSteps: [],
        triageRows: [],
        priorityReveals: [],
        evidenceBoard: [],
        autoInsights: [],
        autoDisplayItems: [],
        decodedSignals: [],
        briefing: "",
        recommendedActions: [],
        summaryCards: [],
        diagnosis: { level: "info", title: "", detail: "" },
        exif,
        exifSummary: [],
        findings: analysis.findings,
        structureRows: analysis.rows,
        hiddenRows: analysis.hiddenRows,
        stegoRows: analysis.stegoRows,
        trailerBytes: analysis.trailerBytes,
        trailerPreview: analysis.trailerPreview,
        trailerText: analysis.trailerText,
        lsbText: analysis.lsbText,
        lsbCandidates: analysis.lsbCandidates,
        hiddenPayloads: analysis.hiddenPayloads,
        repairDownloads: [],
        pngTextEntries: analysis.pngTextEntries,
        pngChunks: analysis.pngChunks,
        hiddenPayloadPreviews: [],
        repairPreviewItems: [],
        autoRevealPreviews: [],
        autoFocusPreviews: [],
        channelDataUrls: emptyImageChannels(placeholderDataUrl)
      });
      setImagePage("overview");
    } catch (caught) {
      if (analysisId !== analysisIdRef.current) return;
      services.revokeImageObjectUrls();
      setImageInfo(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      if (analysisId === analysisIdRef.current) setLoading(false);
    }
  };
  const runHiddenAnalysis = async () => {
    const source = sourceRef.current;
    if (!source || !imageInfo || advancedTask) return;
    const analysisId = analysisIdRef.current;
    setAdvancedTask("hidden");
    setError("");
    try {
      const analysis = source.image
        ? analyzeImageBytes(source.bytes, source.file.type, source.image, source.exif)
        : analyzeUndecodedImageBytes(source.bytes, source.file.type, source.exif, [["Original container", "failed"]]);
      const hiddenPayloadPreviews = await buildHiddenPayloadPreviews(analysis.hiddenPayloads);
      if (analysisId !== analysisIdRef.current) return;
      setImageInfo((current) => current ? { ...current, findings: analysis.findings, hiddenRows: analysis.hiddenRows, stegoRows: analysis.stegoRows, trailerBytes: analysis.trailerBytes, trailerPreview: analysis.trailerPreview, trailerText: analysis.trailerText, lsbText: analysis.lsbText, lsbCandidates: analysis.lsbCandidates, hiddenPayloads: analysis.hiddenPayloads, pngTextEntries: analysis.pngTextEntries, pngChunks: analysis.pngChunks, hiddenPayloadPreviews } : current);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally { if (analysisId === analysisIdRef.current) setAdvancedTask(""); }
  };
  const runChannelAnalysis = () => {
    const source = sourceRef.current;
    if (!source?.image || !imageInfo || advancedTask) return;
    const analysisId = analysisIdRef.current;
    setAdvancedTask("channels");
    setError("");
    window.setTimeout(() => {
      try {
        const channels = createChannelPreviews(source.image!);
        if (analysisId !== analysisIdRef.current) return;
        setImageInfo((current) => current ? { ...current, channelDataUrls: channels, autoRevealPreviews: buildAutoRevealPreviews(channels, false) } : current);
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : String(caught));
      } finally { if (analysisId === analysisIdRef.current) setAdvancedTask(""); }
    }, 0);
  };
  const runRepairAnalysis = async () => {
    const source = sourceRef.current;
    if (!source || !imageInfo || advancedTask) return;
    const analysisId = analysisIdRef.current;
    setAdvancedTask("repair");
    setError("");
    try {
      const candidates: ImageRepairCandidate[] = buildImageRepairCandidates(source.bytes, source.format);
      const rebuiltPng = tryRebuildPngContainer(source.bytes);
      if (rebuiltPng) candidates.push({ label: "Rebuilt PNG critical chunks", note: rebuiltPng.notes.join(" "), bytes: rebuiltPng.bytes, mime: "image/png" });
      const previews: ImageInfo["repairPreviewItems"] = [];
      const rows: Array<[string, string]> = [];
      for (const candidate of candidates) {
        const src = await bytesToDataUrl(candidate.bytes, candidate.mime);
        try { await loadBrowserImage(src); previews.push({ label: candidate.label, src, detail: candidate.note }); rows.push([candidate.label, "decoded"]); }
        catch { rows.push([candidate.label, "failed"]); }
      }
      const normalized = source.image ? createNormalizedImageDataUrl(source.image) : "";
      if (analysisId !== analysisIdRef.current) return;
      setImageInfo((current) => current ? {
        ...current,
        repairedDataUrl: normalized || previews[0]?.src || "",
        repairedContainerBytes: rebuiltPng?.bytes ?? null,
        repairStatus: previews.length || normalized ? (isEnglish ? "Repair results are ready." : "修复结果已生成。") : (isEnglish ? "No repair result could be decoded." : "没有生成可用的修复结果。"),
        recoveryRows: rows,
        repairPreviewItems: previews,
        repairDownloads: candidates.map((candidate) => ({ label: candidate.label, note: candidate.note, size: candidate.bytes.length, sha256: "", extension: imageExtensionForMime(candidate.mime), mime: candidate.mime, bytes: candidate.bytes }))
      } : current);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally { if (analysisId === analysisIdRef.current) setAdvancedTask(""); }
  };
  const handleImageDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsImageDropActive(false);
    void handleImage(event.dataTransfer.files?.[0]);
  };
  const clearImage = () => {
    analysisIdRef.current += 1;
    services.revokeImageObjectUrls();
    setImageInfo(null);
    setError("");
    setLoading(false);
    setAdvancedTask("");
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
    void navigator.clipboard.writeText(content || "");
  };
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
        className={`tool-panel wide-panel image-source-panel ${isImageDropActive ? "active" : ""}`}
        onDragOver={(event) => { event.preventDefault(); setIsImageDropActive(true); }}
        onDragLeave={() => setIsImageDropActive(false)}
        onDrop={handleImageDrop}
      >
        <PanelTitle title={t.uploadImage} />
        <input ref={inputRef} type="file" accept="image/*,.png,.jpg,.jpeg,.gif,.webp,.bmp,.tif,.tiff,.heic,.heif,.bin" onChange={(event) => void handleImage(event.target.files?.[0])} />
        <div className="desktop-drop-zone" role="button" tabIndex={0} onClick={() => inputRef.current?.click()} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}>
          <strong>{imageInfo?.name || t.dropFileTitle}</strong>
          <span>{imageInfo ? `${imageInfo.type} · ${formatBytes(imageInfo.size)}` : (isEnglish ? "PNG, JPEG, GIF, WebP, BMP, TIFF, HEIC, or image-like data" : "支持 PNG、JPEG、GIF、WebP、BMP、TIFF、HEIC 和疑似图片数据")}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="text" disabled={!imageInfo && !error} onClick={clearImage}>{t.clear}</AButton>
        </div>
        {(loading || advancedTask) && <ALinearProgress />}
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {imageInfo && <>
        <ASegmentedGroup className="image-page-tabs wide-panel" value={imagePage} selects="single" aria-label={isEnglish ? "Image result pages" : "图片结果分页"}>
          <ASegmentedButton value="overview" onClick={() => setImagePage("overview")}>{isEnglish ? "Overview" : "概览"}</ASegmentedButton>
          <ASegmentedButton value="structure" onClick={() => setImagePage("structure")}>{isEnglish ? "Structure" : "结构"}</ASegmentedButton>
          <ASegmentedButton value="hidden" onClick={() => setImagePage("hidden")}>{isEnglish ? "Hidden data" : "隐藏数据"}</ASegmentedButton>
          <ASegmentedButton value="channels" onClick={() => setImagePage("channels")}>{isEnglish ? "Channels" : "通道"}</ASegmentedButton>
          <ASegmentedButton value="repair" onClick={() => setImagePage("repair")}>{isEnglish ? "Repair" : "修复"}</ASegmentedButton>
        </ASegmentedGroup>

        {imagePage === "overview" && <div className="tool-panel wide-panel image-simple-overview-panel">
          <div className="image-simple-overview">
            <figure className="image-simple-preview"><img src={imageInfo.dataUrl || imageInfo.repairedDataUrl} alt={imageInfo.name} /></figure>
            <div className="image-simple-facts">
              <PanelTitle title={t.imageOverview} />
              <InfoTable rows={[
                [isEnglish ? "Name" : "名称", imageInfo.name],
                [t.fileType, imageInfo.type],
                [t.fileSize, formatBytes(imageInfo.size)],
                [t.dimensions, imageInfo.width && imageInfo.height ? `${imageInfo.width} × ${imageInfo.height}` : "--"],
                [isEnglish ? "Display" : "显示状态", imageInfo.decoded ? (isEnglish ? "Opened" : "可打开") : (isEnglish ? "Not decoded" : "无法解码")],
                [t.repairStatus, imageInfo.repairStatus],
                ["EXIF", String(Object.keys(imageInfo.exif).length)],
                [isEnglish ? "Extracted items" : "提取项", String(imageInfo.hiddenPayloads.length)],
                [isEnglish ? "Trailer" : "尾部数据", formatBytes(imageInfo.trailerBytes.length)]
              ]} />
              <div className="action-row">
                {imageInfo.decoded && imageInfo.repairedDataUrl && <AButton variant="outlined" href={imageInfo.repairedDataUrl} download={`${imageInfo.name.replace(/\.[^.]+$/, "") || "image"}-normalized.png`}>{t.downloadRepaired}</AButton>}
                <AButton variant="outlined" disabled={!imageInfo.hiddenPayloads.length} onClick={() => setImagePage("hidden")}>{isEnglish ? "View extracted" : "查看提取项"}</AButton>
              </div>
            </div>
          </div>
          {imageInfo.decodedSignals.length > 0 && <div className="image-simple-signals">
            <PanelTitle title={t.decodedSignals} />
            <div className="image-signal-list">{imageInfo.decodedSignals.map((signal) => <div key={`${signal.source}-${signal.type}-${signal.value.slice(0, 20)}`}><strong>{signal.type}</strong><span>{signal.source}</span><code>{signal.value}</code></div>)}</div>
          </div>}
        </div>}

        {imagePage === "structure" && <div className="tool-panel wide-panel image-simple-structure-panel">
          <PanelTitle title={t.imageStructure} />
          <InfoTable rows={imageInfo.structureRows} />
          {imageInfo.pngChunks.length > 0 && <div className="table-scroll image-chunk-scroll"><table className="data-table"><thead><tr><th>#</th><th>Chunk</th><th>{isEnglish ? "Offset" : "偏移"}</th><th>{isEnglish ? "Length" : "长度"}</th><th>CRC</th></tr></thead><tbody>{imageInfo.pngChunks.map((chunk, index) => <tr className={chunk.ok ? "" : "soft-selected-row"} key={`${chunk.offset}-${chunk.type}`}><td>{index + 1}</td><td>{chunk.type}</td><td>0x{chunk.offset.toString(16).toUpperCase()}</td><td>{formatBytes(chunk.length)}</td><td>{chunk.ok ? "OK" : `${chunk.crc} / ${chunk.computed}`}</td></tr>)}</tbody></table></div>}
          <PanelTitle title={t.exif} />
          {Object.keys(imageInfo.exif).length ? <div className="kv-grid">{Object.entries(imageInfo.exif).slice(0, 100).map(([key, value]) => <React.Fragment key={key}><strong>{key}</strong><span>{String(value)}</span></React.Fragment>)}</div> : <div className="empty-state">{t.noExif}</div>}
        </div>}

        {imagePage === "hidden" && <div className="tool-panel wide-panel image-simple-hidden-panel">
          <div className="panel-heading-row"><PanelTitle title={t.hiddenData} /><div className="button-row compact-buttons"><AButton variant="filled" disabled={Boolean(advancedTask)} onClick={() => void runHiddenAnalysis()}>{advancedTask === "hidden" ? (isEnglish ? "Scanning..." : "正在扫描...") : (isEnglish ? "Scan hidden data" : "扫描隐藏数据")}</AButton><AButton variant="outlined" disabled={!imageInfo.trailerBytes.length} onClick={downloadTrailer}>{t.downloadHiddenData}</AButton><AButton variant="text" disabled={!imageInfo.lsbCandidates.length && !imageInfo.pngTextEntries.length && !imageInfo.trailerText} onClick={copyHiddenText}>{t.copyHiddenText}</AButton></div></div>
          <InfoTable rows={imageInfo.hiddenRows} />
          {imageInfo.hiddenPayloads.length > 0 && <><PanelTitle title={t.extractedPayloads} /><div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{isEnglish ? "Source" : "来源"}</th><th>{isEnglish ? "Offset" : "偏移"}</th><th>{isEnglish ? "Type" : "类型"}</th><th>{t.fileSize}</th><th>{t.preview}</th><th></th></tr></thead><tbody>{imageInfo.hiddenPayloads.map((payload, index) => <tr key={`${payload.offset}-${index}`}><td>{payload.source}</td><td>{payload.offset}</td><td>{payload.label}</td><td>{formatBytes(payload.size)}</td><td>{payload.preview.slice(0, 160) || "--"}</td><td><AButton variant="outlined" onClick={() => downloadHiddenPayload(payload, index)}>{t.download}</AButton></td></tr>)}</tbody></table></div></>}
          {imageInfo.pngTextEntries.length > 0 && <><PanelTitle title={t.pngTextMetadata} /><div className="image-text-result-list">{imageInfo.pngTextEntries.map((entry) => <label key={`${entry.offset}-${entry.keyword}`}>{entry.keyword || entry.chunk}<textarea className="single-textarea compact-textarea" value={entry.text} readOnly /></label>)}</div></>}
          {imageInfo.lsbCandidates.length > 0 && <><PanelTitle title={t.lsbCandidates} /><div className="image-text-result-list">{imageInfo.lsbCandidates.map((candidate) => <label key={`${candidate.mode}-${candidate.text.slice(0, 20)}`}>{candidate.mode}<textarea className="single-textarea compact-textarea" value={candidate.text} readOnly /></label>)}</div></>}
          {imageInfo.trailerBytes.length > 0 && <><PanelTitle title={t.trailerData} /><textarea className="single-textarea image-trailer-preview" value={`${imageInfo.trailerPreview || "--"}\n\n${imageInfo.trailerText || ""}`} readOnly /></>}
          {!imageInfo.hiddenPayloads.length && !imageInfo.pngTextEntries.length && !imageInfo.lsbCandidates.length && !imageInfo.trailerBytes.length && <div className="empty-state">{t.noHiddenCandidate}</div>}
        </div>}

        {imagePage === "channels" && <div className="tool-panel wide-panel image-simple-channels-panel">
          <div className="panel-heading-row"><PanelTitle title={t.channels} /><AButton variant="filled" disabled={!imageInfo.decoded || Boolean(advancedTask)} onClick={runChannelAnalysis}>{advancedTask === "channels" ? (isEnglish ? "Generating..." : "正在生成...") : (isEnglish ? "Generate channels" : "生成通道图")}</AButton></div>
          <div className="image-channel-grid">{channelItems.map(([label, src]) => <figure key={label}><img src={src} alt={label} /><figcaption>{label}</figcaption></figure>)}</div>
          {imageInfo.autoRevealPreviews.length > 0 && <><PanelTitle title={t.autoReveal} /><div className="image-channel-grid">{imageInfo.autoRevealPreviews.map((item) => <figure key={item.label}><img src={item.src} alt={item.label} /><figcaption>{item.label}</figcaption></figure>)}</div></>}
        </div>}

        {imagePage === "repair" && <div className="tool-panel wide-panel image-simple-repair-panel">
          <div className="panel-heading-row"><PanelTitle title={t.recoveryPlan} /><div className="button-row compact-buttons"><AButton variant="filled" disabled={Boolean(advancedTask)} onClick={() => void runRepairAnalysis()}>{advancedTask === "repair" ? (isEnglish ? "Generating..." : "正在生成...") : (isEnglish ? "Generate repair results" : "生成修复结果")}</AButton><AButton variant="outlined" disabled={!imageInfo.repairedContainerBytes} onClick={downloadContainerRepair}>{t.downloadContainerRepair}</AButton>{imageInfo.decoded && imageInfo.repairedDataUrl && <AButton variant="outlined" href={imageInfo.repairedDataUrl} download={`${imageInfo.name.replace(/\.[^.]+$/, "") || "image"}-normalized.png`}>{t.downloadRepaired}</AButton>}</div></div>
          <InfoTable rows={imageInfo.recoveryRows} />
          <div className="image-repair-preview-grid">{imageInfo.repairPreviewItems.map((item) => <figure key={`${item.label}-${item.detail}`}><img src={item.src} alt={item.label} /><figcaption><strong>{item.label}</strong><span>{item.detail}</span></figcaption></figure>)}</div>
          {imageInfo.repairDownloads.length > 0 && <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{isEnglish ? "Result" : "结果"}</th><th>{t.fileSize}</th><th>{isEnglish ? "Notes" : "说明"}</th><th></th></tr></thead><tbody>{imageInfo.repairDownloads.map((candidate, index) => <tr key={`${candidate.label}-${index}`}><td>{candidate.label}</td><td>{formatBytes(candidate.size)}</td><td>{candidate.note}</td><td><AButton variant="outlined" onClick={() => downloadRepairCandidate(candidate, index)}>{t.download}</AButton></td></tr>)}</tbody></table></div>}
        </div>}
      </>}
    </div>
  );
}

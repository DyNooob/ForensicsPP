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

import type { ImageInfo } from "../../models";
import { hexPreview, previewText } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { pngCriticalChunks } from "../png/parser";
import { imageObjectUrls, revokeGeneratedImageUrl, imageAnalysisDimensions } from "./objectUrls";
import { extractLsbCandidatesFromImageData, scoreImageBitPlanes, collectLsbPayloadsFromImageData } from "./lsb";
import { collectHiddenPayloads, collectPngChunkPayloads } from "./carve";
import { inspectImageContainerBytes } from "./structure";
import { imageMetadataFieldCount } from "./format";

type ImageMetadata = Record<string, unknown> | number;
type ImagePixelData = { data: Uint8ClampedArray; width: number; height: number };

function loadBrowserImage(src: string) {
  return new Promise<HTMLImageElement>((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = src;
  });
}

function yieldToBrowser() {
  return new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function canvasToPngUrl(canvas: HTMLCanvasElement) {
  return new Promise<string>((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) {
        try {
          resolve(canvas.toDataURL("image/png"));
        } catch (caught) {
          reject(caught);
        }
        return;
      }
      const url = URL.createObjectURL(blob);
      imageObjectUrls.add(url);
      resolve(url);
    }, "image/png");
  });
}

async function createChannelPreviews(image: HTMLImageElement, shouldCancel: () => boolean = () => false) {
  const generatedUrls: string[] = [];
  const cancel = () => {
    generatedUrls.forEach(revokeGeneratedImageUrl);
    return null;
  };
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Canvas is not available");

  const dimensions = imageAnalysisDimensions(image.naturalWidth, image.naturalHeight, 220_000);
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  const source = context.getImageData(0, 0, canvas.width, canvas.height);
  await yieldToBrowser();
  if (shouldCancel()) return cancel();

  const makeChannel = async (channel: "red" | "green" | "blue" | "alpha" | "lsb" | "lsbRed" | "lsbGreen" | "lsbBlue" | "lowBitHeatmap" | "noiseMap") => {
    const output = context.createImageData(source.width, source.height);
    const luminanceAt = (pixel: number) => {
      const base = pixel * 4;
      return source.data[base] * 0.299 + source.data[base + 1] * 0.587 + source.data[base + 2] * 0.114;
    };
    for (let index = 0; index < source.data.length; index += 4) {
      const red = source.data[index];
      const green = source.data[index + 1];
      const blue = source.data[index + 2];
      const alpha = source.data[index + 3];
      const pixel = index / 4;
      const x = pixel % source.width;
      const y = Math.floor(pixel / source.width);
      let value = 0;
      if (channel === "red") value = red;
      if (channel === "green") value = green;
      if (channel === "blue") value = blue;
      if (channel === "alpha") value = alpha;
      if (channel === "lsb") value = ((red & 1) | ((green & 1) << 1) | ((blue & 1) << 2)) * 36;
      if (channel === "lsbRed") value = (red & 1) ? 255 : 0;
      if (channel === "lsbGreen") value = (green & 1) ? 255 : 0;
      if (channel === "lsbBlue") value = (blue & 1) ? 255 : 0;
      if (channel === "lowBitHeatmap") {
        output.data[index] = (red & 3) * 85;
        output.data[index + 1] = (green & 3) * 85;
        output.data[index + 2] = (blue & 3) * 85;
      } else if (channel === "noiseMap") {
        const hasNeighbors = x > 0 && x < source.width - 1 && y > 0 && y < source.height - 1;
        const neighborAverage = hasNeighbors
          ? (luminanceAt(pixel - 1) + luminanceAt(pixel + 1) + luminanceAt(pixel - source.width) + luminanceAt(pixel + source.width)) / 4
          : luminanceAt(pixel);
        const delta = Math.min(255, Math.abs(luminanceAt(pixel) - neighborAverage) * 4);
        output.data[index] = delta;
        output.data[index + 1] = delta > 96 ? Math.min(255, delta + 50) : delta;
        output.data[index + 2] = delta > 96 ? 30 : delta;
      } else {
        output.data[index] = value;
        output.data[index + 1] = value;
        output.data[index + 2] = value;
      }
      output.data[index + 3] = 255;
    }
    context.putImageData(output, 0, 0);
    try {
      const url = await canvasToPngUrl(canvas);
      generatedUrls.push(url);
      return url;
    } catch (caught) {
      generatedUrls.forEach(revokeGeneratedImageUrl);
      throw caught;
    }
  };

  const makeBitPlane = async (channelIndex: 0 | 1 | 2 | 3, bit: number) => {
    const output = context.createImageData(source.width, source.height);
    for (let index = 0; index < source.data.length; index += 4) {
      const value = ((source.data[index + channelIndex] >> bit) & 1) ? 255 : 0;
      output.data[index] = value;
      output.data[index + 1] = value;
      output.data[index + 2] = value;
      output.data[index + 3] = 255;
    }
    context.putImageData(output, 0, 0);
    try {
      const url = await canvasToPngUrl(canvas);
      generatedUrls.push(url);
      return url;
    } catch (caught) {
      generatedUrls.forEach(revokeGeneratedImageUrl);
      throw caught;
    }
  };

  const channels: ImageInfo["channelDataUrls"] = {
    red: "",
    green: "",
    blue: "",
    alpha: "",
    lsb: "",
    lsbRed: "",
    lsbGreen: "",
    lsbBlue: "",
    lowBitHeatmap: "",
    noiseMap: "",
    bitPlanes: []
  };
  const channelNames: Array<"red" | "green" | "blue" | "alpha" | "lsb" | "lsbRed" | "lsbGreen" | "lsbBlue" | "lowBitHeatmap" | "noiseMap"> = [
    "red", "green", "blue", "alpha", "lsb", "lsbRed", "lsbGreen", "lsbBlue", "lowBitHeatmap", "noiseMap"
  ];
  for (const channel of channelNames) {
    await yieldToBrowser();
    if (shouldCancel()) return cancel();
    const src = await makeChannel(channel);
    if (shouldCancel()) {
      return cancel();
    }
    channels[channel] = src;
  }
  const bitPlanes: Array<[string, 0 | 1 | 2 | 3, number]> = [
    ["R bit 0", 0, 0], ["G bit 0", 1, 0], ["B bit 0", 2, 0], ["A bit 0", 3, 0],
    ["R bit 1", 0, 1], ["G bit 1", 1, 1], ["B bit 1", 2, 1], ["A bit 1", 3, 1]
  ];
  for (const [label, channelIndex, bit] of bitPlanes) {
    await yieldToBrowser();
    if (shouldCancel()) return cancel();
    const src = await makeBitPlane(channelIndex, bit);
    if (shouldCancel()) {
      return cancel();
    }
    channels.bitPlanes.push({ label, src });
  }
  return channels;
}

function buildAutoRevealPreviews(channels: ImageInfo["channelDataUrls"], hasAlphaSignal: boolean) {
  const previews = [
    {
      label: "Noise anomaly map",
      src: channels.noiseMap,
      detail: "局部噪声异常图。亮色块、规则边界或文字轮廓可能对应拼接、擦写、局部隐写或异常压缩区域。"
    },
    {
      label: "Low-bit heatmap",
      src: channels.lowBitHeatmap,
      detail: "RGB 低 2 位热力图。规则色块、文字轮廓或明显块状图案通常需要进一步检查。"
    },
    {
      label: "RGB LSB",
      src: channels.lsb,
      detail: "RGB 最低有效位组合图。出现清晰文字、形状或大块规律纹理时，优先怀疑 LSB 隐写。"
    },
    {
      label: "Red LSB",
      src: channels.lsbRed,
      detail: "红色通道最低位。单通道隐藏内容常会在这里形成高对比黑白图。"
    },
    {
      label: "Green LSB",
      src: channels.lsbGreen,
      detail: "绿色通道最低位。用于和 R/B 通道交叉比对，排除自然噪声。"
    },
    {
      label: "Blue LSB",
      src: channels.lsbBlue,
      detail: "蓝色通道最低位。很多简单隐写工具会优先使用 B 通道。"
    }
  ];
  if (hasAlphaSignal) {
    previews.unshift({
      label: "Alpha",
      src: channels.alpha,
      detail: "透明通道可视化。非透明区域异常、文字轮廓或规则图案可能表示隐藏信息。"
    });
  }
  channels.bitPlanes.forEach((plane) => {
    previews.push({
      label: plane.label,
      src: plane.src,
      detail: "自动位平面可视化。若能看到文字、二维码轮廓、规则图案或边界，优先按隐写线索处理。"
    });
  });
  return previews;
}

function scoreImageNoise(source: ImagePixelData) {
  if (source.width < 3 || source.height < 3) {
    return { rows: [["Local noise anomaly", "not available; image too small"]] as Array<[string, string]>, findings: [] as Array<{ level: string; title: string; detail: string }> };
  }
  let total = 0;
  let strong = 0;
  let checked = 0;
  const luminanceAt = (pixel: number) => {
    const base = pixel * 4;
    return source.data[base] * 0.299 + source.data[base + 1] * 0.587 + source.data[base + 2] * 0.114;
  };
  for (let y = 1; y < source.height - 1; y += 1) {
    for (let x = 1; x < source.width - 1; x += 1) {
      const pixel = y * source.width + x;
      const center = luminanceAt(pixel);
      const neighborAverage = (
        luminanceAt(pixel - 1) +
        luminanceAt(pixel + 1) +
        luminanceAt(pixel - source.width) +
        luminanceAt(pixel + source.width)
      ) / 4;
      const delta = Math.abs(center - neighborAverage);
      total += delta;
      if (delta > 52) strong += 1;
      checked += 1;
    }
  }
  const mean = checked ? total / checked : 0;
  const strongRatio = checked ? strong / checked : 0;
  const rows: Array<[string, string]> = [
    ["Local noise mean", mean.toFixed(2)],
    ["Strong local noise pixels", `${(strongRatio * 100).toFixed(2)}%`]
  ];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  if (strongRatio > 0.18 && mean > 26) {
    findings.push({
      level: "warn",
      title: "High local noise anomaly",
      detail: `${(strongRatio * 100).toFixed(2)}% of interior pixels differ strongly from their immediate neighborhood; inspect the noise map for pasted blocks, hidden masks, or generated noise.`
    });
  }
  return { rows, findings };
}

function createImageAnalysisPixels(image: HTMLImageElement): ImagePixelData {
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Canvas is not available");
  const dimensions = imageAnalysisDimensions(image.naturalWidth, image.naturalHeight, 1_000_000);
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  return context.getImageData(0, 0, canvas.width, canvas.height);
}

function analyzeImagePixels(bytes: Uint8Array, fileType: string, imageData: ImagePixelData, exif: ImageMetadata) {
  const container = inspectImageContainerBytes(bytes, fileType, exif);
  const { rows, findings, pngTextEntries, pngChunks, embeddedHits, logicalEnd, trailer } = container;
  let alphaTransparent = 0;
  let alphaNon255 = 0;
  let redOnes = 0;
  let greenOnes = 0;
  let blueOnes = 0;
  const pixels = imageData.width * imageData.height;
  for (let index = 0; index < imageData.data.length; index += 4) {
    if (imageData.data[index + 3] === 0) alphaTransparent += 1;
    if (imageData.data[index + 3] !== 255) alphaNon255 += 1;
    redOnes += imageData.data[index] & 1;
    greenOnes += imageData.data[index + 1] & 1;
    blueOnes += imageData.data[index + 2] & 1;
  }
  rows.push(["Alpha pixels != 255", String(alphaNon255)]);
  rows.push(["Red LSB one ratio", `${(redOnes / pixels * 100).toFixed(2)}%`]);
  rows.push(["Green LSB one ratio", `${(greenOnes / pixels * 100).toFixed(2)}%`]);
  rows.push(["Blue LSB one ratio", `${(blueOnes / pixels * 100).toFixed(2)}%`]);
  const lsbRatios = [
    ["Red", redOnes / pixels],
    ["Green", greenOnes / pixels],
    ["Blue", blueOnes / pixels]
  ] as Array<[string, number]>;
  const unusualRatios = lsbRatios.filter(([, ratio]) => ratio < 0.38 || ratio > 0.62);
  if (unusualRatios.length) {
    findings.push({
      level: "info",
      title: "Low-bit distribution note",
      detail: `${unusualRatios.map(([channel, ratio]) => `${channel} ${(ratio * 100).toFixed(2)}% ones`).join(", ")}. This is a local distribution note, not a standalone hidden-data finding.`
    });
  }
  if (alphaTransparent > 0 || alphaNon255 > pixels * 0.02) findings.push({ level: "warn", title: "Alpha channel carries data", detail: `${alphaNon255} pixels have non-opaque alpha; inspect alpha preview.` });
  const lsbCandidates = extractLsbCandidatesFromImageData(imageData);
  const lsbText = lsbCandidates[0]?.text ?? "";
  rows.push(["Readable LSB candidates", String(lsbCandidates.length)]);
  const bitPlaneScore = scoreImageBitPlanes(imageData);
  findings.push(...bitPlaneScore.findings.slice(0, 6));
  const noiseScore = scoreImageNoise(imageData);
  findings.push(...noiseScore.findings);
  if (lsbCandidates.some((candidate) => /https?:\/\/|flag\{|ctf|password|secret|key=|PK\x03\x04|MZ|%PDF/i.test(candidate.text))) {
    findings.push({ level: "warn", title: "Readable LSB candidate", detail: `${lsbCandidates[0].mode}: ${lsbCandidates[0].text.slice(0, 160)}` });
  } else if (lsbCandidates.length) {
    findings.push({ level: "warn", title: "Printable LSB text candidate", detail: `${lsbCandidates[0].mode}: ${lsbCandidates[0].text.slice(0, 160)}` });
  }
  if (!findings.length) findings.push({ level: "info", title: "No obvious hidden-data marker", detail: "No trailer, CRC error, readable LSB text, or major alpha anomaly was detected by quick checks." });
  const lsbPayloads = collectLsbPayloadsFromImageData(imageData);
  const hiddenPayloads = [
    ...collectHiddenPayloads(bytes, logicalEnd, trailer, embeddedHits),
    ...collectPngChunkPayloads(bytes, pngChunks),
    ...lsbPayloads
  ];
  if (hiddenPayloads.length) {
    const cleanIndex = findings.findIndex((finding) => finding.title === "No obvious hidden-data marker");
    if (cleanIndex >= 0) findings.splice(cleanIndex, 1);
    findings.push({
      level: "warn",
      title: "Extractable payload candidate",
      detail: hiddenPayloads.map((payload) => `${payload.label}@${payload.offset} (${formatBytes(payload.size)})`).join(", ")
    });
  }
  const hiddenRows: Array<[string, string]> = [
    ["Trailing payload", trailer.length ? `${formatBytes(trailer.length)} after logical end` : "not detected"],
    ["Extractable payloads", hiddenPayloads.length ? hiddenPayloads.map((payload) => `${payload.label}@${payload.offset}`).join(", ") : "not detected"],
    ["LSB binary payloads", lsbPayloads.length ? lsbPayloads.map((payload) => `${payload.label}@${payload.offset}`).join(", ") : "not detected"],
    ["PNG extra chunks", pngChunks.filter((chunk) => !pngCriticalChunks.has(chunk.type) && chunk.risk.length).map((chunk) => `${chunk.type}@${chunk.offset}`).join(", ") || "not detected"],
    ["Embedded file signatures", embeddedHits.length ? embeddedHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ") : "not detected"],
    ["Readable LSB candidates", lsbCandidates.length ? lsbCandidates.map((candidate) => candidate.mode).join(", ") : "not detected"],
    ["PNG text metadata", pngTextEntries.length ? pngTextEntries.map((entry) => `${entry.keyword}@${entry.offset}`).join(", ") : "not detected"],
    ["Alpha anomaly", alphaNon255 ? `${alphaNon255} non-opaque pixels` : "not detected"],
    ["Metadata fields", String(imageMetadataFieldCount(exif))]
  ];

  return {
    rows,
    findings,
    hiddenRows,
    stegoRows: [...bitPlaneScore.rows, ...noiseScore.rows],
    trailerBytes: trailer,
    trailerPreview: trailer.length ? hexPreview(trailer, 256) : "",
    trailerText: trailer.length ? previewText(trailer, 4096) : "",
    lsbText,
    lsbCandidates,
    hiddenPayloads,
    pngTextEntries,
    pngChunks
  };
}

function analyzeImageBasics(bytes: Uint8Array, fileType: string, exif: ImageMetadata) {
  const container = inspectImageContainerBytes(bytes, fileType, exif);
  return {
    rows: container.rows,
    findings: container.findings,
    hiddenRows: [],
    stegoRows: [],
    trailerBytes: container.trailer,
    trailerPreview: container.trailer.length ? hexPreview(container.trailer, 256) : "",
    trailerText: container.trailer.length ? previewText(container.trailer, 4096) : "",
    lsbText: "",
    lsbCandidates: [],
    hiddenPayloads: [],
    pngTextEntries: container.pngTextEntries,
    pngChunks: container.pngChunks
  };
}

function analyzeUndecodedImageBytes(bytes: Uint8Array, fileType: string, exif: ImageMetadata, recoveryRows: Array<[string, string]>) {
  const container = inspectImageContainerBytes(bytes, fileType, exif);
  const hiddenPayloads = [
    ...collectHiddenPayloads(bytes, container.logicalEnd, container.trailer, container.embeddedHits),
    ...collectPngChunkPayloads(bytes, container.pngChunks)
  ];
  const findings = [
    {
      level: "warn",
      title: "Pixel decode failed",
      detail: `The browser could not decode the image pixels after ${recoveryRows.length} attempt(s). Container-level evidence is still available; original pixels cannot be reliably reconstructed in-browser.`
    },
    ...container.findings
  ];
  if (hiddenPayloads.length) {
    findings.push({
      level: "warn",
      title: "Extractable payload candidate",
      detail: hiddenPayloads.map((payload) => `${payload.label}@${payload.offset} (${formatBytes(payload.size)})`).join(", ")
    });
  }
  const hiddenRows: Array<[string, string]> = [
    ["Trailing payload", container.trailer.length ? `${formatBytes(container.trailer.length)} after logical end` : "not detected"],
    ["Extractable payloads", hiddenPayloads.length ? hiddenPayloads.map((payload) => `${payload.label}@${payload.offset}`).join(", ") : "not detected"],
    ["LSB binary payloads", "not available; pixel decode failed"],
    ["PNG extra chunks", container.pngChunks.filter((chunk) => !pngCriticalChunks.has(chunk.type) && chunk.risk.length).map((chunk) => `${chunk.type}@${chunk.offset}`).join(", ") || "not detected"],
    ["Embedded file signatures", container.embeddedHits.length ? container.embeddedHits.map((hit) => `${hit.label}@${hit.offset}`).join(", ") : "not detected"],
    ["Readable LSB candidates", "not available; pixel decode failed"],
    ["PNG text metadata", container.pngTextEntries.length ? container.pngTextEntries.map((entry) => `${entry.keyword}@${entry.offset}`).join(", ") : "not detected"],
    ["Alpha anomaly", "not available; pixel decode failed"],
    ["Metadata fields", String(imageMetadataFieldCount(exif))]
  ];
  return {
    rows: container.rows,
    findings,
    hiddenRows,
    stegoRows: [["Pixel-level LSB analysis", "not available; image pixels could not be decoded"]] as Array<[string, string]>,
    trailerBytes: container.trailer,
    trailerPreview: container.trailer.length ? hexPreview(container.trailer, 256) : "",
    trailerText: container.trailer.length ? previewText(container.trailer, 4096) : "",
    lsbText: "",
    lsbCandidates: [],
    hiddenPayloads,
    pngTextEntries: container.pngTextEntries,
    pngChunks: container.pngChunks
  };
}

function analyzeImageBytes(bytes: Uint8Array, fileType: string, image: HTMLImageElement, exif: ImageMetadata) {
  return analyzeImagePixels(bytes, fileType, createImageAnalysisPixels(image), exif);
}

export {
  loadBrowserImage,
  createImageAnalysisPixels,
  createChannelPreviews,
  buildAutoRevealPreviews,
  analyzeImageBasics,
  analyzeUndecodedImageBytes,
  analyzeImagePixels,
  analyzeImageBytes
};

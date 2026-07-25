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

import { readAscii } from "../../utils/binary";
import type { ImageInfo } from "../../models";

const imageObjectUrls = new Set<string>();

function revokeImageObjectUrls() {
  imageObjectUrls.forEach((url) => URL.revokeObjectURL(url));
  imageObjectUrls.clear();
}

function bytesToDataUrl(bytes: Uint8Array, type: string) {
  const source = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? bytes.buffer as ArrayBuffer
    : bytes.slice().buffer;
  const blob = new Blob([source], { type });
  if (bytes.byteLength > 4 * 1024 * 1024) {
    const url = URL.createObjectURL(blob);
    imageObjectUrls.add(url);
    return Promise.resolve(url);
  }
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}

function imagePlaceholderDataUrl(title: string, detail: string, tone: "info" | "warn" | "danger" = "info") {
  const colors = {
    info: ["#E8F2FF", "#0061A4", "#0E2A3F"],
    warn: ["#FFF4D8", "#8A5B00", "#332200"],
    danger: ["#FFF4D8", "#8A5B00", "#332200"]
  }[tone];
  const escape = (value: string) => value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="640" viewBox="0 0 960 640">`,
    `<rect width="960" height="640" fill="${colors[0]}"/>`,
    `<rect x="56" y="56" width="848" height="528" rx="18" fill="white" stroke="${colors[1]}" stroke-width="4"/>`,
    `<path d="M210 388h540L610 234 500 346l-68-78-222 120z" fill="${colors[1]}" opacity=".18"/>`,
    `<circle cx="292" cy="212" r="42" fill="${colors[1]}" opacity=".25"/>`,
    `<text x="96" y="118" font-family="Arial, sans-serif" font-size="34" font-weight="700" fill="${colors[2]}">${escape(title)}</text>`,
    `<foreignObject x="96" y="148" width="768" height="210">`,
    `<div xmlns="http://www.w3.org/1999/xhtml" style="font-family:Arial,sans-serif;font-size:22px;line-height:1.45;color:${colors[2]};overflow-wrap:anywhere">${escape(detail)}</div>`,
    `</foreignObject>`,
    `<text x="96" y="540" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="${colors[1]}">Forensics++ Image Workbench</text>`,
    `</svg>`
  ].join("");
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function emptyImageChannels(src: string): ImageInfo["channelDataUrls"] {
  return {
    red: src,
    green: src,
    blue: src,
    alpha: src,
    lsb: src,
    lsbRed: src,
    lsbGreen: src,
    lsbBlue: src,
    lowBitHeatmap: src,
    noiseMap: src,
    bitPlanes: [
      "R bit 0",
      "G bit 0",
      "B bit 0",
      "A bit 0",
      "R bit 1",
      "G bit 1",
      "B bit 1",
      "A bit 1"
    ].map((label) => ({ label, src }))
  };
}

function guessImageDimensions(bytes: Uint8Array, format: string) {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (format === "PNG" && bytes.length >= 24) return { width: view.getUint32(16), height: view.getUint32(20) };
    if (format === "GIF" && bytes.length >= 10) return { width: view.getUint16(6, true), height: view.getUint16(8, true) };
    if (format === "BMP" && bytes.length >= 26) return { width: Math.abs(view.getInt32(18, true)), height: Math.abs(view.getInt32(22, true)) };
    if (format === "WEBP" && readAscii(bytes, 0, 4) === "RIFF") {
      let offset = 12;
      while (offset + 8 <= bytes.length) {
        const type = readAscii(bytes, offset, 4);
        const size = view.getUint32(offset + 4, true);
        if (type === "VP8X" && offset + 18 <= bytes.length) {
          return {
            width: 1 + bytes[offset + 12] + (bytes[offset + 13] << 8) + (bytes[offset + 14] << 16),
            height: 1 + bytes[offset + 15] + (bytes[offset + 16] << 8) + (bytes[offset + 17] << 16)
          };
        }
        offset += 8 + size + (size % 2);
      }
    }
    if (format === "JPEG" && bytes[0] === 0xff && bytes[1] === 0xd8) {
      let offset = 2;
      while (offset + 9 < bytes.length) {
        while (offset < bytes.length && bytes[offset] !== 0xff) offset += 1;
        while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
        const marker = bytes[offset];
        if (marker === 0xda || marker === 0xd9) break;
        if (offset + 2 >= bytes.length) break;
        const length = view.getUint16(offset + 1);
        if (length < 2 || offset + 1 + length > bytes.length) break;
        if ((marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7) || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf)) {
          return { width: view.getUint16(offset + 6), height: view.getUint16(offset + 4) };
        }
        offset += 1 + length;
      }
    }
  } catch {
    // Dimension guessing is best-effort; structure findings carry the real evidence.
  }
  return { width: 0, height: 0 };
}

function imageAnalysisDimensions(width: number, height: number, maxPixels = 2_000_000) {
  const pixels = Math.max(1, width * height);
  const scale = pixels > maxPixels ? Math.sqrt(maxPixels / pixels) : 1;
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
    scale
  };
}

function revokeGeneratedImageUrl(url: string) {
  if (!url.startsWith("blob:")) return;
  URL.revokeObjectURL(url);
  imageObjectUrls.delete(url);
}

function revokeImagePreviewUrl(url: string) {
  revokeGeneratedImageUrl(url);
}

function revokeImagePreviewUrls(channels: ImageInfo["channelDataUrls"]) {
  [
    channels.red,
    channels.green,
    channels.blue,
    channels.alpha,
    channels.lsb,
    channels.lsbRed,
    channels.lsbGreen,
    channels.lsbBlue,
    channels.lowBitHeatmap,
    channels.noiseMap,
    ...channels.bitPlanes.map((plane) => plane.src)
  ].forEach(revokeGeneratedImageUrl);
}

export {
  imageObjectUrls,
  revokeImageObjectUrls,
  revokeGeneratedImageUrl,
  revokeImagePreviewUrl,
  revokeImagePreviewUrls,
  imagePlaceholderDataUrl,
  emptyImageChannels,
  guessImageDimensions,
  imageAnalysisDimensions,
  bytesToDataUrl
};

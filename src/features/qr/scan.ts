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

import type { QRCode } from "jsqr";

const MAX_QR_SCAN_PIXELS = 4_000_000;
const MAX_QR_SCAN_EDGE = 2048;

export type QrScanSuccess = {
  code: QRCode;
  strategy: string;
  scanWidth: number;
  scanHeight: number;
};

function renderScaled(image: HTMLImageElement, width: number, height: number): Uint8ClampedArray | null {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  // Crisp module edges matter more than smoothing for QR decoding.
  context.imageSmoothingEnabled = false;
  context.drawImage(image, 0, 0, width, height);
  return context.getImageData(0, 0, width, height).data;
}

function toGrayscale(rgba: Uint8ClampedArray): Uint8ClampedArray {
  const gray = new Uint8ClampedArray(rgba.length);
  for (let index = 0; index < rgba.length; index += 4) {
    const luminance = (rgba[index] * 299 + rgba[index + 1] * 587 + rgba[index + 2] * 114 + 500) / 1000;
    gray[index] = gray[index + 1] = gray[index + 2] = luminance;
    gray[index + 3] = 255;
  }
  return gray;
}

function otsuThreshold(gray: Uint8ClampedArray): number {
  const histogram = new Array<number>(256).fill(0);
  const total = gray.length / 4;
  if (total === 0) return 127;
  for (let index = 0; index < gray.length; index += 4) histogram[gray[index]] += 1;
  let sum = 0;
  for (let threshold = 0; threshold < 256; threshold += 1) sum += threshold * histogram[threshold];
  let sumBackground = 0;
  let weightBackground = 0;
  let maxVariance = 0;
  let selected = 127;
  for (let threshold = 0; threshold < 256; threshold += 1) {
    weightBackground += histogram[threshold];
    if (weightBackground === 0) continue;
    const weightForeground = total - weightBackground;
    if (weightForeground === 0) break;
    sumBackground += threshold * histogram[threshold];
    const meanBackground = sumBackground / weightBackground;
    const meanForeground = (sum - sumBackground) / weightForeground;
    const between = weightBackground * weightForeground * (meanBackground - meanForeground) ** 2;
    if (between >= maxVariance) {
      maxVariance = between;
      selected = threshold;
    }
  }
  return selected;
}

function binarize(gray: Uint8ClampedArray, threshold: number, invert: boolean): Uint8ClampedArray {
  const out = new Uint8ClampedArray(gray.length);
  for (let index = 0; index < gray.length; index += 4) {
    const value = gray[index] > threshold ? 255 : 0;
    const resolved = invert ? 255 - value : value;
    out[index] = out[index + 1] = out[index + 2] = resolved;
    out[index + 3] = 255;
  }
  return out;
}

function flipHorizontal(rgba: Uint8ClampedArray, width: number, height: number): Uint8ClampedArray {
  const out = new Uint8ClampedArray(rgba.length);
  const rowStride = width * 4;
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const source = (y * width + x) * 4;
      const destination = (y * width + (width - 1 - x)) * 4;
      out[destination] = rgba[source];
      out[destination + 1] = rgba[source + 1];
      out[destination + 2] = rgba[source + 2];
      out[destination + 3] = rgba[source + 3];
    }
  }
  return out;
}

function buildScales(width: number, height: number): number[] {
  const sourcePixels = width * height;
  const fitScale = Math.min(
    1,
    MAX_QR_SCAN_EDGE / Math.max(width, height),
    Math.sqrt(MAX_QR_SCAN_PIXELS / sourcePixels)
  );
  // Try several render scales so the QR lands at a module size jsQR can read:
  // original, upscale (tiny QR in a large frame), downscale (oversized QR),
  // and the fit-to-limit size for huge images.
  const raw = [1, 2, 0.5, fitScale];
  const clamped = raw.map((scale) =>
    Math.min(scale, MAX_QR_SCAN_EDGE / Math.max(width, height), Math.sqrt(MAX_QR_SCAN_PIXELS / sourcePixels))
  );
  return [...new Set(clamped.filter((scale) => scale > 0))].sort((a, b) => a - b);
}

/**
 * Try several render scales and binarization strategies to maximize the chance
 * of decoding partially damaged, logo-bearing, low-contrast, or small QR codes.
 * jsQR still performs the final decode; this only feeds it better-prepared buffers.
 */
export async function scanQrRobust(image: HTMLImageElement): Promise<QrScanSuccess | null> {
  const naturalWidth = image.naturalWidth;
  const naturalHeight = image.naturalHeight;
  if (!naturalWidth || !naturalHeight) return null;
  const jsQR = (await import("jsqr")).default;

  for (const scale of buildScales(naturalWidth, naturalHeight)) {
    const width = Math.max(1, Math.round(naturalWidth * scale));
    const height = Math.max(1, Math.round(naturalHeight * scale));
    const base = renderScaled(image, width, height);
    if (!base) continue;
    const gray = toGrayscale(base);
    const threshold = otsuThreshold(gray);
    const candidates: Array<{ name: string; data: Uint8ClampedArray }> = [
      { name: "original", data: base },
      { name: "mirror", data: flipHorizontal(base, width, height) },
      { name: "binary", data: binarize(gray, threshold, false) },
      { name: "binary-invert", data: binarize(gray, threshold, true) }
    ];
    for (const candidate of candidates) {
      try {
        const code = jsQR(candidate.data, width, height);
        if (code && code.data) return { code, strategy: candidate.name, scanWidth: width, scanHeight: height };
      } catch {
        // Defensive: a malformed buffer should not abort the whole scan.
      }
    }
  }
  return null;
}

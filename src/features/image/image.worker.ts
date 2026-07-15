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

import {
  analyzeImageBasics,
  analyzeImagePixels,
  analyzeUndecodedImageBytes,
  buildImageRepairCandidates,
  tryRebuildPngContainer
} from "./analyzer";

export type ImageAnalysisResult = ReturnType<typeof analyzeImagePixels>;
export type ImageBasicsWorkerResult = {
  analysis: ReturnType<typeof analyzeImageBasics>;
  exif: Record<string, unknown>;
};
export type ImageRepairWorkerResult = {
  candidates: ReturnType<typeof buildImageRepairCandidates>;
  rebuiltPng: ReturnType<typeof tryRebuildPngContainer>;
};

export type ImageWorkerRequest =
  | { action: "basics"; bytes: ArrayBuffer; fileType: string }
  | { action: "hidden-undecoded"; bytes: ArrayBuffer; fileType: string; metadataFields: number; recoveryRows: Array<[string, string]> }
  | { action: "hidden-pixels"; bytes: ArrayBuffer; fileType: string; metadataFields: number; pixels: ArrayBuffer; width: number; height: number }
  | { action: "repair"; bytes: ArrayBuffer; format: string };

function resultTransferables(value: unknown, buffers = new Set<ArrayBuffer>()): ArrayBuffer[] {
  if (value instanceof Uint8Array || value instanceof Uint8ClampedArray) {
    if (value.buffer instanceof ArrayBuffer) buffers.add(value.buffer);
    return Array.from(buffers);
  }
  if (Array.isArray(value)) value.forEach((item) => resultTransferables(item, buffers));
  else if (value && typeof value === "object") Object.values(value).forEach((item) => resultTransferables(item, buffers));
  return Array.from(buffers);
}

async function parseImageMetadata(bytes: Uint8Array) {
  try {
    const exifrModule = await import("exifr");
    return ((await exifrModule
      .parse(bytes, { tiff: true, xmp: true, iptc: true, icc: true, jfif: true, ihdr: true, gps: true })
      .catch(() => null)) ?? {}) as Record<string, unknown>;
  } catch {
    return {};
  }
}

self.onmessage = async (event: MessageEvent<ImageWorkerRequest>) => {
  try {
    const request = event.data;
    const bytes = new Uint8Array(request.bytes);
    let result: ImageAnalysisResult | ImageBasicsWorkerResult | ImageRepairWorkerResult;
    if (request.action === "basics") {
      const exif = await parseImageMetadata(bytes);
      result = { analysis: analyzeImageBasics(bytes, request.fileType, exif), exif };
    } else if (request.action === "hidden-undecoded") {
      result = analyzeUndecodedImageBytes(bytes, request.fileType, request.metadataFields, request.recoveryRows);
    } else if (request.action === "hidden-pixels") {
      result = analyzeImagePixels(bytes, request.fileType, {
        data: new Uint8ClampedArray(request.pixels),
        width: request.width,
        height: request.height
      }, request.metadataFields);
    } else {
      result = {
        candidates: buildImageRepairCandidates(bytes, request.format),
        rebuiltPng: tryRebuildPngContainer(bytes)
      };
    }
    self.postMessage({ type: "result", result }, { transfer: resultTransferables(result) });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

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

import { evidenceReaderFromBlob } from "../../core/evidence/reader";
import { analyzeFirmware, type FirmwareAnalysisSession } from "./analyzer";

export type FirmwareWorkerRequest = {
  file: File;
  options?: {
    chunkSize?: number;
    maxObjects?: number;
    maxRecursiveBytes?: number;
    maxHashedObjects?: number;
    maxObjectHashBytes?: number;
  };
};

export type FirmwareWorkerProgress = {
  loaded: number;
  total: number;
  phase: "scan" | "resolve" | "recursive";
};

self.onmessage = async (event: MessageEvent<FirmwareWorkerRequest>) => {
  try {
    const { file, options } = event.data;
    if (!(file instanceof Blob)) throw new Error("Firmware worker did not receive a readable file.");
    const result: FirmwareAnalysisSession = await analyzeFirmware(evidenceReaderFromBlob(file), file.name || "firmware.bin", {
      ...options,
      onProgress: (loaded, total, phase) => self.postMessage({ type: "progress", progress: { loaded, total, phase } satisfies FirmwareWorkerProgress })
    });
    self.postMessage({ type: "result", result });
  } catch (caught) {
    self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
  }
};

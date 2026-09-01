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

import { unzipSync } from "fflate";
import { parseTar } from "./tar";
import { parseCpio } from "./cpio";

export type ArchiveFormat = "zip" | "tar" | "cpio";

export type ArchiveWorkerRequest = {
  /** Un-gzipped archive content bytes (the worker never re-runs decompression). */
  bytes: ArrayBuffer;
  entryName: string;
  format: ArchiveFormat;
  /** tar/cpio payload offset + length inside `bytes`; zip extraction ignores these. */
  dataOffset?: number;
  dataLength?: number;
};

/**
 * Pure, synchronous entry extraction used by the worker and unit tests.
 * - zip: inflate the single matching entry via fflate.
 * - tar/cpio: slice the contiguous payload (or re-parse to locate it by name).
 * Returns the raw entry bytes, or null when the entry cannot be extracted.
 */
export function extractEntry(request: ArchiveWorkerRequest): Uint8Array | null {
  const content = new Uint8Array(request.bytes);

  if (request.format === "zip") {
    const data = unzipSync(content, { filter: (entry) => entry.name === request.entryName });
    return data[request.entryName] ?? null;
  }

  if ((request.format === "tar" || request.format === "cpio") && typeof request.dataOffset === "number" && typeof request.dataLength === "number") {
    return content.subarray(request.dataOffset, request.dataOffset + request.dataLength);
  }

  const parsed = request.format === "tar" ? parseTar(content) : parseCpio(content);
  const entry = parsed.entries.find((candidate) => candidate.name === request.entryName);
  if (!entry) return null;
  return content.subarray(entry.dataOffset, entry.dataOffset + entry.dataLength);
}

if (typeof self !== "undefined") {
  self.onmessage = (event: MessageEvent<ArchiveWorkerRequest>) => {
    try {
      const slice = extractEntry(event.data);
      if (!slice) {
        self.postMessage({ type: "error", error: "Entry could not be extracted." });
        return;
      }
      const result = slice.buffer.slice(slice.byteOffset, slice.byteOffset + slice.byteLength);
      self.postMessage({ type: "result", result });
    } catch (caught) {
      self.postMessage({ type: "error", error: caught instanceof Error ? caught.message : String(caught) });
    }
  };
}

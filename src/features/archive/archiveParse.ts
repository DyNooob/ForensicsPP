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

import { gunzipSync } from "fflate";
import { parseZipCentralDirectory, type ZipDirectoryEntry } from "./zipDirectory";
import { parseTar, detectTar } from "./tar";
import { parseCpio, detectCpio } from "./cpio";

export type ArchiveFormat = "zip" | "tar" | "cpio";

export type ArchiveParseResult = {
  format: ArchiveFormat;
  entries: ZipDirectoryEntry[];
  skipped: number;
  contentBytes: Uint8Array;
  gzipped: boolean;
};

const DECOMPRESSED_CAP = 512 * 1024 * 1024;

function toZipEntry(name: string, size: number, dataOffset?: number, dataLength?: number): ZipDirectoryEntry {
  const entry: ZipDirectoryEntry = { name, method: 0, compressed: size, uncompressed: size, encrypted: false };
  if (typeof dataOffset === "number" && typeof dataLength === "number") {
    entry.dataOffset = dataOffset;
    entry.dataLength = dataLength;
  }
  return entry;
}

/**
 * Detect the container format and list its entries without inflating content.
 *
 * Order: gzip unwrap (transparent) -> cpio magic -> tar header checksum ->
 * ZIP central directory. Returns the bytes the extraction worker should slice
 * from (`contentBytes`) so callers never need to re-run decompression.
 */
export function parseArchive(bytes: Uint8Array, maxEntries = 2000): ArchiveParseResult | null {
  let contentBytes = bytes;
  let gzipped = false;
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    contentBytes = gunzipSync(bytes);
    gzipped = true;
    if (contentBytes.length > DECOMPRESSED_CAP) {
      throw new Error("Decompressed archive exceeds the 512 MiB safety limit.");
    }
  }

  if (detectCpio(contentBytes)) {
    const parsed = parseCpio(contentBytes, maxEntries);
    return {
      format: "cpio",
      entries: parsed.entries.map((entry) => toZipEntry(entry.name, entry.size, entry.dataOffset, entry.dataLength)),
      skipped: parsed.skipped,
      contentBytes,
      gzipped
    };
  }

  if (detectTar(contentBytes)) {
    const parsed = parseTar(contentBytes, maxEntries);
    if (parsed.entries.length > 0) {
      return {
        format: "tar",
        entries: parsed.entries.map((entry) => toZipEntry(entry.name, entry.size, entry.dataOffset, entry.dataLength)),
        skipped: parsed.skipped,
        contentBytes,
        gzipped
      };
    }
  }

  const directory = parseZipCentralDirectory(contentBytes, maxEntries);
  if (directory && directory.entries.length > 0) {
    return { format: "zip", entries: directory.entries, skipped: directory.skipped, contentBytes, gzipped };
  }

  return null;
}

export { parseArchiveEntriesShim as parseArchiveEntries };

/**
 * Backwards-compatible shim kept for any external caller that only needs the
 * ZIP-family listing. Prefer `parseArchive` for multi-format handling.
 */
function parseArchiveEntriesShim(bytes: Uint8Array): { entries: ZipDirectoryEntry[]; skipped: number } {
  const result = parseArchive(bytes);
  if (!result) return { entries: [], skipped: 0 };
  return { entries: result.entries, skipped: result.skipped };
}

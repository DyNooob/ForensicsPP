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

import { containerKind, expandContainer } from "./containerExtractors";
import { scanCarvableObjects, type CarverHit } from "./carver";

export type RecursiveCarverObject = CarverHit & {
  virtualPath: string;
  origin: "signature" | "archive-entry" | "decompressed";
  bytes: Uint8Array;
};

export type RecursiveCarverOptions = {
  maxDepth?: number;
  maxObjects?: number;
  maxExpandedBytes?: number;
  maxObjectBytes?: number;
};

const DEFAULT_MAX_DEPTH = 4;
const DEFAULT_MAX_OBJECTS = 256;
const DEFAULT_MAX_EXPANDED = 128 * 1024 * 1024;
const DEFAULT_MAX_OBJECT = 32 * 1024 * 1024;

function extensionForName(name: string) {
  const match = name.match(/\.([A-Za-z0-9]{1,12})$/);
  return match?.[1]?.toLowerCase() ?? "bin";
}

function mimeForName(name: string) {
  const ext = extensionForName(name);
  if (["png", "jpg", "jpeg", "gif", "webp", "bmp"].includes(ext)) return `image/${ext === "jpg" ? "jpeg" : ext}`;
  if (ext === "pdf") return "application/pdf";
  if (["apk", "jar", "zip"].includes(ext)) return "application/zip";
  if (["sqlite", "db", "sqlite3"].includes(ext)) return "application/vnd.sqlite3";
  if (ext === "json") return "application/json";
  if (ext === "xml") return "application/xml";
  return "application/octet-stream";
}

function labelForEntry(name: string, bytes: Uint8Array) {
  const first = scanCarvableObjects(bytes, { startOffset: 0, maxHits: 8 }).find((hit) => hit.offset === 0);
  if (first) return first.label;
  const ext = extensionForName(name);
  if (ext === "apk") return "APK / ZIP archive";
  if (["sqlite", "db", "sqlite3"].includes(ext)) return "SQLite";
  return `Container entry (.${ext})`;
}

export function scanRecursiveCarvableObjects(source: Uint8Array, options: RecursiveCarverOptions = {}) {
  const maxDepth = Math.max(0, Math.min(8, options.maxDepth ?? DEFAULT_MAX_DEPTH));
  const maxObjects = Math.max(1, Math.min(4096, options.maxObjects ?? DEFAULT_MAX_OBJECTS));
  const maxExpandedBytes = Math.max(1024, options.maxExpandedBytes ?? DEFAULT_MAX_EXPANDED);
  const maxObjectBytes = Math.max(1024, options.maxObjectBytes ?? DEFAULT_MAX_OBJECT);
  const output: RecursiveCarverObject[] = [];
  let expandedBytes = 0;

  const add = (item: RecursiveCarverObject) => {
    if (output.length >= maxObjects) return false;
    output.push(item);
    return true;
  };

  const walk = (bytes: Uint8Array, path: string, depth: number, origin: RecursiveCarverObject["origin"]) => {
    if (depth > maxDepth || output.length >= maxObjects || !bytes.length) return;

    const signatures = scanCarvableObjects(bytes, { startOffset: 0, maxHits: Math.min(128, maxObjects - output.length) });
    for (const hit of signatures) {
      if (hit.offset === 0 && origin !== "signature") continue;
      const retained = hit.repairedBytes && hit.repairedBytes.length
        ? hit.repairedBytes
        : (hit.size > 0 && hit.size <= maxObjectBytes && hit.offset + hit.size <= bytes.length
          ? bytes.slice(hit.offset, hit.offset + hit.size)
          : new Uint8Array());
      const virtualPath = `${path}::${hit.label}@0x${hit.offset.toString(16).toUpperCase()}`;
      if (!add({ ...hit, depth, virtualPath, origin: "signature", bytes: retained })) return;
      const isWholeCurrentObject = hit.offset === 0 && hit.size === bytes.length;
      if (!isWholeCurrentObject && retained.length && depth < maxDepth && containerKind(retained)) {
        walk(retained, virtualPath, depth + 1, "signature");
      }
    }

    if (depth >= maxDepth || output.length >= maxObjects || !containerKind(bytes)) return;
    try {
      const entries = expandContainer(bytes, {
        maxEntries: Math.min(4096, maxObjects * 8),
        maxEntryBytes: maxObjectBytes,
        maxTotalBytes: Math.max(1024, maxExpandedBytes - expandedBytes),
        maxCompressionRatio: 250
      });
      for (const entry of entries) {
        if (output.length >= maxObjects) break;
        if (!entry.bytes.length || expandedBytes + entry.bytes.length > maxExpandedBytes) continue;
        expandedBytes += entry.bytes.length;
        const entryPath = `${path}!/${entry.name}`;
        const first = scanCarvableObjects(entry.bytes, { startOffset: 0, maxHits: 8, pngTolerant: false }).find((hit) => hit.offset === 0);
        const expandedOrigin: RecursiveCarverObject["origin"] = entry.sourceKind === "zip" || entry.sourceKind === "tar" || entry.sourceKind === "cpio"
          ? "archive-entry"
          : "decompressed";
        const item: RecursiveCarverObject = {
          label: labelForEntry(entry.name, entry.bytes),
          offset: 0,
          size: entry.bytes.length,
          extension: first?.extension ?? extensionForName(entry.name),
          mime: first?.mime ?? mimeForName(entry.name),
          confidence: first?.confidence ?? "medium",
          extent: first?.extent ?? "exact",
          detail: first?.detail ?? `Expanded ${entry.sourceKind} container entry`,
          depth: depth + 1,
          virtualPath: entryPath,
          origin: expandedOrigin,
          bytes: entry.bytes.slice()
        };
        if (!add(item)) break;
        walk(entry.bytes, entryPath, depth + 1, expandedOrigin);
      }
    } catch {
      // Preserve signature evidence even when a container is malformed or exceeds safety limits.
    }
  };

  walk(source, "source", 0, "signature");
  const unique = new Map<string, RecursiveCarverObject>();
  for (const item of output) {
    const key = `${item.virtualPath}|${item.size}|${item.label}`;
    if (!unique.has(key)) unique.set(key, item);
  }
  return Array.from(unique.values()).slice(0, maxObjects);
}

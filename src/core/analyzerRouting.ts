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

import type { ToolId } from "../config/app";

export type ArtifactRoutingInput = {
  label: string;
  extension?: string;
  mime?: string;
  bytes?: Uint8Array;
};

function bytesContainAscii(bytes: Uint8Array | undefined, text: string) {
  if (!bytes?.length || !text) return false;
  const pattern = Array.from(text, (char) => char.charCodeAt(0));
  outer: for (let offset = 0; offset + pattern.length <= bytes.length; offset += 1) {
    for (let index = 0; index < pattern.length; index += 1) {
      if (bytes[offset + index] !== pattern[index]) continue outer;
    }
    return true;
  }
  return false;
}

export function analyzerForArtifact(input: ArtifactRoutingInput): ToolId {
  const descriptor = `${input.label} ${input.extension ?? ""} ${input.mime ?? ""}`.toLowerCase();
  if (/sqlite|\.db\b/.test(descriptor)) return "sqlite";
  if (/png|jpeg|jpg|gif|webp|bmp|image\//.test(descriptor)) return "image";
  if (/pdf|ole|officedocument|msword|document/.test(descriptor)) return "documentforensics";
  if (/pcap|pcapng/.test(descriptor)) return "pcap";
  if (/\bapk\b|android/.test(descriptor)) return "android";
  if (/zip|jar|archive|7z|rar|tar|cpio|gzip|bzip|xz|zstandard|zlib/.test(descriptor)) {
    if (bytesContainAscii(input.bytes, "AndroidManifest.xml") && bytesContainAscii(input.bytes, "classes.dex")) return "android";
    return "archive";
  }
  if (/fat|exfat|ntfs|ext\b|iso9660|filesystem|disk image/.test(descriptor)) return "disk";
  if (/\$mft|usnjrnl|prefetch|lnk|zone\.identifier|windows artifact/.test(descriptor)) return "windows";
  return "binary";
}

export function analyzerTargetLabel(tool: ToolId, english: boolean) {
  const labels: Partial<Record<ToolId, [string, string]>> = {
    sqlite: ["SQLite", "SQLite"],
    image: ["图片", "Image"],
    documentforensics: ["文档取证", "Document"],
    android: ["Android APK", "Android APK"],
    archive: ["压缩包", "Archive"],
    disk: ["磁盘镜像", "Disk Image"],
    windows: ["Windows", "Windows"],
    pcap: ["流量包", "PCAP"],
    binary: ["二进制", "Binary"]
  };
  return labels[tool]?.[english ? 1 : 0] ?? tool;
}

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

import type { CaseEvidenceFile } from "../../models";
import { hashFileInWorker } from "../hash/task";
import { hashSelectedFile } from "../../utils/hash";

const toolFileSources = new WeakMap<HTMLElement, Map<EventTarget, File[]>>();

export function evidenceFileKey(file: Pick<File, "name" | "size" | "lastModified">) {
  return `${file.name}:${file.size}:${file.lastModified}`;
}

function toolRoot(target: EventTarget | null) {
  return target instanceof Element ? target.closest<HTMLElement>(".tool-retained-view") : null;
}

export function rememberEvidenceFiles(target: EventTarget | null, files: FileList | File[]) {
  const root = toolRoot(target);
  if (!root) return;
  const source = target ?? root;
  const sources = toolFileSources.get(root) ?? new Map<EventTarget, File[]>();
  sources.set(source, Array.from(files));
  toolFileSources.set(root, sources);
}

export function rememberedEvidenceFiles(root: HTMLElement) {
  const sources = toolFileSources.get(root);
  if (!sources) return [];
  return Array.from(new Map(
    Array.from(sources.values()).flat().map((file) => [evidenceFileKey(file), file])
  ).values());
}

export async function fingerprintEvidenceFiles(files: File[]): Promise<CaseEvidenceFile[]> {
  const uniqueFiles = Array.from(new Map(files.map((file) => [evidenceFileKey(file), file])).values());
  const records: CaseEvidenceFile[] = [];
  for (const file of uniqueFiles) {
    let sha256 = "";
    try {
      const result = typeof Worker === "undefined"
        ? await hashSelectedFile(file, ["sha256"])
        : await hashFileInWorker(file, ["sha256"]);
      sha256 = result.sha256 ?? "";
    } catch {
      // Keep the metadata record when the browser refuses a later read.
    }
    records.push({
      name: file.name,
      size: file.size,
      type: file.type || "application/octet-stream",
      lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : "",
      ...(sha256 ? { sha256 } : {})
    });
  }
  return records;
}

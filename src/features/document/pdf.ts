/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

import { GlobalWorkerOptions, getDocument } from "pdfjs-dist";
import pdfWorkerUrl from "./pdfjs.worker.ts?worker&url";
import type { DocumentAnalysis, DocumentFinding, DocumentExtract } from "./analyzer";

GlobalWorkerOptions.workerSrc = pdfWorkerUrl;

function ensureModernUint8Array() {
  const promiseConstructor = Promise as unknown as {
    try?: (callback: (...args: unknown[]) => unknown, ...args: unknown[]) => Promise<unknown>;
  };
  promiseConstructor.try ??= (callback, ...args) => new Promise((resolve, reject) => {
    try {
      resolve(callback(...args));
    } catch (error) {
      reject(error);
    }
  });
  const prototype = Uint8Array.prototype as Uint8Array & { toHex?: (this: Uint8Array) => string; toBase64?: (this: Uint8Array) => string };
  prototype.toHex ??= function toHex(this: Uint8Array) {
    return Array.from(this, (value) => value.toString(16).padStart(2, "0")).join("");
  };
  prototype.toBase64 ??= function toBase64(this: Uint8Array) {
    let binary = "";
    for (let offset = 0; offset < this.length; offset += 0x8000) binary += String.fromCharCode(...this.subarray(offset, offset + 0x8000));
    return btoa(binary);
  };
  const mapPrototype = Map.prototype as unknown as { getOrInsertComputed?: (this: Map<unknown, unknown>, key: unknown, callback: (key: unknown) => unknown) => unknown };
  mapPrototype.getOrInsertComputed ??= function getOrInsertComputed(this: Map<unknown, unknown>, key: unknown, callback: (key: unknown) => unknown) {
    if (this.has(key)) return this.get(key);
    const value = callback(key);
    this.set(key, value);
    return value;
  };
}

async function rawSignals(bytes: Uint8Array) {
  const tokens: Array<[RegExp, DocumentFinding["category"], string]> = [
    [/\/OpenAction\b/g, "action", "OpenAction"], [/\/AA\b/g, "action", "Additional actions"], [/\/JavaScript\b/g, "action", "JavaScript action"],
    [/\/Launch\b/g, "action", "Launch action"], [/\/EmbeddedFile\b/g, "embedded", "Embedded file"], [/\/AcroForm\b/g, "structure", "AcroForm"],
    [/\/XFA\b/g, "structure", "XFA form"], [/\/Encrypt\b/g, "structure", "Encryption dictionary"], [/\/ObjStm\b/g, "structure", "Object stream"]
  ];
  const findings: DocumentFinding[] = [];
  const seen = new Set<string>();
  const eofOffsets = new Set<number>();
  let encrypted = false;
  const chunkSize = 4 * 1024 * 1024;
  for (let start = 0; start < bytes.byteLength; start += chunkSize) {
    const from = Math.max(0, start - 64);
    const raw = new TextDecoder("latin1").decode(bytes.subarray(from, Math.min(bytes.byteLength, start + chunkSize)));
    tokens.forEach(([pattern, category, label]) => {
      pattern.lastIndex = 0;
      for (const match of raw.matchAll(pattern)) {
        const offset = from + (match.index ?? 0);
        if (offset < start - 64 || seen.has(`${label}:${offset}`)) continue;
        seen.add(`${label}:${offset}`);
        findings.push({ category, label, detail: `Token at byte offset ${offset}`, location: `offset ${offset}` });
        if (label === "Encryption dictionary") encrypted = true;
        if (findings.filter((item) => item.label === label).length >= 100) break;
      }
    });
    for (const match of raw.matchAll(/%%EOF/g)) eofOffsets.add(from + (match.index ?? 0));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  return { findings, revisions: Math.max(1, eofOffsets.size), encrypted };
}

export async function analyzePdf(bytes: Uint8Array, name: string): Promise<DocumentAnalysis> {
  ensureModernUint8Array();
  const structural = await rawSignals(bytes);
  const loading = getDocument({ data: bytes.slice(), useWorkerFetch: false, useWasm: false, verbosity: 0 });
  const pdf = await loading.promise;
  try {
    const metadataResult = await pdf.getMetadata().catch(() => null);
    const info = (metadataResult?.info ?? {}) as Record<string, unknown>;
    const metadata = Object.entries(info).filter(([, value]) => value != null && String(value)).map(([key, value]) => [key, String(value)] as [string, string]);
    const attachments = await pdf.getAttachments().catch(() => null);
    const extracts: DocumentExtract[] = [];
    const findings = [...structural.findings];
    if (attachments) for (const [attachmentName, attachment] of attachments) {
      const resolved = attachment.content ?? await pdf.getAttachmentContent(attachmentName);
      if (!resolved) continue;
      const content = resolved instanceof Uint8Array ? resolved : new Uint8Array(resolved);
      extracts.push({ id: `pdf:${attachmentName}`, name: attachmentName, size: content.byteLength, kind: "PDF attachment", bytes: content });
      findings.push({ category: "embedded", label: "PDF attachment", detail: `${content.byteLength} bytes`, location: attachmentName });
    }
    const actions = await pdf.getJSActions().catch(() => null);
    if (actions && Object.keys(actions).length) findings.push({ category: "action", label: "Document JavaScript actions", detail: Object.keys(actions).join(", "), location: "PDF catalog" });
    const outline = await pdf.getOutline().catch(() => null);
    return {
      name, size: bytes.byteLength, kind: "PDF", subtype: `PDF ${info.PDFFormatVersion ?? ""}`.trim(), metadata, findings,
      entries: extracts.map((extract) => ({ name: extract.name, size: extract.size, kind: extract.kind })), extracts,
      pages: pdf.numPages, revisions: structural.revisions, encrypted: structural.encrypted, notes: outline?.length ? [`Outline entries: ${outline.length}`] : []
    };
  } finally {
    await loading.destroy();
  }
}

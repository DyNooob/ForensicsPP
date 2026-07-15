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

import * as CFB from "cfb";
import { unzipSync } from "fflate";

export type DocumentFinding = {
  category: "metadata" | "external" | "embedded" | "macro" | "action" | "structure";
  label: string;
  detail: string;
  location: string;
};

export type DocumentEntry = {
  name: string;
  size: number;
  kind: string;
};

export type DocumentExtract = {
  id: string;
  name: string;
  size: number;
  kind: string;
  bytes: Uint8Array;
};

export type DocumentAnalysis = {
  name: string;
  size: number;
  kind: "PDF" | "OOXML" | "OLE";
  subtype: string;
  metadata: Array<[string, string]>;
  findings: DocumentFinding[];
  entries: DocumentEntry[];
  extracts: DocumentExtract[];
  pages: number;
  revisions: number;
  encrypted: boolean;
  notes: string[];
};

// Keep the workspace useful after navigation without letting embedded objects
// consume the whole browser quota. The live analysis still retains the full
// extraction set; this limit applies only to the persisted snapshot.
export const MAX_PERSISTED_DOCUMENT_EXTRACT_BYTES = 8 * 1024 * 1024;

export function persistableDocumentAnalysis(analysis: DocumentAnalysis): DocumentAnalysis {
  let retained = 0;
  return {
    ...analysis,
    extracts: analysis.extracts.map((extract) => {
      if (extract.bytes.byteLength > 0 && retained + extract.bytes.byteLength <= MAX_PERSISTED_DOCUMENT_EXTRACT_BYTES) {
        retained += extract.bytes.byteLength;
        return { ...extract, bytes: extract.bytes.slice() };
      }
      return { ...extract, bytes: new Uint8Array() };
    })
  };
}

const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_EXTRACT_BYTES = 128 * 1024 * 1024;

function decodeXml(value: string) {
  return value.replace(/&#x([0-9a-f]+);/gi, (_, raw: string) => String.fromCodePoint(Number.parseInt(raw, 16)))
    .replace(/&#(\d+);/g, (_, raw: string) => String.fromCodePoint(Number.parseInt(raw, 10)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function xmlText(xml: string, localName: string) {
  const match = xml.match(new RegExp(`<(?:[\\w.-]+:)?${localName}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${localName}>`, "i"));
  return match ? decodeXml(match[1].replace(/<[^>]+>/g, "").trim()) : "";
}

function text(bytes?: Uint8Array) {
  return bytes ? new TextDecoder("utf-8", { fatal: false }).decode(bytes) : "";
}

function ooxmlSubtype(names: string[]) {
  if (names.some((name) => name.startsWith("word/"))) return "Word OOXML";
  if (names.some((name) => name.startsWith("xl/"))) return "Excel OOXML";
  if (names.some((name) => name.startsWith("ppt/"))) return "PowerPoint OOXML";
  return "OOXML package";
}

function kindForEntry(name: string) {
  if (/vbaproject\.bin$/i.test(name)) return "VBA project";
  if (/(?:^|\/)embeddings\//i.test(name)) return "Embedded object";
  if (/(?:^|\/)activeX\//i.test(name)) return "ActiveX";
  if (/\.rels$/i.test(name)) return "Relationships";
  if (/\.xml$/i.test(name)) return "XML";
  if (/\.(?:png|jpe?g|gif|bmp|tiff?|emf|wmf)$/i.test(name)) return "Media";
  return "Package part";
}

function addExtract(extracts: DocumentExtract[], name: string, kind: string, bytes: Uint8Array) {
  const used = extracts.reduce((sum, item) => sum + item.size, 0);
  if (!bytes.byteLength || bytes.byteLength > MAX_ENTRY_BYTES || used + bytes.byteLength > MAX_EXTRACT_BYTES) return false;
  extracts.push({ id: `${name}:${bytes.byteLength}`, name: name.split("/").pop() || name, size: bytes.byteLength, kind, bytes });
  return true;
}

function inspectCfb(bytes: Uint8Array, source: string) {
  const findings: DocumentFinding[] = [];
  const entries: DocumentEntry[] = [];
  const extracts: DocumentExtract[] = [];
  const cfb = CFB.parse(bytes, { type: "array" });
  cfb.FileIndex.forEach((entry, index) => {
    const path = cfb.FullPaths[index] ?? entry.name;
    if (entry.type !== 2 || !entry.content) return;
    const content = entry.content instanceof Uint8Array ? entry.content : new Uint8Array(entry.content);
    const kind = /VBA|_VBA_PROJECT|dir$/i.test(path) ? "VBA stream" : /ObjectPool|Ole10Native|Package/i.test(path) ? "Embedded object stream" : "OLE stream";
    entries.push({ name: path, size: content.byteLength, kind });
    if (kind !== "OLE stream") {
      findings.push({ category: kind === "VBA stream" ? "macro" : "embedded", label: kind, detail: `${content.byteLength} bytes`, location: path });
      addExtract(extracts, `${source}-${entry.name}.bin`, kind, content);
    }
  });
  return { findings, entries, extracts };
}

export function analyzeOoxml(bytes: Uint8Array, name: string): DocumentAnalysis {
  const files = unzipSync(bytes, {
    filter: (entry) => entry.originalSize <= MAX_ENTRY_BYTES && !(entry.size > 0 && entry.originalSize / entry.size > 500 && entry.originalSize > 16 * 1024 * 1024)
  });
  const names = Object.keys(files).sort();
  if (!names.some((entry) => entry.toLowerCase() === "[content_types].xml")) throw new Error("The ZIP file is not an OOXML package.");
  const metadata: Array<[string, string]> = [];
  const findings: DocumentFinding[] = [];
  const extracts: DocumentExtract[] = [];
  const notes: string[] = [];
  const entriesExtra: DocumentEntry[] = [];
  const core = text(files["docProps/core.xml"]);
  const app = text(files["docProps/app.xml"]);
  const metadataFields: Array<[string, string]> = [
    ["Title", xmlText(core, "title")], ["Subject", xmlText(core, "subject")], ["Creator", xmlText(core, "creator")],
    ["Last modified by", xmlText(core, "lastModifiedBy")], ["Created", xmlText(core, "created")], ["Modified", xmlText(core, "modified")],
    ["Application", xmlText(app, "Application")], ["App version", xmlText(app, "AppVersion")], ["Company", xmlText(app, "Company")]
  ];
  metadata.push(...metadataFields.filter((row) => row[1]));

  for (const relationName of names.filter((entry) => entry.endsWith(".rels"))) {
    const xml = text(files[relationName]);
    for (const match of xml.matchAll(/<Relationship\b([^>]*)\/?\s*>/gi)) {
      const attrs = match[1];
      const target = attrs.match(/\bTarget=(?:"([^"]*)"|'([^']*)')/i)?.slice(1).find(Boolean) ?? "";
      const mode = attrs.match(/\bTargetMode=(?:"([^"]*)"|'([^']*)')/i)?.slice(1).find(Boolean) ?? "";
      const type = attrs.match(/\bType=(?:"([^"]*)"|'([^']*)')/i)?.slice(1).find(Boolean)?.split("/").pop() ?? "relationship";
      if (mode.toLowerCase() === "external" || /^(?:https?|file|ftp|mailto):/i.test(target)) findings.push({ category: "external", label: `External ${type}`, detail: decodeXml(target), location: relationName });
    }
  }

  for (const entryName of names) {
    const content = files[entryName];
    const kind = kindForEntry(entryName);
    if (kind === "VBA project" || kind === "Embedded object" || kind === "ActiveX") {
      const category = kind === "VBA project" ? "macro" : "embedded";
      findings.push({ category, label: kind, detail: `${content.byteLength} bytes`, location: entryName });
      if (!addExtract(extracts, entryName, kind, content)) notes.push(`Not retained for extraction: ${entryName}`);
      if (kind === "VBA project" || (kind === "Embedded object" && content[0] === 0xd0 && content[1] === 0xcf)) {
        try {
          const nested = inspectCfb(content, entryName);
          findings.push(...nested.findings);
          nested.entries.forEach((entry) => entriesExtra.push(entry));
          nested.extracts.forEach((extract) => addExtract(extracts, `${entryName}-${extract.name}`, extract.kind, extract.bytes));
        } catch {
          notes.push(`Compound streams could not be enumerated: ${entryName}`);
        }
      }
    }
  }
  const entries = names.map((entryName) => ({ name: entryName, size: files[entryName].byteLength, kind: kindForEntry(entryName) }));
  entries.push(...entriesExtra);
  return { name, size: bytes.byteLength, kind: "OOXML", subtype: ooxmlSubtype(names), metadata, findings, entries, extracts, pages: 0, revisions: 0, encrypted: names.some((entry) => /EncryptedPackage/i.test(entry)), notes };
}

export function analyzeOle(bytes: Uint8Array, name: string): DocumentAnalysis {
  const inspected = inspectCfb(bytes, name);
  return {
    name, size: bytes.byteLength, kind: "OLE", subtype: "OLE Compound File", metadata: [], findings: inspected.findings,
    entries: inspected.entries, extracts: inspected.extracts, pages: 0, revisions: 0, encrypted: false, notes: []
  };
}

export function isPdf(bytes: Uint8Array) {
  return new TextDecoder("ascii").decode(bytes.subarray(0, 8)).startsWith("%PDF-");
}

export function isOle(bytes: Uint8Array) {
  return bytes.byteLength >= 8 && [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((value, index) => bytes[index] === value);
}

export function isZip(bytes: Uint8Array) {
  return bytes.byteLength >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && [0x03, 0x05, 0x07].includes(bytes[2]);
}

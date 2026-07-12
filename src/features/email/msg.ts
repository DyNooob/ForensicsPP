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

import * as CFB from "cfb";
import type { EmailAnalysis, EmailAttachmentRow } from "../../models";
import { fileSignatureForBytes } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { parseEmail } from "./workbench";

type MsgStream = { path: string; name: string; bytes: Uint8Array };

function streamBytes(content: number[] | Uint8Array) {
  return content instanceof Uint8Array ? content : new Uint8Array(content);
}

function normalizePath(value: string) {
  return value.replace(/^[^/]+\//, "").replace(/\/$/, "");
}

function findProperty(streams: MsgStream[], property: string, prefix = "") {
  const expression = new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:/)?__substg1\\.0_${property}(001F|001E|0102)$`, "i");
  return streams.find((stream) => expression.test(stream.path));
}

function decodeProperty(stream: MsgStream | undefined) {
  if (!stream) return "";
  if (/001F$/i.test(stream.name)) return new TextDecoder("utf-16le").decode(stream.bytes).replace(/\0+$/g, "");
  if (/001E$/i.test(stream.name)) return new TextDecoder("windows-1252").decode(stream.bytes).replace(/\0+$/g, "");
  return new TextDecoder().decode(stream.bytes).replace(/\0+$/g, "");
}

function propertyText(streams: MsgStream[], property: string, prefix = "") {
  return decodeProperty(findProperty(streams, property, prefix));
}

function extensionOf(name: string) {
  return name.includes(".") ? name.split(".").pop()?.toLowerCase() || "--" : "--";
}

function msgAttachments(streams: MsgStream[]): EmailAttachmentRow[] {
  const prefixes = Array.from(new Set(streams.map((stream) => stream.path.match(/^(__attach_version1\.0_#[^/]+)/i)?.[1]).filter(Boolean) as string[]));
  return prefixes.flatMap((prefix, index) => {
    const dataStream = findProperty(streams, "3701", prefix);
    if (!dataStream) return [];
    const content = dataStream.bytes.slice();
    const filename = propertyText(streams, "3707", prefix) || propertyText(streams, "3704", prefix) || `attachment-${index + 1}`;
    const contentType = propertyText(streams, "370E", prefix) || "application/octet-stream";
    const extension = extensionOf(filename);
    const detected = fileSignatureForBytes(content);
    return [{
      filename,
      contentType,
      size: content.byteLength,
      sha256: "",
      extension,
      signature: detected?.label ?? (content.byteLength ? "Unknown" : "--"),
      mismatch: Boolean(detected && extension !== "--" && !detected.extensions.includes(extension)),
      risk: [], preview: "", content, iocs: [], urlRows: [], nestedHeaders: []
    }];
  });
}

function headerLine(name: string, value: string) {
  return value ? `${name}: ${value.replace(/[\r\n]+/g, " ")}` : "";
}

export function isMsgFile(file: File, bytes?: Uint8Array) {
  return /\.msg$/i.test(file.name) || file.type === "application/vnd.ms-outlook" || Boolean(bytes && bytes.byteLength >= 8 && [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((value, index) => bytes[index] === value));
}

export async function parseMsg(bytes: Uint8Array): Promise<{ analysis: EmailAnalysis; source: string }> {
  const oleMagic = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  if (bytes.byteLength < 512 || !oleMagic.every((value, index) => bytes[index] === value)) throw new Error("不是有效的 Outlook MSG 文件。");
  let cfb: CFB.CFB$Container;
  try {
    cfb = CFB.parse(bytes, { type: "array" });
  } catch {
    throw new Error("Outlook MSG 容器无法读取。");
  }
  const streams: MsgStream[] = cfb.FileIndex.flatMap((entry, index) => {
    if (entry.type !== 2 || !entry.content) return [];
    const path = normalizePath(cfb.FullPaths[index] ?? entry.name);
    return [{ path, name: path.split("/").pop() ?? entry.name, bytes: streamBytes(entry.content) }];
  });
  const hasRootProperties = streams.some((stream) => /^__properties_version1\.0$/i.test(stream.path));
  const hasRootMapiProperty = streams.some((stream) => /^__substg1\.0_(?:0037|007D|0C1A|0C1F|0E03|0E04|1000|1013|1035|5D01)/i.test(stream.path));
  if (!hasRootProperties && !hasRootMapiProperty) throw new Error("不是有效的 Outlook MSG 文件：未找到邮件属性流。");
  const subject = propertyText(streams, "0037");
  const fromName = propertyText(streams, "0C1A");
  const fromAddress = propertyText(streams, "5D01") || propertyText(streams, "0C1F");
  const to = propertyText(streams, "0E04");
  const cc = propertyText(streams, "0E03");
  const messageId = propertyText(streams, "1035");
  const transportHeaders = propertyText(streams, "007D");
  const bodyText = propertyText(streams, "1000");
  const htmlStream = findProperty(streams, "1013");
  const bodyHtml = htmlStream ? decodeProperty(htmlStream) : "";
  const from = fromAddress ? (fromName ? `${fromName} <${fromAddress}>` : fromAddress) : fromName;
  const fallbackHeaders = [
    headerLine("From", from), headerLine("To", to), headerLine("Cc", cc), headerLine("Subject", subject), headerLine("Message-ID", messageId),
    "MIME-Version: 1.0", `Content-Type: ${bodyHtml ? "text/html" : "text/plain"}; charset=utf-8`
  ].filter(Boolean).join("\r\n");
  const source = `${transportHeaders.trim() || fallbackHeaders}\r\n\r\n${bodyHtml || bodyText}`;
  const analysis = await parseEmail(source);
  const attachments = msgAttachments(streams);
  analysis.rawSize = bytes.byteLength;
  analysis.attachments = attachments;
  analysis.bodyText = bodyText || analysis.bodyText;
  analysis.bodyHtml = bodyHtml || analysis.bodyHtml;
  analysis.rows = analysis.rows.map(([key, value]) => key === "Raw size" ? [key, formatBytes(bytes.byteLength)] : key === "Attachments" ? [key, String(attachments.length)] : [key, value]);
  analysis.headers = analysis.headers.filter(([name]) => name.toLowerCase() !== "content-type" || transportHeaders.trim());
  return { analysis, source: ["Outlook MSG", `Streams: ${streams.length}`, `Attachments: ${attachments.length}`, "", ...analysis.headers.map(([name, value]) => `${name}: ${value}`)].join("\n") };
}

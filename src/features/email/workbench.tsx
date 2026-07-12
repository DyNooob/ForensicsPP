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

import PostalMime, { decodeWords } from "postal-mime";
import type { EmailAnalysis, EmailAttachmentRow, IocRecord } from "../../models";
import { fileSignatureForBytes } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { defangIocValue, extractIocs, iocRisk, normalizeIoc } from "../ioc/analyzer";

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function decodeQuotedPrintableText(input: string) {
  const normalized = input.replace(/=\r?\n/g, "");
  const bytes: number[] = [];
  for (let index = 0; index < normalized.length; index += 1) {
    const hex = normalized.slice(index + 1, index + 3);
    if (normalized[index] === "=" && /^[0-9a-fA-F]{2}$/.test(hex)) {
      bytes.push(Number.parseInt(hex, 16));
      index += 2;
    } else bytes.push(normalized.charCodeAt(index));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

export function quotedPrintableEncode(input: string) {
  return Array.from(new TextEncoder().encode(input)).map((byte) => {
    if (byte === 9 || byte === 32 || (byte >= 33 && byte <= 60) || (byte >= 62 && byte <= 126)) return String.fromCharCode(byte);
    return `=${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }).join("");
}

export function base32Encode(input: string) {
  const bytes = new TextEncoder().encode(input);
  const bits = Array.from(bytes).map((byte) => byte.toString(2).padStart(8, "0")).join("");
  return (bits.match(/.{1,5}/g) ?? []).map((chunk) => base32Alphabet[Number.parseInt(chunk.padEnd(5, "0"), 2)]).join("").padEnd(Math.ceil(bytes.length / 5) * 8, "=");
}

export function base32Decode(input: string) {
  const clean = input.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  const bits = Array.from(clean).map((char) => base32Alphabet.indexOf(char).toString(2).padStart(5, "0")).join("");
  return new TextDecoder().decode(new Uint8Array(bits.match(/.{8}/g)?.map((chunk) => Number.parseInt(chunk, 2)) ?? []));
}

export function base58Encode(input: string) {
  const bytes = new TextEncoder().encode(input);
  let value = Array.from(bytes).reduce((result, byte) => (result << 8n) + BigInt(byte), 0n);
  let encoded = "";
  while (value > 0n) {
    encoded = base58Alphabet[Number(value % 58n)] + encoded;
    value /= 58n;
  }
  const leadingZeros = Array.from(bytes).findIndex((byte) => byte !== 0);
  return `${"1".repeat(leadingZeros < 0 ? bytes.length : leadingZeros)}${encoded}`;
}

export function base58Decode(input: string) {
  const clean = input.replace(/\s+/g, "");
  let value = 0n;
  for (const char of clean) {
    const index = base58Alphabet.indexOf(char);
    if (index < 0) throw new Error(`Invalid Base58 character: ${char}`);
    value = value * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  const leadingZeros = clean.match(/^1+/)?.[0].length ?? 0;
  return new TextDecoder().decode(new Uint8Array([...Array.from({ length: leadingZeros }, () => 0), ...bytes]));
}

export function stripEmailHtml(input: string) {
  if (!input.trim()) return "--";
  return input
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<(br|p|div|tr|li|h[1-6])\b[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, "\"")
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim() || "--";
}

export function alignedEmailDomains(left: string, right: string) {
  if (!left || !right) return false;
  const base = (value: string) => {
    const parts = value.toLowerCase().replace(/[>;)\]]+$/g, "").split(".").filter(Boolean);
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
  };
  return left === right || base(left) === base(right) || left.endsWith(`.${right}`) || right.endsWith(`.${left}`);
}

export function emailIocRecords(text: string, source = "text"): IocRecord[] {
  const records: IocRecord[] = [];
  Object.entries(extractIocs(text)).forEach(([type, values]) => values.forEach((value, index) => {
    const normalized = normalizeIoc(type, value);
    records.push({ id: `${type}-${index}-${value}`, type, value, normalized, line: 0, lines: [], count: 1, context: source, contexts: [source], defanged: defangIocValue(normalized), risk: iocRisk(type, value) });
  }));
  return records.slice(0, 500);
}

function unfoldHeaders(raw: string) {
  return raw.replace(/\r\n/g, "\n").split("\n").reduce<string[]>((lines, line) => {
    if (/^[\t ]/.test(line) && lines.length) lines[lines.length - 1] += ` ${line.trim()}`;
    else lines.push(line);
    return lines;
  }, []);
}

function headerValue(headers: Array<[string, string]>, name: string) {
  return headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ?? "--";
}

function emailDomain(value: string) {
  return value.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i)?.[1]?.toLowerCase() ?? "";
}

function normalizeAddress(address: { name?: string; address?: string } | undefined) {
  if (!address?.address) return "--";
  return address.name ? `${address.name} <${address.address}>` : address.address;
}

function normalizeAddressList(addresses: Array<{ name?: string; address?: string; group?: Array<{ name?: string; address?: string }> }> | undefined) {
  if (!addresses?.length) return "--";
  return addresses.flatMap((item) => item.group ?? [item]).map(normalizeAddress).join(", ");
}

function authStatus(value: string, key: "spf" | "dkim" | "dmarc") {
  return value.match(new RegExp(`\\b${key}=([a-z]+)`, "i"))?.[1]?.toLowerCase() ?? "--";
}

function authDomain(value: string, key: string) {
  return value.match(new RegExp(`\\b${key.replace(".", "\\.")}=([^;\\s]+)`, "i"))?.[1]?.replace(/[<>()[\],]+$/g, "").toLowerCase() ?? "";
}

function parseReceivedHop(raw: string, index: number) {
  return {
    index,
    from: raw.match(/\bfrom\s+(.+?)(?=\s+(?:by|with|id|via)\b|;|$)/i)?.[1]?.trim() ?? "--",
    by: raw.match(/\bby\s+(.+?)(?=\s+(?:with|id|via|for)\b|;|$)/i)?.[1]?.trim() ?? "--",
    ip: raw.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/)?.[1] ?? raw.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)?.[1] ?? "--",
    date: raw.includes(";") ? raw.split(";").pop()?.trim() || "--" : "--",
    raw,
    risk: []
  };
}

function attachmentBytes(content: ArrayBuffer | Uint8Array | string) {
  if (typeof content === "string") return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? content : new Uint8Array(content);
}

function extensionOf(filename: string) {
  return filename.includes(".") ? filename.split(".").pop()?.toLowerCase() ?? "" : "";
}

export function emailAttachmentPreferredExtension(attachment: EmailAttachmentRow) {
  return fileSignatureForBytes(attachment.content)?.extensions[0] || (attachment.extension !== "--" ? attachment.extension : "bin");
}

export function emailSummaryValue(analysis: EmailAnalysis, label: string) {
  return analysis.rows.find(([key]) => key === label)?.[1] ?? "--";
}

export async function parseEmail(raw: string): Promise<EmailAnalysis> {
  const normalized = raw.replace(/\r\n/g, "\n");
  const [head = ""] = normalized.split(/\n\n/);
  const fallbackHeaders = unfoldHeaders(head).map((line) => {
    const index = line.indexOf(":");
    return index > -1 ? ([line.slice(0, index).trim(), decodeWords(line.slice(index + 1).trim())] as [string, string]) : null;
  }).filter(Boolean) as Array<[string, string]>;
  const parsed = await PostalMime.parse(raw, { attachmentEncoding: "arraybuffer", rfc822Attachments: true });
  const headers = parsed.headers.length ? parsed.headers.map((header) => [header.originalKey || header.key, decodeWords(header.value)] as [string, string]) : fallbackHeaders;
  const get = (name: string) => headerValue(headers, name);
  const received = headers.filter(([key]) => key.toLowerCase() === "received").map(([, value]) => value);
  const receivedHops = received.map((value, index) => parseReceivedHop(value, index + 1));
  const authHeader = headers.filter(([key]) => key.toLowerCase() === "authentication-results").map(([, value]) => value).join("\n") || "--";
  const from = normalizeAddress(parsed.from as { name?: string; address?: string } | undefined);
  const to = normalizeAddressList(parsed.to as Array<{ name?: string; address?: string }> | undefined);
  const replyTo = normalizeAddressList(parsed.replyTo as Array<{ name?: string; address?: string }> | undefined);
  const returnPath = parsed.returnPath || get("Return-Path");
  const subject = parsed.subject || get("Subject");
  const date = parsed.date || get("Date");
  const messageId = parsed.messageId || get("Message-ID");
  const fromDomain = emailDomain(from === "--" ? get("From") : from);
  const dkimSignature = get("DKIM-Signature");
  const dkimDomain = dkimSignature.match(/(?:^|;)\s*d=([^;\s]+)/i)?.[1]?.toLowerCase() ?? "";
  const spfMailFrom = authDomain(authHeader, "smtp.mailfrom");
  const authHeaderFrom = authDomain(authHeader, "header.from");
  const authDkim = authDomain(authHeader, "header.d");
  const spf = authStatus(authHeader, "spf");
  const dkim = authStatus(authHeader, "dkim");
  const dmarc = authStatus(authHeader, "dmarc");
  const authAssessments: EmailAnalysis["authAssessments"] = [
    { mechanism: "SPF", result: spf, domain: spfMailFrom || "--", aligned: fromDomain && spfMailFrom ? (alignedEmailDomains(fromDomain, spfMailFrom) ? "yes" : "no") : "--", source: "Authentication-Results smtp.mailfrom", verdict: spf },
    { mechanism: "DKIM", result: dkim, domain: dkimDomain || authDkim || "--", aligned: fromDomain && (dkimDomain || authDkim) ? (alignedEmailDomains(fromDomain, dkimDomain || authDkim) ? "yes" : "no") : "--", source: "DKIM-Signature d= / Authentication-Results header.d", verdict: dkim },
    { mechanism: "DMARC", result: dmarc, domain: authHeaderFrom || fromDomain || "--", aligned: fromDomain && authHeaderFrom ? (alignedEmailDomains(fromDomain, authHeaderFrom) ? "yes" : "no") : "--", source: "Authentication-Results header.from", verdict: dmarc }
  ];
  const attachments: EmailAnalysis["attachments"] = parsed.attachments.map((attachment, index) => {
    const content = attachmentBytes(attachment.content);
    const filename = attachment.filename || `attachment-${index + 1}`;
    const extension = extensionOf(filename);
    const signature = fileSignatureForBytes(content);
    return { filename, contentType: attachment.mimeType || "application/octet-stream", size: content.byteLength, sha256: "", extension: extension || "--", signature: signature?.label ?? (content.byteLength ? "Unknown" : "--"), mismatch: Boolean(signature && extension && !signature.extensions.includes(extension)), risk: [], preview: "", content, iocs: [], urlRows: [], nestedHeaders: [] };
  });
  const rawSize = new TextEncoder().encode(raw).byteLength;
  const rows: Array<[string, string]> = [["Raw size", formatBytes(rawSize)], ["From", from === "--" ? get("From") : from], ["To", to === "--" ? get("To") : to], ["Subject", subject], ["Date", date], ["Message-ID", messageId], ["Reply-To", replyTo], ["Return-Path", returnPath], ["From domain", fromDomain || "--"], ["SPF / DKIM / DMARC", `${spf} / ${dkim} / ${dmarc}`], ["Received hops", String(receivedHops.length)], ["Attachments", String(attachments.length)]];
  return {
    rawSha256: "", rawSize, rows, headers, received, receivedHops, attachments,
    contentSignals: [], findings: [], evidencePoints: [], scoreFactors: [], evidenceMatrix: [], authLedger: [], identityRows: [], infrastructureRows: [],
    routeRows: receivedHops.map((hop) => [`#${hop.index}`, `${hop.from} -> ${hop.by} · ${hop.ip} · ${hop.date}`]),
    verdict: { label: "parsed", detail: `SPF=${spf}, DKIM=${dkim}, DMARC=${dmarc}` },
    auth: [["SPF", spf], ["DKIM", dkim], ["DMARC", dmarc], ["Authentication-Results", authHeader], ["DKIM-Signature", dkimSignature]],
    authAssessments, dkimDetails: [], urls: [], linkRows: [], urlRows: [], iocs: [], bodyTimeline: [], domainAlignment: [], decoded: [], bodyText: parsed.text || "", bodyHtml: parsed.html || ""
  };
}

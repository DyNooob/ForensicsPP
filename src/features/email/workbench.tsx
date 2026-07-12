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

import React from "react";
import CryptoJS from "crypto-js";
import PostalMime, { decodeWords } from "postal-mime";
import { AButton, InfoTable, PanelTitle } from "../../components/ui";
import {
  defangIocValue,
  extractIocs,
  iocRecordsToCsv,
  iocRisk,
  normalizeIoc
} from "../ioc/analyzer";
import { parseTimestampCandidates } from "../timestamp/analyzer";
import { copy } from "../../i18n";
import type {
  EmailActionItem,
  EmailAnalysis,
  EmailAttachmentRow,
  EmailAuthLedgerRow,
  EmailContentSignal,
  EmailEvidenceMatrixRow,
  EmailEvidencePoint,
  EmailIdentityRow,
  EmailInfrastructureRow,
  EmailScoreFactor,
  IocRecord
} from "../../models";
import { fileSignatureForBytes, hexPreview, previewText } from "../../utils/binary";
import { uniqueValues } from "../../utils/collections";
import { downloadTextFile, formatBytes, limitReportText } from "../../utils/files";
import { isPrivateHost } from "../../utils/forensics";
import { bytesToWordArray, sha256Bytes } from "../../utils/hash";

export function unfoldEmailHeaders(raw: string) {
  return raw.replace(/\r\n/g, "\n").split("\n").reduce<string[]>((lines, line) => {
    if (/^[\t ]/.test(line) && lines.length) lines[lines.length - 1] += ` ${line.trim()}`;
    else lines.push(line);
    return lines;
  }, []);
}

export function getEmailHeader(headers: Array<[string, string]>, name: string) {
  return headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ?? "--";
}

export function extractEmailAddress(value: string) {
  return value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0]?.toLowerCase() ?? "";
}

export function extractEmailDomain(value: string) {
  return extractEmailAddress(value).split("@")[1] ?? "";
}

export function normalizeMailAddress(address: { name?: string; address?: string } | undefined) {
  if (!address?.address) return "--";
  return address.name ? `${address.name} <${address.address}>` : address.address;
}

export function normalizeMailAddressList(addresses: Array<{ name?: string; address?: string; group?: Array<{ name?: string; address?: string }> }> | undefined) {
  if (!addresses?.length) return "--";
  return addresses.flatMap((item) => item.group ?? [item]).map((item) => normalizeMailAddress(item)).join(", ");
}

export function decodeQuotedPrintableText(input: string) {
  const normalized = input.replace(/=\r?\n/g, "");
  const bytes: number[] = [];
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index];
    const hex = normalized.slice(index + 1, index + 3);
    if (char === "=" && /^[0-9a-fA-F]{2}$/.test(hex)) {
      bytes.push(Number.parseInt(hex, 16));
      index += 2;
    } else {
      bytes.push(char.charCodeAt(0));
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base32Encode(input: string) {
  const bytes = new TextEncoder().encode(input);
  let bits = "";
  bytes.forEach((byte) => {
    bits += byte.toString(2).padStart(8, "0");
  });
  const chunks = bits.match(/.{1,5}/g) ?? [];
  return chunks
    .map((chunk) => base32Alphabet[Number.parseInt(chunk.padEnd(5, "0"), 2)])
    .join("")
    .padEnd(Math.ceil(bytes.length / 5) * 8, "=");
}

export function base32Decode(input: string) {
  const clean = input.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of clean) {
    const value = base32Alphabet.indexOf(char);
    if (value >= 0) bits += value.toString(2).padStart(5, "0");
  }
  const bytes = bits.match(/.{8}/g)?.map((chunk) => Number.parseInt(chunk, 2)) ?? [];
  return new TextDecoder().decode(new Uint8Array(bytes));
}

export function base58Encode(input: string) {
  const bytes = new TextEncoder().encode(input);
  let value = 0n;
  bytes.forEach((byte) => {
    value = (value << 8n) + BigInt(byte);
  });
  let encoded = "";
  while (value > 0n) {
    const index = Number(value % 58n);
    encoded = base58Alphabet[index] + encoded;
    value /= 58n;
  }
  const leadingZeros = Array.from(bytes).findIndex((byte) => byte !== 0);
  return `${"1".repeat(leadingZeros < 0 ? bytes.length : leadingZeros)}${encoded || ""}`;
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

export function quotedPrintableEncode(input: string) {
  const bytes = new TextEncoder().encode(input);
  return Array.from(bytes)
    .map((byte) => {
      if (byte === 9 || byte === 32 || (byte >= 33 && byte <= 60) || (byte >= 62 && byte <= 126)) return String.fromCharCode(byte);
      return `=${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    })
    .join("");
}

export function decodeBase64EmailText(input: string) {
  const clean = input.replace(/\s+/g, "");
  const binary = atob(clean.padEnd(Math.ceil(clean.length / 4) * 4, "="));
  return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

export function safeDecodeBase64EmailText(input: string) {
  try {
    return decodeBase64EmailText(input);
  } catch {
    return "--";
  }
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

export function decodeHtmlEntities(input: string) {
  const named: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };
  return input.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, token: string) => {
    if (token[0] === "#") {
      const hex = token[1]?.toLowerCase() === "x";
      const value = Number.parseInt(token.slice(hex ? 2 : 1), hex ? 16 : 10);
      return Number.isFinite(value) ? String.fromCodePoint(value) : match;
    }
    return named[token.toLowerCase()] ?? match;
  });
}

function parseEmailUrl(value: string) {
  const trimmed = value.trim();
  return new URL(/^[a-z][a-z0-9+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`);
}

function safeDecodeEmailUri(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function hostFromMaybeUrl(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    return parseEmailUrl(trimmed).hostname.toLowerCase();
  } catch {
    const domain = trimmed.match(/\b(?:https?:\/\/)?([A-Z0-9.-]+\.[A-Z]{2,})(?:[/?#:]|$)/i)?.[1] ?? "";
    return domain.toLowerCase();
  }
}

export function parseDkimSignatureRows(signature: string): Array<[string, string]> {
  if (!signature || signature === "--") return [["DKIM-Signature", "--"]];
  const parts = Object.fromEntries(signature.split(";").map((part) => {
    const index = part.indexOf("=");
    return index > -1 ? [part.slice(0, index).trim(), part.slice(index + 1).trim()] : ["", ""];
  }).filter(([key]) => key));
  const signedHeaders = String(parts.h ?? "").split(":").map((item) => item.trim()).filter(Boolean);
  return [
    ["Version", String(parts.v ?? "--")],
    ["Algorithm", String(parts.a ?? "--")],
    ["Canonicalization", String(parts.c ?? "--")],
    ["Signing domain d=", String(parts.d ?? "--")],
    ["Selector s=", String(parts.s ?? "--")],
    ["Identity i=", String(parts.i ?? "--")],
    ["Signed headers", signedHeaders.join(", ") || "--"],
    ["Header count", signedHeaders.length ? String(signedHeaders.length) : "--"],
    ["Body hash bh=", String(parts.bh ?? "--")],
    ["Signature length", parts.b ? String(String(parts.b).replace(/\s+/g, "").length) : "--"]
  ];
}

export function decodeEmailSamples(headers: Array<[string, string]>, bodyText: string, bodyHtml: string, raw: string) {
  const headerText = headers.map(([key, value]) => `${key}: ${value}`).join("\n");
  const htmlText = stripEmailHtml(bodyHtml);
  const qpSource = /=\r?\n|=[0-9a-fA-F]{2}/.test(bodyText) ? bodyText : raw.match(/(?:Content-Transfer-Encoding:\s*quoted-printable[\s\S]{0,6000})/i)?.[0] ?? "";
  const base64Source = /^[A-Za-z0-9+/=\s]{40,}$/.test(bodyText.trim()) ? bodyText.trim() : "";
  const urlEncodedBody = /%[0-9a-f]{2}/i.test(`${bodyText}\n${bodyHtml}`) ? safeDecodeEmailUri(`${bodyText}\n${stripEmailHtml(bodyHtml)}`.slice(0, 8000)) : "--";
  const htmlEntityBody = /&[a-zA-Z#0-9]+;/.test(bodyHtml) ? decodeHtmlEntities(stripEmailHtml(bodyHtml).slice(0, 8000)) : "--";
  const encodedHeaderLines = headerText.split("\n").filter((line) => /=\?[^?]+\?[bq]\?/i.test(line)).slice(0, 20).join("\n");
  return [
    ["Subject RFC2047", decodeWords(getEmailHeader(headers, "Subject"))],
    ["From RFC2047", decodeWords(getEmailHeader(headers, "From"))],
    ["To RFC2047", decodeWords(getEmailHeader(headers, "To"))],
    ["Reply-To RFC2047", decodeWords(getEmailHeader(headers, "Reply-To"))],
    ["Encoded header lines", encodedHeaderLines ? decodeWords(encodedHeaderLines) : "--"],
    ["HTML text", htmlText.slice(0, 8000)],
    ["HTML entity decoded", htmlEntityBody.slice(0, 8000)],
    ["URL decoded body sample", urlEncodedBody.slice(0, 8000)],
    ["Quoted-Printable body", qpSource ? decodeQuotedPrintableText(qpSource).slice(0, 8000) : "--"],
    ["Base64 body candidate", base64Source ? safeDecodeBase64EmailText(base64Source).slice(0, 8000) : "--"],
    ["Raw header QP sample", decodeQuotedPrintableText(raw.slice(0, 4000))]
  ] as Array<[string, string]>;
}

export function getAuthStatus(authenticationResults: string, token: "spf" | "dkim" | "dmarc") {
  return authenticationResults.match(new RegExp(`\\b${token}=([a-z]+)`, "i"))?.[1]?.toLowerCase() ?? "--";
}

export function parseReceivedHop(raw: string, index: number) {
  const from = raw.match(/\bfrom\s+(.+?)(?=\s+(?:by|with|id|via)\b|;|$)/i)?.[1]?.trim() ?? "--";
  const by = raw.match(/\bby\s+(.+?)(?=\s+(?:with|id|via|for)\b|;|$)/i)?.[1]?.trim() ?? "--";
  const ip = raw.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/)?.[1] ?? raw.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)?.[1] ?? "--";
  const date = raw.includes(";") ? raw.split(";").pop()?.trim() || "--" : "--";
  const risk = [
    ip !== "--" && isPrivateHost(ip) ? "private IP" : "",
    /localhost|127\.0\.0\.1|\[::1\]/i.test(raw) ? "localhost relay" : "",
    !/\bby\b/i.test(raw) ? "missing by" : "",
    !/\bfrom\b/i.test(raw) ? "missing from" : "",
    date === "--" ? "missing date" : ""
  ].filter(Boolean);
  return { index, from, by, ip, date, raw, risk };
}

export function extractDkimDomain(signature: string) {
  return signature.match(/(?:^|;)\s*d=([^;\s]+)/i)?.[1]?.toLowerCase() ?? "";
}

export function baseEmailDomain(domain: string) {
  const cleaned = domain.toLowerCase().replace(/[>;)\]]+$/g, "");
  const parts = cleaned.split(".").filter(Boolean);
  return parts.length <= 2 ? cleaned : parts.slice(-2).join(".");
}

export function alignedEmailDomains(left: string, right: string) {
  if (!left || !right) return false;
  return left === right || baseEmailDomain(left) === baseEmailDomain(right) || left.endsWith(`.${right}`) || right.endsWith(`.${left}`);
}

export function analyzeEmailUrls(urls: string[], fromDomain: string) {
  return urls.map((url) => {
    const risk: string[] = [];
    let host = "--";
    try {
      const parsed = parseEmailUrl(url);
      host = parsed.hostname.toLowerCase();
      if (parsed.protocol !== "https:") risk.push("non-HTTPS");
      if (parsed.username || parsed.password) risk.push("credential in URL");
      if (isPrivateHost(host)) risk.push("private host");
      if (/%25[0-9a-f]{2}/i.test(url)) risk.push("double encoded");
      if (/xn--/i.test(host)) risk.push("punycode");
      if ((parsed.search.match(/https?:/gi) ?? []).length) risk.push("URL nested in query");
      if (fromDomain && !alignedEmailDomains(host, fromDomain)) risk.push("host differs from From");
    } catch {
      risk.push("invalid URL");
    }
    return { url, host, risk };
  });
}

export function analyzeEmailHtmlLinks(bodyHtml: string, fromDomain: string): EmailAnalysis["linkRows"] {
  const rows: EmailAnalysis["linkRows"] = [];
  const linkRegex = /<a\b([^>]*?)>([\s\S]*?)<\/a>/gi;
  for (const match of bodyHtml.matchAll(linkRegex)) {
    const attrs = match[1] ?? "";
    const href = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i)?.slice(1).find(Boolean) ?? "";
    const text = decodeHtmlEntities(stripEmailHtml(match[2] ?? "")).replace(/\s+/g, " ").trim();
    if (!href && !text) continue;
    const decodedHref = safeDecodeEmailUri(href.replace(/&amp;/gi, "&"));
    const host = hostFromMaybeUrl(decodedHref) || "--";
    const displayHost = hostFromMaybeUrl(text) || extractEmailDomain(text) || "--";
    const risk = [
      /^javascript:|^data:/i.test(decodedHref) ? "script/data href" : "",
      decodedHref && !/^https:/i.test(decodedHref) && /^https?:/i.test(decodedHref) ? "non-HTTPS link" : "",
      displayHost !== "--" && host !== "--" && !alignedEmailDomains(displayHost, host) ? `display host differs: ${displayHost}` : "",
      fromDomain && host !== "--" && !alignedEmailDomains(host, fromDomain) ? "href host differs from From" : "",
      /%25[0-9a-f]{2}|%2f%2f/i.test(href) ? "encoded redirect marker" : "",
      /login|verify|password|credential|invoice|payment|download|安全|验证|登录|密码|付款|发票/i.test(`${text} ${decodedHref}`) ? "credential/action wording" : "",
      /xn--/i.test(host) ? "punycode host" : "",
      /@/.test(decodedHref.replace(/^mailto:/i, "")) && /^https?:/i.test(decodedHref) ? "at-sign in URL" : ""
    ].filter(Boolean);
    rows.push({
      text: text || "--",
      href: decodedHref || href || "--",
      host,
      displayHost,
      risk
    });
  }
  return rows.slice(0, 300);
}

export function emailIocRecords(text: string, source = "email"): IocRecord[] {
  const grouped = extractIocs(text);
  const rows: IocRecord[] = [];
  Object.entries(grouped).forEach(([type, values]) => {
    values.forEach((value, index) => {
      rows.push({
        id: `${type}-${index}-${value}`,
        type,
        value,
        normalized: normalizeIoc(type, value),
        line: 0,
        lines: [],
        count: 1,
        context: source,
        contexts: [source],
        defanged: defangIocValue(normalizeIoc(type, value)),
        risk: iocRisk(type, value)
      });
    });
  });
  return rows.slice(0, 500);
}

export function addEmailContentSignal(signals: EmailContentSignal[], signal: EmailContentSignal) {
  const normalized = `${signal.source}|${signal.type}|${signal.value.slice(0, 280)}`;
  if (signals.some((item) => `${item.source}|${item.type}|${item.value.slice(0, 280)}` === normalized)) return;
  signals.push(signal);
}

export function emailAddressValues(value: string) {
  return uniqueValues(value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) ?? [], 60).map((item) => item.toLowerCase());
}

export function buildEmailIdentityRows(info: {
  from: string;
  to: string;
  replyTo: string;
  returnPath: string;
  messageId: string;
  fromDomain: string;
  returnDomain: string;
  replyDomain: string;
  messageIdDomain: string;
  dkimDomain: string;
  spfMailFrom: string;
  authHeaderFrom: string;
  authDkimHeader: string;
  displaySpoofDomain: string;
}) {
  const rows: EmailIdentityRow[] = [];
  const add = (role: string, value: string, domain: string, source: string, options?: { address?: string; align?: boolean; extraRisk?: string[] }) => {
    const address = options?.address ?? extractEmailAddress(value);
    const derivedDomain = (domain || extractEmailDomain(address || value)).toLowerCase();
    const aligned = info.fromDomain && derivedDomain ? (alignedEmailDomains(info.fromDomain, derivedDomain) ? "yes" : "no") : "--";
    const risk = [
      !value || value === "--" ? "missing" : "",
      options?.align && aligned === "no" ? "not aligned with From" : "",
      /xn--/i.test(derivedDomain) ? "punycode domain" : "",
      isPrivateHost(derivedDomain) ? "private/internal domain" : "",
      ...(options?.extraRisk ?? [])
    ].filter(Boolean);
    rows.push({
      role,
      value: value || "--",
      address: address || "--",
      domain: derivedDomain || "--",
      alignedWithFrom: aligned,
      risk: Array.from(new Set(risk)),
      source
    });
  };
  add("Visible From", info.from, info.fromDomain, "From header");
  emailAddressValues(info.to).slice(0, 20).forEach((address, index) => add(`Recipient ${index + 1}`, address, extractEmailDomain(address), "To header", { address }));
  add("Reply-To", info.replyTo, info.replyDomain, "Reply-To header", { align: Boolean(info.replyDomain) });
  add("Return-Path", info.returnPath, info.returnDomain, "Return-Path / envelope sender", { align: Boolean(info.returnDomain) });
  add("Message-ID", info.messageId, info.messageIdDomain, "Message-ID domain", { align: Boolean(info.messageIdDomain), address: info.messageId.match(/<([^>]+)>/)?.[1] ?? "" });
  add("DKIM d=", info.dkimDomain || "--", info.dkimDomain, "DKIM-Signature d=", { align: Boolean(info.dkimDomain) });
  add("SPF mailfrom", info.spfMailFrom || "--", info.spfMailFrom, "Authentication-Results smtp.mailfrom", { align: Boolean(info.spfMailFrom) });
  add("Auth header.from", info.authHeaderFrom || "--", info.authHeaderFrom, "Authentication-Results header.from", { align: Boolean(info.authHeaderFrom) });
  add("Auth header.d", info.authDkimHeader || "--", info.authDkimHeader, "Authentication-Results header.d", { align: Boolean(info.authDkimHeader) });
  if (info.displaySpoofDomain) {
    add("Display-name email", info.displaySpoofDomain, info.displaySpoofDomain, "From display name", {
      align: true,
      extraRisk: alignedEmailDomains(info.fromDomain, info.displaySpoofDomain) ? [] : ["display-name email domain differs"]
    });
  }
  return rows.filter((row, index, list) => list.findIndex((item) => `${item.role}|${item.value}|${item.source}` === `${row.role}|${row.value}|${row.source}`) === index);
}

export function emailIdentityRowsToCsv(rows: EmailIdentityRow[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["role", "value", "address", "domain", "aligned_with_from", "risk", "source"].join(","),
    ...rows.map((row) => [row.role, row.value, row.address, row.domain, row.alignedWithFrom, row.risk.join("; "), row.source].map(escape).join(","))
  ].join("\n");
}

export function buildEmailRouteRows(receivedHops: EmailAnalysis["receivedHops"]) {
  const newest = receivedHops[0] ?? null;
  const oldest = receivedHops[receivedHops.length - 1] ?? null;
  const fallbackOriginIp = [...receivedHops].reverse().find((hop) => hop.ip && hop.ip !== "--")?.ip ?? "--";
  const originIp = oldest?.ip && oldest.ip !== "--" ? oldest.ip : fallbackOriginIp;
  const originFrom = oldest?.from || "--";
  const finalBy = newest?.by || "--";
  const risks = Array.from(new Set(receivedHops.flatMap((hop) => hop.risk)));
  return [
    ["Hop count", String(receivedHops.length)],
    ["Apparent origin", receivedHops.length ? `${originFrom} / ${originIp}` : "--"],
    ["First timestamp", oldest?.date || "--"],
    ["Final relay", finalBy],
    ["Final timestamp", newest?.date || "--"],
    ["Route risk", risks.join(", ") || "--"]
  ] as Array<[string, string]>;
}

export function addEmailInfrastructure(map: Map<string, EmailInfrastructureRow>, kind: string, value: string, source: string, fromDomain: string) {
  const normalized = value.trim().toLowerCase().replace(/[<>()\[\],;]+$/g, "");
  if (!normalized || normalized === "--") return;
  const key = `${kind}|${normalized}`;
  const existing = map.get(key);
  const risk = [
    kind === "domain" && /xn--/i.test(normalized) ? "punycode" : "",
    kind === "domain" && isPrivateHost(normalized) ? "private/internal" : "",
    kind === "ip" && isPrivateHost(normalized) ? "private IP" : "",
    kind === "domain" && fromDomain && !alignedEmailDomains(normalized, fromDomain) ? "differs from From" : "",
    kind === "url-host" && fromDomain && !alignedEmailDomains(normalized, fromDomain) ? "URL host differs from From" : ""
  ].filter(Boolean);
  if (existing) {
    existing.count += 1;
    if (!existing.sources.includes(source)) existing.sources.push(source);
    existing.risk = Array.from(new Set([...existing.risk, ...risk]));
    return;
  }
  map.set(key, { kind, value: normalized, sources: [source], count: 1, risk: Array.from(new Set(risk)) });
}

export function buildEmailInfrastructureRows(info: {
  fromDomain: string;
  domainAlignment: Array<[string, string]>;
  receivedHops: EmailAnalysis["receivedHops"];
  urlRows: EmailAnalysis["urlRows"];
  linkRows: EmailAnalysis["linkRows"];
  attachments: EmailAnalysis["attachments"];
  iocs: IocRecord[];
}) {
  const map = new Map<string, EmailInfrastructureRow>();
  info.domainAlignment.forEach(([key, value]) => {
    if (/domain|DKIM|SPF|Auth|helo/i.test(key) && value && value !== "--" && !/^(yes|no)$/i.test(value)) addEmailInfrastructure(map, "domain", value, key, info.fromDomain);
  });
  info.receivedHops.forEach((hop) => {
    addEmailInfrastructure(map, "mail-host", hop.from, `Received #${hop.index} from`, info.fromDomain);
    addEmailInfrastructure(map, "mail-host", hop.by, `Received #${hop.index} by`, info.fromDomain);
    addEmailInfrastructure(map, "ip", hop.ip, `Received #${hop.index}`, info.fromDomain);
  });
  info.urlRows.forEach((row) => addEmailInfrastructure(map, "url-host", row.host, "Body URL", info.fromDomain));
  info.linkRows.forEach((row) => {
    addEmailInfrastructure(map, "url-host", row.host, "HTML href", info.fromDomain);
    addEmailInfrastructure(map, "display-host", row.displayHost, "HTML display text", info.fromDomain);
  });
  info.attachments.forEach((attachment) => {
    attachment.urlRows.forEach((row) => addEmailInfrastructure(map, "url-host", row.host, `Attachment ${attachment.filename}`, info.fromDomain));
    attachment.iocs.forEach((record) => {
      if (record.type === "DOMAIN") addEmailInfrastructure(map, "domain", record.normalized, `Attachment ${attachment.filename}`, info.fromDomain);
      if (record.type === "IPv4") addEmailInfrastructure(map, "ip", record.normalized, `Attachment ${attachment.filename}`, info.fromDomain);
    });
  });
  info.iocs.forEach((record) => {
    if (record.type === "DOMAIN") addEmailInfrastructure(map, "domain", record.normalized, "Email IOC", info.fromDomain);
    if (record.type === "IPv4") addEmailInfrastructure(map, "ip", record.normalized, "Email IOC", info.fromDomain);
  });
  return Array.from(map.values())
    .sort((left, right) => right.risk.length - left.risk.length || right.count - left.count || left.kind.localeCompare(right.kind))
    .slice(0, 240);
}

export function emailInfrastructureRowsToCsv(rows: EmailInfrastructureRow[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["kind", "value", "count", "sources", "risk"].join(","),
    ...rows.map((row) => [row.kind, row.value, row.count, row.sources.join("; "), row.risk.join("; ")].map(escape).join(","))
  ].join("\n");
}

export function analyzeEmailContentSignals(source: string, text: string, fromDomain: string): EmailContentSignal[] {
  const sample = text.trim().slice(0, 12000);
  const signals: EmailContentSignal[] = [];
  if (!sample) return signals;
  const credentialHits = Array.from(new Set(sample.match(/(?:password|passwd|pwd|secret|token|api[_-]?key|session|otp|验证码|密码|令牌)\s*[:=：]\s*["']?[^"'\s,;<>]{4,}/gi) ?? [])).slice(0, 10);
  if (credentialHits.length) {
    addEmailContentSignal(signals, {
      source,
      type: "Credential-like content",
      level: "warn",
      value: credentialHits.join("\n"),
      detail: "正文或附件文本出现凭据/令牌字段，建议作为敏感线索复核。",
      risk: ["credential keyword", "possible secret leakage"]
    });
  }
  const actionWords = Array.from(new Set(sample.match(/\b(?:verify|login|password|payment|invoice|urgent|wire|download|security alert|account suspended)\b|(?:验证|登录|密码|付款|发票|紧急|转账|下载|安全提醒|账号异常)/gi) ?? [])).slice(0, 12);
  if (actionWords.length) {
    addEmailContentSignal(signals, {
      source,
      type: "Phishing wording",
      level: "warn",
      value: actionWords.join(", "),
      detail: "命中登录、验证、付款、紧急等社工话术，需结合链接和发件域名复核。",
      risk: ["social engineering wording"]
    });
  }
  if (/<form\b|<input\b|action\s*=|type\s*=\s*["']?password/i.test(sample)) {
    addEmailContentSignal(signals, {
      source,
      type: "HTML credential form",
      level: "warn",
      value: sample.match(/<form[\s\S]{0,1200}?<\/form>/i)?.[0] ?? sample.slice(0, 1200),
      detail: "HTML 中出现表单、输入框或密码字段，建议结合链接目标和邮件上下文复核。",
      risk: ["html form", "credential capture"]
    });
  }
  if (/display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|visibility\s*:\s*hidden|mso-hide\s*:\s*all/i.test(sample)) {
    addEmailContentSignal(signals, {
      source,
      type: "Hidden HTML content",
      level: "warn",
      value: sample.match(/(?:display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|visibility\s*:\s*hidden|mso-hide\s*:\s*all).{0,300}/i)?.[0] ?? "hidden CSS marker",
      detail: "HTML 中出现隐藏内容 CSS，可能用于规避人工阅读或安全网关。",
      risk: ["hidden html"]
    });
  }
  const urls = uniqueValues(extractIocs(sample).URL, 20);
  const riskyUrls = analyzeEmailUrls(urls, fromDomain).filter((row) => row.risk.length);
  if (riskyUrls.length) {
    addEmailContentSignal(signals, {
      source,
      type: "URL review marker",
      level: "warn",
      value: riskyUrls.slice(0, 12).map((row) => `${row.url} (${row.risk.join(", ")})`).join("\n"),
      detail: "正文或附件文本中存在带复核标记的 URL。",
      risk: Array.from(new Set(riskyUrls.flatMap((row) => row.risk))).slice(0, 8)
    });
  }
  const riskyIocs = emailIocRecords(sample, source).filter((record) => record.risk.length).slice(0, 16);
  if (riskyIocs.length) {
    addEmailContentSignal(signals, {
      source,
      type: "IOC review marker",
      level: "warn",
      value: riskyIocs.map((record) => `${record.type}: ${record.value} (${record.risk.join(", ")})`).join("\n"),
      detail: "文本中命中 IOC 本地规则，建议单独登记。",
      risk: Array.from(new Set(riskyIocs.flatMap((record) => record.risk))).slice(0, 8)
    });
  }
  return signals.slice(0, 20);
}

export function emailUrlsToCsv(rows: EmailAnalysis["urlRows"]) {
  const escape = (value: string) => `"${value.replace(/"/g, "\"\"")}"`;
  return [
    ["url", "host", "risk"].join(","),
    ...rows.map((row) => [row.url, row.host, row.risk.join("; ")].map(escape).join(","))
  ].join("\n");
}

export function emailAttachmentsToCsv(rows: EmailAnalysis["attachments"]) {
  const escape = (value: string | number | boolean) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["filename", "content_type", "size", "extension", "signature", "mismatch", "risk", "ioc_count", "url_count", "nested_header_count", "sha256", "preview"].join(","),
    ...rows.map((row) => [
      row.filename,
      row.contentType,
      row.size,
      row.extension,
      row.signature,
      row.mismatch,
      row.risk.join("; "),
      row.iocs.length,
      row.urlRows.length,
      row.nestedHeaders.length,
      row.sha256,
      row.preview.slice(0, 500)
    ].map(escape).join(","))
  ].join("\n");
}

export function emailHeadersToCsv(rows: Array<[string, string]>) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["header", "value"].join(","),
    ...rows.map(([key, value]) => [key, value].map(escape).join(","))
  ].join("\n");
}

export function emailReceivedToCsv(rows: EmailAnalysis["receivedHops"]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["index", "from", "by", "ip", "date", "risk", "raw"].join(","),
    ...rows.map((row) => [row.index, row.from, row.by, row.ip, row.date, row.risk.join("; "), row.raw].map(escape).join(","))
  ].join("\n");
}

export function emailAuthAssessmentsToCsv(rows: EmailAnalysis["authAssessments"]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["mechanism", "result", "domain", "aligned", "source", "verdict"].join(","),
    ...rows.map((row) => [row.mechanism, row.result, row.domain, row.aligned, row.source, row.verdict].map(escape).join(","))
  ].join("\n");
}

export function emailAuthLedgerToCsv(rows: EmailAuthLedgerRow[]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["claim", "evidence", "result", "level", "confidence", "action"].join(","),
    ...rows.map((row) => [row.claim, row.evidence, row.result, row.level, row.confidence, row.action].map(escape).join(","))
  ].join("\n");
}

export function buildEmailAuthLedger(info: {
  rawSha256: string;
  from: string;
  fromDomain: string;
  returnPath: string;
  replyTo: string;
  messageId: string;
  authAssessments: EmailAnalysis["authAssessments"];
  domainAlignment: Array<[string, string]>;
  receivedHops: EmailAnalysis["receivedHops"];
  urlRows: EmailAnalysis["urlRows"];
  linkRows: EmailAnalysis["linkRows"];
  attachments: EmailAnalysis["attachments"];
  findings: Array<{ level: string; title: string; detail: string }>;
}) {
  const ledger: EmailAuthLedgerRow[] = [];
  const add = (row: EmailAuthLedgerRow) => ledger.push(row);
  const authHardFails = info.authAssessments.filter((item) => /fail|policy fail/i.test(`${item.result} ${item.verdict}`));
  const authNeedsReview = info.authAssessments.filter((item) => /not aligned/i.test(`${item.result} ${item.verdict}`));
  const authAligned = info.authAssessments.filter((item) => item.result === "pass" && item.aligned === "yes");
  const authMissing = info.authAssessments.filter((item) => item.result === "--");
  const alignmentNo = info.domainAlignment.filter(([key, value]) => /aligned/i.test(key) && value === "no");
  const alignmentYes = info.domainAlignment.filter(([key, value]) => /aligned/i.test(key) && value === "yes");
  const riskyLinks = info.linkRows.filter((row) => row.risk.length);
  const displayMismatch = info.linkRows.filter((row) => row.risk.some((risk) => /display host differs|script\/data|at-sign/i.test(risk)));
  const riskyUrls = info.urlRows.filter((row) => row.risk.length);
  const riskyAttachments = info.attachments.filter((item) => item.risk.length || item.mismatch);
  const routeRisks = info.receivedHops.filter((hop) => hop.risk.length);
  const structuralFindings = info.findings.filter((finding) => /Duplicate|Missing or invalid From|Future Date|Hidden HTML|HTML credential form|Display-name email spoofing/i.test(finding.title));

  add({
    claim: "原始 EML 是证据基准",
    evidence: `Raw SHA256 ${info.rawSha256}`,
    result: "所有派生结论必须回链原始邮件",
    level: "info",
    confidence: "high",
    action: "报告中记录原始 SHA256；附件、CSV、截图只作为派生材料。"
  });

  add({
    claim: "可见发件人身份",
    evidence: `From=${info.from || "--"}; domain=${info.fromDomain || "--"}`,
    result: info.fromDomain ? "可解析 From 域名" : "From 缺失或不可解析",
    level: info.fromDomain ? "info" : "warn",
    confidence: info.fromDomain ? "medium" : "high",
    action: "将 From 与 Return-Path、Reply-To、Message-ID、DKIM d=、SPF mailfrom 对齐关系一起判断。"
  });

  add({
    claim: "SPF/DKIM/DMARC 认证线索",
    evidence: info.authAssessments.map((item) => `${item.mechanism}=${item.result}, domain=${item.domain}, aligned=${item.aligned}`).join("; "),
    result: authHardFails.length ? "存在认证失败记录" : authNeedsReview.length ? "存在未对齐项，需复核上下文" : authAligned.length ? "存在对齐通过项" : authMissing.length ? "认证证据不足" : "需人工复核",
    level: authHardFails.length || authNeedsReview.length || authMissing.length ? "warn" : "info",
    confidence: authHardFails.length || authAligned.length ? "medium" : "low",
    action: authHardFails.length ? "复核 Authentication-Results 原文、DNS 策略和邮件服务商日志。" : "即使 pass，也要结合身份字段、投递路径和链接/附件判断；未对齐不等于身份异常结论。"
  });

  add({
    claim: "关键身份域名一致",
    evidence: [
      alignmentNo.length ? `not aligned: ${alignmentNo.map(([key]) => key).join(" / ")}` : "",
      alignmentYes.length ? `aligned: ${alignmentYes.map(([key]) => key).join(" / ")}` : "",
      `Return-Path=${info.returnPath || "--"}`,
      `Reply-To=${info.replyTo || "--"}`,
      `Message-ID=${info.messageId || "--"}`
    ].filter(Boolean).join("; "),
    result: alignmentNo.length ? "身份域名存在不一致" : alignmentYes.length ? "至少部分身份域名一致" : "对齐证据不足",
    level: alignmentNo.length ? "warn" : "info",
    confidence: alignmentNo.length || alignmentYes.length ? "medium" : "low",
    action: "重点核对 Reply-To、Return-Path 和 Message-ID 是否存在回复劫持或身份混淆线索。"
  });

  add({
    claim: "投递路径线索",
    evidence: info.receivedHops.length ? info.receivedHops.slice(0, 5).map((hop) => `#${hop.index} from=${hop.from} by=${hop.by} ip=${hop.ip}${hop.risk.length ? ` notes=${hop.risk.join("/")}` : ""}`).join("; ") : "No Received headers",
    result: !info.receivedHops.length ? "缺少 Received 链" : routeRisks.length ? "Received 链需检查" : "Received 链可解析",
    level: !info.receivedHops.length || routeRisks.length ? "warn" : "info",
    confidence: info.receivedHops.length ? "medium" : "low",
    action: "按时间顺序和服务器日志核对 from/by/IP；本地解析只说明这些头部字段存在。"
  });

  add({
    claim: "正文链接未伪装",
    evidence: [
      `${info.urlRows.length} URL row(s)`,
      `${info.linkRows.length} HTML link row(s)`,
      displayMismatch.length ? `${displayMismatch.length} display/href mismatch` : "",
      riskyUrls.length ? `${riskyUrls.length} URL note row(s)` : ""
    ].filter(Boolean).join("; "),
    result: displayMismatch.length ? "存在链接展示/实际目标冲突" : riskyLinks.length || riskyUrls.length ? "链接需要检查" : info.urlRows.length || info.linkRows.length ? "未命中重点链接规则" : "未发现链接",
    level: displayMismatch.length || riskyLinks.length || riskyUrls.length ? "warn" : "info",
    confidence: displayMismatch.length ? "high" : info.urlRows.length || info.linkRows.length ? "medium" : "low",
    action: "导出 URL/HTML 表，保留展示文本、href、host、From 域名差异和检查项。"
  });

  add({
    claim: "附件检查情况",
    evidence: info.attachments.length ? info.attachments.slice(0, 6).map((item) => `${item.filename} ${item.signature}${item.risk.length ? ` notes=${item.risk.join("/")}` : ""}${item.mismatch ? " mismatch" : ""}`).join("; ") : "No attachments",
    result: riskyAttachments.length ? "附件存在检查提示" : info.attachments.length ? "附件未命中重点规则" : "无附件",
    level: riskyAttachments.length ? "warn" : "info",
    confidence: info.attachments.length ? "medium" : "high",
    action: riskyAttachments.length ? "下载附件后单独哈希，送文件头、压缩包、YARA、图片工具继续分析。" : "记录附件数量和 SHA256；无附件仅代表当前 MIME 未解析到附件。"
  });

  if (structuralFindings.length) {
    add({
      claim: "头部和 HTML 结构正常",
      evidence: structuralFindings.map((finding) => `${finding.title}: ${finding.detail}`).join(" / "),
      result: "结构异常命中",
      level: "warn",
      confidence: "high",
      action: "保留原始头部片段和 HTML 片段，必要时进入编码转换工具复核隐藏内容。"
    });
  }

  const order = { danger: 0, warn: 1, info: 2 } as Record<string, number>;
  return ledger.sort((left, right) => (order[left.level] ?? 2) - (order[right.level] ?? 2));
}

export function buildEmailEvidencePoints(info: {
  authAssessments: EmailAnalysis["authAssessments"];
  findings: Array<{ level: string; title: string; detail: string }>;
  identityRows: EmailIdentityRow[];
  receivedHops: EmailAnalysis["receivedHops"];
  urlRows: EmailAnalysis["urlRows"];
  linkRows: EmailAnalysis["linkRows"];
  attachments: EmailAnalysis["attachments"];
  contentSignals: EmailContentSignal[];
  domainAlignment: Array<[string, string]>;
}) {
  const points: EmailEvidencePoint[] = [];
  const add = (point: EmailEvidencePoint) => {
    const key = `${point.group}|${point.title}|${point.detail}`;
    if (!points.some((item) => `${item.group}|${item.title}|${item.detail}` === key)) points.push(point);
  };
  const alignedPass = info.authAssessments.filter((item) => item.result === "pass" && item.aligned === "yes");
  const hardFailAuth = info.authAssessments.filter((item) => /fail|policy fail/i.test(`${item.result} ${item.verdict}`));
  const unalignedAuth = info.authAssessments.filter((item) => /not aligned/i.test(`${item.result} ${item.verdict}`));
  if (alignedPass.length) {
    add({
      group: "support",
      level: "info",
      title: "认证结果存在对齐通过项",
      detail: alignedPass.map((item) => `${item.mechanism}: ${item.domain}`).join(" / "),
      source: "Authentication-Results"
    });
  }
  if (hardFailAuth.length) {
    add({
      group: "review",
      level: "warn",
      title: "认证失败需复核",
      detail: hardFailAuth.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / "),
      source: "Authentication records"
    });
  }
  if (unalignedAuth.length) {
    add({
      group: "review",
      level: "warn",
      title: "认证未显式对齐，需复核",
      detail: unalignedAuth.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / "),
      source: "Authentication records"
    });
  }
  const alignmentProblems = info.domainAlignment.filter(([key, value]) => /aligned/i.test(key) && value === "no");
  const identityProblems = info.identityRows.filter((row) => row.risk.length);
  if (alignmentProblems.length) {
    add({
      group: "review",
      level: "warn",
      title: "关键域名不一致",
      detail: alignmentProblems.map(([key]) => key).join(" / "),
      source: "Domain alignment"
    });
  }
  if (identityProblems.length) {
    add({
      group: "review",
      level: "warn",
      title: "身份字段需复核",
      detail: identityProblems.slice(0, 8).map((row) => `${row.role}: ${row.risk.join(", ")}`).join(" / "),
      source: "Identity records"
    });
  }
  if (info.receivedHops.length) {
    const riskyHops = info.receivedHops.filter((hop) => hop.risk.length);
    add({
      group: riskyHops.length ? "review" : "support",
      level: riskyHops.length ? "warn" : "info",
      title: riskyHops.length ? "Received 链存在异常跳点" : "Received 链可解析",
      detail: riskyHops.length ? riskyHops.slice(0, 5).map((hop) => `#${hop.index} ${hop.risk.join(", ")}`).join(" / ") : `${info.receivedHops.length} hop(s) parsed.`,
      source: "Received headers"
    });
  } else {
    add({ group: "review", level: "warn", title: "缺少 Received 链", detail: "无法从邮件头复核投递路径。", source: "Received headers" });
  }
  const riskyLinks = info.linkRows.filter((row) => row.risk.length);
  const riskyUrls = info.urlRows.filter((row) => row.risk.length);
  if (riskyLinks.length || riskyUrls.length) {
    add({
      group: "review",
      level: "warn",
      title: "链接存在复核线索",
      detail: [
        riskyLinks.length ? `${riskyLinks.length} HTML link issue(s)` : "",
        riskyUrls.length ? `${riskyUrls.length} URL issue(s)` : ""
      ].filter(Boolean).join(" / "),
      source: "Body URL / HTML href"
    });
  }
  const riskyAttachments = info.attachments.filter((item) => item.risk.length || item.mismatch);
  if (riskyAttachments.length) {
    add({
      group: "review",
      level: "warn",
      title: "附件存在复核提示",
      detail: riskyAttachments.slice(0, 5).map((item) => `${item.filename}: ${item.risk.join(", ") || "extension/header mismatch"}`).join(" / "),
      source: "MIME attachments"
    });
  }
  const dangerousSignals = info.contentSignals.filter((signal) => signal.level === "danger");
  const warningSignals = info.contentSignals.filter((signal) => signal.level === "warn");
  if (dangerousSignals.length || warningSignals.length) {
    add({
      group: "review",
      level: "warn",
      title: "正文 / 附件文本命中复核信号",
      detail: [...dangerousSignals, ...warningSignals].slice(0, 6).map((signal) => `${signal.source}: ${signal.type}`).join(" / "),
      source: "Decoded body and attachment text"
    });
  }
  info.findings
    .filter((finding) => finding.level === "danger")
    .slice(0, 6)
    .forEach((finding) => add({ group: "review", level: "warn", title: finding.title, detail: finding.detail, source: "Findings" }));
  if (!points.some((point) => point.group === "review")) {
    add({
      group: "review",
      level: "info",
      title: "仍需结合原始邮件头复核",
      detail: "本地解析可辅助判断认证、链路、链接和附件，但不能替代邮件服务商日志或 DNS 历史记录。",
      source: "Analyst review"
    });
  }
  const order = { risk: 0, review: 1, support: 2 } as Record<EmailEvidencePoint["group"], number>;
  const levelOrder = { danger: 0, warn: 1, info: 2 } as Record<string, number>;
  return points.sort((left, right) => order[left.group] - order[right.group] || (levelOrder[left.level] ?? 2) - (levelOrder[right.level] ?? 2)).slice(0, 12);
}

export function buildEmailScoreFactors(info: {
  authAssessments: EmailAnalysis["authAssessments"];
  findings: Array<{ level: string; title: string; detail: string }>;
  identityRows: EmailIdentityRow[];
  receivedHops: EmailAnalysis["receivedHops"];
  urlRows: EmailAnalysis["urlRows"];
  linkRows: EmailAnalysis["linkRows"];
  attachments: EmailAnalysis["attachments"];
  contentSignals: EmailContentSignal[];
  domainAlignment: Array<[string, string]>;
}) {
  const factors: EmailScoreFactor[] = [];
  const add = (factor: EmailScoreFactor) => {
    const key = `${factor.label}|${factor.detail}|${factor.evidence}`;
    if (!factors.some((item) => `${item.label}|${item.detail}|${item.evidence}` === key)) factors.push(factor);
  };
  const authHardFails = info.authAssessments.filter((item) => /fail|policy fail/i.test(`${item.result} ${item.verdict}`));
  const authUnaligned = info.authAssessments.filter((item) => /not aligned/i.test(`${item.result} ${item.verdict}`));
  const authAligned = info.authAssessments.filter((item) => item.result === "pass" && item.aligned === "yes");
  const authMissing = info.authAssessments.filter((item) => item.result === "--");
  if (authHardFails.length) {
    add({
      label: "Authentication",
      level: "warn",
      impact: -15,
      detail: authHardFails.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / "),
      evidence: "SPF/DKIM/DMARC returned a failure; review the original Authentication-Results and provider logs before drawing a conclusion."
    });
  } else if (authUnaligned.length) {
    add({
      label: "Authentication",
      level: "warn",
      impact: -8,
      detail: authUnaligned.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / "),
      evidence: "Authentication passed or exists but local alignment evidence is incomplete; review context before drawing a conclusion."
    });
  } else if (authAligned.length) {
    add({
      label: "Authentication",
      level: "info",
      impact: 18,
      detail: authAligned.map((item) => `${item.mechanism}: ${item.domain}`).join(" / "),
      evidence: "At least one authentication mechanism passed with From-domain alignment."
    });
  } else if (authMissing.length) {
    add({
      label: "Authentication",
      level: "warn",
      impact: -12,
      detail: authMissing.map((item) => item.mechanism).join(" / "),
      evidence: "Authentication-Results did not expose enough SPF/DKIM/DMARC evidence."
    });
  }

  const alignmentProblems = info.domainAlignment.filter(([key, value]) => /aligned/i.test(key) && value === "no");
  const identityProblems = info.identityRows.filter((row) => row.risk.length);
  if (alignmentProblems.length) {
    add({
      label: "Domain alignment",
      level: "warn",
      impact: -14,
      detail: alignmentProblems.map(([key]) => key).join(" / "),
      evidence: "Header identity domains differ from visible From domain."
    });
  } else if (info.domainAlignment.some(([key, value]) => /aligned/i.test(key) && value === "yes")) {
    add({
      label: "Domain alignment",
      level: "info",
      impact: 8,
      detail: info.domainAlignment.filter(([key, value]) => /aligned/i.test(key) && value === "yes").map(([key]) => key).join(" / "),
      evidence: "Visible sender domain is aligned with one or more technical identity domains."
    });
  }

  if (identityProblems.length) {
    add({
      label: "Identity fields",
      level: "warn",
      impact: -10,
      detail: identityProblems.slice(0, 6).map((row) => `${row.role}: ${row.risk.join(", ")}`).join(" / "),
      evidence: "Visible sender, envelope sender, reply identity, Message-ID, DKIM/SPF, or display-name identity differs from From and needs context."
    });
  }

  const riskyHops = info.receivedHops.filter((hop) => hop.risk.length);
  if (!info.receivedHops.length) {
    add({ label: "Received chain", level: "warn", impact: -10, detail: "No relay trace found.", evidence: "Missing Received headers reduce delivery-path confidence." });
  } else if (riskyHops.length) {
    add({
      label: "Received chain",
      level: "warn",
      impact: -12,
      detail: riskyHops.slice(0, 5).map((hop) => `#${hop.index}: ${hop.risk.join(", ")}`).join(" / "),
      evidence: "Delivery path can be parsed but contains review markers."
    });
  } else {
    add({ label: "Received chain", level: "info", impact: 6, detail: `${info.receivedHops.length} hop(s) parsed.`, evidence: "Relay trace is present and parseable." });
  }

  const displayMismatch = info.linkRows.filter((row) => row.risk.some((risk) => /display host differs|script\/data|at-sign/i.test(risk)));
  const riskyUrls = info.urlRows.filter((row) => row.risk.length);
  if (displayMismatch.length) {
    add({
      label: "HTML links",
      level: "warn",
      impact: -16,
      detail: displayMismatch.slice(0, 5).map((row) => `${row.text || row.displayHost || "--"} -> ${row.host}`).join(" / "),
      evidence: "Displayed link text and actual href differ, or href uses script/data/@ marker; treat as a review lead."
    });
  } else if (riskyUrls.length || info.linkRows.some((row) => row.risk.length)) {
    add({
      label: "URLs",
      level: "warn",
      impact: -14,
      detail: `${riskyUrls.length} URL note row(s), ${info.linkRows.filter((row) => row.risk.length).length} HTML link note row(s).`,
      evidence: "Body links contain review markers such as host, encoding, or sender-domain mismatch."
    });
  }

  const riskyAttachments = info.attachments.filter((item) => item.risk.length || item.mismatch);
  const dangerousAttachments = riskyAttachments.filter((item) => item.risk.some((risk) => /executable|macro|active content|disk image|double extension/i.test(risk)));
  if (dangerousAttachments.length) {
    add({
      label: "Attachments",
      level: "warn",
      impact: -18,
      detail: dangerousAttachments.slice(0, 5).map((item) => `${item.filename}: ${item.risk.join(", ")}`).join(" / "),
      evidence: "Attachment type, filename, or file header suggests executable, macro, active content, or disguise marker."
    });
  } else if (riskyAttachments.length) {
    add({
      label: "Attachments",
      level: "warn",
      impact: -13,
      detail: riskyAttachments.slice(0, 5).map((item) => `${item.filename}: ${item.risk.join(", ") || "extension/header mismatch"}`).join(" / "),
      evidence: "Attachment needs review due to metadata, URLs/IOCs, nested headers, or file-signature mismatch."
    });
  } else if (info.attachments.length) {
    add({ label: "Attachments", level: "info", impact: 4, detail: `${info.attachments.length} attachment(s) parsed without priority marker.`, evidence: "Attachment metadata and headers were inspected locally." });
  }

  const dangerousSignals = info.contentSignals.filter((signal) => signal.level === "danger");
  const warningSignals = info.contentSignals.filter((signal) => signal.level === "warn");
  if (dangerousSignals.length) {
    add({
      label: "Body/content",
      level: "warn",
      impact: -14,
      detail: dangerousSignals.slice(0, 6).map((signal) => `${signal.source}: ${signal.type}`).join(" / "),
      evidence: "Decoded body or attachment text contains credential, IOC, or social-engineering wording marker; this is not a final verdict."
    });
  } else if (warningSignals.length) {
    add({
      label: "Body/content",
      level: "warn",
      impact: -10,
      detail: warningSignals.slice(0, 6).map((signal) => `${signal.source}: ${signal.type}`).join(" / "),
      evidence: "Decoded body or attachment text contains language, URL, or IOC-like signal that needs review."
    });
  }

  const structuralFindings = info.findings.filter((finding) => /Duplicate|Missing or invalid From|Future Date|Hidden HTML|HTML credential form/i.test(finding.title));
  if (structuralFindings.length) {
    add({
      label: "Header/body structure",
      level: "warn",
      impact: -9,
      detail: structuralFindings.slice(0, 5).map((finding) => finding.title).join(" / "),
      evidence: "Header duplication, invalid identity, unusual Date, credential form, or hidden HTML marker was found."
    });
  }

  const order = { danger: 0, warn: 1, info: 2 } as Record<string, number>;
  return factors.sort((left, right) => (order[left.level] ?? 2) - (order[right.level] ?? 2) || left.impact - right.impact).slice(0, 12);
}

export function buildEmailEvidenceMatrix(info: {
  verdict: EmailAnalysis["verdict"];
  rawSha256: string;
  rawSize: number;
  authAssessments: EmailAnalysis["authAssessments"];
  identityRows: EmailIdentityRow[];
  receivedHops: EmailAnalysis["receivedHops"];
  routeRows: Array<[string, string]>;
  linkRows: EmailAnalysis["linkRows"];
  urlRows: EmailAnalysis["urlRows"];
  attachments: EmailAnalysis["attachments"];
  contentSignals: EmailContentSignal[];
  infrastructureRows: EmailInfrastructureRow[];
  findings: Array<{ level: string; title: string; detail: string }>;
}) {
  const rows: EmailEvidenceMatrixRow[] = [];
  const add = (row: EmailEvidenceMatrixRow) => rows.push(row);
  const hardFailedAuth = info.authAssessments.filter((item) => /fail|policy fail/i.test(`${item.result} ${item.verdict}`));
  const reviewAuth = info.authAssessments.filter((item) => /not aligned/i.test(`${item.result} ${item.verdict}`));
  const alignedAuth = info.authAssessments.filter((item) => item.result === "pass" && item.aligned === "yes");
  const missingAuth = info.authAssessments.filter((item) => item.result === "--");
  const identityRisks = info.identityRows.filter((row) => row.risk.length);
  const severeIdentity = identityRisks.filter((row) => row.risk.some((risk) => /display-name|missing/i.test(risk)));
  const routeRisks = info.receivedHops.filter((hop) => hop.risk.length);
  const linkDisplayRisks = info.linkRows.filter((row) => row.risk.some((risk) => /display host differs|script\/data|at-sign/i.test(risk)));
  const riskyUrls = info.urlRows.filter((row) => row.risk.length);
  const riskyAttachments = info.attachments.filter((item) => item.risk.length || item.mismatch);
  const dangerousAttachments = riskyAttachments.filter((item) => item.risk.some((risk) => /executable|macro|active content|disk image|double extension/i.test(risk)));
  const dangerousSignals = info.contentSignals.filter((signal) => signal.level === "danger");
  const warningSignals = info.contentSignals.filter((signal) => signal.level === "warn");
  const riskyInfra = info.infrastructureRows.filter((row) => row.risk.length);
  const dangerFindings = info.findings.filter((finding) => finding.level === "danger");
  const warnFindings = info.findings.filter((finding) => finding.level === "warn");

  add({
    area: "解析摘要",
    verdict: `${dangerFindings.length + warnFindings.length} review note(s)`,
    level: dangerFindings.length || warnFindings.length ? "warn" : "info",
    evidence: info.verdict.detail,
    reportValue: `${dangerFindings.length} priority / ${warnFindings.length} notice`,
    nextAction: "保留原始 SHA256、认证记录、URL 和附件表；这些提示不是邮件身份的最终结论。"
  });
  add({
    area: "原始 EML",
    verdict: "证据基准",
    level: "info",
    evidence: `Raw SHA256 ${info.rawSha256}`,
    reportValue: formatBytes(info.rawSize),
    nextAction: "所有派生截图、CSV、附件下载都必须回链到原始 EML 哈希。"
  });
  add({
    area: "SPF / DKIM / DMARC",
    verdict: hardFailedAuth.length ? "认证失败记录" : reviewAuth.length ? "认证未显式对齐，需复核" : alignedAuth.length ? "存在对齐通过项" : missingAuth.length ? "认证证据不足" : "需复核",
    level: hardFailedAuth.length || reviewAuth.length || missingAuth.length ? "warn" : "info",
    evidence: hardFailedAuth.length
      ? hardFailedAuth.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / ")
      : reviewAuth.length
      ? reviewAuth.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / ")
      : alignedAuth.length
      ? alignedAuth.map((item) => `${item.mechanism}: ${item.domain}`).join(" / ")
      : info.authAssessments.map((item) => `${item.mechanism}: ${item.result}`).join(" / "),
    reportValue: info.authAssessments.map((item) => `${item.mechanism}=${item.result}, aligned=${item.aligned}`).join("; "),
    nextAction: hardFailedAuth.length ? "复核 Authentication-Results 原文、DNS 记录和邮件服务商投递日志。" : "记录通过机制和未对齐项，但不要只凭单个字段作身份判断。"
  });
  add({
    area: "身份一致性",
    verdict: severeIdentity.length ? "身份冲突明显" : identityRisks.length ? "身份字段需复核" : "身份字段本地一致",
    level: severeIdentity.length || identityRisks.length ? "warn" : "info",
    evidence: identityRisks.length ? identityRisks.slice(0, 8).map((row) => `${row.role}: ${row.risk.join(", ")}`).join(" / ") : "From / Reply-To / Return-Path / DKIM / SPF / Message-ID 未命中本地冲突规则",
    reportValue: info.identityRows.slice(0, 12).map((row) => `${row.role}:${row.domain || "--"}:${row.alignedWithFrom}`).join("; "),
    nextAction: "重点核对显示名邮箱、Reply-To、Return-Path、Message-ID 和 DKIM d= 是否与 From 域名叙事一致。"
  });
  add({
    area: "投递路径",
    verdict: !info.receivedHops.length ? "缺少 Received 链" : routeRisks.length ? "Received 链需复核" : "Received 链可解析",
    level: !info.receivedHops.length || routeRisks.length ? "warn" : "info",
    evidence: routeRisks.length ? routeRisks.slice(0, 6).map((hop) => `#${hop.index}: ${hop.risk.join(", ")}`).join(" / ") : `${info.receivedHops.length} hop(s)`,
    reportValue: info.routeRows.map(([key, value]) => `${key}: ${value}`).join("; "),
    nextAction: "按 Received 顺序核对时间、from/by 主机、IP 和组织日志；本地解析只说明这些头部字段存在。"
  });
  add({
    area: "链接 / HTML",
    verdict: linkDisplayRisks.length ? "展示文本和实际链接冲突" : riskyUrls.length ? "链接需复核" : info.urlRows.length ? "链接未命中重点规则" : "未发现正文 URL",
    level: linkDisplayRisks.length || riskyUrls.length ? "warn" : "info",
    evidence: linkDisplayRisks.length
      ? linkDisplayRisks.slice(0, 5).map((row) => `${row.text || row.displayHost || "--"} -> ${row.host}`).join(" / ")
      : riskyUrls.length
      ? riskyUrls.slice(0, 6).map((row) => `${row.host}: ${row.risk.join(", ")}`).join(" / ")
      : `${info.urlRows.length} URL row(s), ${info.linkRows.length} HTML link row(s)`,
    reportValue: `${info.urlRows.length} URL / ${info.linkRows.length} HTML href / ${riskyUrls.length + linkDisplayRisks.length} notes`,
    nextAction: "导出 URL/HTML 链接表，保留 href、展示文本、host 和复核项。"
  });
  add({
    area: "附件",
    verdict: riskyAttachments.length ? "附件存在复核提示" : info.attachments.length ? "附件未命中重点规则" : "无附件",
    level: riskyAttachments.length ? "warn" : "info",
    evidence: riskyAttachments.length ? riskyAttachments.slice(0, 6).map((item) => `${item.filename}: ${item.risk.join(", ") || "extension/header mismatch"}`).join(" / ") : `${info.attachments.length} attachment(s)`,
    reportValue: `${info.attachments.length} files / ${riskyAttachments.length} notes / ${info.attachments.reduce((sum, item) => sum + item.urlRows.length + item.iocs.length, 0)} embedded indicators`,
    nextAction: "如需继续分析，可下载附件后单独哈希、隔离查看；嵌套 EML 可继续走邮件工具。"
  });
  add({
    area: "正文 / 解码内容",
    verdict: dangerousSignals.length || warningSignals.length ? "正文存在复核提示" : info.contentSignals.length ? "有内容信号" : "未命中内容提示",
    level: dangerousSignals.length || warningSignals.length ? "warn" : "info",
    evidence: [...dangerousSignals, ...warningSignals].slice(0, 8).map((signal) => `${signal.source}: ${signal.type}`).join(" / ") || "未发现凭据、社工、编码载荷或重点 IOC 规则命中",
    reportValue: `${info.contentSignals.length} signal(s)`,
    nextAction: "将正文、HTML、解码样本和附件文本中的命中项导出，必要时进入编码转换和 IOC 工具复核。"
  });
  add({
    area: "基础设施 / IOC",
    verdict: riskyInfra.length ? "基础设施存在复核标记" : info.infrastructureRows.length ? "已提取基础设施画像" : "未提取到基础设施",
    level: riskyInfra.length ? "warn" : "info",
    evidence: riskyInfra.slice(0, 8).map((row) => `${row.kind}:${row.value} (${row.risk.join(", ")})`).join(" / ") || `${info.infrastructureRows.length} domain/IP/host item(s)`,
    reportValue: `${info.infrastructureRows.length} infrastructure item(s), ${riskyInfra.length} review-marked`,
    nextAction: "把 host/IP/domain 与 Received、URL、附件来源交叉引用，避免孤立使用 IOC。"
  });

  const order = { danger: 0, warn: 1, info: 2 } as Record<string, number>;
  return rows.sort((left, right) => (order[left.level] ?? 2) - (order[right.level] ?? 2));
}

export function emailEvidenceMatrixToCsv(rows: EmailEvidenceMatrixRow[]) {
  const escape = (value: string) => /[",\n\r]/.test(value) ? `"${value.replace(/"/g, "\"\"")}"` : value;
  return [
    ["area", "verdict", "level", "evidence", "report_value", "next_action"].join(","),
    ...rows.map((row) => [row.area, row.verdict, row.level, row.evidence, row.reportValue, row.nextAction].map(escape).join(","))
  ].join("\n");
}

export function emailRecommendedActions(analysis: EmailAnalysis | null, selectedUrl?: EmailAnalysis["urlRows"][number] | null, selectedAttachment?: EmailAnalysis["attachments"][number] | null) {
  if (!analysis) return [] as EmailActionItem[];
  const actions: EmailActionItem[] = [];
  const add = (item: EmailActionItem) => {
    const key = `${item.title}|${item.detail}|${item.value}`;
    if (!actions.some((action) => `${action.title}|${action.detail}|${action.value}` === key)) actions.push(item);
  };
  const riskyAuth = analysis.authAssessments.filter((item) => /fail|policy fail/i.test(`${item.result} ${item.verdict}`));
  const reviewAuth = analysis.authAssessments.filter((item) => /not aligned/i.test(`${item.result} ${item.verdict}`));
  if (riskyAuth.length) {
    add({
      level: "warn",
      title: "复核认证失败记录",
      detail: riskyAuth.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / "),
      action: "导出认证明细，结合邮件服务商日志、DNS SPF/DKIM/DMARC 记录和原始邮件头复核。",
      value: emailAuthAssessmentsToCsv(analysis.authAssessments)
    });
  } else if (reviewAuth.length) {
    add({
      level: "warn",
      title: "复核认证未对齐",
      detail: reviewAuth.map((item) => `${item.mechanism}: ${item.verdict}`).join(" / "),
      action: "未对齐通常需要结合转发、代发平台和 Authentication-Results 原文判断，不应单独作为身份结论。",
      value: emailAuthAssessmentsToCsv(analysis.authAssessments)
    });
  }
  if (selectedUrl) {
    add({
      level: selectedUrl.risk.length ? "warn" : "info",
      title: "检查当前 URL",
      detail: `${selectedUrl.host}; ${selectedUrl.risk.join(", ") || "no local review marker"}`,
      action: "复制 URL 到 URL 分析器，重点核对跳转、参数、展示文本和 From 域名关系。",
      value: `${selectedUrl.url}\nhost=${selectedUrl.host}\nchecks=${selectedUrl.risk.join(", ") || "--"}`
    });
  }
  const riskyLinks = analysis.linkRows.filter((row) => row.risk.length);
  if (riskyLinks.length) {
    add({
      level: "warn",
      title: "导出链接复核表",
      detail: `${riskyLinks.length} HTML link issue(s), ${analysis.urlRows.filter((row) => row.risk.length).length} URL note row(s).`,
      action: "保留 href、展示文本、host 和复核项，作为邮件链接分析证据。",
      value: emailUrlsToCsv(analysis.urlRows)
    });
  }
  if (selectedAttachment) {
    add({
      level: selectedAttachment.risk.length || selectedAttachment.mismatch ? "warn" : "info",
      title: "复核当前附件",
      detail: `${selectedAttachment.filename}; ${formatBytes(selectedAttachment.size)}; ${selectedAttachment.risk.join(", ") || selectedAttachment.signature}`,
      action: "下载附件并单独哈希登记；如有 URL/IOC/嵌套邮件头，继续用对应工具分析。",
      value: [
        `Name: ${selectedAttachment.filename}`,
        `Type: ${selectedAttachment.contentType}`,
        `Size: ${selectedAttachment.size}`,
        `SHA256: ${selectedAttachment.sha256}`,
        `Check: ${selectedAttachment.risk.join(", ") || "--"}`,
        "",
        selectedAttachment.preview
      ].join("\n")
    });
  }
  const riskyAttachments = analysis.attachments.filter((item) => item.risk.length || item.mismatch);
  if (riskyAttachments.length) {
    add({
      level: "warn",
      title: "批量登记需复核附件",
      detail: riskyAttachments.slice(0, 5).map((item) => `${item.filename}: ${item.risk.join(", ") || "extension/header mismatch"}`).join(" / "),
      action: "导出附件 CSV，下载原始附件，逐个计算哈希并隔离分析。",
      value: emailAttachmentsToCsv(riskyAttachments)
    });
  }
  if (analysis.iocs.length || analysis.contentSignals.length) {
    add({
      level: "warn",
      title: "导出 IOC / 内容信号",
      detail: `${analysis.iocs.length} IOC-like value(s), ${analysis.contentSignals.length} decoded content signal(s).`,
      action: "把 IOC 和正文/附件解码信号作为报告附件，必要时进入 IOC 提取工具继续规范化。",
      value: [
        "# IOC",
        iocRecordsToCsv(analysis.iocs),
        "",
        "# Content Signals",
        analysis.contentSignals.map((signal) => `[${signal.level}] ${signal.source} / ${signal.type}\n${signal.value}`).join("\n\n")
      ].join("\n")
    });
  }
  add({
    level: "info",
    title: "保留原始 EML 证据基准",
    detail: `Raw SHA256 ${analysis.rawSha256}; size ${formatBytes(analysis.rawSize)}; notes ${emailReviewItemCount(analysis)}.`,
    action: "始终以原始 EML 哈希为基准；截图、导出表和附件只作为派生分析材料。",
    value: [
      `Raw SHA256: ${analysis.rawSha256}`,
      `Raw size: ${analysis.rawSize}`,
      `Notes: ${emailReviewItemCount(analysis)}`,
      `Detail: ${analysis.verdict.detail}`
    ].join("\n")
  });
  const order = { danger: 0, warn: 1, info: 2 } as Record<string, number>;
  return actions.sort((left, right) => (order[left.level] ?? 2) - (order[right.level] ?? 2)).slice(0, 8);
}

export function emailReportText(analysis: EmailAnalysis) {
  return [
    "# Email Analysis",
    "",
    "## Evidence",
    `- Raw size: ${formatBytes(analysis.rawSize)}`,
    `- Raw SHA256: ${analysis.rawSha256}`,
    "",
    "## Summary",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${limitReportText(value, 800)}`),
    "",
    "## Authentication Summary",
    `- Notes: ${emailReviewItemCount(analysis)}`,
    "- Method: browser-local heuristic extraction; not a final authenticity decision",
    `- Detail: ${analysis.verdict.detail}`,
    "",
    "## Details",
    ...(analysis.evidenceMatrix.length
      ? analysis.evidenceMatrix.map((row) => `- [${row.level}] ${row.area}: ${row.verdict}\n  Evidence: ${limitReportText(row.evidence, 800)}\n  Report: ${limitReportText(row.reportValue, 800)}\n  Action: ${row.nextAction}`)
      : ["- --"]),
    "",
    "## Authentication Records",
    ...(analysis.authLedger.length
      ? analysis.authLedger.map((row) => `- [${row.level}] ${row.claim}: ${row.result}\n  Evidence: ${limitReportText(row.evidence, 900)}\n  Confidence: ${row.confidence}\n  Action: ${row.action}`)
      : ["- --"]),
    "",
    "## Check Details",
    ...(analysis.scoreFactors.length
      ? analysis.scoreFactors.map((factor) => `- [${factor.level}] ${factor.label}\n  ${limitReportText(factor.detail, 800)}\n  Evidence: ${limitReportText(factor.evidence, 800)}`)
      : ["- --"]),
    "",
    "## Suggested Checks",
    ...emailRecommendedActions(analysis).map((action, index) => `${index + 1}. [${action.level}] ${action.title}: ${action.action}\n   ${limitReportText(action.detail, 800)}`),
    "",
    "## Evidence Notes",
    ...(analysis.evidencePoints.length
      ? analysis.evidencePoints.map((point) => `- [${point.group}/${point.level}] ${point.title}: ${limitReportText(point.detail, 800)} (${point.source})`)
      : ["- --"]),
    "",
    "## Identity Details",
    ...(analysis.identityRows.length
      ? analysis.identityRows.map((row) => `- ${row.role}: value=${limitReportText(row.value, 400)} domain=${row.domain} aligned=${row.alignedWithFrom}${row.risk.length ? ` notes=${row.risk.join(", ")}` : ""}`)
      : ["- --"]),
    "",
    "## Delivery Route Summary",
    ...analysis.routeRows.map(([key, value]) => `- ${key}: ${limitReportText(value, 800)}`),
    "",
    "## Infrastructure Profile",
    ...(analysis.infrastructureRows.length
      ? analysis.infrastructureRows.slice(0, 120).map((row) => `- ${row.kind} ${row.value} count=${row.count} sources=${row.sources.join("; ")}${row.risk.length ? ` notes=${row.risk.join(", ")}` : ""}`)
      : ["- --"]),
    "",
    "## Authentication Details",
    ...(analysis.authAssessments.length
      ? analysis.authAssessments.map((item) => `- ${item.mechanism}: result=${item.result}, domain=${item.domain}, aligned=${item.aligned}, verdict=${item.verdict}`)
      : ["- --"]),
    "",
    "## DKIM / Header Details",
    ...analysis.dkimDetails.map(([key, value]) => `- ${key}: ${limitReportText(value, 800)}`),
    "",
    "## Findings",
    ...(analysis.findings.length
      ? analysis.findings.map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 1200)}`)
      : ["- --"]),
    "",
    "## Content Signals",
    ...(analysis.contentSignals.length
      ? analysis.contentSignals.map((signal) => `- [${signal.level}] ${signal.source} / ${signal.type}: ${limitReportText(signal.detail, 500)}\n  ${limitReportText(signal.value, 1000)}`)
      : ["- --"]),
    "",
    "## Received Chain",
    ...(analysis.receivedHops.length
      ? analysis.receivedHops.map((hop) => `- #${hop.index} from=${hop.from} by=${hop.by} ip=${hop.ip} date=${hop.date}${hop.risk.length ? ` notes=${hop.risk.join(", ")}` : ""}`)
      : ["- --"]),
    "",
    "## URLs",
    ...(analysis.urlRows.length
      ? analysis.urlRows.slice(0, 120).map((row) => `- ${row.url} host=${row.host}${row.risk.length ? ` notes=${row.risk.join(", ")}` : ""}`)
      : ["- --"]),
    "",
    "## HTML Links",
    ...(analysis.linkRows.length
      ? analysis.linkRows.slice(0, 120).map((row) => `- text=${limitReportText(row.text, 200)} href=${row.href} host=${row.host} display=${row.displayHost}${row.risk.length ? ` notes=${row.risk.join(", ")}` : ""}`)
      : ["- --"]),
    "",
    "## Attachments",
    ...(analysis.attachments.length
      ? analysis.attachments.map((item) => `- ${item.filename} ${formatBytes(item.size)} ${item.signature} sha256=${item.sha256}${item.risk.length ? ` notes=${item.risk.join(", ")}` : ""}${item.urlRows.length ? ` urls=${item.urlRows.length}` : ""}${item.iocs.length ? ` iocs=${item.iocs.length}` : ""}${item.nestedHeaders.length ? ` nested_headers=${item.nestedHeaders.length}` : ""}`)
      : ["- --"]),
    "",
    "## Timeline Candidates",
    ...(analysis.bodyTimeline.length
      ? analysis.bodyTimeline.slice(0, 80).map((event) => `- ${event.iso} | ${event.format} | ${limitReportText(event.context, 800)}`)
      : ["- --"])
  ].join("\n");
}

export function emailUrlKey(row: EmailAnalysis["urlRows"][number]) {
  return `${row.url}|${row.host}|${row.risk.join(",")}`;
}

export function emailAttachmentKey(row: EmailAnalysis["attachments"][number]) {
  return `${row.filename}|${row.size}|${row.sha256}`;
}

export function softenEmailLevel(level: string) {
  return level === "danger" ? "warn" : level;
}

export function softenEmailReviewText(text: string) {
  return text
    .replace(/\bverdict\b/gi, "summary")
    .replace(/\bthreat\b/gi, "note")
    .replace(/\bsuspicious\b/gi, "needs check")
    .replace(/\blikely forged\b/gi, "needs further check")
    .replace(/\bforged\b/gi, "needs check")
    .replace(/\bphishing\b/gi, "social-engineering check")
    .replace(/\bhigh[-\s]?risk\b/gi, "needs check")
    .replace(/\bcritical\b/gi, "needs check")
    .replace(/\bdanger\b/gi, "check")
    .replace(/\breview\b/gi, "check")
    .replace(/真伪鉴定|真伪|可信度|可信评分|风险评分/g, "解析摘要")
    .replace(/高风险|严重|威胁|可疑/g, "需要检查")
    .replace(/高危|危险/g, "需要检查")
    .replace(/伪造|冒充/g, "需结合原始邮件进一步检查")
    .replace(/钓鱼/g, "社工/链接检查")
    .replace(/复核/g, "检查");
}

export function emailUiNoteText(text: string) {
  return softenEmailReviewText(text)
    .replace(/\bwarn(?:ing)?\b/gi, "note")
    .replace(/\bfailed\b/gi, "not pass")
    .replace(/\bfail\b/gi, "not pass")
    .replace(/警告/g, "提示")
    .replace(/失败/g, "未通过");
}

export function softenEmailSignalType(type: string) {
  return softenEmailReviewText(type)
    .replace(/social-engineering check wording/gi, "Body wording marker")
    .replace(/Credential-like content/gi, "Credential keyword marker")
    .replace(/Credential-like text/gi, "Credential keyword marker")
    .replace(/HTML credential form/gi, "HTML form marker")
    .replace(/URL review marker/gi, "URL marker")
    .replace(/IOC review marker/gi, "IOC marker")
    .replace(/IOC check marker/gi, "IOC marker");
}

export function softenEmailAnalysis(analysis: EmailAnalysis): EmailAnalysis {
  const softenFinding = (finding: { level: string; title: string; detail: string }) => ({
    ...finding,
    level: softenEmailLevel(finding.level),
    title: softenEmailReviewText(finding.title),
    detail: softenEmailReviewText(finding.detail)
  });
  return {
    ...analysis,
    findings: analysis.findings.map(softenFinding),
    contentSignals: analysis.contentSignals.map((signal) => ({
      ...signal,
      level: softenEmailLevel(signal.level),
      type: softenEmailSignalType(signal.type),
      detail: softenEmailReviewText(signal.detail)
    })),
    evidencePoints: analysis.evidencePoints.map((point) => ({
      ...point,
      group: point.group === "risk" ? "review" : point.group,
      level: softenEmailLevel(point.level),
      title: softenEmailReviewText(point.title),
      detail: softenEmailReviewText(point.detail)
    })),
    scoreFactors: analysis.scoreFactors.map((factor) => ({
      ...factor,
      level: softenEmailLevel(factor.level),
      label: softenEmailReviewText(factor.label),
      detail: softenEmailReviewText(factor.detail),
      evidence: softenEmailReviewText(factor.evidence)
    })),
    evidenceMatrix: analysis.evidenceMatrix.map((row) => ({
      ...row,
      level: softenEmailLevel(row.level),
      verdict: softenEmailReviewText(row.verdict),
      nextAction: softenEmailReviewText(row.nextAction)
    })),
    authLedger: analysis.authLedger.map((row) => ({
      ...row,
      level: softenEmailLevel(row.level),
      action: softenEmailReviewText(row.action)
    })),
    verdict: {
      ...analysis.verdict,
      label: "parsed facts",
      detail: `${softenEmailReviewText(analysis.verdict.detail)}; browser-local parse only, not an authenticity decision`
    }
  };
}

export function emailReviewItemCount(analysis: EmailAnalysis) {
  return analysis.findings.filter((finding) => finding.level === "warn" || finding.level === "danger").length;
}

export function emailSummaryValue(analysis: EmailAnalysis, label: string) {
  return analysis.rows.find(([key]) => key === label)?.[1] ?? "--";
}

export function emailFirstValue(rows: Array<[string, string]>, labels: string[]) {
  for (const label of labels) {
    const value = rows.find(([key]) => key === label)?.[1];
    if (value && value !== "--") return value;
  }
  return "--";
}

export function EmailOverviewPanel({ parsed, t }: { parsed: EmailAnalysis | null; t: (typeof copy)["zh"] }) {
  if (!parsed) return null;
  const authValue = emailSummaryValue(parsed, "SPF / DKIM / DMARC");
  const reviewCards = emailTriageCards(parsed);
  const english = t.waiting === "Waiting";
  const apparentOrigin = emailFirstValue(parsed.routeRows, ["Apparent origin", "Origin"]);
  const routeSummary = emailFirstValue(parsed.routeRows, ["Route", "Path", "Relay path"]);
  const newestHop = parsed.receivedHops[0] ?? null;
  const oldestHop = parsed.receivedHops[parsed.receivedHops.length - 1] ?? null;
  const verdict = (() => {
    const danger = parsed.findings.filter((finding) => finding.level === "danger");
    const warn = parsed.findings.filter((finding) => finding.level === "warn");
    if (danger.length) {
      return {
        level: "danger",
        title: english ? "Review sender identity and delivery path" : "需要复核发件身份和投递路径",
        detail: danger.slice(0, 2).map((finding) => finding.title).join(" / ")
      };
    }
    if (warn.length) {
      return {
        level: "warn",
        title: english ? "Local email review ready" : "邮件本地复核已整理",
        detail: warn.slice(0, 2).map((finding) => finding.title).join(" / ")
      };
    }
    return {
      level: "info",
      title: english ? "Message parsed locally" : "邮件已在本地解析",
      detail: `${authValue || "--"} · ${parsed.receivedHops.length} hop(s) · ${parsed.attachments.length} attachment(s)`
    };
  })();
  const countCards = [
    [t.emailAuth, authValue],
    [t.fileSize, emailSummaryValue(parsed, "Raw size")],
    [t.receivedChain, String(parsed.receivedHops.length)],
    [t.emailUrls, String(parsed.urlRows.length)],
    [t.attachments, String(parsed.attachments.length)],
    [t.waiting === "Waiting" ? "Notes" : "记录项", String(emailReviewItemCount(parsed))]
  ] as Array<[string, string]>;
  const identityFacts = [
    ["From", emailSummaryValue(parsed, "From")],
    ["Reply-To", emailSummaryValue(parsed, "Reply-To")],
    ["Return-Path", emailSummaryValue(parsed, "Return-Path")],
    ["To", emailSummaryValue(parsed, "To")],
    ["From domain", emailSummaryValue(parsed, "From domain")],
    ["Origin", apparentOrigin],
    ["Route", routeSummary]
  ] as Array<[string, string]>;
  const messageFacts = [
    ["Date", emailSummaryValue(parsed, "Date")],
    ["Message-ID", emailSummaryValue(parsed, "Message-ID")],
    ["SHA256", parsed.rawSha256],
    ["Newest hop", newestHop ? `${newestHop.by || "--"} · ${newestHop.ip || "--"}` : "--"],
    ["Oldest hop", oldestHop ? `${oldestHop.from || "--"} · ${oldestHop.ip || "--"}` : "--"]
  ] as Array<[string, string]>;
  return (
    <div className="tool-panel wide-panel email-overview-panel">
      <div className="panel-heading-row">
        <PanelTitle title={t.emailOverview} />
        <div className="button-row compact-buttons">
          <AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(parsed.rawSha256)}>SHA256</AButton>
          <AButton variant="text" onClick={() => void navigator.clipboard.writeText(`${emailSummaryValue(parsed, "Subject") || "--"}\n${emailSummaryValue(parsed, "From") || "--"} -> ${emailSummaryValue(parsed, "To") || "--"}`)}>
            {english ? "Copy Message" : "复制消息摘要"}
          </AButton>
        </div>
      </div>
      <div className="email-overview-primary">
        <section className={`email-overview-hero ${verdict.level}`}>
          <div className="email-overview-hero-main">
            <span>{english ? "Review status" : "当前判读"}</span>
            <strong>{verdict.title}</strong>
            <em>{verdict.detail}</em>
          </div>
          <div className="email-overview-counts">
            {countCards.map(([label, value]) => (
              <button className="result-copy-card" type="button" key={label} disabled={value === "--"} onClick={() => value !== "--" && void navigator.clipboard.writeText(value)}>
                <span>{label}</span>
                <strong>{value}</strong>
              </button>
            ))}
          </div>
        </section>
        <section className="email-overview-review">
          <div className="section-kicker">{english ? "Current message" : "当前邮件"}</div>
          <InfoTable rows={messageFacts} />
          <div className="email-review-grid email-review-grid-inline">
            {reviewCards.map((card) => (
              <button
                className={`email-review-card ${card.level}`}
                type="button"
                key={`${card.label}-${card.value}`}
                onClick={() => void navigator.clipboard.writeText(`${card.label}\n${card.value}\n${card.detail}`)}
              >
                <span>{card.label}</span>
                <strong>{card.value}</strong>
                <em>{card.detail}</em>
              </button>
            ))}
          </div>
        </section>
      </div>
      <div className="email-overview-grid email-overview-grid-compact">
        <section className="email-overview-section">
          <h3>{t.waiting === "Waiting" ? "Identity and Route" : "身份与路径"}</h3>
          <InfoTable rows={identityFacts} />
        </section>
        <section className="email-overview-section">
          <h3>{t.waiting === "Waiting" ? "Message Ledger" : "消息记录"}</h3>
          <InfoTable rows={[
            ["Subject", emailSummaryValue(parsed, "Subject")],
            [t.emailAuth, authValue],
            ["Received hops", String(parsed.receivedHops.length)],
            [t.emailUrls, String(parsed.urlRows.length)],
            [t.attachments, String(parsed.attachments.length)],
            [t.waiting === "Waiting" ? "Notes" : "记录项", String(emailReviewItemCount(parsed))]
          ]} />
        </section>
      </div>
    </div>
  );
}

export function EmailTracePanel({ parsed, t }: { parsed: EmailAnalysis | null; t: (typeof copy)["zh"] }) {
  if (!parsed) return null;
  const authRows = parsed.authAssessments.length
    ? parsed.authAssessments.slice(0, 6)
    : parsed.auth.map(([mechanism, result]) => ({
      mechanism,
      result,
      domain: "--",
      aligned: "--",
      source: "Authentication-Results",
      verdict: result
    }));
  const receivedRows = parsed.receivedHops.slice(0, 8);
  const traceText = [
    "Authentication",
    ...authRows.map((row) => `${row.mechanism}: ${row.result}; domain=${row.domain}; aligned=${row.aligned}; source=${row.source}`),
    "",
    "Received",
    ...parsed.receivedHops.map((hop) => `#${hop.index} from=${hop.from} by=${hop.by} ip=${hop.ip} date=${hop.date}${hop.risk.length ? ` notes=${hop.risk.join(", ")}` : ""}`)
  ].join("\n");
  return (
    <div className="tool-panel wide-panel email-trace-panel">
      <div className="panel-heading-row">
        <PanelTitle title={t.waiting === "Waiting" ? "Authentication & Delivery Path" : "认证与投递路径"} />
        <div className="button-row compact-buttons">
          <AButton variant="outlined" disabled={!authRows.length && !receivedRows.length} onClick={() => void navigator.clipboard.writeText(traceText)}>
            {t.copy}
          </AButton>
          <AButton variant="outlined" disabled={!receivedRows.length} onClick={() => downloadTextFile(`email-received-${Date.now()}.csv`, emailReceivedToCsv(parsed.receivedHops), "text/csv;charset=utf-8")}>
            Received CSV
          </AButton>
        </div>
      </div>
      <div className="email-trace-grid">
        <section>
          <div className="section-kicker">{t.emailAuth}</div>
          <div className="email-trace-card-grid">
            {authRows.length ? authRows.map((row) => (
              <button
                className={/fail|not aligned/i.test(`${row.result} ${row.aligned} ${row.verdict}`) ? "email-trace-card noted" : "email-trace-card"}
                type="button"
                key={`${row.mechanism}-${row.result}-${row.domain}-${row.source}`}
                onClick={() => void navigator.clipboard.writeText(`${row.mechanism}: ${row.result}; domain=${row.domain}; aligned=${row.aligned}; source=${row.source}`)}
              >
                <span>{row.mechanism}</span>
                <strong>{row.result || "--"}</strong>
                <em>{row.domain || "--"} · aligned {row.aligned || "--"}</em>
                <small>{row.source || row.verdict || "--"}</small>
              </button>
            )) : <div className="empty-state">--</div>}
          </div>
        </section>
        <section>
          <div className="section-kicker">{t.receivedChain}</div>
          <div className="email-trace-card-grid">
            {receivedRows.length ? receivedRows.map((hop) => (
              <button
                className={hop.risk.length ? "email-trace-card noted" : "email-trace-card"}
                type="button"
                key={`${hop.index}-${hop.raw}`}
                onClick={() => void navigator.clipboard.writeText(hop.raw)}
              >
                <span>Hop {hop.index}</span>
                <strong>{hop.by || "--"}</strong>
                <em>{hop.from || "--"}</em>
                <small>{hop.ip || "--"} · {hop.date || "--"}</small>
              </button>
            )) : <div className="empty-state">--</div>}
          </div>
        </section>
      </div>
    </div>
  );
}

export function EmailBodyPanel({ parsed, t }: { parsed: EmailAnalysis | null; t: (typeof copy)["zh"] }) {
  if (!parsed) return null;
  const decodedRows = parsed.decoded.filter(([, value]) => value && value !== "--").slice(0, 4);
  const textPreview = parsed.bodyText || stripEmailHtml(parsed.bodyHtml) || "";
  const htmlPreview = parsed.bodyHtml || "";
  const signalRows = parsed.contentSignals.slice(0, 5);
  return (
    <div className="tool-panel wide-panel email-body-panel">
      <div className="panel-heading-row">
        <PanelTitle title={t.waiting === "Waiting" ? "Body and Encoding" : "正文与编码"} />
        <div className="button-row compact-buttons">
          <AButton variant="outlined" disabled={!textPreview} onClick={() => void navigator.clipboard.writeText(textPreview)}>
            Text
          </AButton>
          <AButton variant="outlined" disabled={!htmlPreview} onClick={() => void navigator.clipboard.writeText(htmlPreview)}>
            HTML
          </AButton>
        </div>
      </div>
      <div className="email-body-grid">
        <section>
          <div className="section-kicker">{t.emailBody}</div>
          <textarea className="single-textarea email-body-preview" value={limitReportText(textPreview || htmlPreview || "--", 5000)} readOnly />
        </section>
        <section>
          <div className="section-kicker">{t.emailDecoded}</div>
          {decodedRows.length ? (
            <div className="email-decoded-list">
              {decodedRows.map(([label, value]) => (
                <button className="email-decoded-item" type="button" key={label} onClick={() => void navigator.clipboard.writeText(value)}>
                  <strong>{label}</strong>
                  <span>{limitReportText(value, 240)}</span>
                </button>
              ))}
            </div>
          ) : <div className="empty-state">--</div>}
          {signalRows.length ? (
            <div className="email-body-signals">
              {signalRows.map((signal) => (
                <button className="email-body-signal" type="button" key={`${signal.source}-${signal.type}-${signal.value}`} onClick={() => void navigator.clipboard.writeText(signal.value)}>
                  <span>{signal.source}</span>
                  <strong>{signal.type}</strong>
                  <em>{signal.detail}</em>
                </button>
              ))}
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

export function emailTriageCards(analysis: EmailAnalysis | null) {
  if (!analysis) {
    return [
      { label: "来源", value: "--", detail: "等待邮件源码或 EML。", level: "info" },
      { label: "认证", value: "--", detail: "等待 SPF / DKIM / DMARC。", level: "info" },
      { label: "链接", value: "--", detail: "等待正文和 HTML 链接。", level: "info" },
      { label: "附件", value: "--", detail: "等待 MIME 附件。", level: "info" }
    ];
  }
  const reviewItems = emailReviewItemCount(analysis);
  const failedAuth = analysis.authAssessments.filter((item) => /fail|policy fail/i.test(`${item.result} ${item.verdict}`));
  const reviewAuth = analysis.authAssessments.filter((item) => /not aligned/i.test(`${item.result} ${item.verdict}`));
  const identityRisks = analysis.identityRows.filter((row) => row.risk.length);
  const riskyUrls = analysis.urlRows.filter((row) => row.risk.length);
  const riskyLinks = analysis.linkRows.filter((row) => row.risk.length);
  const riskyAttachments = analysis.attachments.filter((item) => item.risk.length || item.mismatch);
  const receivedNotes = analysis.receivedHops.filter((hop) => hop.risk.length);
  const contentNotes = analysis.contentSignals.filter((signal) => signal.level === "warn" || signal.level === "danger");
  const embeddedAttachmentSignals = analysis.attachments.reduce((sum, item) => sum + item.urlRows.length + item.iocs.length, 0);
  return [
    {
      label: "原始邮件",
      value: formatBytes(analysis.rawSize),
      detail: `SHA256 ${analysis.rawSha256.slice(0, 18)}...；浏览器本地解析。`,
      level: "info"
    },
    {
      label: "认证 / 身份",
      value: analysis.rows.find(([key]) => key === "SPF / DKIM / DMARC")?.[1] ?? "--",
      detail: failedAuth.length
        ? failedAuth.map((item) => `${item.mechanism}: ${emailUiNoteText(item.verdict)}`).join(" / ")
        : reviewAuth.length || identityRisks.length
          ? `${reviewAuth.length} 条认证记录，${identityRisks.length} 条身份记录。`
          : "认证记录通过；仍保留原始邮件头用于复核。",
      level: failedAuth.length ? "warn" : "info"
    },
    {
      label: "投递 / 链接",
      value: `${analysis.receivedHops.length} hops / ${analysis.urlRows.length} URLs`,
      detail: `${receivedNotes.length} 条投递复核项，${riskyUrls.length + riskyLinks.length} 条链接复核项。`,
      level: riskyUrls.some((row) => row.risk.some((item) => /credential|external redirect|private|punycode|shortener|mismatch/i.test(item))) ? "warn" : "info"
    },
    {
      label: "附件 / 正文",
      value: `${analysis.attachments.length} files / ${analysis.contentSignals.length} items`,
      detail: `${riskyAttachments.length} 条附件复核项，${contentNotes.length} 条正文提取项，${embeddedAttachmentSignals} 个附件内 URL/IOC。`,
      level: riskyAttachments.some((item) => item.mismatch || item.risk.some((risk) => /executable|macro|script|archive|mismatch/i.test(risk))) ? "warn" : "info"
    }
  ];
}

export function emailBriefing(analysis: EmailAnalysis | null, selectedUrl?: EmailAnalysis["urlRows"][number] | null, selectedAttachment?: EmailAnalysis["attachments"][number] | null) {
  if (!analysis) return "# Email Briefing\n\nWaiting for email source.";
  const actions = emailRecommendedActions(analysis, selectedUrl, selectedAttachment);
  const lines = [
    "# Email Briefing",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Notes Summary",
    `- Notes: ${emailReviewItemCount(analysis)}`,
    "- Method: browser-local heuristic extraction; not a final authenticity decision",
    `- Detail: ${analysis.verdict.detail}`,
    "",
    "## Details",
    ...(analysis.evidenceMatrix.length
      ? analysis.evidenceMatrix.map((row) => `- [${row.level}] ${row.area}: ${row.verdict} - ${limitReportText(row.evidence, 500)}`)
      : ["- --"]),
    "",
    "## Check Details",
    ...(analysis.scoreFactors.length
      ? analysis.scoreFactors.map((factor) => `- [${factor.level}] ${factor.label} - ${limitReportText(factor.detail, 700)} (${factor.evidence})`)
      : ["- --"]),
    "",
    "## Suggested Checks",
    ...(actions.length
      ? actions.map((action, index) => `${index + 1}. [${action.level}] ${action.title} - ${action.action} (${action.detail})`)
      : ["- --"]),
    "",
    "## Evidence Notes",
    ...(analysis.evidencePoints.length
      ? analysis.evidencePoints.map((point) => `- [${point.group.toUpperCase()} / ${point.level}] ${point.title}: ${limitReportText(point.detail, 700)} (${point.source})`)
      : ["- --"]),
    "",
    "## Identity Details",
    ...(analysis.identityRows.length
      ? analysis.identityRows.slice(0, 24).map((row) => `- ${row.role}: ${row.domain}; aligned=${row.alignedWithFrom}; notes=${row.risk.join(", ") || "--"}`)
      : ["- --"]),
    "",
    "## Route Summary",
    ...analysis.routeRows.map(([key, value]) => `- ${key}: ${limitReportText(value, 500)}`),
    "",
    "## Infrastructure",
    ...(analysis.infrastructureRows.length
      ? analysis.infrastructureRows.slice(0, 40).map((row) => `- ${row.kind} ${row.value}; count=${row.count}; notes=${row.risk.join(", ") || "--"}; sources=${row.sources.slice(0, 4).join("; ")}`)
      : ["- --"]),
    "",
    "## Summary",
    ...analysis.rows.map(([key, value]) => `- ${key}: ${limitReportText(value, 500)}`),
    "",
    "## Current URL",
    selectedUrl
      ? `- URL: ${selectedUrl.url}\n- Host: ${selectedUrl.host}\n- Check: ${selectedUrl.risk.join(", ") || "--"}`
      : "- --",
    "",
    "## Current Attachment",
    selectedAttachment
      ? `- Name: ${selectedAttachment.filename}\n- Type: ${selectedAttachment.contentType}\n- Size: ${formatBytes(selectedAttachment.size)}\n- Signature: ${selectedAttachment.signature}${selectedAttachment.mismatch ? ` / .${selectedAttachment.extension}` : ""}\n- SHA256: ${selectedAttachment.sha256}\n- Check: ${selectedAttachment.risk.join(", ") || "--"}\n- URLs/IOCs/Nested EML: ${selectedAttachment.urlRows.length} / ${selectedAttachment.iocs.length} / ${selectedAttachment.nestedHeaders.length}\n- Preview: ${limitReportText(selectedAttachment.preview, 1200)}`
      : "- --",
    "",
    "## Findings",
    ...(analysis.findings.length
      ? analysis.findings.slice(0, 30).map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 900)}`)
      : ["- --"]),
    "",
    "## Authentication Details",
    ...(analysis.authAssessments.length
      ? analysis.authAssessments.map((item) => `- ${item.mechanism}: ${item.result}, domain=${item.domain}, aligned=${item.aligned}, verdict=${item.verdict}`)
      : ["- --"]),
    "",
    "## Content Signals",
    ...(analysis.contentSignals.length
      ? analysis.contentSignals.slice(0, 24).map((signal) => `- [${signal.level}] ${signal.source} / ${signal.type}: ${limitReportText(signal.value, 700).replace(/\n/g, " ")}`)
      : ["- --"]),
    "",
    "## URL Notes",
    ...(analysis.urlRows.filter((row) => row.risk.length).length
      ? analysis.urlRows.filter((row) => row.risk.length).slice(0, 60).map((row) => `- ${row.url} (${row.host}) notes=${row.risk.join(", ")}`)
      : ["- --"]),
    "",
    "## Attachments",
    ...(analysis.attachments.length
      ? analysis.attachments.slice(0, 40).map((item) => `- ${item.filename} ${formatBytes(item.size)} ${item.signature} sha256=${item.sha256}${item.risk.length ? ` notes=${item.risk.join(", ")}` : ""}`)
      : ["- --"])
  ];
  return limitReportText(lines.join("\n"), 30000);
}

export function attachmentBytes(content: ArrayBuffer | Uint8Array | string) {
  if (typeof content === "string") return new TextEncoder().encode(content);
  if (content instanceof Uint8Array) return content;
  return new Uint8Array(content);
}

export function extensionOfFilename(filename: string) {
  return filename.includes(".") ? filename.split(".").pop()?.toLowerCase() ?? "" : "";
}

export function analyzeEmailAttachment(filename: string, contentType: string, content: Uint8Array, fromDomain = "") {
  const extension = extensionOfFilename(filename);
  const signature = fileSignatureForBytes(content);
  const mismatch = Boolean(signature && extension && !signature.extensions.includes(extension));
  const lower = filename.toLowerCase();
  const preview = previewText(content, 12000);
  const attachmentIocs = emailIocRecords(preview, `attachment ${filename}`).slice(0, 120);
  const attachmentUrls = analyzeEmailUrls(uniqueValues(extractIocs(preview).URL, 80), fromDomain);
  const nestedHeaders = /\.(eml)$/i.test(filename) || /message\/rfc822/i.test(contentType) || /^From:|^Return-Path:|^Received:/im.test(preview)
    ? unfoldEmailHeaders(preview.split(/\n\n/)[0] ?? "")
      .flatMap((line) => {
        const index = line.indexOf(":");
        return index > -1 ? [[line.slice(0, index).trim(), decodeWords(line.slice(index + 1).trim())] as [string, string]] : [];
      })
      .filter(([key]) => /^(From|To|Cc|Bcc|Subject|Date|Message-ID|Reply-To|Return-Path|Authentication-Results|Received)$/i.test(key))
      .slice(0, 80) as Array<[string, string]>
    : [];
  const risk = [
    /\.(exe|scr|js|vbs|ps1|bat|cmd|hta|lnk|jar|apk|com|pif)$/i.test(filename) ? "executable/script extension" : "",
    /\.(docm|xlsm|pptm|xlam)$/i.test(filename) ? "macro-enabled Office file" : "",
    /\.(eml|msg)$/i.test(filename) || /message\/rfc822|application\/vnd\.ms-outlook/i.test(contentType) ? "nested email attachment" : "",
    /\.(iso|img|vhd|vhdx)$/i.test(filename) ? "disk image attachment" : "",
    /\.(html?|svg|shtml)$/i.test(filename) || /text\/html|image\/svg/i.test(contentType) ? "active content attachment" : "",
    /\.(zip|rar|7z|gz|tgz)$/i.test(filename) || /archive|compressed|zip|rar|7z/i.test(contentType) ? "archive attachment" : "",
    /\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|txt)\.(exe|scr|js|vbs|ps1|bat|cmd|hta|lnk|jar)$/i.test(lower) ? "double extension disguise" : "",
    mismatch ? `extension/header mismatch: .${extension} vs ${signature?.label}` : "",
    content.byteLength === 0 ? "empty attachment" : "",
    content.byteLength > 25 * 1024 * 1024 ? "large attachment" : "",
    /password|invoice|payment|receipt|urgent|verify|登录|发票|付款|密码|验证/i.test(filename) ? "credential-themed filename" : "",
    attachmentUrls.some((row) => row.risk.length) ? "risky URL inside attachment" : "",
    attachmentIocs.some((record) => record.risk.length) ? "IOC review marker inside attachment" : "",
    nestedHeaders.length ? "nested EML headers parsed" : ""
  ].filter(Boolean);
  return {
    extension: extension || "--",
    signature: signature?.label ?? (content.byteLength ? "Unknown" : "--"),
    mismatch,
    risk,
    preview: preview.slice(0, 4096),
    iocs: attachmentIocs,
    urlRows: attachmentUrls,
    nestedHeaders
  };
}

export function emailAttachmentPreferredExtension(attachment: EmailAttachmentRow) {
  const signature = fileSignatureForBytes(attachment.content);
  if (signature?.extensions.length) return signature.extensions[0];
  if (attachment.extension && attachment.extension !== "--") return attachment.extension;
  return "bin";
}

export function emailAttachmentHexPreview(attachment: EmailAttachmentRow, bytes = 512) {
  return hexPreview(attachment.content, bytes);
}

export function emailAttachmentManifestText(attachment: EmailAttachmentRow) {
  return [
    `Name: ${attachment.filename}`,
    `Content-Type: ${attachment.contentType}`,
    `Size: ${formatBytes(attachment.size)}`,
    `Signature: ${attachment.signature}`,
    `Extension: ${attachment.extension || "--"}`,
    `Mismatch: ${attachment.mismatch ? "yes" : "no"}`,
    `SHA256: ${attachment.sha256}`,
    `Check markers: ${attachment.risk.join(", ") || "--"}`,
    `URLs: ${attachment.urlRows.length}`,
    `IOC: ${attachment.iocs.length}`,
    `Nested EML headers: ${attachment.nestedHeaders.length}`,
    "",
    "Text preview:",
    limitReportText(attachment.preview || "--", 3000),
    "",
    "Hex preview:",
    emailAttachmentHexPreview(attachment, 512)
  ].join("\n");
}

export function authDomainValue(authenticationResults: string, key: string) {
  return authenticationResults.match(new RegExp(`\\b${key.replace(".", "\\.")}=([^;\\s]+)`, "i"))?.[1]?.replace(/[<>()[\],]+$/g, "").toLowerCase() ?? "";
}

export function displayNameEmailDomain(value: string) {
  const address = extractEmailAddress(value);
  const display = value.replace(/<[^>]+>/g, " ");
  const displayEmail = display.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i)?.[0] ?? "";
  if (!displayEmail || displayEmail.toLowerCase() === address.toLowerCase()) return "";
  return extractEmailDomain(displayEmail);
}

export async function parseEmail(raw: string): Promise<EmailAnalysis> {
  const normalized = raw.replace(/\r\n/g, "\n");
  const rawBytes = new TextEncoder().encode(raw);
  const rawSha256 = sha256Bytes(rawBytes);
  const [head = ""] = normalized.split(/\n\n/);
  const fallbackHeaders = unfoldEmailHeaders(head)
    .map((line) => {
      const index = line.indexOf(":");
      return index > -1 ? ([line.slice(0, index).trim(), decodeWords(line.slice(index + 1).trim())] as [string, string]) : null;
    })
    .filter(Boolean) as Array<[string, string]>;
  const parsed = await PostalMime.parse(raw, { attachmentEncoding: "arraybuffer", rfc822Attachments: true });
  const headers = parsed.headers.length
    ? parsed.headers.map((header) => [header.originalKey || header.key, decodeWords(header.value)] as [string, string])
    : fallbackHeaders;
  const get = (name: string) => getEmailHeader(headers, name);
  const received = headers.filter(([key]) => key.toLowerCase() === "received").map(([, value]) => value);
  const receivedHops = received.map((value, index) => parseReceivedHop(value, index + 1));
  for (let index = 0; index + 1 < receivedHops.length; index += 1) {
    const newer = Date.parse(receivedHops[index].date);
    const older = Date.parse(receivedHops[index + 1].date);
    if (Number.isFinite(newer) && Number.isFinite(older) && newer < older) receivedHops[index].risk.push("received time order anomaly");
  }
  const auth = headers.filter(([key]) => key.toLowerCase() === "authentication-results").map(([, value]) => value).join("\n") || "--";
  const dkimSignature = get("DKIM-Signature");
  const parsedFrom = normalizeMailAddress(parsed.from as { name?: string; address?: string } | undefined);
  const parsedTo = normalizeMailAddressList(parsed.to as Array<{ name?: string; address?: string }> | undefined);
  const parsedReplyTo = normalizeMailAddressList(parsed.replyTo as Array<{ name?: string; address?: string }> | undefined);
  const from = parsedFrom === "--" ? get("From") : parsedFrom;
  const to = parsedTo === "--" ? get("To") : parsedTo;
  const replyTo = parsedReplyTo === "--" ? get("Reply-To") : parsedReplyTo;
  const returnPath = parsed.returnPath || get("Return-Path");
  const subject = parsed.subject || get("Subject");
  const date = parsed.date || get("Date");
  const messageId = parsed.messageId || get("Message-ID");
  const bodyText = parsed.text || "";
  const bodyHtml = parsed.html || "";
  const body = `${bodyText}\n${bodyHtml}`;
  const htmlText = stripEmailHtml(bodyHtml);
  const bodyTimeline = parseTimestampCandidates(`${headers.map(([key, value]) => `${key}: ${value}`).join("\n")}\n\n${bodyText}\n${htmlText}`, "email headers/body").slice(0, 500);
  const quotedPrintableBody = /=\r?\n|=[0-9a-fA-F]{2}/.test(bodyText) ? decodeQuotedPrintableText(bodyText) : "--";
  const base64Body = /^[A-Za-z0-9+/=\s]{40,}$/.test(bodyText.trim()) ? safeDecodeBase64EmailText(bodyText.trim()) : "--";
  const urls = uniqueValues(extractIocs(body).URL, 200);
  const fromDomain = extractEmailDomain(from || get("From"));
  const returnDomain = extractEmailDomain(returnPath);
  const replyDomain = extractEmailDomain(replyTo);
  const displaySpoofDomain = displayNameEmailDomain(from || get("From"));
  const messageIdDomain = messageId.match(/@([^>]+)/)?.[1]?.toLowerCase() ?? "";
  const dkimDomain = extractDkimDomain(dkimSignature);
  const spf = getAuthStatus(auth, "spf");
  const dkim = getAuthStatus(auth, "dkim");
  const dmarc = getAuthStatus(auth, "dmarc");
  const spfMailFrom = authDomainValue(auth, "smtp.mailfrom");
  const authHeaderFrom = authDomainValue(auth, "header.from");
  const authDkimHeader = authDomainValue(auth, "header.d");
  const authHeaderI = authDomainValue(auth, "header.i");
  const authSmtpHelo = authDomainValue(auth, "smtp.helo");
  const dkimAligned = Boolean(fromDomain && (dkimDomain || authDkimHeader) && alignedEmailDomains(fromDomain, dkimDomain || authDkimHeader));
  const spfAligned = Boolean(fromDomain && spfMailFrom && alignedEmailDomains(fromDomain, spfMailFrom));
  const dmarcDomainAligned = Boolean(fromDomain && (!authHeaderFrom || alignedEmailDomains(fromDomain, authHeaderFrom)));
  const dkimDetails = parseDkimSignatureRows(dkimSignature);
  const authAssessments: EmailAnalysis["authAssessments"] = [
    {
      mechanism: "SPF",
      result: spf,
      domain: spfMailFrom || "--",
      aligned: fromDomain && spfMailFrom ? (spfAligned ? "yes" : "no") : "--",
      source: "Authentication-Results smtp.mailfrom",
      verdict: spf === "pass" && spfAligned ? "pass aligned" : spf === "pass" ? "pass but not aligned" : spf
    },
    {
      mechanism: "DKIM",
      result: dkim,
      domain: dkimDomain || authDkimHeader || "--",
      aligned: fromDomain && (dkimDomain || authDkimHeader) ? (dkimAligned ? "yes" : "no") : "--",
      source: dkimDomain ? "DKIM-Signature d=" : "Authentication-Results header.d",
      verdict: dkim === "pass" && dkimAligned ? "pass aligned" : dkim === "pass" ? "pass but not aligned" : dkim
    },
    {
      mechanism: "DMARC",
      result: dmarc,
      domain: authHeaderFrom || fromDomain || "--",
      aligned: fromDomain ? (dmarcDomainAligned ? "yes" : "no") : "--",
      source: "Authentication-Results header.from",
      verdict: dmarc === "pass" ? "policy pass" : dmarc
    }
  ];
  const arcAuth = get("ARC-Authentication-Results");
  if (arcAuth && arcAuth !== "--") {
    authAssessments.push({
      mechanism: "ARC",
      result: "present",
      domain: "--",
      aligned: "--",
      source: "ARC-Authentication-Results",
      verdict: "forwarding context; review chain"
    });
  }
  const urlRows = analyzeEmailUrls(urls, fromDomain);
  const linkRows = analyzeEmailHtmlLinks(bodyHtml, fromDomain);
  const iocs = emailIocRecords(`${headers.map(([key, value]) => `${key}: ${value}`).join("\n")}\n\n${body}`, "email");
  const headerCount = (name: string) => headers.filter(([key]) => key.toLowerCase() === name.toLowerCase()).length;
  const domainAlignment: Array<[string, string]> = [
    ["From domain", fromDomain || "--"],
    ["Return-Path domain", returnDomain || "--"],
    ["Reply-To domain", replyDomain || "--"],
    ["Message-ID domain", messageIdDomain || "--"],
    ["DKIM d=", dkimDomain || "--"],
    ["SPF smtp.mailfrom", spfMailFrom || "--"],
    ["SPF smtp.helo", authSmtpHelo || "--"],
    ["Auth header.from", authHeaderFrom || "--"],
    ["Auth header.d", authDkimHeader || "--"],
    ["Auth header.i", authHeaderI || "--"],
    ["Return-Path aligned", fromDomain && returnDomain ? (alignedEmailDomains(fromDomain, returnDomain) ? "yes" : "no") : "--"],
    ["Reply-To aligned", fromDomain && replyDomain ? (alignedEmailDomains(fromDomain, replyDomain) ? "yes" : "no") : "--"],
    ["Message-ID aligned", fromDomain && messageIdDomain ? (alignedEmailDomains(fromDomain, messageIdDomain) ? "yes" : "no") : "--"],
    ["DKIM aligned", fromDomain && dkimDomain ? (alignedEmailDomains(fromDomain, dkimDomain) ? "yes" : "no") : "--"],
    ["SPF mailfrom aligned", fromDomain && spfMailFrom ? (alignedEmailDomains(fromDomain, spfMailFrom) ? "yes" : "no") : "--"],
    ["Display-name email domain", displaySpoofDomain || "--"]
  ];
  const identityRows = buildEmailIdentityRows({
    from,
    to,
    replyTo,
    returnPath,
    messageId,
    fromDomain,
    returnDomain,
    replyDomain,
    messageIdDomain,
    dkimDomain,
    spfMailFrom,
    authHeaderFrom,
    authDkimHeader,
    displaySpoofDomain
  });
  const routeRows = buildEmailRouteRows(receivedHops);
  const attachmentRows = await Promise.all(parsed.attachments.map(async (attachment, index) => {
    const content = attachmentBytes(attachment.content);
    const filename = attachment.filename || `attachment-${index + 1}`;
    const contentType = attachment.mimeType || "application/octet-stream";
    const attachmentAnalysis = analyzeEmailAttachment(filename, contentType, content, fromDomain);
    return {
      filename,
      contentType,
      size: content.byteLength,
      sha256: CryptoJS.SHA256(bytesToWordArray(content)).toString(),
      ...attachmentAnalysis,
      content
    };
  }));
  const decodedSamples = decodeEmailSamples(headers, bodyText, bodyHtml, raw);
  const infrastructureRows = buildEmailInfrastructureRows({
    fromDomain,
    domainAlignment,
    receivedHops,
    urlRows,
    linkRows,
    attachments: attachmentRows,
    iocs
  });
  const contentSignals = [
    ...analyzeEmailContentSignals("Text body", bodyText, fromDomain),
    ...analyzeEmailContentSignals("HTML body", bodyHtml, fromDomain),
    ...decodedSamples.flatMap(([label, value]) => value && value !== "--" ? analyzeEmailContentSignals(`Decoded ${label}`, value, fromDomain) : []),
    ...attachmentRows.flatMap((item) => analyzeEmailContentSignals(`Attachment ${item.filename}`, item.preview, fromDomain))
  ].slice(0, 80);
  const attachmentUrlCount = attachmentRows.reduce((sum, item) => sum + item.urlRows.length, 0);
  const attachmentIocCount = attachmentRows.reduce((sum, item) => sum + item.iocs.length, 0);
  const authHardFail = dmarc === "fail" || (spf === "fail" && dkim === "fail");
  const authSoftFail = spf === "fail" || dkim === "fail" || dmarc === "fail";
  const displayHrefMismatch = linkRows.some((row) => row.risk.some((risk) => /display host differs|script\/data|at-sign/i.test(risk)));
  const dangerousAttachment = attachmentRows.some((item) => item.risk.some((risk) => /executable|macro|double extension|active content|disk image/i.test(risk)));
  const dangerousContentSignal = contentSignals.some((signal) => signal.level === "danger");
  const identitySevere = Boolean(displaySpoofDomain && fromDomain && !alignedEmailDomains(displaySpoofDomain, fromDomain));
  const findings = [
    !fromDomain ? { level: "warn", title: "Missing or invalid From address", detail: "The From header could not be parsed as an email address." } : null,
    headerCount("From") > 1 ? { level: "warn", title: "Duplicate From headers", detail: `${headerCount("From")} From headers found.` } : null,
    headerCount("Subject") > 1 ? { level: "warn", title: "Duplicate Subject headers", detail: `${headerCount("Subject")} Subject headers found.` } : null,
    headerCount("Date") > 1 ? { level: "warn", title: "Duplicate Date headers", detail: `${headerCount("Date")} Date headers found.` } : null,
    authSoftFail ? { level: "warn", title: "Authentication result needs review", detail: `SPF=${spf}, DKIM=${dkim}, DMARC=${dmarc}` } : null,
    spf === "--" && dkim === "--" && dmarc === "--" ? { level: "info", title: "Authentication results not found", detail: "No SPF/DKIM/DMARC result found in Authentication-Results." } : null,
    replyDomain && fromDomain && !alignedEmailDomains(replyDomain, fromDomain) ? { level: "warn", title: "Reply-To domain differs", detail: `${fromDomain} -> ${replyDomain}` } : null,
    returnDomain && fromDomain && !alignedEmailDomains(returnDomain, fromDomain) ? { level: "warn", title: "Return-Path domain differs", detail: `${fromDomain} vs ${returnDomain}` } : null,
    messageIdDomain && fromDomain && !alignedEmailDomains(messageIdDomain, fromDomain) ? { level: "warn", title: "Message-ID domain differs", detail: `${fromDomain} vs ${messageIdDomain}` } : null,
    dkimDomain && fromDomain && !alignedEmailDomains(dkimDomain, fromDomain) ? { level: "warn", title: "DKIM signing domain differs", detail: `${fromDomain} vs d=${dkimDomain}` } : null,
    spfMailFrom && fromDomain && !alignedEmailDomains(spfMailFrom, fromDomain) ? { level: "warn", title: "SPF mailfrom domain differs", detail: `${fromDomain} vs ${spfMailFrom}` } : null,
    dmarc === "pass" && !dkimAligned && !spfAligned ? { level: "warn", title: "DMARC pass lacks visible alignment evidence", detail: "DMARC passed in Authentication-Results, but local DKIM/SPF alignment fields did not show an aligned domain." } : null,
    dmarc === "--" && (spf === "pass" || dkim === "pass") ? { level: "info", title: "DMARC policy result not found", detail: "SPF/DKIM exist, but DMARC result was not found." } : null,
    identitySevere ? { level: "warn", title: "Display-name email needs review", detail: `Display name contains ${displaySpoofDomain}, but From address uses ${fromDomain}.` } : null,
    !dkimSignature || dkimSignature === "--" ? { level: "info", title: "DKIM-Signature header not found", detail: "The message does not expose a DKIM-Signature header." } : null,
    urls.length > 8 ? { level: "info", title: "Many URLs in body", detail: String(urls.length) } : null,
    urls.some((url) => /xn--|@|%2f%2f|%252f|(?:\d{1,3}\.){3}\d{1,3}/i.test(url)) ? { level: "warn", title: "Suspicious URL marker", detail: "Punycode, @ marker, double encoding, or IP host found." } : null,
    urlRows.some((row) => row.risk.includes("host differs from From")) ? { level: "info", title: "External URL host differs from From", detail: urlRows.filter((row) => row.risk.includes("host differs from From")).slice(0, 6).map((row) => row.host).join(", ") } : null,
    displayHrefMismatch ? { level: "warn", title: "HTML link display/href mismatch", detail: linkRows.filter((row) => row.risk.length).slice(0, 6).map((row) => `${row.text} -> ${row.href} (${row.risk.join(", ")})`).join(" / ") } : null,
    linkRows.some((row) => row.risk.includes("href host differs from From")) ? { level: "info", title: "External HTML link host differs from From", detail: linkRows.filter((row) => row.risk.includes("href host differs from From")).slice(0, 8).map((row) => row.host).join(", ") } : null,
    dangerousAttachment ? { level: "warn", title: "Attachment needs review", detail: attachmentRows.filter((item) => item.risk.length).map((item) => `${item.filename}: ${item.risk.join(", ")}`).join(" / ") } : null,
    attachmentRows.some((item) => item.mismatch) ? { level: "warn", title: "Attachment extension/header mismatch", detail: attachmentRows.filter((item) => item.mismatch).map((item) => `${item.filename}: ${item.signature}`).join(" / ") } : null,
    attachmentRows.some((item) => item.urlRows.some((row) => row.risk.length)) ? { level: "warn", title: "Attachment link worth review", detail: attachmentRows.filter((item) => item.urlRows.some((row) => row.risk.length)).slice(0, 6).map((item) => `${item.filename}: ${item.urlRows.filter((row) => row.risk.length).map((row) => row.host).join(", ")}`).join(" / ") } : null,
    attachmentRows.some((item) => item.iocs.some((record) => record.risk.length)) ? { level: "warn", title: "Attachment IOC worth review", detail: attachmentRows.filter((item) => item.iocs.some((record) => record.risk.length)).slice(0, 6).map((item) => `${item.filename}: ${item.iocs.filter((record) => record.risk.length).slice(0, 4).map((record) => `${record.type} ${record.value}`).join(", ")}`).join(" / ") } : null,
    dangerousContentSignal ? { level: "warn", title: "Body/attachment content needs review", detail: contentSignals.filter((signal) => signal.level === "danger").slice(0, 8).map((signal) => `${signal.source}: ${signal.type}`).join(" / ") } : null,
    contentSignals.some((signal) => signal.level === "warn") ? { level: "warn", title: "Body/attachment content review signal", detail: contentSignals.filter((signal) => signal.level === "warn").slice(0, 8).map((signal) => `${signal.source}: ${signal.type}`).join(" / ") } : null,
    /<form\b|<input\b|action\s*=/i.test(bodyHtml) ? { level: "warn", title: "HTML credential form", detail: "HTML body contains form/input/action markers." } : null,
    /display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|visibility\s*:\s*hidden/i.test(bodyHtml) ? { level: "warn", title: "Hidden HTML content", detail: "HTML body contains hidden-content CSS markers." } : null,
    /(password|verify|urgent|invoice|payment|login|credential|登录|验证|密码|付款|发票|紧急)/i.test(body) ? { level: "warn", title: "Social-engineering wording marker", detail: "credential/payment/urgent wording" } : null,
    Number.isFinite(Date.parse(String(date))) && Date.parse(String(date)) > Date.now() + 24 * 60 * 60 * 1000 ? { level: "warn", title: "Future Date header", detail: String(date) } : null,
    /^--$/.test(arcAuth) ? null : arcAuth && dmarc === "fail" ? { level: "warn", title: "ARC present with DMARC failure", detail: "ARC may indicate forwarding context, but it does not prove authenticity by itself." } : null,
    received.length === 0 ? { level: "warn", title: "Missing Received chain", detail: "No relay trace found." } : null,
    receivedHops.some((hop) => hop.risk.length) ? { level: "warn", title: "Received chain anomaly", detail: receivedHops.filter((hop) => hop.risk.length).map((hop) => `#${hop.index}: ${hop.risk.join(", ")}`).join(" / ") } : null
  ].filter(Boolean) as Array<{ level: string; title: string; detail: string }>;
  const identityRiskRows = identityRows.filter((row) => row.risk.length);
  if (identityRiskRows.length) {
    findings.push({
      level: "warn",
      title: "Identity fields need review",
      detail: identityRiskRows.slice(0, 8).map((row) => `${row.role}: ${row.risk.join(", ")}`).join(" / ")
    });
  }
  const infrastructureRiskRows = infrastructureRows.filter((row) => row.risk.length);
  if (infrastructureRiskRows.length) {
    findings.push({
      level: infrastructureRiskRows.some((row) => row.risk.some((risk) => /punycode|private|URL host differs/i.test(risk))) ? "warn" : "info",
      title: "Infrastructure indicators need review",
      detail: infrastructureRiskRows.slice(0, 10).map((row) => `${row.kind}:${row.value} (${row.risk.join(", ")})`).join(" / ")
    });
  }
  const warnCount = findings.filter((finding) => finding.level === "warn").length;
  const verdictLabel = "parsed";
  const verdict = {
    label: verdictLabel,
    detail: `SPF=${spf}, DKIM=${dkim}, DMARC=${dmarc}; localNotes=${warnCount}`
  };
  const scoreFactors = buildEmailScoreFactors({
    authAssessments,
    findings,
    identityRows,
    receivedHops,
    urlRows,
    linkRows,
    attachments: attachmentRows,
    contentSignals,
    domainAlignment
  });
  const evidencePoints = buildEmailEvidencePoints({
    authAssessments,
    findings,
    identityRows,
    receivedHops,
    urlRows,
    linkRows,
    attachments: attachmentRows,
    contentSignals,
    domainAlignment
  });
  const evidenceMatrix = buildEmailEvidenceMatrix({
    verdict,
    rawSha256,
    rawSize: rawBytes.byteLength,
    authAssessments,
    identityRows,
    receivedHops,
    routeRows,
    linkRows,
    urlRows,
    attachments: attachmentRows,
    contentSignals,
    infrastructureRows,
    findings
  });
  const authLedger = buildEmailAuthLedger({
    rawSha256,
    from,
    fromDomain,
    returnPath,
    replyTo,
    messageId,
    authAssessments,
    domainAlignment,
    receivedHops,
    urlRows,
    linkRows,
    attachments: attachmentRows,
    findings
  });
  return {
    rawSha256,
    rawSize: rawBytes.byteLength,
    rows: [
      ["Raw size", formatBytes(rawBytes.byteLength)],
      ["Raw SHA256", rawSha256],
      ["From", from || get("From")],
      ["To", to],
      ["Subject", subject],
      ["Date", date],
      ["Message-ID", messageId],
      ["Reply-To", replyTo],
      ["Return-Path", returnPath],
      ["From domain", fromDomain || "--"],
      ["SPF / DKIM / DMARC", `${spf} / ${dkim} / ${dmarc}`],
      ["Received hops", String(received.length)],
      ["Attachments", String(attachmentRows.length)],
      ["Attachment URLs / IOCs", `${attachmentUrlCount} / ${attachmentIocCount}`],
      ["Identity risks", String(identityRiskRows.length)],
      ["Infrastructure indicators", String(infrastructureRows.length)],
      ["URLs in body", String(urls.length)],
      ["Content signals", String(contentSignals.length)],
      ["Timeline candidates", String(bodyTimeline.length)]
    ],
    headers,
    received,
    receivedHops,
    attachments: attachmentRows,
    contentSignals,
    findings,
    evidencePoints,
    scoreFactors,
    evidenceMatrix,
    authLedger,
    identityRows,
    infrastructureRows,
    routeRows,
    verdict,
    auth: [
      ["SPF", spf],
      ["DKIM", dkim],
      ["DMARC", dmarc],
      ["DKIM d=", dkimDomain || "--"],
      ["SPF smtp.mailfrom", spfMailFrom || "--"],
      ["SPF smtp.helo", authSmtpHelo || "--"],
      ["Auth header.from", authHeaderFrom || "--"],
      ["Auth header.d", authDkimHeader || "--"],
      ["Auth header.i", authHeaderI || "--"],
      ["Authentication-Results", auth],
      ["ARC-Authentication-Results", arcAuth],
      ["DKIM-Signature", dkimSignature]
    ],
    authAssessments,
    dkimDetails,
    urls,
    linkRows,
    urlRows,
    iocs,
    bodyTimeline,
    domainAlignment,
    decoded: decodedSamples,
    bodyText,
    bodyHtml
  };
}

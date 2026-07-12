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

import { alignedEmailDomains, emailIocRecords } from "../email/workbench";
import { isPrivateHost } from "../../utils/forensics";
import { safeDecodeURIComponent } from "../../utils/url";

function refangUrlText(value: string) {
  return value
    .trim()
    .replace(/^hxxps?:/i, (match) => match.toLowerCase().replace("hxxp", "http"))
    .replace(/\[\.\]|\(\.\)|\{\.}/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/")
    .replace(/\s+/g, "");
}

function defangUrlText(value: string) {
  return value
    .replace(/^http/i, (match) => match.toLowerCase().replace("http", "hxxp"))
    .replace(/\./g, "[.]");
}

function parseUrlInput(raw: string) {
  const trimmed = refangUrlText(raw);
  if (!trimmed) throw new Error("Empty URL");
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL(candidate);
}

function extractRawUrlHost(raw: string) {
  const refanged = refangUrlText(raw);
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(refanged) ? refanged : `https://${refanged}`;
  return withScheme.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/\s]+@)?(\[[^\]]+\]|[^:/?#]+)/i)?.[1]?.replace(/^\[|\]$/g, "") ?? "";
}

function parseIPv4Segment(segment: string) {
  if (/^0x[0-9a-f]+$/i.test(segment)) return Number.parseInt(segment.slice(2), 16);
  if (/^0[0-7]+$/.test(segment) && segment !== "0") return Number.parseInt(segment, 8);
  if (/^\d+$/.test(segment)) return Number.parseInt(segment, 10);
  return Number.NaN;
}

function ipv4FromNumber(value: number) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) return "";
  return [24, 16, 8, 0].map((shift) => String((value >>> shift) & 0xff)).join(".");
}

function normalizeIPv4Host(host: string) {
  const raw = host.toLowerCase();
  if (/^0x[0-9a-f]+$/i.test(raw)) return ipv4FromNumber(Number.parseInt(raw.slice(2), 16));
  if (/^\d+$/.test(raw) && Number(raw) > 255) return ipv4FromNumber(Number(raw));
  const parts = raw.split(".");
  if (parts.length === 4) {
    const numbers = parts.map(parseIPv4Segment);
    if (numbers.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) return numbers.join(".");
  }
  return "";
}

function ipVariantRows(rawHost: string, normalizedHost: string) {
  const normalizedIp = normalizeIPv4Host(rawHost) || normalizeIPv4Host(normalizedHost);
  if (!normalizedIp) return [];
  const parts = normalizedIp.split(".").map(Number);
  const number = parts.reduce((acc, part) => (acc << 8) + part, 0) >>> 0;
  return [
    ["Normalized IPv4", normalizedIp],
    ["Decimal integer", String(number)],
    ["Hex integer", `0x${number.toString(16).toUpperCase()}`],
    ["Dotted hex", parts.map((part) => `0x${part.toString(16)}`).join(".")],
    ["Dotted octal", parts.map((part) => `0${part.toString(8)}`).join(".")]
  ] as Array<[string, string]>;
}

function urlHostProfile(hostname: string) {
  const lower = hostname.toLowerCase();
  const labels = lower.split(".").filter(Boolean);
  return [
    ["Registered-ish domain", labels.length >= 2 ? labels.slice(-2).join(".") : lower || "--"],
    ["Subdomain depth", labels.length > 2 ? String(labels.length - 2) : "0"],
    ["Punycode", /xn--/i.test(lower) ? "yes" : "no"],
    ["Private/internal", isPrivateHost(lower) ? "yes" : "no"],
    ["Dynamic DNS", /(?:duckdns\.org|no-ip\.|dynu\.|ddns\.|hopto\.org|servehttp\.com)$/i.test(lower) ? "yes" : "no"],
    ["Shortener", /(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at)$/i.test(lower) ? "yes" : "no"]
  ] as Array<[string, string]>;
}

function urlPathRows(pathname: string) {
  const decodedPath = safeDecodeURIComponent(pathname);
  const parts = decodedPath.split("/").filter(Boolean);
  return [
    ["Decoded path", decodedPath || "/"],
    ["Path segments", parts.length ? parts.join(" / ") : "--"],
    ["Extension", decodedPath.match(/\.([a-z0-9]{1,8})(?:$|[?#])/i)?.[1]?.toLowerCase() ?? "--"],
    ["Traversal marker", /(?:\.\.\/|%2e%2e%2f|%252e%252e)/i.test(pathname) || decodedPath.includes("../") ? "yes" : "no"],
    ["Review keywords", parts.filter((part) => /(login|signin|verify|invoice|payment|download|update|payload|gate|panel|admin|wp-admin)/i.test(part)).join(", ") || "--"]
  ] as Array<[string, string]>;
}

function urlDecodeDepth(value: string) {
  const once = safeDecodeURIComponent(value);
  const twice = safeDecodeURIComponent(once);
  if (twice !== once) return { depth: "2+", once, twice };
  if (once !== value) return { depth: "1", once, twice };
  return { depth: "0", once, twice };
}

function looksLikeNavigationParam(key: string) {
  return /(redirect|return|next|url|uri|target|continue|callback|dest|destination|r|u|webhook|proxy|fetch|file|path)/i.test(key);
}

function analyzeNavigationTarget(item: { decodedKey: string; decodedValue: string; decodedTwice?: string }, baseUrl: URL) {
  const rawTarget = (item.decodedTwice && item.decodedTwice !== item.decodedValue ? item.decodedTwice : item.decodedValue).trim();
  const schemeRelative = rawTarget.startsWith("//") ? `${baseUrl.protocol}${rawTarget}` : rawTarget;
  const risk: string[] = [];
  let target: URL | null = null;
  let scheme = "--";
  let host = "--";
  try {
    if (/^[a-z][a-z0-9+.-]*:/i.test(schemeRelative) || schemeRelative.startsWith("//")) {
      target = new URL(schemeRelative, baseUrl.href);
      scheme = target.protocol.replace(":", "");
      host = target.hostname || "--";
    } else if (/^[^\s/@]+\.[a-z]{2,}(?:[/:?#]|$)/i.test(schemeRelative)) {
      target = parseUrlInput(schemeRelative);
      scheme = target.protocol.replace(":", "");
      host = target.hostname;
    } else {
      scheme = "relative";
      host = baseUrl.hostname;
    }
  } catch {
    scheme = rawTarget.match(/^([a-z][a-z0-9+.-]*):/i)?.[1] ?? "--";
  }
  const sameHost = host !== "--" && (host === baseUrl.hostname || alignedEmailDomains(host, baseUrl.hostname));
  if (schemeRelative.startsWith("//")) risk.push("scheme-relative target");
  if (scheme && !["--", "http", "https", "relative"].includes(scheme)) risk.push("non-web scheme");
  if (/^(javascript|data|file|ftp|smb|ldap|gopher|dict)$/i.test(scheme)) risk.push("dangerous/fetchable scheme");
  if (host !== "--" && !sameHost) risk.push("external target");
  if (host !== "--" && isPrivateHost(host)) risk.push("local/internal target");
  if (/169\.254\.169\.254|metadata\.google\.internal|metadata/i.test(rawTarget)) risk.push("cloud metadata target");
  if (/(?:\.\.\/|%2e%2e%2f|%252e%252e)/i.test(rawTarget)) risk.push("path traversal target");
  if (/%25[0-9a-f]{2}/i.test(rawTarget)) risk.push("double-encoded target");
  return {
    key: item.decodedKey,
    value: rawTarget,
    host,
    sameHost,
    scheme,
    risk: Array.from(new Set(risk))
  };
}

function analyzeUrl(raw: string) {
  const url = parseUrlInput(raw);
  const refanged = refangUrlText(raw);
  const rawHost = extractRawUrlHost(raw);
  const decodedHref = safeDecodeURIComponent(url.href);
  const doubleDecodedHref = safeDecodeURIComponent(decodedHref);
  const sorted = new URL(url.href);
  const sortedParams = Array.from(sorted.searchParams.entries()).sort(([left], [right]) => left.localeCompare(right));
  sorted.search = new URLSearchParams(sortedParams).toString();
  const params = Array.from(url.searchParams.entries()).map(([key, value]) => {
    const decodedKey = safeDecodeURIComponent(key);
    const decoded = urlDecodeDepth(value);
    const decodedValue = decoded.once;
    const decodedTwice = decoded.twice;
    const notes = [
      /(token|key|secret|session|auth|password|passwd|pwd|jwt|sid|csrf)/i.test(key) ? "sensitive key" : "",
      looksLikeNavigationParam(key) ? "navigation/fetch key" : "",
      /(https?:\/\/|%2f%2f)/i.test(value) ? "nested URL" : "",
      /(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1)/i.test(decodedValue) ? "local/metadata target" : "",
      /(?:\.\.\/|%2e%2e%2f|%252e%252e)/i.test(value) ? "path traversal marker" : "",
      /\.(exe|dll|scr|js|vbs|ps1|bat|cmd|hta|jar|apk|iso|img|docm|xlsm)(?:$|[?#])/i.test(decodedValue) ? "risky extension" : "",
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value) ? "JWT-like" : "",
      /^[A-Za-z0-9+/=_-]{24,}$/.test(value) && value.length % 4 !== 1 ? "encoded-looking value" : "",
      decoded.depth === "2+" ? "multi-layer percent encoding" : "",
      decodedValue !== decodedTwice ? "double decoded differs" : ""
    ].filter(Boolean);
    return {
      key,
      value,
      decodedKey,
      decodedValue,
      decodedTwice,
      length: decodedValue.length,
      decodeDepth: decoded.depth,
      notes
    };
  });
  const redirectParams = params
    .filter((item) => looksLikeNavigationParam(item.decodedKey) && (
      /(?:^[a-z][a-z0-9+.-]*:|^\/\/|https?:\/\/|%2f%2f|\.{2}\/|^[^\s/@]+\.[a-z]{2,})/i.test(item.decodedValue) ||
      item.decodedValue !== item.decodedTwice
    ))
    .map((item) => analyzeNavigationTarget(item, url));
  const ipRows = ipVariantRows(rawHost, url.hostname);
  const hostRows = urlHostProfile(url.hostname);
  const pathRows = urlPathRows(url.pathname);
  const iocs = emailIocRecords(`${raw}\n${decodedHref}\n${doubleDecodedHref}\n${params.map((item) => item.decodedValue).join("\n")}`, "URL analysis");
  const findings = [
    url.username || url.password ? ["danger", "Credentials in URL", `${url.username}:${url.password ? "******" : ""}`] : null,
    url.protocol !== "https:" ? ["warn", "Non-HTTPS scheme", url.protocol.replace(":", "")] : null,
    refanged !== raw.trim() ? ["info", "Defanged URL was refanged", refanged] : null,
    /%25[0-9a-f]{2}/i.test(raw) ? ["warn", "Double encoding marker", "%25xx"] : null,
    decodedHref !== doubleDecodedHref ? ["warn", "Nested percent encoding", "Decoded and double-decoded URL differ."] : null,
    /(?:\.\.\/|%2e%2e%2f|%252e%252e)/i.test(raw) ? ["danger", "Path traversal marker", "../ or encoded variant"] : null,
    params.some((item) => looksLikeNavigationParam(item.decodedKey)) ? ["warn", "Navigation/fetch parameter", "Check open redirect, SSRF, callback, webhook, proxy, or file-fetch context"] : null,
    redirectParams.some((item) => !item.sameHost) ? ["danger", "External redirect target", redirectParams.filter((item) => !item.sameHost).map((item) => `${item.key} -> ${item.host}`).join(", ")] : null,
    redirectParams.some((item) => item.risk.includes("dangerous/fetchable scheme")) ? ["danger", "Dangerous navigation scheme", redirectParams.filter((item) => item.risk.includes("dangerous/fetchable scheme")).map((item) => `${item.key}=${item.scheme}`).join(", ")] : null,
    redirectParams.some((item) => item.risk.includes("local/internal target") || item.risk.includes("cloud metadata target")) ? ["danger", "SSRF target in navigation parameter", redirectParams.filter((item) => item.risk.includes("local/internal target") || item.risk.includes("cloud metadata target")).map((item) => `${item.key} -> ${item.value}`).join(", ")] : null,
    params.some((item) => item.notes.includes("sensitive key")) ? ["warn", "Sensitive query key", "token / key / secret / session / password"] : null,
    /xn--/i.test(url.hostname) ? ["warn", "Punycode hostname", url.hostname] : null,
    isPrivateHost(url.hostname) ? ["danger", "Private/internal host", url.hostname] : null,
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(url.hostname) ? ["warn", "IP address host", url.hostname] : null,
    url.port && !["80", "443", "8080", "8443"].includes(url.port) ? ["warn", "Unusual URL port", url.port] : null,
    ipRows.length && rawHost && rawHost !== url.hostname ? ["warn", "Obfuscated IPv4 host", `${rawHost} -> ${ipRows[0]?.[1]}`] : null,
    /(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at)$/i.test(url.hostname) ? ["warn", "URL shortener host", url.hostname] : null,
    /(?:duckdns\.org|no-ip\.|dynu\.|ddns\.|hopto\.org|servehttp\.com)$/i.test(url.hostname) ? ["warn", "Dynamic DNS host", url.hostname] : null,
    /\.(exe|dll|scr|js|vbs|ps1|bat|cmd|hta|jar|apk|iso|img|docm|xlsm)(?:$|[?#])/i.test(url.pathname) ? ["warn", "Download extension worth review", url.pathname] : null,
    params.some((item) => item.notes.includes("local/metadata target")) ? ["warn", "SSRF/local target marker", params.filter((item) => item.notes.includes("local/metadata target")).map((item) => `${item.decodedKey}=${item.decodedValue}`).join(", ")] : null,
    params.some((item) => item.notes.includes("encoded-looking value")) ? ["info", "Encoded-looking parameter", params.filter((item) => item.notes.includes("encoded-looking value")).map((item) => item.decodedKey).join(", ")] : null
  ]
    .filter(Boolean)
    .map((item) => {
      const [level, title, detail] = item as string[];
      return { level, title, detail };
    });

  return {
    rows: [
      ["Scheme", url.protocol.replace(":", "")],
      ["Host", url.hostname],
      ["Raw host", rawHost || "--"],
      ["Port", url.port || "--"],
      ["Path", url.pathname || "/"],
      ["Hash", url.hash || "--"],
      ["Origin", url.origin],
      ["Username", url.username || "--"]
    ] as Array<[string, string]>,
    params,
    redirectParams,
    ipRows,
    hostRows,
    pathRows,
    iocs,
    findings,
    outputs: [
      ["Refanged", refanged],
      ["Normalized", url.href],
      ["Defanged", defangUrlText(url.href)],
      ["Decoded", decodedHref],
      ["Double decoded", doubleDecodedHref],
      ["Encoded", encodeURI(decodedHref)],
      ["Sorted params", sorted.href],
      ["Query only", url.search ? url.search.slice(1) : "--"],
      ["Path only", `${url.pathname}${url.hash}`]
    ] as Array<[string, string]>
  };
}

export { analyzeUrl, parseUrlInput };

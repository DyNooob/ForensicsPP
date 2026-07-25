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

export function ipFromBytes(bytes: Uint8Array, offset: number) {
  if (offset + 4 > bytes.length) return "";
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

export function ipv6FromBytes(bytes: Uint8Array, offset: number) {
  if (offset + 16 > bytes.length) return "";
  const parts = Array.from({ length: 8 }, (_, index) => ((bytes[offset + index * 2] << 8) | bytes[offset + index * 2 + 1]).toString(16));
  return parts.join(":").replace(/(?:^|:)0(?::0)+(?::|$)/, "::");
}

export function tcpFlags(byte: number) {
  return [
    byte & 0x01 ? "FIN" : "",
    byte & 0x02 ? "SYN" : "",
    byte & 0x04 ? "RST" : "",
    byte & 0x08 ? "PSH" : "",
    byte & 0x10 ? "ACK" : "",
    byte & 0x20 ? "URG" : "",
    byte & 0x40 ? "ECE" : "",
    byte & 0x80 ? "CWR" : ""
  ].filter(Boolean).join(",");
}

export function parseDnsNameFromPayload(payload: Uint8Array, offset: number, depth = 0): { name: string; next: number } {
  if (depth > 8) return { name: "", next: offset };
  const labels: string[] = [];
  let cursor = offset;
  let next = offset;
  while (cursor < payload.length) {
    const length = payload[cursor];
    if (length === 0) {
      next = cursor + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | payload[cursor + 1];
      const pointed = parseDnsNameFromPayload(payload, pointer, depth + 1);
      if (pointed.name) labels.push(pointed.name);
      next = cursor + 2;
      break;
    }
    const start = cursor + 1;
    const end = start + length;
    if (end > payload.length) break;
    labels.push(new TextDecoder().decode(payload.slice(start, end)));
    cursor = end;
  }
  return { name: labels.join("."), next };
}

export function networkEndpoint(host: string, port: number | null) {
  if (port == null) return host;
  return host.includes(":") && !host.startsWith("[") ? `[${host}]:${port}` : `${host}:${port}`;
}

export function dnsTypeName(value: number) {
  return ({ 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS" } as Record<number, string>)[value] ?? String(value);
}

export function parseHttpPayload(payloadText: string) {
  const firstLine = payloadText.split(/\r?\n/)[0] ?? "";
  const request = firstLine.match(/^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP\/\d(?:\.\d)?/i);
  const response = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i);
  const header = (name: string) => payloadText.match(new RegExp(`\\n${name}:\\s*([^\\r\\n]+)`, "i"))?.[1]?.trim() ?? "--";
  const headerEnd = payloadText.search(/\r?\n\r?\n/);
  const bodyText = headerEnd >= 0 ? payloadText.slice(headerEnd).replace(/^\r?\n\r?\n/, "") : "";
  const host = header("Host");
  const method = request?.[1]?.toUpperCase() ?? (response ? "RESPONSE" : "--");
  const path = request?.[2] ?? "--";
  const userAgent = header("User-Agent");
  const contentType = header("Content-Type");
  const risk = [
    host !== "--" ? "cleartext HTTP" : "",
    /Authorization:\s*Basic\s+/i.test(payloadText) ? "Basic auth in cleartext" : "",
    /Cookie:\s*[^;\r\n]*(session|token|auth|sid|jwt)/i.test(payloadText) ? "session cookie in cleartext" : "",
    /password|passwd|pwd|token|secret|api[_-]?key/i.test(path) ? "sensitive parameter path" : "",
    /(?:\.\.\/|%2e%2e%2f|%252e%252e)/i.test(path) ? "path traversal marker" : "",
    /%25[0-9a-f]{2}/i.test(path) ? "double-encoded URL" : "",
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) ? "IP host" : "",
    /xn--/i.test(host) ? "punycode host" : "",
    /application\/(?:octet-stream|x-msdownload|zip|pdf)|image\/|audio\/|video\//i.test(contentType) ? "download-like content" : "",
    response && Number(response[1]) >= 400 ? `HTTP ${response[1]}` : ""
  ].filter(Boolean);
  return { firstLine, host, method, path, userAgent, contentType, bodyText, risk };
}

export function httpFilenameFromHeaders(payloadText: string, path: string, packetNo: number) {
  const disposition = payloadText.match(/\nContent-Disposition:\s*[^\r\n]*filename\*?=(?:"([^"]+)"|([^;\r\n]+))/i);
  const fromDisposition = disposition?.[1] ?? disposition?.[2];
  if (fromDisposition) return decodeURIComponent(fromDisposition.trim().replace(/^UTF-8''/i, ""));
  const cleanPath = path.split("?")[0].split("/").filter(Boolean).pop();
  return cleanPath && /\.[a-z0-9]{1,8}$/i.test(cleanPath) ? cleanPath : `http-packet-${packetNo}.bin`;
}

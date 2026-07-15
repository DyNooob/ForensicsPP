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

import { analyzeCodecCandidates } from "../codec/analyzer";
import { parseUrlInput, safeDecodeURIComponent } from "../../utils/url";

function classifyQrPayload(payload: string) {
  const trimmed = payload.trim();
  if (!trimmed) return "Empty";
  if (/^otpauth:\/\/(?:totp|hotp)\//i.test(trimmed)) return "OTP Secret";
  if (/^(?:bitcoin|ethereum|litecoin|monero|dogecoin|solana):/i.test(trimmed)) return "Crypto Payment";
  if (/^(?:upi:\/\/pay|alipay|alipays|weixin|wxp|paypal):/i.test(trimmed)) return "Payment / App Link";
  if (/^MECARD:/i.test(trimmed)) return "MeCard";
  if (/BEGIN:VEVENT/i.test(trimmed)) return "Calendar Event";
  if (/^https?:\/\//i.test(trimmed) || /^www\./i.test(trimmed) || /^[^\s/@]+\.[a-z]{2,}(?:[/:?#]|$)/i.test(trimmed)) return "URL";
  if (/^WIFI:/i.test(trimmed)) return "WiFi Config";
  if (/BEGIN:VCARD/i.test(trimmed)) return "vCard";
  if (/^MATMSG:/i.test(trimmed) || /^mailto:/i.test(trimmed)) return "Email";
  if (/^geo:/i.test(trimmed)) return "Geo";
  if (/^tel:/i.test(trimmed)) return "Telephone";
  if (/^sms:/i.test(trimmed)) return "SMS";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return "App Deep Link";
  return "Text";
}

function splitQrEscapedFields(value: string) {
  const fields: string[] = [];
  let current = "";
  let escaped = false;
  for (const char of value) {
    if (escaped) {
      current += char;
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === ";") {
      fields.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (current || value.endsWith(";")) fields.push(current);
  return fields.filter((field) => field.length);
}

function unescapeQrField(value: string) {
  return value.replace(/\\([\\;,:"])/g, "$1").replace(/\\n/gi, "\n");
}

function compactQrRows(rows: Array<[string, string]>) {
  return rows.filter(([, value]) => value.trim() !== "" && value !== "--");
}

function parseQrPayloadDetails(payload: string, payloadType: string): Array<[string, string]> {
  const trimmed = payload.trim();
  if (!trimmed) return [["Status", "No decoded payload"]];
  const byteSize = new Blob([payload]).size;
  const baseRows: Array<[string, string]> = [
    ["Payload type", payloadType],
    ["Characters", String(payload.length)],
    ["Bytes", String(byteSize)],
    ["Lines", String(payload.split(/\r?\n/).length)]
  ];

  if (payloadType === "WiFi Config") {
    const body = trimmed.replace(/^WIFI:/i, "").replace(/;{1,2}$/g, "");
    const fields = splitQrEscapedFields(body).reduce<Record<string, string>>((acc, field) => {
      const separator = field.indexOf(":");
      if (separator <= 0) return acc;
      acc[field.slice(0, separator).toUpperCase()] = unescapeQrField(field.slice(separator + 1));
      return acc;
    }, {});
    return compactQrRows([
      ...baseRows,
      ["SSID", fields.S ?? "--"],
      ["Auth", fields.T || "nopass"],
      ["Password present", fields.P ? "yes" : "no"],
      ["Password", fields.P ? "******" : "--"],
      ["Hidden network", /^true$/i.test(fields.H ?? "") ? "yes" : "no"],
      ["EAP identity", fields.I ?? "--"],
      ["Anonymous identity", fields.A ?? "--"],
      ["Phase 2", fields.PH2 ?? "--"]
    ]);
  }

  if (payloadType === "OTP Secret") {
    try {
      const url = new URL(trimmed);
      const label = safeDecodeURIComponent(url.pathname.replace(/^\/+/, ""));
      return compactQrRows([
        ...baseRows,
        ["OTP type", url.hostname.toUpperCase()],
        ["Label", label || "--"],
        ["Issuer", url.searchParams.get("issuer") ?? "--"],
        ["Account", label.includes(":") ? label.split(":").slice(1).join(":") : label || "--"],
        ["Secret present", url.searchParams.get("secret") ? "yes" : "no"],
        ["Algorithm", url.searchParams.get("algorithm") ?? "SHA1"],
        ["Digits", url.searchParams.get("digits") ?? "6"],
        ["Period", url.searchParams.get("period") ?? "--"],
        ["Counter", url.searchParams.get("counter") ?? "--"]
      ]);
    } catch {
      return baseRows;
    }
  }

  if (payloadType === "Crypto Payment") {
    const match = trimmed.match(/^([a-z][a-z0-9+.-]*):([^?]*)(?:\?(.*))?$/i);
    const params = new URLSearchParams(match?.[3] ?? "");
    return compactQrRows([
      ...baseRows,
      ["Scheme", match?.[1] ?? "--"],
      ["Address", safeDecodeURIComponent(match?.[2] ?? "") || "--"],
      ["Amount", params.get("amount") ?? params.get("value") ?? "--"],
      ["Label", params.get("label") ?? "--"],
      ["Message", params.get("message") ?? "--"]
    ]);
  }

  if (payloadType === "Payment / App Link" || payloadType === "App Deep Link") {
    try {
      const url = new URL(trimmed);
      return compactQrRows([
        ...baseRows,
        ["Scheme", url.protocol.replace(":", "")],
        ["Host", url.hostname || "--"],
        ["Path", url.pathname || "--"],
        ["Query params", String(Array.from(url.searchParams.keys()).length)],
        ["Action keywords", /(pay|transfer|login|auth|verify|open|scan|callback|redirect|token)/i.test(trimmed) ? "yes" : "no"]
      ]);
    } catch {
      const scheme = trimmed.match(/^([a-z][a-z0-9+.-]*):/i)?.[1] ?? "--";
      return compactQrRows([...baseRows, ["Scheme", scheme], ["Raw length", String(trimmed.length)]]);
    }
  }

  if (payloadType === "MeCard") {
    const body = trimmed.replace(/^MECARD:/i, "").replace(/;{1,2}$/g, "");
    const fields = splitQrEscapedFields(body).reduce<Record<string, string[]>>((acc, field) => {
      const separator = field.indexOf(":");
      if (separator <= 0) return acc;
      const key = field.slice(0, separator).toUpperCase();
      acc[key] = [...(acc[key] ?? []), unescapeQrField(field.slice(separator + 1))];
      return acc;
    }, {});
    return compactQrRows([
      ...baseRows,
      ["Name", fields.N?.join(", ") ?? "--"],
      ["Phone", fields.TEL?.join(", ") ?? "--"],
      ["Email", fields.EMAIL?.join(", ") ?? "--"],
      ["URL", fields.URL?.join(", ") ?? "--"],
      ["Address", fields.ADR?.join(", ") ?? "--"],
      ["Note", fields.NOTE?.join("\n").slice(0, 240) ?? "--"]
    ]);
  }

  if (payloadType === "Calendar Event") {
    const unfolded = trimmed.replace(/\r?\n[ \t]/g, "");
    const rows = unfolded.split(/\r?\n/)
      .map((line) => {
        const separator = line.indexOf(":");
        if (separator <= 0) return null;
        const key = line.slice(0, separator).split(";")[0].toUpperCase();
        const value = unescapeQrField(line.slice(separator + 1));
        if (!["SUMMARY", "DTSTART", "DTEND", "LOCATION", "ORGANIZER", "ATTENDEE", "DESCRIPTION", "URL"].includes(key)) return null;
        return [key, value] as [string, string];
      })
      .filter(Boolean) as Array<[string, string]>;
    return compactQrRows([...baseRows, ...rows.slice(0, 18)]);
  }

  if (payloadType === "vCard") {
    const unfolded = trimmed.replace(/\r?\n[ \t]/g, "");
    const rows = unfolded.split(/\r?\n/)
      .map((line) => {
        const separator = line.indexOf(":");
        if (separator <= 0) return null;
        const key = line.slice(0, separator).split(";")[0].toUpperCase();
        const value = unescapeQrField(line.slice(separator + 1));
        if (!["FN", "N", "ORG", "TITLE", "TEL", "EMAIL", "URL", "ADR", "NOTE"].includes(key)) return null;
        return [key, value] as [string, string];
      })
      .filter(Boolean) as Array<[string, string]>;
    return compactQrRows([...baseRows, ...rows.slice(0, 16)]);
  }

  if (payloadType === "Email") {
    if (/^mailto:/i.test(trimmed)) {
      try {
        const mail = new URL(trimmed);
        return compactQrRows([
          ...baseRows,
          ["To", safeDecodeURIComponent(mail.pathname)],
          ["Subject", mail.searchParams.get("subject") ?? "--"],
          ["CC", mail.searchParams.get("cc") ?? "--"],
          ["BCC", mail.searchParams.get("bcc") ?? "--"],
          ["Body length", String(mail.searchParams.get("body")?.length ?? 0)]
        ]);
      } catch {
        return baseRows;
      }
    }
    const body = trimmed.replace(/^MATMSG:/i, "").replace(/;{1,2}$/g, "");
    const fields = splitQrEscapedFields(body).reduce<Record<string, string>>((acc, field) => {
      const separator = field.indexOf(":");
      if (separator <= 0) return acc;
      acc[field.slice(0, separator).toUpperCase()] = unescapeQrField(field.slice(separator + 1));
      return acc;
    }, {});
    return compactQrRows([
      ...baseRows,
      ["To", fields.TO ?? "--"],
      ["Subject", fields.SUB ?? "--"],
      ["Body length", String(fields.BODY?.length ?? 0)],
      ["Body preview", fields.BODY?.slice(0, 220) ?? "--"]
    ]);
  }

  if (payloadType === "Geo") {
    const match = trimmed.match(/^geo:([^,?]+),([^?]+)(?:\?(.*))?$/i);
    return compactQrRows([
      ...baseRows,
      ["Latitude", match?.[1] ?? "--"],
      ["Longitude", match?.[2] ?? "--"],
      ["Query", match?.[3] ? safeDecodeURIComponent(match[3]) : "--"]
    ]);
  }

  if (payloadType === "Telephone" || payloadType === "SMS") {
    const normalized = trimmed.replace(/^(tel|sms):/i, "");
    const [target, query = ""] = normalized.split("?");
    const params = new URLSearchParams(query);
    return compactQrRows([
      ...baseRows,
      ["Number", safeDecodeURIComponent(target)],
      ["Body length", payloadType === "SMS" ? String(params.get("body")?.length ?? 0) : "--"],
      ["Body preview", payloadType === "SMS" ? params.get("body")?.slice(0, 220) ?? "--" : "--"]
    ]);
  }

  if (payloadType === "URL") {
    try {
      const url = parseUrlInput(trimmed);
      return compactQrRows([
        ...baseRows,
        ["Scheme", url.protocol.replace(":", "")],
        ["Host", url.hostname],
        ["Path", url.pathname || "/"],
        ["Query params", String(Array.from(url.searchParams.keys()).length)]
      ]);
    } catch {
      return baseRows;
    }
  }

  const printable = trimmed.match(/[\t\n\r -~\u00a0-\uffff]/g)?.length ?? 0;
  const codec = analyzeCodecCandidates(trimmed);
  return [
    ...baseRows,
    ["Printable ratio", `${(printable / Math.max(trimmed.length, 1) * 100).toFixed(1)}%`],
    ["Base64-like", /^[A-Za-z0-9+/=_-]{32,}$/.test(trimmed.replace(/\s+/g, "")) ? "yes" : "no"],
    ["JSON-like", /^[\[{]/.test(trimmed) ? "yes" : "no"],
    ["Codec candidates", codec.candidates.slice(0, 3).map((candidate) => `${candidate.label} score=${candidate.score}`).join(" / ") || "--"]
  ];
}

function qrPointRow(label: string, point: unknown): [string, string] | null {
  if (!point || typeof point !== "object") return null;
  const candidate = point as { x?: number; y?: number };
  if (typeof candidate.x !== "number" || typeof candidate.y !== "number") return null;
  return [label, `${candidate.x.toFixed(1)}, ${candidate.y.toFixed(1)}`];
}

function qrPointValue(point: unknown): { x: number; y: number } | null {
  if (!point || typeof point !== "object") return null;
  const candidate = point as { x?: number; y?: number };
  return typeof candidate.x === "number" && typeof candidate.y === "number" ? { x: candidate.x, y: candidate.y } : null;
}

function qrDistance(a: { x: number; y: number }, b: { x: number; y: number }) {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

function qrGeometryRows(location: Record<string, unknown>, imageWidth: number, imageHeight: number): Array<[string, string]> {
  const topLeft = qrPointValue(location.topLeftCorner);
  const topRight = qrPointValue(location.topRightCorner);
  const bottomLeft = qrPointValue(location.bottomLeftCorner);
  const bottomRight = qrPointValue(location.bottomRightCorner);
  const points = [topLeft, topRight, bottomLeft, bottomRight].filter(Boolean) as Array<{ x: number; y: number }>;
  if (points.length < 3) return [["Geometry", "--"]];
  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const width = maxX - minX;
  const height = maxY - minY;
  const coverage = imageWidth && imageHeight ? (width * height) / (imageWidth * imageHeight) : 0;
  const angle = topLeft && topRight ? Math.atan2(topRight.y - topLeft.y, topRight.x - topLeft.x) * 180 / Math.PI : 0;
  const rows: Array<[string, string]> = [
    ["Bounding box", `${minX.toFixed(1)},${minY.toFixed(1)} - ${maxX.toFixed(1)},${maxY.toFixed(1)}`],
    ["Box size", `${width.toFixed(1)} x ${height.toFixed(1)}`],
    ["Coverage", `${(coverage * 100).toFixed(2)}%`],
    ["Center", `${((minX + maxX) / 2).toFixed(1)}, ${((minY + maxY) / 2).toFixed(1)}`],
    ["Rotation", `${angle.toFixed(2)} deg`]
  ];
  if (topLeft && topRight) rows.push(["Top edge", topLeft && topRight ? qrDistance(topLeft, topRight).toFixed(1) : "--"]);
  if (topLeft && bottomLeft) rows.push(["Left edge", qrDistance(topLeft, bottomLeft).toFixed(1)]);
  if (bottomLeft && bottomRight) rows.push(["Bottom edge", qrDistance(bottomLeft, bottomRight).toFixed(1)]);
  if (topRight && bottomRight) rows.push(["Right edge", qrDistance(topRight, bottomRight).toFixed(1)]);
  return rows;
}

export { classifyQrPayload, parseQrPayloadDetails, qrGeometryRows, qrPointRow };

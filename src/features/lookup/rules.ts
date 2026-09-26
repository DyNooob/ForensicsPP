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

export type LookupKind = "auto" | "ip" | "phone" | "id" | "bank";
export type ResolvedLookupKind = Exclude<LookupKind, "auto">;

export type LookupResult = {
  input: string;
  normalized: string;
  kind: ResolvedLookupKind;
  valid: boolean;
  matched: boolean;
  summary: string;
  fields: Record<string, string>;
  notes: string[];
  source: string;
  dataVersion: string;
};

const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2] as const;
const ID_CHECK_CODES = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"] as const;

export function normalizeLookupValue(value: string) {
  return value.trim().replace(/[\u200B-\u200D\uFEFF]/g, "");
}

export function splitLookupInput(input: string, limit = 5000) {
  const lines = input
    .split(/[\r\n,;，；\t]+/)
    .map(normalizeLookupValue)
    .filter(Boolean);
  return Array.from(new Set(lines)).slice(0, limit);
}

function isValidDate(year: number, month: number, day: number) {
  if (year < 1800 || year > new Date().getFullYear() || month < 1 || month > 12 || day < 1 || day > 31) return false;
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

export function calculateChineseIdCheckCode(first17: string) {
  if (!/^\d{17}$/.test(first17)) return "";
  const sum = Array.from(first17).reduce((total, digit, index) => total + Number(digit) * ID_WEIGHTS[index], 0);
  return ID_CHECK_CODES[sum % 11];
}

export type ChineseIdValidation = {
  valid: boolean;
  normalized: string;
  legacy: boolean;
  regionCode: string;
  birthDate: string;
  gender: "male" | "female" | "unknown";
  checkCode: string;
  expectedCheckCode: string;
  reason: string;
};

export function validateChineseId(value: string): ChineseIdValidation {
  const normalized = normalizeLookupValue(value).toUpperCase();
  const invalid = (reason: string): ChineseIdValidation => ({
    valid: false,
    normalized,
    legacy: normalized.length === 15,
    regionCode: normalized.slice(0, 6),
    birthDate: "",
    gender: "unknown",
    checkCode: normalized.slice(-1),
    expectedCheckCode: "",
    reason
  });

  if (/^\d{15}$/.test(normalized)) {
    const year = Number(`19${normalized.slice(6, 8)}`);
    const month = Number(normalized.slice(8, 10));
    const day = Number(normalized.slice(10, 12));
    if (!isValidDate(year, month, day)) return invalid("invalid-birth-date");
    if (normalized.slice(12) === "000") return invalid("invalid-sequence");
    const first17 = `${normalized.slice(0, 6)}19${normalized.slice(6)}`;
    return {
      valid: true,
      normalized: `${first17}${calculateChineseIdCheckCode(first17)}`,
      legacy: true,
      regionCode: normalized.slice(0, 6),
      birthDate: `${year.toString().padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`,
      gender: Number(normalized[14]) % 2 ? "male" : "female",
      checkCode: "--",
      expectedCheckCode: calculateChineseIdCheckCode(first17),
      reason: "legacy-15-digit"
    };
  }

  if (!/^\d{17}[\dX]$/.test(normalized)) return invalid("invalid-format");
  const year = Number(normalized.slice(6, 10));
  const month = Number(normalized.slice(10, 12));
  const day = Number(normalized.slice(12, 14));
  if (!isValidDate(year, month, day)) return invalid("invalid-birth-date");
  if (normalized.slice(14, 17) === "000") return invalid("invalid-sequence");
  const expected = calculateChineseIdCheckCode(normalized.slice(0, 17));
  if (normalized[17] !== expected) {
    const result = invalid("invalid-checksum");
    result.expectedCheckCode = expected;
    return result;
  }
  return {
    valid: true,
    normalized,
    legacy: false,
    regionCode: normalized.slice(0, 6),
    birthDate: `${year.toString().padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`,
    gender: Number(normalized[16]) % 2 ? "male" : "female",
    checkCode: normalized[17],
    expectedCheckCode: expected,
    reason: "valid"
  };
}

export function validatePhone(value: string) {
  const normalized = normalizeLookupValue(value).replace(/^\+?86/, "").replace(/[\s-]/g, "");
  return { normalized, valid: /^1[3-9]\d{9}$/.test(normalized) };
}

export function luhnCheck(value: string) {
  const normalized = normalizeLookupValue(value).replace(/[\s-]/g, "");
  if (!/^\d{12,19}$/.test(normalized)) return { normalized, valid: false };
  let sum = 0;
  let doubleDigit = false;
  for (let index = normalized.length - 1; index >= 0; index -= 1) {
    let digit = Number(normalized[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return { normalized, valid: sum % 10 === 0 };
}

export function cardNetwork(value: string) {
  const digits = value.replace(/\D/g, "");
  if (/^62/.test(digits)) return "UnionPay";
  if (/^4/.test(digits)) return "Visa";
  const first4 = Number(digits.slice(0, 4));
  if (/^5[1-5]/.test(digits) || (first4 >= 2221 && first4 <= 2720)) return "Mastercard";
  if (/^3[47]/.test(digits)) return "American Express";
  if (first4 >= 3528 && first4 <= 3589) return "JCB";
  if (/^(6011|65|64[4-9])/.test(digits)) return "Discover";
  if (/^35/.test(digits)) return "JCB";
  return "Unknown";
}

export function parseIpv4(value: string) {
  const parts = normalizeLookupValue(value).split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255 || String(Number(part)) !== part)) return null;
  return new Uint8Array(parts.map(Number));
}

export function ipv4Number(bytes: Uint8Array) {
  return (((bytes[0] << 24) >>> 0) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]) >>> 0;
}

const SPECIAL_IPV4_RANGES: Array<[number, number, string]> = [
  [0x00000000, 0xff000000, "Current network / software"],
  [0x0a000000, 0xff000000, "Private network (RFC 1918)"],
  [0x64400000, 0xffc00000, "Shared address space (RFC 6598)"],
  [0x7f000000, 0xff000000, "Loopback"],
  [0xa9fe0000, 0xffff0000, "Link-local"],
  [0xac100000, 0xfff00000, "Private network (RFC 1918)"],
  [0xc0000000, 0xffffff00, "IETF protocol assignments"],
  [0xc0000200, 0xffffff00, "Documentation (TEST-NET-1)"],
  [0xc0a80000, 0xffff0000, "Private network (RFC 1918)"],
  [0xc6120000, 0xfffe0000, "Benchmark testing"],
  [0xc6336400, 0xffffff00, "Documentation (TEST-NET-2)"],
  [0xcb007100, 0xffffff00, "Documentation (TEST-NET-3)"],
  [0xe0000000, 0xf0000000, "Multicast"],
  [0xf0000000, 0xf0000000, "Reserved / broadcast"]
];

export function classifySpecialIpv4(bytes: Uint8Array) {
  const value = ipv4Number(bytes);
  return SPECIAL_IPV4_RANGES.find(([network, mask]) => ((value & mask) >>> 0) === (network >>> 0))?.[2] ?? "";
}

export function detectLookupKind(value: string): ResolvedLookupKind {
  const normalized = normalizeLookupValue(value);
  if (parseIpv4(normalized) || normalized.includes(":")) return "ip";
  if (/^\d{17}[\dXx]$/.test(normalized) || (/^\d{15}$/.test(normalized) && /^(18|19|20)\d{2}$/.test(`19${normalized.slice(6, 8)}`))) return "id";
  const phone = validatePhone(normalized);
  if (phone.valid) return "phone";
  if (/^[\d\s-]{12,24}$/.test(normalized)) return "bank";
  return "ip";
}

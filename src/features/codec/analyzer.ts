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

import { decodeWords } from "postal-mime";
import type { IocRecord } from "../../models";
import { base64UrlDecode } from "../../utils/base64";
import { hexPreview } from "../../utils/binary";
import { detectHashType } from "../../utils/hash";
import { safeDecodeURIComponent } from "../../utils/url";
import { chineseTelegraphMap, coreValues } from "./constants";
import { caesar, morseDecode } from "../crypto/algorithms";
import { base32Decode, base32Encode, base58Decode, base58Encode, decodeQuotedPrintableText, emailIocRecords, quotedPrintableEncode } from "../email/workbench";
import { extractIocs } from "../ioc/analyzer";

function transformText(operation: string, input: string) {
  if (operation === "autocodec") return autoDetectCodec(input);
  if (operation === "utf8hex") return encodedBytesReport(input, "utf-8");
  if (operation === "utf16lehex") return encodedBytesReport(input, "utf-16le");
  if (operation === "windows1252hex") return encodedBytesReport(input, "windows-1252");
  if (operation === "gb18030d") return decodeBytesWithEncoding(codecInputToBytes(input), "gb18030");
  if (operation === "gbkd") return decodeBytesWithEncoding(codecInputToBytes(input), "gbk");
  if (operation === "big5d") return decodeBytesWithEncoding(codecInputToBytes(input), "big5");
  if (operation === "shiftjisd") return decodeBytesWithEncoding(codecInputToBytes(input), "shift_jis");
  if (operation === "euckrd") return decodeBytesWithEncoding(codecInputToBytes(input), "euc-kr");
  if (operation === "utf16led") return decodeBytesWithEncoding(codecInputToBytes(input), "utf-16le");
  if (operation === "utf16bed") return decodeBytesWithEncoding(codecInputToBytes(input), "utf-16be");
  if (operation === "iso88591d") return decodeBytesWithEncoding(codecInputToBytes(input), "iso-8859-1");
  if (operation === "windows1252d") return decodeBytesWithEncoding(codecInputToBytes(input), "windows-1252");
  if (operation === "b64e") return base64EncodeText(input);
  if (operation === "b64d") return base64DecodeLoose(input);
  if (operation === "b64ue") return base64EncodeText(input).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  if (operation === "b64ud") return base64UrlDecode(input);
  if (operation === "base100e") {
    return Array.from(new TextEncoder().encode(input))
      .map((byte) => String.fromCodePoint(0x1f300 + byte))
      .join("");
  }
  if (operation === "base100d") {
    const bytes = Array.from(input)
      .map((char) => char.codePointAt(0) ?? 0)
      .filter((point) => point >= 0x1f300 && point <= 0x1f3ff)
      .map((point) => point - 0x1f300);
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
  if (operation === "base32e") return base32Encode(input);
  if (operation === "base32d") return base32Decode(input);
  if (operation === "base58e") return base58Encode(input);
  if (operation === "base58d") return base58Decode(input);
  if (operation === "qpe") return quotedPrintableEncode(input);
  if (operation === "qpd") return decodeQuotedPrintableText(input);
  if (operation === "urle") return encodeURIComponent(input);
  if (operation === "urld") return safeDecodeURIComponent(input);
  if (operation === "hex") {
    return Array.from(new TextEncoder().encode(input))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(" ");
  }
  if (operation === "unhex") {
    const bytes = input
      .replace(/0x/gi, "")
      .replace(/[^a-fA-F0-9]/g, "")
      .match(/.{1,2}/g)
      ?.map((chunk) => parseInt(chunk, 16));
    return bytes ? new TextDecoder().decode(new Uint8Array(bytes)) : "";
  }
  if (operation === "unicode") {
    return Array.from(input)
      .map((char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`)
      .join("");
  }
  if (operation === "ununicode") {
    return input.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
  if (operation === "bin") {
    return Array.from(new TextEncoder().encode(input))
      .map((byte) => byte.toString(2).padStart(8, "0"))
      .join(" ");
  }
  if (operation === "unbin") {
    const bytes = input
      .trim()
      .split(/[^01]+/)
      .filter(Boolean)
      .map((chunk) => parseInt(chunk, 2));
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
  if (operation === "shell") {
    return Array.from(new TextEncoder().encode(input))
      .map((byte) => `\\x${byte.toString(16).padStart(2, "0")}`)
      .join("");
  }
  if (operation === "unshell") {
    const bytes = (input.match(/(?:\\x|0x)?[a-fA-F0-9]{2}/g) ?? []).map((chunk) =>
      parseInt(chunk.replace(/\\x|0x/gi, ""), 16)
    );
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
  if (operation === "zwe") {
    const bytes = Array.from(new TextEncoder().encode(input));
    return bytes
      .map((byte) =>
        byte
          .toString(2)
          .padStart(8, "0")
          .replace(/0/g, "\u200b")
          .replace(/1/g, "\u200c")
      )
      .join("\u200d");
  }
  if (operation === "zwd") {
    const binary = input
      .split("\u200d")
      .map((chunk) => chunk.replace(/\u200b/g, "0").replace(/\u200c/g, "1"))
      .filter((chunk) => /^[01]{8}$/.test(chunk));
    return new TextDecoder().decode(new Uint8Array(binary.map((chunk) => parseInt(chunk, 2))));
  }
  if (operation === "coree") return coreValuesEncode(input);
  if (operation === "cored") return coreValuesDecode(input);
  if (operation === "bfrun") return runBrainfuck(input);
  if (operation === "bf2ook") return brainfuckToOok(input);
  if (operation === "ook2bf") return ookToBrainfuck(input);
  if (operation === "telegraph") return chineseTelegraphLookup(input);
  if (operation === "pawn") return pawnshopDecode(input);
  if (operation === "qwee") return qweTransform(input, false);
  if (operation === "qwed") return qweTransform(input, true);
  if (operation === "escapee") return escapeEncode(input);
  if (operation === "escaped") return escapeDecode(input);
  if (operation === "detectjs") return detectObfuscation(input);
  if (operation === "html") {
    return input
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  if (operation === "unhtml") {
    const textarea = document.createElement("textarea");
    textarea.innerHTML = input;
    return textarea.value;
  }
  if (operation === "rot13") {
    return input.replace(/[a-zA-Z]/g, (char) => {
      const base = char <= "Z" ? 65 : 97;
      return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
    });
  }
  if (operation === "reverse") return Array.from(input).reverse().join("");
  if (operation === "upper") return input.toUpperCase();
  if (operation === "lower") return input.toLowerCase();
  return input;
}

type AutoCodecCandidate = {
  label: string;
  value: string;
  score: number;
  note?: string;
};

type CodecChainCandidate = {
  steps: string[];
  value: string;
  score: number;
  iocCount: number;
};

type CodecArtifactCandidate = {
  label: string;
  source: string;
  index: number;
  value: string;
  decoded: string;
  score: number;
  iocCount: number;
  risk: string[];
};

type CodecAnalysis = {
  candidates: AutoCodecCandidate[];
  chains: CodecChainCandidate[];
  artifacts: CodecArtifactCandidate[];
  iocs: IocRecord[];
  attempted: string[];
  findings: Array<{ level: string; title: string; detail: string }>;
};

function normalizeCandidateValue(value: string) {
  return value.replace(/\0/g, "").trim();
}

function printableRatio(value: string) {
  if (!value) return 0;
  const chars = Array.from(value);
  const printable = chars.filter((char) => {
    const code = char.charCodeAt(0);
    return char === "\n" || char === "\r" || char === "\t" || code >= 32 || /[\u4e00-\u9fff]/.test(char);
  }).length;
  return printable / chars.length;
}

function candidateScore(value: string) {
  const normalized = normalizeCandidateValue(value);
  if (!normalized) return 0;
  let score = 0;
  const ratio = printableRatio(normalized);
  if (ratio > 0.95) score += 3;
  if (ratio > 0.8) score += 2;
  if (/[A-Za-z0-9_\-{}@./:=]/.test(normalized)) score += 1;
  if (/flag|ctf|key|token|password|secret|admin|root|user|http|select|insert/i.test(normalized)) score += 2;
  if (/^[\x20-\x7e\r\n\t]+$/.test(normalized)) score += 1;
  if (/[\u4e00-\u9fff]/.test(normalized)) score += 1;
  if (normalized.length >= 4) score += 1;
  if (normalized.length > 3000) score -= 1;
  if (/�/.test(normalized)) score -= 3;
  return score;
}

function letterRatio(value: string) {
  const visible = Array.from(value).filter((char) => /\S/.test(char));
  if (!visible.length) return 0;
  return visible.filter((char) => /[A-Za-z]/.test(char)).length / visible.length;
}

function addAutoCandidate(candidates: AutoCodecCandidate[], label: string, value: string, note?: string) {
  const normalized = normalizeCandidateValue(value);
  if (!normalized) return;
  const score = candidateScore(normalized);
  const same = candidates.some((candidate) => candidate.value === normalized && candidate.label === label);
  if (!same) candidates.push({ label, value: normalized, score, note });
}

function tryAutoCandidate(candidates: AutoCodecCandidate[], label: string, run: () => string, note?: string) {
  try {
    addAutoCandidate(candidates, label, run(), note);
  } catch {
    // Keep auto mode noisy only for useful candidates.
  }
}

function countIocValues(text: string) {
  const iocs = extractIocs(text);
  return Object.values(iocs).reduce((sum, values) => sum + values.length, 0);
}

function codecChainTransforms(value: string) {
  const transforms: Array<{ label: string; run: (input: string) => string }> = [];
  if (/%(?:u[0-9a-f]{4}|[0-9a-f]{2})/i.test(value)) transforms.push({ label: "URL decode", run: (input) => decodeURIComponent(input) });
  if (/%(?:u[0-9a-f]{4}|[0-9a-f]{2})|\\x[0-9a-f]{2}/i.test(value)) transforms.push({ label: "Escape decode", run: escapeDecode });
  if (/&[a-zA-Z#0-9]+;/.test(value)) transforms.push({ label: "HTML entity decode", run: (input) => transformText("unhtml", input) });
  if (/\\u[0-9a-f]{4}/i.test(value)) transforms.push({ label: "Unicode escape decode", run: (input) => transformText("ununicode", input) });
  if (/(?:\\x|0x)[a-fA-F0-9]{2}/.test(value)) transforms.push({ label: "Shellcode decode", run: (input) => transformText("unshell", input) });
  if (/^[a-f0-9\s:,-]{8,}$/i.test(value) && value.replace(/[^a-f0-9]/gi, "").length % 2 === 0) transforms.push({ label: "Hex decode", run: (input) => transformText("unhex", input) });
  if (/^(?:[01]{8}[\s,;]*){2,}$/i.test(value)) transforms.push({ label: "Binary decode", run: (input) => transformText("unbin", input) });
  if (/^[A-Za-z0-9+/=\s]{12,}$/.test(value) && value.replace(/\s+/g, "").length % 4 !== 1) transforms.push({ label: "Base64 decode", run: base64DecodeLoose });
  if (/^[A-Za-z0-9_-]{12,}={0,2}$/.test(value)) transforms.push({ label: "Base64URL decode", run: base64UrlDecode });
  if (/^[A-Z2-7=\s]{12,}$/i.test(value)) transforms.push({ label: "Base32 decode", run: base32Decode });
  if (/^[1-9A-HJ-NP-Za-km-z]{12,}$/.test(value)) transforms.push({ label: "Base58 decode", run: base58Decode });
  if (/=\r?\n|=[0-9a-fA-F]{2}/.test(value)) transforms.push({ label: "Quoted-Printable decode", run: decodeQuotedPrintableText });
  if (/[\u200b\u200c\u200d]/.test(value)) transforms.push({ label: "Zero-width decode", run: (input) => transformText("zwd", input) });
  return transforms;
}

function analyzeCodecChains(input: string, maxDepth = 3) {
  const start = normalizeCandidateValue(input);
  if (!start) return [];
  const queue: Array<{ value: string; steps: string[] }> = [{ value: start, steps: [] }];
  const seen = new Set([start]);
  const output: CodecChainCandidate[] = [];
  for (let cursor = 0; cursor < queue.length && cursor < 80; cursor += 1) {
    const item = queue[cursor];
    if (item.steps.length >= maxDepth) continue;
    for (const transform of codecChainTransforms(item.value)) {
      try {
        const next = normalizeCandidateValue(transform.run(item.value));
        if (!next || next === item.value || seen.has(next) || next.length > 50000) continue;
        seen.add(next);
        const steps = [...item.steps, transform.label];
        const score = candidateScore(next);
        const iocCount = countIocValues(next);
        if (score >= 5 || iocCount > 0 || /[{[]["\w-]+["\w-]*\s*:|<html|BEGIN [A-Z ]+|flag\{|ctf/i.test(next)) {
          output.push({ steps, value: next, score, iocCount });
        }
        queue.push({ value: next, steps });
      } catch {
        // Bad branches are expected when probing encodings.
      }
    }
  }
  return output
    .sort((left, right) => right.score - left.score || right.iocCount - left.iocCount || left.steps.length - right.steps.length)
    .slice(0, 16);
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.slice(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(input: string) {
  const clean = input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const padded = clean.padEnd(Math.ceil(clean.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function codecInputToBytes(input: string) {
  const text = input.trim();
  if (!text) return new Uint8Array();
  const escapedHex = text.match(/(?:\\x|0x)[0-9a-fA-F]{2}/g);
  if (escapedHex?.length) {
    return Uint8Array.from(escapedHex.map((chunk) => parseInt(chunk.replace(/\\x|0x/gi, ""), 16)));
  }
  const percentBytes = text.match(/%[0-9a-fA-F]{2}/g);
  if (percentBytes && percentBytes.length >= Math.max(2, Math.floor(text.length / 6))) {
    return Uint8Array.from(percentBytes.map((chunk) => parseInt(chunk.slice(1), 16)));
  }
  const compactHex = text.replace(/0x/gi, "").replace(/[^a-fA-F0-9]/g, "");
  if (compactHex.length >= 2 && compactHex.length % 2 === 0 && compactHex.length >= text.replace(/\s+/g, "").length * 0.7) {
    return Uint8Array.from(compactHex.match(/.{2}/g)?.map((chunk) => parseInt(chunk, 16)) ?? []);
  }
  if (/^[A-Za-z0-9+/_=-]{8,}$/.test(text.replace(/\s+/g, ""))) {
    try {
      return base64ToBytes(text);
    } catch {
      // Fall through to UTF-8 bytes.
    }
  }
  return new TextEncoder().encode(input);
}

function base64EncodeText(input: string) {
  return bytesToBase64(new TextEncoder().encode(input));
}

function decodeBytesWithEncoding(bytes: Uint8Array, encoding: string) {
  try {
    return new TextDecoder(encoding, { fatal: false }).decode(bytes);
  } catch {
    return "";
  }
}

function encodeTextWithEncoding(input: string, encoding: string) {
  if (encoding === "utf-8") return new TextEncoder().encode(input);
  if (encoding === "utf-16le") {
    const bytes = new Uint8Array(input.length * 2);
    for (let index = 0; index < input.length; index += 1) {
      const code = input.charCodeAt(index);
      bytes[index * 2] = code & 0xff;
      bytes[index * 2 + 1] = code >> 8;
    }
    return bytes;
  }
  if (encoding === "windows-1252") {
    return Uint8Array.from(Array.from(input).map((char) => {
      const code = char.codePointAt(0) ?? 0x3f;
      return code <= 0xff ? code : 0x3f;
    }));
  }
  return new TextEncoder().encode(input);
}

function encodedBytesReport(input: string, encoding: string) {
  const bytes = encodeTextWithEncoding(input, encoding);
  return [
    `Encoding: ${encoding}`,
    `Bytes: ${bytes.length}`,
    `Base64: ${bytesToBase64(bytes)}`,
    `Hex: ${hexPreview(bytes, Math.min(bytes.length, 4096))}`
  ].join("\n");
}

function base64DecodeLoose(input: string) {
  return decodeBytesWithEncoding(base64ToBytes(input), "utf-8");
}

function formatAutoCandidates(candidates: AutoCodecCandidate[], attempted: string[]) {
  const useful = candidates
    .filter((candidate) => candidate.score > 0)
    .sort((left, right) => right.score - left.score || left.label.localeCompare(right.label))
    .slice(0, 28);
  const lowConfidence = candidates
    .filter((candidate) => candidate.score <= 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, 8);

  const sections: string[] = [];
  if (useful.length) {
    sections.push(
      useful
        .map((candidate) => {
          const note = candidate.note ? ` (${candidate.note})` : "";
          return `[${candidate.label}] signals ${candidate.score}${note}\n${candidate.value}`;
        })
        .join("\n\n---\n\n")
    );
  }
  if (lowConfidence.length && useful.length < 6) {
    sections.push(
      `Other attempts\n${lowConfidence
        .map((candidate) => `[${candidate.label}] signals ${candidate.score}\n${candidate.value}`)
        .join("\n\n---\n\n")}`
    );
  }
  sections.push(`Attempted transforms\n${Array.from(new Set(attempted)).join(", ")}`);
  return sections.join("\n\n===\n\n");
}

function addCodecArtifact(artifacts: CodecArtifactCandidate[], label: string, source: string, index: number, value: string, run: () => string) {
  try {
    const decoded = normalizeCandidateValue(run());
    if (!decoded || decoded === value.trim()) return;
    const score = candidateScore(decoded);
    const iocCount = countIocValues(decoded);
    const risk = [
      /(password|passwd|secret|token|api[_-]?key|session|cookie|bearer|authorization)/i.test(decoded) ? "credential marker" : "",
      /https?:\/\/|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}/i.test(decoded) ? "IOC-like decoded text" : "",
      score < 3 ? "weak match" : "",
      decoded.length > 4000 ? "long decoded output" : ""
    ].filter(Boolean);
    if (score < 2 && !iocCount && !risk.length) return;
    const key = `${label}|${index}|${decoded}`;
    if (artifacts.some((artifact) => `${artifact.label}|${artifact.index}|${artifact.decoded}` === key)) return;
    artifacts.push({ label, source, index, value, decoded, score, iocCount, risk });
  } catch {
    // Artifact probing is intentionally best-effort.
  }
}

function analyzeCodecArtifacts(input: string) {
  const artifacts: CodecArtifactCandidate[] = [];
  const limited = input.slice(0, 300_000);
  const seen = new Set<string>();
  const addMatches = (label: string, regex: RegExp, run: (value: string) => string) => {
    for (const match of limited.matchAll(regex)) {
      const value = match[0];
      const index = match.index ?? 0;
      const key = `${label}|${index}|${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const lineStart = limited.lastIndexOf("\n", index) + 1;
      const lineEnd = limited.indexOf("\n", index);
      const source = limited.slice(lineStart, lineEnd >= 0 ? lineEnd : Math.min(limited.length, lineStart + 500)).slice(0, 500);
      addCodecArtifact(artifacts, label, source, index, value, () => run(value));
      if (artifacts.length >= 120) return;
    }
  };

  addMatches("RFC2047 encoded word", /=\?[^?\s]{2,40}\?[bqBQ]\?[^?\r\n]{4,300}\?=/g, (value) => decodeWords(value));
  addMatches("Base64URL token", /\b[A-Za-z0-9_-]{20,}(?:={0,2})\b/g, (value) => base64UrlDecode(value));
  addMatches("Base64 blob", /\b(?:[A-Za-z0-9+/]{4}){5,}(?:={1,2})?\b/g, (value) => base64DecodeLoose(value));
  addMatches("Percent encoded fragment", /(?:%[0-9a-fA-F]{2}){2,}(?:(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]|%[0-9a-fA-F]{2}){0,500})/g, (value) => safeDecodeURIComponent(value));
  addMatches("Quoted-Printable fragment", /(?:=[0-9a-fA-F]{2}|=\r?\n){3,}(?:[A-Za-z0-9=+\-/\s]{0,600})/g, (value) => decodeQuotedPrintableText(value));
  addMatches("Unicode escape fragment", /(?:\\u[0-9a-fA-F]{4}){2,}/g, (value) => transformText("ununicode", value));
  addMatches("Shellcode / hex escape fragment", /(?:(?:\\x|0x)[0-9a-fA-F]{2}){3,}/g, (value) => transformText("unshell", value));
  addMatches("Hex byte run", /\b(?:[0-9a-fA-F]{2}[\s:,-]+){5,}[0-9a-fA-F]{2}\b/g, (value) => transformText("unhex", value));
  addMatches("Zero-width run", /[\u200b\u200c\u200d]{16,}/g, (value) => transformText("zwd", value));

  return artifacts
    .sort((left, right) => right.score - left.score || right.iocCount - left.iocCount || left.index - right.index)
    .slice(0, 80);
}

function analyzeCodecCandidates(input: string): CodecAnalysis {
  const text = input.trim();
  if (!text) {
    return {
      candidates: [],
      chains: [],
      artifacts: [],
      iocs: [],
      attempted: [],
      findings: [{ level: "info", title: "No input", detail: "Paste encoded text to run local codec detection." }]
    };
  }
  const candidates: AutoCodecCandidate[] = [];
  const attempted: string[] = [];
  const attempt = (label: string, run: () => string, note?: string) => {
    attempted.push(label);
    tryAutoCandidate(candidates, label, run, note);
  };

  if (/^[a-f0-9\s:,-]+$/i.test(text) && text.replace(/[^a-f0-9]/gi, "").length >= 4) {
    attempt("Hex decode", () => transformText("unhex", text), "hex-like marker");
  }
  if (/^(?:[01]{8}[\s,;]*){2,}$/i.test(text)) {
    attempt("Binary decode", () => transformText("unbin", text), "8-bit binary marker");
  }
  if (/%(?:u[0-9a-f]{4}|[0-9a-f]{2})/i.test(text)) {
    attempt("URL decode", () => decodeURIComponent(text), "percent marker");
    attempt("Escape decode", () => escapeDecode(text), "percent marker");
  }
  if (/\\u[0-9a-f]{4}/i.test(text)) {
    attempt("Unicode escape decode", () => text.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))));
  }
  if (/^(?:[A-Za-z0-9+/]{4}){2,}={0,2}$/.test(text)) {
    attempt("Base64 decode", () => base64DecodeLoose(text), "base64 alphabet");
    attempt("Base64 decode GB18030", () => decodeBytesWithEncoding(base64ToBytes(text), "gb18030"), "Chinese charset candidate");
    attempt("Base64 decode Big5", () => decodeBytesWithEncoding(base64ToBytes(text), "big5"), "Traditional Chinese charset candidate");
    attempt("Base64 decode Shift_JIS", () => decodeBytesWithEncoding(base64ToBytes(text), "shift_jis"), "Japanese charset candidate");
  }
  if (/^[A-Za-z0-9_-]{8,}={0,2}$/.test(text)) {
    attempt("Base64URL decode", () => base64UrlDecode(text), "base64url alphabet");
  }
  if (/^[A-Z2-7=\s]{12,}$/i.test(text)) {
    attempt("Base32 decode", () => base32Decode(text), "base32 alphabet");
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{12,}$/.test(text)) {
    attempt("Base58 decode", () => base58Decode(text), "base58 alphabet");
  }
  if (/=\r?\n|=[0-9a-fA-F]{2}/.test(text)) {
    attempt("Quoted-Printable decode", () => decodeQuotedPrintableText(text), "quoted-printable marker");
  }
  if (/^[\u{1f300}-\u{1f3ff}]+$/u.test(text)) {
    attempt("Base100 decode", () => transformText("base100d", text), "Base100 emoji range");
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/.test(text)) {
    attempt("JWT decode", () => {
      const [header, payload] = text.split(".");
      return `${base64UrlDecode(header)}\n${base64UrlDecode(payload)}`;
    });
  }
  if (/[&][a-zA-Z#0-9]+;/.test(text)) attempt("HTML entity decode", () => transformText("unhtml", text));
  if (/(?:\\x|0x)[a-fA-F0-9]{2}/.test(text)) attempt("Shellcode decode", () => transformText("unshell", text));
  if (/[\u200b\u200c\u200d]/.test(text)) attempt("Zero-width decode", () => transformText("zwd", text));
  if (coreValues.some((word) => text.includes(word))) attempt("Core values decode", () => transformText("cored", text));
  if (/^[.\-\/\s]+$/.test(text) && /[.-]/.test(text)) attempt("Morse decode", () => morseDecode(text));
  if (/^[+=<>.,\-[\]]+$/.test(text)) attempt("Brainfuck run", () => transformText("bfrun", text));
  if (/Ook[.!?]/i.test(text)) attempt("Ook to Brainfuck", () => transformText("ook2bf", text));
  if (/[零壹贰叁肆伍陆柒捌玖拾佰仟万整]/.test(text)) attempt("Pawnshop decode", () => transformText("pawn", text));
  if (/^[qwertyuiopasdfghjklzxcvbnm\s]+$/i.test(text) && text.length >= 4) attempt("QWE keyboard decode", () => transformText("qwed", text));
  if (/^[0-9\s]+$/.test(text) && text.replace(/\D/g, "").length >= 4) attempt("Chinese telegraph lookup", () => transformText("telegraph", text));

  const byteLikeInput =
    /(?:\\x|0x)[0-9a-fA-F]{2}/.test(text) ||
    /(?:%[0-9a-fA-F]{2}){2,}/.test(text) ||
    (/^[a-f0-9\s:,-]{8,}$/i.test(text) && text.replace(/[^a-f0-9]/gi, "").length % 2 === 0) ||
    (/^[A-Za-z0-9+/_=-]{12,}$/.test(text.replace(/\s+/g, "")) && text.replace(/\s+/g, "").length % 4 !== 1);
  if (byteLikeInput) {
    const bytes = codecInputToBytes(text);
    if (bytes.length >= 2 && bytes.length <= 500_000) {
      [
        ["Bytes as UTF-8", "utf-8", "byte charset candidate"],
        ["Bytes as GB18030", "gb18030", "Chinese charset candidate"],
        ["Bytes as GBK", "gbk", "Chinese charset candidate"],
        ["Bytes as Big5", "big5", "Traditional Chinese charset candidate"],
        ["Bytes as Shift_JIS", "shift_jis", "Japanese charset candidate"],
        ["Bytes as EUC-KR", "euc-kr", "Korean charset candidate"],
        ["Bytes as UTF-16LE", "utf-16le", "UTF-16 little-endian candidate"],
        ["Bytes as UTF-16BE", "utf-16be", "UTF-16 big-endian candidate"],
        ["Bytes as ISO-8859-1", "iso-8859-1", "single-byte charset candidate"],
        ["Bytes as Windows-1252", "windows-1252", "single-byte charset candidate"]
      ].forEach(([label, encoding, note]) => {
        attempt(label, () => decodeBytesWithEncoding(bytes, encoding), note);
      });
    }
  }

  const textLetterRatio = letterRatio(text);
  if (textLetterRatio > 0.45) {
    attempt("ROT13", () => transformText("rot13", text));
  } else {
    attempted.push("ROT13");
  }
  attempt("Reverse", () => transformText("reverse", text));
  if (textLetterRatio > 0.45) {
    for (let shift = 1; shift <= 25; shift += 1) {
      attempt(`Caesar -${shift}`, () => caesar(text, -shift));
    }
  } else {
    attempted.push("Caesar rotations");
  }

  const hashType = detectHashType(text);
  if (hashType) addAutoCandidate(candidates, "Hash marker", hashType, "not reversible");
  const jsDetect = detectObfuscation(text);
  if (!jsDetect.startsWith("No known")) addAutoCandidate(candidates, "JS/CTF marker", jsDetect, "detector");

  const sorted = candidates
    .filter((candidate) => candidate.score > 0)
    .sort((left, right) => right.score - left.score || left.label.localeCompare(right.label));
  const chains = analyzeCodecChains(text);
  const artifacts = analyzeCodecArtifacts(input);
  chains.forEach((chain) => addAutoCandidate(candidates, `Chain: ${chain.steps.join(" -> ")}`, chain.value, `${chain.steps.length} step(s), IOC=${chain.iocCount}`));
  const allDecodedText = [
    text,
    ...sorted.slice(0, 24).map((candidate) => candidate.value),
    ...chains.map((chain) => chain.value),
    ...artifacts.map((artifact) => artifact.decoded)
  ].join("\n");
  const iocs = emailIocRecords(allDecodedText, "codec decoded candidates").slice(0, 200);
  const finalCandidates = candidates
    .filter((candidate) => candidate.score > 0)
    .sort((left, right) => right.score - left.score || left.label.localeCompare(right.label));
  const findings: CodecAnalysis["findings"] = [
    finalCandidates.length || artifacts.length ? { level: "info", title: "Codec candidates found", detail: `${finalCandidates.length} whole-input candidate(s), ${artifacts.length} embedded artifact(s), ${chains.length} chain(s), ${attempted.length} transform(s) attempted.` } : { level: "warn", title: "No strong codec candidate", detail: `${attempted.length} transform(s) were attempted, but no high-confidence printable output was produced.` }
  ];
  if (chains.length) findings.push({ level: "info", title: "Layered decoding path found", detail: chains.slice(0, 4).map((chain) => chain.steps.join(" -> ")).join(" / ") });
  if (artifacts.length) findings.push({ level: "info", title: "Embedded encoded artifacts", detail: artifacts.slice(0, 8).map((artifact) => `${artifact.label}@${artifact.index} score=${artifact.score}`).join(" / ") });
  if (artifacts.some((artifact) => artifact.risk.some((risk) => /credential|IOC/i.test(risk)))) findings.push({ level: "warn", title: "Embedded artifacts worth review", detail: artifacts.filter((artifact) => artifact.risk.length).slice(0, 8).map((artifact) => `${artifact.label}@${artifact.index}: ${artifact.risk.join(", ")}`).join(" / ") });
  if (finalCandidates.some((candidate) => /(password|secret|token|key|admin|root|bearer|cookie)/i.test(candidate.value))) {
    findings.unshift({ level: "warn", title: "Sensitive-looking decoded text", detail: "One or more candidates contain credential/session keywords." });
  }
  if (iocs.length) {
    findings.push({ level: "warn", title: "IOC-like decoded text", detail: `${iocs.length} indicator(s) extracted from input and decoded candidates.` });
  }
  return { candidates: finalCandidates.slice(0, 36), chains, artifacts, iocs, attempted: Array.from(new Set(attempted)), findings };
}

function autoDetectCodec(input: string) {
  const analysis = analyzeCodecCandidates(input);
  if (!input.trim()) return "No input";
  return formatAutoCandidates(analysis.candidates, analysis.attempted);
}

function coreValuesEncode(text: string) {
  return Array.from(new TextEncoder().encode(text))
    .map((byte) => {
      const high = Math.floor(byte / coreValues.length);
      const low = byte % coreValues.length;
      return `${coreValues[high]}${coreValues[low]}`;
    })
    .join("");
}

function coreValuesDecode(text: string) {
  const tokens = text.match(new RegExp(coreValues.join("|"), "g")) ?? [];
  const bytes: number[] = [];
  for (let index = 0; index < tokens.length; index += 2) {
    const high = coreValues.indexOf(tokens[index]);
    const low = coreValues.indexOf(tokens[index + 1]);
    if (high >= 0 && low >= 0) bytes.push(high * coreValues.length + low);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

function runBrainfuck(code: string, input = "") {
  const tape = new Uint8Array(30000);
  const output: string[] = [];
  let pointer = 0;
  let inputIndex = 0;
  const loopMap = new Map<number, number>();
  const stack: number[] = [];
  const instructions = code.replace(/[^\[\]<>+\-.,]/g, "");
  for (let index = 0; index < instructions.length; index += 1) {
    if (instructions[index] === "[") stack.push(index);
    if (instructions[index] === "]") {
      const start = stack.pop();
      if (start != null) {
        loopMap.set(start, index);
        loopMap.set(index, start);
      }
    }
  }
  for (let index = 0; index < instructions.length; index += 1) {
    const command = instructions[index];
    if (command === ">") pointer = Math.min(pointer + 1, tape.length - 1);
    if (command === "<") pointer = Math.max(pointer - 1, 0);
    if (command === "+") tape[pointer] += 1;
    if (command === "-") tape[pointer] -= 1;
    if (command === ".") output.push(String.fromCharCode(tape[pointer]));
    if (command === ",") tape[pointer] = input.charCodeAt(inputIndex++) || 0;
    if (command === "[" && tape[pointer] === 0) index = loopMap.get(index) ?? index;
    if (command === "]" && tape[pointer] !== 0) index = loopMap.get(index) ?? index;
    if (index > 200000) return "Execution stopped: too many steps";
  }
  return output.join("");
}

const bfToOokMap: Record<string, string> = {
  ">": "Ook. Ook?",
  "<": "Ook? Ook.",
  "+": "Ook. Ook.",
  "-": "Ook! Ook!",
  ".": "Ook! Ook.",
  ",": "Ook. Ook!",
  "[": "Ook! Ook?",
  "]": "Ook? Ook!"
};

function brainfuckToOok(code: string) {
  return code
    .replace(/[^<>+\-.,[\]]/g, "")
    .split("")
    .map((char) => bfToOokMap[char])
    .join(" ");
}

function ookToBrainfuck(text: string) {
  const reverse = Object.fromEntries(Object.entries(bfToOokMap).map(([key, value]) => [value, key]));
  const pairs = text.match(/Ook[.!?]\s+Ook[.!?]/g) ?? [];
  return pairs.map((pair) => reverse[pair.replace(/\s+/g, " ")] ?? "").join("");
}

function chineseTelegraphLookup(text: string) {
  return Array.from(text)
    .map((char) => `${char}: ${chineseTelegraphMap[char] ?? "----"}`)
    .join("\n");
}

const pawnshopDigits: Record<string, string> = {
  田: "0",
  由: "1",
  中: "2",
  人: "3",
  工: "4",
  大: "5",
  王: "6",
  夫: "7",
  井: "8",
  羊: "9",
  口: "0"
};

function pawnshopDecode(text: string) {
  return Array.from(text)
    .map((char) => pawnshopDigits[char] ?? (/\d/.test(char) ? char : " "))
    .join("")
    .replace(/\s+/g, " ")
    .trim();
}

const qwerty = "QWERTYUIOPASDFGHJKLZXCVBNM";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function qweTransform(text: string, decode = false) {
  const from = decode ? qwerty : alphabet;
  const to = decode ? alphabet : qwerty;
  return text.replace(/[a-zA-Z]/g, (char) => {
    const upper = char.toUpperCase();
    const index = from.indexOf(upper);
    if (index < 0) return char;
    const mapped = to[index];
    return char === upper ? mapped : mapped.toLowerCase();
  });
}

function escapeEncode(text: string) {
  return Array.from(text)
    .map((char) => {
      const code = char.charCodeAt(0);
      if (code <= 0xff) return `%${code.toString(16).padStart(2, "0")}`;
      return `%u${code.toString(16).padStart(4, "0")}`;
    })
    .join("");
}

function escapeDecode(text: string) {
  return text
    .replace(/%u([a-fA-F0-9]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/%([a-fA-F0-9]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function detectObfuscation(text: string) {
  const findings: string[] = [];
  const compact = text.replace(/\s+/g, "");
  if (/^[\[\]\(\)!+]+$/.test(compact) && compact.length > 20) {
    findings.push("JSFuck: only []()!+ characters detected");
  }
  if (/ﾟωﾟ|ﾟДﾟ|_ﾟ|c,o,n,s,t,r,u,c,t,o,r/.test(text)) {
    findings.push("AAEncode: Japanese emoticon markers detected");
  }
  if (/\$=~\[\]|_=\$|\\x[0-9a-fA-F]{2}|\"_\"\+/.test(text) && /function|constructor|return|\$/.test(text)) {
    findings.push("JJEncode-like JavaScript obfuscation markers detected");
  }
  if (/佛曰|如是我闻/.test(text)) {
    findings.push("Buddha/FoYue style text detected");
  }
  if (/社会主义核心价值观|富强|民主|文明|和谐/.test(text)) {
    findings.push("Core Values style text detected");
  }
  return findings.length ? findings.join("\n") : "No known JS/CTF obfuscation marker detected";
}

export { analyzeCodecCandidates, base64DecodeLoose, transformText };

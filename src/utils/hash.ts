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

import CryptoJS from "crypto-js";
import { sm3 } from "sm-crypto";
import type { HashBundle } from "../models";

export function bytesToWordArray(bytes: Uint8Array) {
  const words: number[] = [];
  for (let index = 0; index < bytes.length; index += 1) {
    words[index >>> 2] |= bytes[index] << (24 - (index % 4) * 8);
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

export async function fileHashes(file: File) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const wordArray = bytesToWordArray(bytes);
  return {
    md5: CryptoJS.MD5(wordArray).toString(),
    sha1: CryptoJS.SHA1(wordArray).toString(),
    sha256: CryptoJS.SHA256(wordArray).toString(),
    sha512: CryptoJS.SHA512(wordArray).toString()
  };
}

export function hashBytes(bytes: Uint8Array): HashBundle {
  const wordArray = bytesToWordArray(bytes);
  return {
    md5: CryptoJS.MD5(wordArray).toString(),
    sha1: CryptoJS.SHA1(wordArray).toString(),
    sha256: CryptoJS.SHA256(wordArray).toString(),
    sha512: CryptoJS.SHA512(wordArray).toString(),
    sha3: CryptoJS.SHA3(wordArray).toString(),
    sm3: sm3(Array.from(bytes))
  };
}

export function sha256Bytes(bytes: Uint8Array) {
  return CryptoJS.SHA256(bytesToWordArray(bytes)).toString();
}

export async function sha256BytesAsync(bytes: Uint8Array) {
  const source = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? bytes.buffer as ArrayBuffer
    : bytes.slice().buffer;
  const digest = await crypto.subtle.digest("SHA-256", source);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function hashSelectedBytes(bytes: Uint8Array, algorithms: string[]) {
  const selected = new Set(algorithms.map((algorithm) => algorithm.toLowerCase()));
  const result: Partial<HashBundle> = {};
  const cryptoJsAlgorithms = ["md5", "sha1", "sha512", "sha3"].filter((algorithm) => selected.has(algorithm));
  const wordArray = cryptoJsAlgorithms.length ? bytesToWordArray(bytes) : null;
  if (selected.has("md5") && wordArray) result.md5 = CryptoJS.MD5(wordArray).toString();
  if (selected.has("sha1") && wordArray) result.sha1 = CryptoJS.SHA1(wordArray).toString();
  if (selected.has("sha256")) result.sha256 = await sha256BytesAsync(bytes);
  if (selected.has("sha512") && wordArray) result.sha512 = CryptoJS.SHA512(wordArray).toString();
  if (selected.has("sha3") && wordArray) result.sha3 = CryptoJS.SHA3(wordArray).toString();
  if (selected.has("sm3")) result.sm3 = sm3(Array.from(bytes));
  return result;
}

export function formatHashCase(value: string, mode: "lower" | "upper") {
  return mode === "upper" ? value.toUpperCase() : value.toLowerCase();
}

export function detectHashType(value: string) {
  const trimmed = value.trim();
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(trimmed)) return "bcrypt";
  if (/^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$/.test(trimmed)) return "Django PBKDF2-SHA256";
  if (/^\$P\$[./A-Za-z0-9]{31}$|^\$H\$[./A-Za-z0-9]{31}$/.test(trimmed)) return "WordPress phpass";
  if (/^\*[A-F0-9]{40}$/.test(trimmed)) return "MySQL native password";
  if (/^\{SHA\}[A-Za-z0-9+/=]+$/i.test(trimmed)) return "LDAP {SHA}";
  if (/^[a-f0-9]{32}$/i.test(trimmed)) return "MD5-like";
  if (/^[a-f0-9]{40}$/i.test(trimmed)) return "SHA1 / RIPEMD-160-like";
  if (/^[a-f0-9]{64}$/i.test(trimmed)) return "SHA256-like";
  if (/^[a-f0-9]{128}$/i.test(trimmed)) return "SHA512 / SHA3-512-like";
  return "";
}

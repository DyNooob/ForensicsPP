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
  return hashSelectedFile(file, ["md5", "sha1", "sha256", "sha512"]);
}

export function hashBytes(bytes: Uint8Array): HashBundle {
  const wordArray = bytesToWordArray(bytes);
  return {
    md5: CryptoJS.MD5(wordArray).toString(),
    sha1: CryptoJS.SHA1(wordArray).toString(),
    sha256: CryptoJS.SHA256(wordArray).toString(),
    sha512: CryptoJS.SHA512(wordArray).toString(),
    sha3: CryptoJS.SHA3(wordArray).toString(),
    sm3: sm3(bytes as unknown as number[])
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
  if (selected.has("sm3")) result.sm3 = sm3(bytes as unknown as number[]);
  return result;
}

export const SM3_FILE_SIZE_LIMIT = 8 * 1024 * 1024;

export type FileHashProgress = {
  loaded: number;
  total: number;
};

export type FileHashOptions = {
  chunkSize?: number;
  signal?: AbortSignal;
  onProgress?: (progress: FileHashProgress) => void;
};

function abortError() {
  return new DOMException("Hash calculation cancelled", "AbortError");
}

export async function hashSelectedFile(file: Blob, algorithms: string[], options: FileHashOptions = {}) {
  const selected = new Set(algorithms.map((algorithm) => algorithm.toLowerCase()));
  if (selected.has("sm3") && file.size > SM3_FILE_SIZE_LIMIT) {
    throw new RangeError(`SM3_FILE_TOO_LARGE:${SM3_FILE_SIZE_LIMIT}`);
  }

  const hashers: Array<{ id: keyof HashBundle; value: ReturnType<typeof CryptoJS.algo.MD5.create> }> = [];
  if (selected.has("md5")) hashers.push({ id: "md5", value: CryptoJS.algo.MD5.create() });
  if (selected.has("sha1")) hashers.push({ id: "sha1", value: CryptoJS.algo.SHA1.create() });
  if (selected.has("sha256")) hashers.push({ id: "sha256", value: CryptoJS.algo.SHA256.create() });
  if (selected.has("sha512")) hashers.push({ id: "sha512", value: CryptoJS.algo.SHA512.create() });
  if (selected.has("sha3")) hashers.push({ id: "sha3", value: CryptoJS.algo.SHA3.create({ outputLength: 512 }) });

  const chunkSize = Math.max(64 * 1024, options.chunkSize ?? 4 * 1024 * 1024);
  const sm3Bytes = selected.has("sm3") ? new Uint8Array(file.size) : null;
  let offset = 0;
  options.onProgress?.({ loaded: 0, total: file.size });

  while (offset < file.size) {
    if (options.signal?.aborted) throw abortError();
    const end = Math.min(file.size, offset + chunkSize);
    const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    if (options.signal?.aborted) throw abortError();
    const wordArray = bytesToWordArray(chunk);
    hashers.forEach((hasher) => hasher.value.update(wordArray));
    sm3Bytes?.set(chunk, offset);
    offset = end;
    options.onProgress?.({ loaded: offset, total: file.size });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  if (options.signal?.aborted) throw abortError();
  const result: Partial<HashBundle> = {};
  hashers.forEach((hasher) => {
    result[hasher.id] = hasher.value.finalize().toString();
  });
  if (sm3Bytes) result.sm3 = sm3(sm3Bytes as unknown as number[]);
  return result;
}

export function formatHashCase(value: string, mode: "lower" | "upper") {
  return mode === "upper" ? value.toUpperCase() : value.toLowerCase();
}

export function normalizeHashAlgorithms(value: unknown) {
  const supported = new Set(["md5", "sha1", "sha256", "sha512", "sha3", "sm3"]);
  const selected = Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string").map((item) => item.toLowerCase()).filter((item) => supported.has(item))
    : [];
  return selected.length ? Array.from(new Set(selected)) : ["sha256"];
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

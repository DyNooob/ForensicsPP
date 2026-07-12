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

import { morseMap } from "../codec/constants";

export function caesar(text: string, shift: number) {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - base + shift + 26) % 26) + base);
  });
}

export function atbash(text: string) {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97;
    return String.fromCharCode(base + 25 - (char.charCodeAt(0) - base));
  });
}

export function rot47(text: string) {
  return text.replace(/[!-~]/g, (char) => String.fromCharCode(33 + ((char.charCodeAt(0) - 33 + 47) % 94)));
}

export function vigenere(text: string, key: string, decode = false) {
  const cleanKey = key.replace(/[^a-zA-Z]/g, "").toUpperCase();
  if (!cleanKey) return text;
  let keyIndex = 0;
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97;
    const shift = cleanKey.charCodeAt(keyIndex % cleanKey.length) - 65;
    keyIndex += 1;
    return String.fromCharCode(((char.charCodeAt(0) - base + (decode ? -shift : shift) + 26) % 26) + base);
  });
}

function modInverse(value: number, modulo: number) {
  const normalized = ((value % modulo) + modulo) % modulo;
  for (let index = 1; index < modulo; index += 1) {
    if ((normalized * index) % modulo === 1) return index;
  }
  return null;
}

export function affine(text: string, a: number, b: number, decode = false) {
  const inverse = modInverse(a, 26);
  if (decode && inverse == null) return "Invalid affine key: a must be coprime with 26";
  return text.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97;
    const x = char.charCodeAt(0) - base;
    const value = decode ? (inverse! * (x - b + 26)) % 26 : (a * x + b) % 26;
    return String.fromCharCode(((value + 26) % 26) + base);
  });
}

export function morseEncode(text: string) {
  return text
    .toUpperCase()
    .split("")
    .map((char) => (char === " " ? "/" : morseMap[char] ?? char))
    .join(" ");
}

export function morseDecode(text: string) {
  const reverse = Object.fromEntries(Object.entries(morseMap).map(([key, value]) => [value, key]));
  return text
    .trim()
    .split(/\s+/)
    .map((part) => (part === "/" ? " " : reverse[part] ?? "?"))
    .join("");
}

export function baconEncode(text: string) {
  return text
    .toUpperCase()
    .replace(/[A-Z]/g, (char) => {
      const value = char.charCodeAt(0) - 65;
      return value.toString(2).padStart(5, "0").replace(/0/g, "A").replace(/1/g, "B");
    });
}

export function baconDecode(text: string) {
  return (text.match(/[ABab]{5}/g) ?? [])
    .map((chunk) => String.fromCharCode(parseInt(chunk.toUpperCase().replace(/A/g, "0").replace(/B/g, "1"), 2) + 65))
    .join("");
}

export function railFence(text: string, rails: number) {
  if (rails <= 1) return text;
  const rows = Array.from({ length: rails }, () => "");
  let row = 0;
  let step = 1;
  for (const char of text) {
    rows[row] += char;
    if (row === 0) step = 1;
    if (row === rails - 1) step = -1;
    row += step;
  }
  return rows.join("");
}

export function railFenceDecode(cipher: string, rails: number) {
  if (rails <= 1) return cipher;
  const pattern: number[] = [];
  let row = 0;
  let step = 1;
  for (let index = 0; index < cipher.length; index += 1) {
    pattern.push(row);
    if (row === 0) step = 1;
    if (row === rails - 1) step = -1;
    row += step;
  }

  const counts = Array.from({ length: rails }, (_, rail) => pattern.filter((item) => item === rail).length);
  const rows: string[][] = [];
  let offset = 0;
  counts.forEach((count) => {
    rows.push(cipher.slice(offset, offset + count).split(""));
    offset += count;
  });

  return pattern.map((rail) => rows[rail].shift() ?? "").join("");
}

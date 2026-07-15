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

export type PlistValue = null | boolean | number | string | Date | Uint8Array | PlistValue[] | { [key: string]: PlistValue };
export type PlistEntry = { key: string; path: string; type: string; preview: string; value: PlistValue };

function readUnsigned(bytes: Uint8Array, offset: number, length: number) {
  if (length > 8 || offset < 0 || offset + length > bytes.byteLength) throw new Error("Plist 整数超出可读取范围。");
  let value = 0n;
  for (let index = 0; index < length; index += 1) value = value * 256n + BigInt(bytes[offset + index]);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Plist 整数超出浏览器可读取范围。");
  return Number(value);
}

function decodeUtf16Be(bytes: Uint8Array) {
  const swapped = new Uint8Array(bytes.byteLength);
  for (let index = 0; index + 1 < bytes.byteLength; index += 2) {
    swapped[index] = bytes[index + 1];
    swapped[index + 1] = bytes[index];
  }
  return new TextDecoder("utf-16le").decode(swapped);
}

function parseBinaryPlist(bytes: Uint8Array): PlistValue {
  if (bytes.byteLength < 40) throw new Error("二进制 Plist 不完整。");
  const trailer = bytes.byteLength - 32;
  const offsetSize = bytes[trailer + 6];
  const refSize = bytes[trailer + 7];
  const objectCount = readUnsigned(bytes, trailer + 8, 8);
  const topObject = readUnsigned(bytes, trailer + 16, 8);
  const offsetTable = readUnsigned(bytes, trailer + 24, 8);
  if (!objectCount || objectCount > 500000 || offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8) throw new Error("二进制 Plist 结构无效或对象过多。");
  if (offsetTable + objectCount * offsetSize > trailer) throw new Error("二进制 Plist 偏移表越界。");
  const offsets = Array.from({ length: objectCount }, (_, index) => readUnsigned(bytes, offsetTable + index * offsetSize, offsetSize));
  const cache = new Map<number, PlistValue>();
  const reading = new Set<number>();

  const lengthAt = (offset: number, info: number) => {
    if (info < 15) return { length: info, next: offset };
    const marker = bytes[offset];
    if ((marker >> 4) !== 1) throw new Error("Plist 长度字段无效。");
    const size = 2 ** (marker & 15);
    return { length: readUnsigned(bytes, offset + 1, size), next: offset + 1 + size };
  };
  const parseObject = (index: number, depth = 0): PlistValue => {
    if (depth > 256 || index < 0 || index >= objectCount) throw new Error("Plist 对象引用无效。");
    if (cache.has(index)) return cache.get(index)!;
    if (reading.has(index)) throw new Error("Plist 包含循环引用。");
    reading.add(index);
    const offset = offsets[index];
    if (offset >= offsetTable) throw new Error("Plist 对象偏移越界。");
    const marker = bytes[offset];
    const type = marker >> 4;
    const info = marker & 15;
    let value: PlistValue;
    if (type === 0) value = info === 8 ? false : info === 9 ? true : null;
    else if (type === 1) value = readUnsigned(bytes, offset + 1, 2 ** info);
    else if (type === 2) {
      const size = 2 ** info;
      const view = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, size);
      value = size === 4 ? view.getFloat32(0, false) : view.getFloat64(0, false);
    } else if (type === 3) {
      const seconds = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 8).getFloat64(0, false);
      value = new Date(Date.UTC(2001, 0, 1) + seconds * 1000);
    } else if (type === 4 || type === 5 || type === 6) {
      const sized = lengthAt(offset + 1, info);
      const byteLength = type === 6 ? sized.length * 2 : sized.length;
      if (sized.next + byteLength > offsetTable) throw new Error("Plist 数据越界。");
      const data = bytes.slice(sized.next, sized.next + byteLength);
      value = type === 4 ? data : type === 5 ? new TextDecoder("ascii").decode(data) : decodeUtf16Be(data);
    } else if (type === 8) value = readUnsigned(bytes, offset + 1, info + 1);
    else if (type === 10 || type === 12) {
      const sized = lengthAt(offset + 1, info);
      const refs = Array.from({ length: sized.length }, (_, item) => readUnsigned(bytes, sized.next + item * refSize, refSize));
      value = refs.map((ref) => parseObject(ref, depth + 1));
    } else if (type === 13) {
      const sized = lengthAt(offset + 1, info);
      const valuesOffset = sized.next + sized.length * refSize;
      const result: Record<string, PlistValue> = {};
      for (let item = 0; item < sized.length; item += 1) {
        const keyRef = readUnsigned(bytes, sized.next + item * refSize, refSize);
        const valueRef = readUnsigned(bytes, valuesOffset + item * refSize, refSize);
        result[String(parseObject(keyRef, depth + 1))] = parseObject(valueRef, depth + 1);
      }
      value = result;
    } else throw new Error(`暂不支持的二进制 Plist 对象类型：0x${type.toString(16)}`);
    reading.delete(index);
    cache.set(index, value);
    return value;
  };
  return parseObject(topObject);
}

function xmlNodeValue(node: Element): PlistValue {
  switch (node.tagName) {
    case "dict": {
      const result: Record<string, PlistValue> = {};
      const children = Array.from(node.children);
      for (let index = 0; index < children.length; index += 2) {
        if (children[index]?.tagName !== "key" || !children[index + 1]) continue;
        result[children[index].textContent ?? ""] = xmlNodeValue(children[index + 1]);
      }
      return result;
    }
    case "array": return Array.from(node.children).map(xmlNodeValue);
    case "true": return true;
    case "false": return false;
    case "integer": return Number.parseInt(node.textContent ?? "0", 10);
    case "real": return Number.parseFloat(node.textContent ?? "0");
    case "date": return new Date(node.textContent ?? "");
    case "data": {
      const binary = atob((node.textContent ?? "").replace(/\s+/g, ""));
      return Uint8Array.from(binary, (character) => character.charCodeAt(0));
    }
    default: return node.textContent ?? "";
  }
}

export function parsePlist(bytes: Uint8Array): { format: "binary" | "xml"; value: PlistValue } {
  if (new TextDecoder("ascii").decode(bytes.subarray(0, 8)) === "bplist00") return { format: "binary", value: parseBinaryPlist(bytes) };
  const text = new TextDecoder().decode(bytes);
  const document = new DOMParser().parseFromString(text, "application/xml");
  const error = document.querySelector("parsererror");
  const root = document.querySelector("plist")?.firstElementChild;
  if (error || !root) throw new Error("不是有效的 XML 或二进制 Plist 文件。");
  return { format: "xml", value: xmlNodeValue(root) };
}

export function plistType(value: PlistValue) {
  if (value === null) return "null";
  if (value instanceof Date) return "date";
  if (value instanceof Uint8Array) return "data";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") return "dict";
  return typeof value;
}

export function plistPreview(value: PlistValue) {
  const type = plistType(value);
  if (type === "dict") return `${Object.keys(value as Record<string, PlistValue>).length} keys`;
  if (type === "array") return `${(value as PlistValue[]).length} items`;
  if (type === "data") return `${(value as Uint8Array).byteLength} bytes`;
  if (type === "date") return (value as Date).toISOString();
  return String(value ?? "null");
}

export function plistChildren(value: PlistValue, path = "$"): PlistEntry[] {
  if (Array.isArray(value)) return value.map((item, index) => ({ key: String(index), path: `${path}[${index}]`, type: plistType(item), preview: plistPreview(item), value: item }));
  if (value && typeof value === "object" && !(value instanceof Date) && !(value instanceof Uint8Array)) {
    return Object.entries(value).map(([key, item]) => ({ key, path: `${path}.${key}`, type: plistType(item), preview: plistPreview(item), value: item }));
  }
  return [];
}

export function plistJson(value: PlistValue) {
  return JSON.stringify(value, (_key, item) => {
    if (!(item instanceof Uint8Array)) return item;
    let binary = "";
    for (let offset = 0; offset < item.byteLength; offset += 0x8000) binary += String.fromCharCode(...item.subarray(offset, offset + 0x8000));
    return { type: "data", base64: btoa(binary) };
  }, 2);
}

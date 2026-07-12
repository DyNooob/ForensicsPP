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

export type RegistryValue = { name: string; type: string; value: string; size: number };
export type RegistryKey = { id: number; parentId: number | null; name: string; path: string; lastWrite: string; children: number[]; values: RegistryValue[] };
export type RegistryHive = {
  rootId: number;
  keys: RegistryKey[];
  sequence1: number;
  sequence2: number;
  dirty: boolean;
  warnings: string[];
};

const HIVE_BASE = 0x1000;
const MAX_KEYS = 250000;
const MAX_VALUES = 750000;

function signature(bytes: Uint8Array, offset: number) {
  return String.fromCharCode(bytes[offset] ?? 0, bytes[offset + 1] ?? 0);
}

function filetimeToIso(view: DataView, offset: number) {
  const ticks = view.getBigUint64(offset, true);
  if (!ticks) return "--";
  const milliseconds = ticks / 10000n - 11644473600000n;
  const date = new Date(Number(milliseconds));
  return Number.isNaN(date.getTime()) ? "--" : date.toISOString();
}

function decodeName(bytes: Uint8Array, compressed: boolean) {
  return new TextDecoder(compressed ? "windows-1252" : "utf-16le").decode(bytes).replace(/\0+$/g, "");
}

function decodeRegistryData(type: number, bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (type === 1 || type === 2 || type === 6) return new TextDecoder("utf-16le").decode(bytes).replace(/\0+$/g, "");
  if (type === 7) return new TextDecoder("utf-16le").decode(bytes).split("\0").filter(Boolean).join("\n");
  if (type === 4 && bytes.byteLength >= 4) return String(view.getUint32(0, true));
  if (type === 5 && bytes.byteLength >= 4) return String(view.getUint32(0, false));
  if (type === 11 && bytes.byteLength >= 8) return view.getBigUint64(0, true).toString();
  const shown = bytes.subarray(0, 256);
  return `${Array.from(shown, (byte) => byte.toString(16).padStart(2, "0")).join(" ")}${bytes.byteLength > shown.byteLength ? " ..." : ""}`;
}

const registryTypes = ["REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCRIPTOR", "REG_RESOURCE_REQUIREMENTS_LIST", "REG_QWORD"];

export function parseRegistryHive(bytes: Uint8Array): RegistryHive {
  if (bytes.byteLength < HIVE_BASE + 32 || new TextDecoder("ascii").decode(bytes.subarray(0, 4)) !== "regf") throw new Error("不是有效的 Windows Registry Hive。");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const sequence1 = view.getUint32(0x04, true);
  const sequence2 = view.getUint32(0x08, true);
  const majorVersion = view.getUint32(0x14, true);
  const minorVersion = view.getUint32(0x18, true);
  const fileType = view.getUint32(0x1c, true);
  const fileFormat = view.getUint32(0x20, true);
  const binsDataSize = view.getUint32(0x28, true);
  if (majorVersion !== 1 || minorVersion < 3 || minorVersion > 6 || fileType !== 0 || fileFormat !== 1) throw new Error("Registry Hive 文件头版本或格式无效。");
  if (!binsDataSize || binsDataSize % 0x1000 !== 0 || HIVE_BASE + binsDataSize > bytes.byteLength) throw new Error("Registry Hive 数据区大小无效。");
  if (new TextDecoder("ascii").decode(bytes.subarray(HIVE_BASE, HIVE_BASE + 4)) !== "hbin") throw new Error("Registry Hive 缺少首个 HBIN 数据块。");
  const firstBinOffset = view.getUint32(HIVE_BASE + 4, true);
  const firstBinSize = view.getUint32(HIVE_BASE + 8, true);
  if (firstBinOffset !== 0 || firstBinSize < 0x1000 || firstBinSize % 0x1000 !== 0 || HIVE_BASE + firstBinSize > bytes.byteLength) throw new Error("Registry Hive 首个 HBIN 数据块无效。");
  let headerChecksum = 0;
  for (let offset = 0; offset < 0x1fc; offset += 4) headerChecksum = (headerChecksum ^ view.getUint32(offset, true)) >>> 0;
  const warnings: string[] = [];
  if (sequence1 !== sequence2) warnings.push("主序列号与次序列号不一致，Hive 可能需要事务日志恢复。");
  if (headerChecksum !== view.getUint32(0x1fc, true)) warnings.push("Hive 文件头校验和不匹配。");
  const rootOffset = view.getUint32(0x24, true);
  const hiveEnd = HIVE_BASE + binsDataSize;
  const cellData = (relativeOffset: number) => {
    const absolute = HIVE_BASE + relativeOffset;
    if (relativeOffset % 8 !== 0 || absolute < HIVE_BASE || absolute + 6 > hiveEnd) throw new Error("Hive 单元偏移越界。");
    const signedSize = view.getInt32(absolute, true);
    const size = Math.abs(signedSize);
    if (size < 8 || size % 8 !== 0 || absolute + size > hiveEnd) throw new Error("Hive 单元大小无效。");
    return { offset: absolute + 4, size: size - 4, allocated: signedSize < 0 };
  };

  let valueCounter = 0;
  const parseValue = (relativeOffset: number): RegistryValue => {
    if (++valueCounter > MAX_VALUES) throw new Error("Hive 值数量超过浏览器解析上限。");
    const cell = cellData(relativeOffset);
    if (signature(bytes, cell.offset) !== "vk" || cell.size < 20) throw new Error("Hive 值单元无效。");
    const nameLength = view.getUint16(cell.offset + 2, true);
    const rawDataSize = view.getUint32(cell.offset + 4, true);
    const dataOffset = view.getUint32(cell.offset + 8, true);
    const type = view.getUint32(cell.offset + 12, true);
    const flags = view.getUint16(cell.offset + 16, true);
    if (20 + nameLength > cell.size) throw new Error("Hive 值名称长度无效。");
    const name = nameLength ? decodeName(bytes.subarray(cell.offset + 20, cell.offset + 20 + nameLength), Boolean(flags & 1)) : "(Default)";
    const dataSize = rawDataSize & 0x7fffffff;
    let data = new Uint8Array();
    if (dataSize && dataSize <= 0x10000000) {
      if (rawDataSize & 0x80000000) data = bytes.slice(cell.offset + 8, cell.offset + 8 + Math.min(dataSize, 4));
      else {
        const dataCell = cellData(dataOffset);
        if (signature(bytes, dataCell.offset) === "db" && dataCell.size >= 8) {
          const segmentCount = view.getUint16(dataCell.offset + 2, true);
          const listCell = cellData(view.getUint32(dataCell.offset + 4, true));
          const chunks: Uint8Array[] = [];
          let collected = 0;
          for (let index = 0; index < segmentCount && index * 4 + 4 <= listCell.size && collected < dataSize; index += 1) {
            const segment = cellData(view.getUint32(listCell.offset + index * 4, true));
            const chunk = bytes.slice(segment.offset, segment.offset + Math.min(segment.size, dataSize - collected));
            chunks.push(chunk);
            collected += chunk.byteLength;
          }
          data = new Uint8Array(collected);
          let cursor = 0;
          for (const chunk of chunks) { data.set(chunk, cursor); cursor += chunk.byteLength; }
        } else data = bytes.slice(dataCell.offset, dataCell.offset + Math.min(dataSize, dataCell.size));
      }
    }
    return { name, type: registryTypes[type] ?? `REG_${type}`, value: decodeRegistryData(type, data), size: dataSize };
  };

  const subkeyOffsets = (relativeOffset: number, visited = new Set<number>()): number[] => {
    if (relativeOffset === 0xffffffff || visited.has(relativeOffset)) return [];
    visited.add(relativeOffset);
    const cell = cellData(relativeOffset);
    const kind = signature(bytes, cell.offset);
    const count = view.getUint16(cell.offset + 2, true);
    if (count > 200000) throw new Error("Hive 子项索引数量异常。");
    const stride = kind === "lf" || kind === "lh" ? 8 : 4;
    if ((kind === "li" || kind === "lf" || kind === "lh" || kind === "ri") && 4 + count * stride > cell.size) throw new Error("Hive 子项索引长度无效。");
    if (kind === "li") return Array.from({ length: count }, (_, index) => view.getUint32(cell.offset + 4 + index * 4, true));
    if (kind === "lf" || kind === "lh") return Array.from({ length: count }, (_, index) => view.getUint32(cell.offset + 4 + index * 8, true));
    if (kind === "ri") return Array.from({ length: count }, (_, index) => view.getUint32(cell.offset + 4 + index * 4, true)).flatMap((offset) => subkeyOffsets(offset, visited));
    return [];
  };

  const keys: RegistryKey[] = [];
  const offsetsToIds = new Map<number, number>();
  const pending: Array<{ offset: number; parentId: number | null; parentPath: string }> = [{ offset: rootOffset, parentId: null, parentPath: "" }];
  while (pending.length) {
    if (keys.length >= MAX_KEYS) throw new Error("Hive 键数量超过浏览器解析上限。");
    const item = pending.pop()!;
    if (offsetsToIds.has(item.offset)) continue;
    const cell = cellData(item.offset);
    if (signature(bytes, cell.offset) !== "nk" || cell.size < 76 || !cell.allocated) continue;
    const id = keys.length;
    offsetsToIds.set(item.offset, id);
    const flags = view.getUint16(cell.offset + 2, true);
    const nameLength = view.getUint16(cell.offset + 72, true);
    if (76 + nameLength > cell.size) throw new Error("Hive 键名称长度无效。");
    const name = decodeName(bytes.subarray(cell.offset + 76, cell.offset + 76 + nameLength), Boolean(flags & 0x20));
    const path = item.parentPath ? `${item.parentPath}\\${name}` : name;
    const childOffsets = subkeyOffsets(view.getUint32(cell.offset + 28, true));
    const valueCount = view.getUint32(cell.offset + 36, true);
    const valueListOffset = view.getUint32(cell.offset + 40, true);
    const values: RegistryValue[] = [];
    if (valueCount > MAX_VALUES) throw new Error("Hive 值数量超过浏览器解析上限。");
    if (valueCount) {
      const list = cellData(valueListOffset);
      if (valueCount * 4 > list.size) throw new Error("Hive 值列表长度无效。");
      for (let index = 0; index < valueCount && index * 4 + 4 <= list.size; index += 1) values.push(parseValue(view.getUint32(list.offset + index * 4, true)));
    }
    keys.push({ id, parentId: item.parentId, name, path, lastWrite: filetimeToIso(view, cell.offset + 4), children: [], values });
    for (let index = childOffsets.length - 1; index >= 0; index -= 1) pending.push({ offset: childOffsets[index], parentId: id, parentPath: path });
  }
  for (const key of keys) if (key.parentId != null) keys[key.parentId]?.children.push(key.id);
  if (!keys.length) throw new Error("Hive 根键无法读取。");
  return { rootId: 0, keys, sequence1, sequence2, dirty: sequence1 !== sequence2, warnings };
}

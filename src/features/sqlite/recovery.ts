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

export type SqliteRecoveryArea = "freelist" | "freeblock" | "unallocated" | "wal-frame";
export type SqliteRecoveryMode = "cell" | "cell-overflow" | "record-payload";
export type SqliteRecoveredValueKind = "NULL" | "INTEGER" | "REAL" | "TEXT" | "BLOB";

export type SqliteRecoveryRegion = {
  pageNumber: number;
  start: number;
  end: number;
  area: SqliteRecoveryArea;
  source: "main" | "wal";
  walFrame?: number | null;
};

export type SqliteRecoveredValue = {
  serialType: number;
  kind: SqliteRecoveredValueKind;
  value: string;
  byteLength: number;
};

export type SqliteRecoveredRecord = {
  pageNumber: number;
  offset: number;
  payloadOffset: number;
  source: "main" | "wal";
  area: SqliteRecoveryArea;
  walFrame: number | null;
  recovery: SqliteRecoveryMode;
  rowid: string | null;
  payloadSize: number;
  columnCount: number;
  values: SqliteRecoveredValue[];
  confidence: "low" | "medium" | "high";
  tableCandidates: Array<{ table: string; score: number }>;
  overflowPages: number[];
  overflowBytes: number;
  notes: string[];
};

export type SqliteSchemaHint = {
  table: string;
  columns: Array<{ name: string; type: string }>;
};

type Varint = { value: bigint; length: number };
type ParsedPayload = {
  size: number;
  values: SqliteRecoveredValue[];
  textValues: number;
  nonNullValues: number;
};

const maximumRecoveredRecords = 500;
const maximumColumns = 64;
const maximumHeaderBytes = 1024;
const maximumScanBytes = 16 * 1024 * 1024;

function readVarint(bytes: Uint8Array, offset: number, end: number): Varint | null {
  if (offset < 0 || offset >= end || end > bytes.length) return null;
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    const cursor = offset + index;
    if (cursor >= end) return null;
    const byte = bytes[cursor];
    value = (value << 7n) | BigInt(byte & 0x7f);
    if ((byte & 0x80) === 0) return { value, length: index + 1 };
  }
  if (offset + 8 >= end) return null;
  value = (value << 8n) | BigInt(bytes[offset + 8]);
  return { value, length: 9 };
}

function safeNumber(value: bigint) {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}

function serialByteLength(serialType: number) {
  if (serialType === 0 || serialType === 8 || serialType === 9) return 0;
  if (serialType >= 1 && serialType <= 4) return serialType;
  if (serialType === 5) return 6;
  if (serialType === 6 || serialType === 7) return 8;
  if (serialType === 10 || serialType === 11) return -1;
  if (serialType >= 12) return serialType % 2 === 0 ? (serialType - 12) / 2 : (serialType - 13) / 2;
  return -1;
}

function signedBigEndian(bytes: Uint8Array, offset: number, length: number) {
  let value = 0n;
  for (let index = 0; index < length; index += 1) value = (value << 8n) | BigInt(bytes[offset + index]);
  if (length && (bytes[offset] & 0x80)) value -= 1n << BigInt(length * 8);
  return value;
}

function decoderFor(encoding: string) {
  try {
    if (/UTF-16LE/i.test(encoding)) return new TextDecoder("utf-16le", { fatal: false });
    if (/UTF-16BE/i.test(encoding)) return new TextDecoder("utf-16be", { fatal: false });
  } catch {
    // UTF-8 is available in all supported browsers and remains a safe fallback.
  }
  return new TextDecoder("utf-8", { fatal: false });
}

function blobPreview(bytes: Uint8Array) {
  const visible = bytes.subarray(0, Math.min(24, bytes.length));
  const hex = Array.from(visible, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join("");
  return `${bytes.length} B${hex ? ` · ${hex}${bytes.length > visible.length ? "…" : ""}` : ""}`;
}

function decodeValue(bytes: Uint8Array, offset: number, serialType: number, encoding: string): SqliteRecoveredValue | null {
  const byteLength = serialByteLength(serialType);
  if (byteLength < 0 || offset + byteLength > bytes.length) return null;
  if (serialType === 0) return { serialType, kind: "NULL", value: "NULL", byteLength };
  if (serialType >= 1 && serialType <= 6) {
    return { serialType, kind: "INTEGER", value: signedBigEndian(bytes, offset, byteLength).toString(), byteLength };
  }
  if (serialType === 7) {
    const value = new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getFloat64(0, false);
    if (!Number.isFinite(value)) return null;
    return { serialType, kind: "REAL", value: String(value), byteLength };
  }
  if (serialType === 8) return { serialType, kind: "INTEGER", value: "0", byteLength };
  if (serialType === 9) return { serialType, kind: "INTEGER", value: "1", byteLength };
  const raw = bytes.subarray(offset, offset + byteLength);
  if (serialType % 2 === 0) return { serialType, kind: "BLOB", value: blobPreview(raw), byteLength };
  const decoded = decoderFor(encoding).decode(raw).replace(/\u0000/g, "");
  return { serialType, kind: "TEXT", value: decoded.slice(0, 500), byteLength };
}

function textLooksPlausible(value: string) {
  if (!value) return true;
  let printable = 0;
  let replacement = 0;
  for (const char of value) {
    if (char === "�") replacement += 1;
    const code = char.codePointAt(0) ?? 0;
    if (code === 0x09 || code === 0x0a || code === 0x0d || code >= 0x20) printable += 1;
  }
  return replacement <= Math.max(1, value.length * 0.15) && printable / Math.max(1, value.length) >= 0.75;
}

function parseRecordPayload(bytes: Uint8Array, offset: number, end: number, encoding: string): ParsedPayload | null {
  const headerVarint = readVarint(bytes, offset, end);
  if (!headerVarint) return null;
  const headerSize = safeNumber(headerVarint.value);
  if (headerSize == null || headerSize < headerVarint.length + 1 || headerSize > maximumHeaderBytes) return null;
  const headerEnd = offset + headerSize;
  if (headerEnd > end) return null;

  const serialTypes: number[] = [];
  let headerCursor = offset + headerVarint.length;
  while (headerCursor < headerEnd && serialTypes.length < maximumColumns) {
    const serial = readVarint(bytes, headerCursor, headerEnd);
    if (!serial) return null;
    const serialType = safeNumber(serial.value);
    if (serialType == null || serialType > 1_000_000 || serialType === 10 || serialType === 11) return null;
    serialTypes.push(serialType);
    headerCursor += serial.length;
  }
  if (headerCursor !== headerEnd || !serialTypes.length || serialTypes.length >= maximumColumns) return null;

  let dataCursor = headerEnd;
  const values: SqliteRecoveredValue[] = [];
  let textValues = 0;
  let nonNullValues = 0;
  for (const serialType of serialTypes) {
    const byteLength = serialByteLength(serialType);
    if (byteLength < 0 || dataCursor + byteLength > end) return null;
    const value = decodeValue(bytes, dataCursor, serialType, encoding);
    if (!value) return null;
    if (value.kind === "TEXT") {
      if (!textLooksPlausible(value.value)) return null;
      if (value.value.trim()) textValues += 1;
    }
    if (value.kind !== "NULL") nonNullValues += 1;
    values.push(value);
    dataCursor += byteLength;
  }
  if (!nonNullValues) return null;
  return { size: dataCursor - offset, values, textValues, nonNullValues };
}


function sqlitePageGeometry(bytes: Uint8Array) {
  if (bytes.length < 100 || new TextDecoder().decode(bytes.subarray(0, 16)) !== "SQLite format 3\u0000") return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rawPageSize = view.getUint16(16, false);
  const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
  const reserved = bytes[20] ?? 0;
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0 || reserved >= pageSize) return null;
  return { pageSize, usableSize: pageSize - reserved };
}

function localTableLeafPayloadBytes(payloadSize: number, usableSize: number) {
  const maxLocal = usableSize - 35;
  if (payloadSize <= maxLocal) return payloadSize;
  const minLocal = Math.floor(((usableSize - 12) * 32) / 255) - 23;
  const candidate = minLocal + ((payloadSize - minLocal) % (usableSize - 4));
  return candidate <= maxLocal ? candidate : minLocal;
}

function readOverflowPayload(database: Uint8Array, firstPage: number, bytesNeeded: number, pageSize: number, usableSize: number) {
  const output = new Uint8Array(bytesNeeded);
  const pages: number[] = [];
  const seen = new Set<number>();
  let cursor = 0;
  let page = firstPage;
  while (page && cursor < bytesNeeded && pages.length < 256) {
    if (seen.has(page)) return null;
    seen.add(page);
    const pageStart = (page - 1) * pageSize;
    if (pageStart < 0 || pageStart + 4 > database.length) return null;
    const pageEnd = Math.min(database.length, pageStart + usableSize);
    const next = new DataView(database.buffer, database.byteOffset + pageStart, 4).getUint32(0, false);
    const available = Math.max(0, pageEnd - (pageStart + 4));
    const take = Math.min(bytesNeeded - cursor, available);
    if (!take) return null;
    output.set(database.subarray(pageStart + 4, pageStart + 4 + take), cursor);
    cursor += take;
    pages.push(page);
    page = next;
  }
  return cursor === bytesNeeded ? { bytes: output, pages } : null;
}
function recordKey(record: SqliteRecoveredRecord) {
  return `${record.pageNumber}:${record.payloadOffset}:${record.values.map((value) => `${value.serialType}:${value.value}`).join("|")}`;
}

function confidenceForPayload(parsed: ParsedPayload, mode: SqliteRecoveryMode) {
  if (mode === "cell" && parsed.values.length >= 2 && (parsed.textValues || parsed.values.length >= 3)) return "high" as const;
  if (parsed.values.length >= 3 && parsed.textValues) return "medium" as const;
  return "low" as const;
}

function addRecord(output: SqliteRecoveredRecord[], seen: Set<string>, record: SqliteRecoveredRecord) {
  if (output.length >= maximumRecoveredRecords) return false;
  const key = recordKey(record);
  if (seen.has(key)) return true;
  seen.add(key);
  output.push(record);
  return true;
}

export function recoverSqliteTableLeafCell(
  bytes: Uint8Array,
  offset: number,
  end: number,
  encoding: string,
  context: Pick<SqliteRecoveryRegion, "pageNumber" | "area" | "source" | "walFrame">
): SqliteRecoveredRecord | null {
  const payloadLengthVarint = readVarint(bytes, offset, end);
  if (!payloadLengthVarint) return null;
  const payloadSize = safeNumber(payloadLengthVarint.value);
  if (payloadSize == null || payloadSize < 2 || payloadSize > 512 * 1024 * 1024) return null;
  const rowidOffset = offset + payloadLengthVarint.length;
  const rowidVarint = readVarint(bytes, rowidOffset, end);
  if (!rowidVarint) return null;
  const payloadOffset = rowidOffset + rowidVarint.length;

  let payloadBytes: Uint8Array;
  let overflowPages: number[] = [];
  let overflowBytes = 0;
  let recovery: SqliteRecoveryMode = "cell";
  const geometry = sqlitePageGeometry(bytes);
  if (geometry) {
    const localBytes = localTableLeafPayloadBytes(payloadSize, geometry.usableSize);
    const localEnd = payloadOffset + localBytes;
    if (localEnd > end || localEnd > bytes.length) return null;
    if (localBytes < payloadSize) {
      if (localEnd + 4 > end || localEnd + 4 > bytes.length) return null;
      const firstOverflowPage = new DataView(bytes.buffer, bytes.byteOffset + localEnd, 4).getUint32(0, false);
      const overflow = readOverflowPayload(bytes, firstOverflowPage, payloadSize - localBytes, geometry.pageSize, geometry.usableSize);
      if (!overflow) return null;
      payloadBytes = new Uint8Array(payloadSize);
      payloadBytes.set(bytes.subarray(payloadOffset, localEnd));
      payloadBytes.set(overflow.bytes, localBytes);
      overflowPages = overflow.pages;
      overflowBytes = overflow.bytes.length;
      recovery = "cell-overflow";
    } else {
      payloadBytes = bytes.slice(payloadOffset, payloadOffset + payloadSize);
    }
  } else {
    const payloadEnd = payloadOffset + payloadSize;
    if (payloadEnd > end) return null;
    payloadBytes = bytes.slice(payloadOffset, payloadEnd);
  }

  const parsed = parseRecordPayload(payloadBytes, 0, payloadBytes.length, encoding);
  if (!parsed || parsed.size !== payloadSize) return null;
  return {
    pageNumber: context.pageNumber,
    offset,
    payloadOffset,
    source: context.source,
    area: context.area,
    walFrame: context.walFrame ?? null,
    recovery,
    rowid: rowidVarint.value.toString(),
    payloadSize,
    columnCount: parsed.values.length,
    values: parsed.values,
    confidence: confidenceForPayload(parsed, "cell"),
    tableCandidates: [],
    overflowPages,
    overflowBytes,
    notes: [recovery === "cell-overflow"
      ? `Recovered an intact table-leaf cell and reconstructed ${overflowBytes} overflow byte(s) across page(s) ${overflowPages.join(", ")}.`
      : context.area === "wal-frame"
        ? "Recovered from an intact table-leaf cell in a historical or uncommitted WAL page version. Historical WAL overflow chains are not mixed with main-database pages."
        : "Recovered from an intact table-leaf-cell shaped byte sequence."]
  };
}

export function recoverSqliteRecords(bytes: Uint8Array, regions: SqliteRecoveryRegion[], encoding: string) {
  const output: SqliteRecoveredRecord[] = [];
  const seen = new Set<string>();
  let scanned = 0;

  for (const region of regions) {
    if (output.length >= maximumRecoveredRecords || scanned >= maximumScanBytes) break;
    const start = Math.max(0, region.start);
    const end = Math.min(bytes.length, region.end);
    if (end - start < 4) continue;
    const regionBudget = Math.min(end - start, maximumScanBytes - scanned);
    const scanEnd = start + regionBudget;
    scanned += regionBudget;

    for (let offset = start; offset < scanEnd - 3 && output.length < maximumRecoveredRecords; offset += 1) {
      const cell = recoverSqliteTableLeafCell(bytes, offset, scanEnd, encoding, region);
      if (cell) addRecord(output, seen, cell);

      const payload = parseRecordPayload(bytes, offset, scanEnd, encoding);
      if (!payload || payload.values.length < 2 || (payload.textValues === 0 && payload.values.length < 3)) continue;
      addRecord(output, seen, {
        pageNumber: region.pageNumber,
        offset,
        payloadOffset: offset,
        source: region.source,
        area: region.area,
        walFrame: region.walFrame ?? null,
        recovery: "record-payload",
        rowid: null,
        payloadSize: payload.size,
        columnCount: payload.values.length,
        values: payload.values,
        confidence: confidenceForPayload(payload, "record-payload"),
        tableCandidates: [],
        overflowPages: [],
        overflowBytes: 0,
        notes: [region.area === "freeblock"
          ? "The freeblock header overwrites bytes at the start of a deleted cell; only the surviving SQLite record payload could be reconstructed, so rowid is unavailable."
          : "Recovered as a SQLite record payload candidate without a surviving table-leaf cell prefix; rowid is unavailable."]
      });
    }
  }

  return output.sort((left, right) => {
    const rank = { high: 0, medium: 1, low: 2 } as const;
    return rank[left.confidence] - rank[right.confidence] || left.pageNumber - right.pageNumber || left.offset - right.offset;
  });
}

function declaredAffinity(type: string) {
  const value = type.toUpperCase();
  if (value.includes("INT")) return "INTEGER";
  if (/(CHAR|CLOB|TEXT)/.test(value)) return "TEXT";
  if (value.includes("BLOB") || !value.trim()) return "BLOB";
  if (/(REAL|FLOA|DOUB)/.test(value)) return "REAL";
  return "NUMERIC";
}

function valueAffinityScore(kind: SqliteRecoveredValueKind, declaredType: string) {
  if (kind === "NULL") return 0.5;
  const affinity = declaredAffinity(declaredType);
  if (affinity === kind) return 2;
  if (affinity === "NUMERIC" && (kind === "INTEGER" || kind === "REAL")) return 1.5;
  if (affinity === "BLOB") return 0.75;
  return 0;
}

export function annotateSqliteRecoveredRecords(records: SqliteRecoveredRecord[], schemas: SqliteSchemaHint[]) {
  return records.map((record) => {
    const candidates = schemas
      .filter((schema) => schema.columns.length === record.columnCount)
      .map((schema) => {
        const raw = schema.columns.reduce((sum, column, index) => sum + valueAffinityScore(record.values[index]?.kind ?? "NULL", column.type), 0);
        const score = Math.round((raw / Math.max(1, record.columnCount * 2)) * 100);
        return { table: schema.table, score };
      })
      .filter((candidate) => candidate.score >= 35)
      .sort((left, right) => right.score - left.score || left.table.localeCompare(right.table))
      .slice(0, 3);
    return { ...record, tableCandidates: candidates };
  });
}

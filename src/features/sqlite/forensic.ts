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

import { applySqliteWal, inspectSqliteWal, type SqliteWalFrameInfo, type SqliteWalInfo } from "./wal";
import { recoverSqliteRecords, recoverSqliteTableLeafCell, type SqliteRecoveredRecord, type SqliteRecoveryRegion } from "./recovery";

export type SqlitePageKind =
  | "database-header"
  | "table-interior"
  | "table-leaf"
  | "index-interior"
  | "index-leaf"
  | "freelist-trunk"
  | "freelist-leaf"
  | "empty"
  | "unknown";

export type SqlitePageInfo = {
  pageNumber: number;
  offset: number;
  kind: SqlitePageKind;
  source: "main" | "wal";
  walFrame: number | null;
  cellCount: number | null;
  freeBytes: number;
  firstFreeblock: number | null;
  contentOffset: number | null;
};

export type SqliteRecoveredFragment = {
  pageNumber: number;
  offset: number;
  source: "main" | "wal";
  area: "freelist" | "freeblock" | "unallocated";
  encoding: "ASCII" | "UTF-16LE";
  text: string;
};

export type SqliteForensicAnalysis = {
  header: {
    pageSize: number;
    filePages: number;
    headerPages: number;
    changeCounter: number;
    schemaCookie: number;
    schemaFormat: number;
    freelistFirstPage: number;
    freelistPages: number;
    encoding: string;
    userVersion: number;
    applicationId: number;
    sqliteVersion: number;
  };
  pages: SqlitePageInfo[];
  fragments: SqliteRecoveredFragment[];
  recoveredRecords: SqliteRecoveredRecord[];
  wal: { info: SqliteWalInfo; frames: SqliteWalFrameInfo[]; trailingBytes: number } | null;
  walError: string | null;
};

type FragmentRegion = {
  pageNumber: number;
  start: number;
  end: number;
  area: SqliteRecoveredFragment["area"];
};

const textDecoder = new TextDecoder("ascii");
const maximumFragments = 500;
const maximumFragmentLength = 240;

function viewFor(bytes: Uint8Array) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function readU16(bytes: Uint8Array, offset: number) {
  return offset >= 0 && offset + 2 <= bytes.byteLength ? viewFor(bytes).getUint16(offset, false) : 0;
}

function readU32(bytes: Uint8Array, offset: number) {
  return offset >= 0 && offset + 4 <= bytes.byteLength ? viewFor(bytes).getUint32(offset, false) : 0;
}

export function sqliteDatabasePageSize(database: Uint8Array) {
  if (database.byteLength < 100 || textDecoder.decode(database.subarray(0, 16)) !== "SQLite format 3\0") {
    throw new Error("不是有效的 SQLite 数据库文件。");
  }
  const raw = readU16(database, 16);
  const pageSize = raw === 1 ? 65536 : raw;
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0) throw new Error("SQLite 页大小无效。");
  return pageSize;
}

function sqliteEncoding(value: number) {
  if (value === 1) return "UTF-8";
  if (value === 2) return "UTF-16LE";
  if (value === 3) return "UTF-16BE";
  return value === 0 ? "unspecified" : `unknown (${value})`;
}

function btreeKind(flag: number): SqlitePageKind {
  if (flag === 0x02) return "index-interior";
  if (flag === 0x05) return "table-interior";
  if (flag === 0x0a) return "index-leaf";
  if (flag === 0x0d) return "table-leaf";
  return "unknown";
}

function pageIsEmpty(bytes: Uint8Array, start: number, end: number) {
  for (let offset = start; offset < end; offset += 1) if (bytes[offset] !== 0) return false;
  return true;
}

function collectFreelistPages(bytes: Uint8Array, pageSize: number) {
  const trunks = new Set<number>();
  const leaves = new Set<number>();
  const pageCount = Math.floor(bytes.byteLength / pageSize);
  let trunk = readU32(bytes, 32);
  for (let visited = 0; trunk && visited < pageCount; visited += 1) {
    if (trunk > pageCount || trunks.has(trunk)) break;
    trunks.add(trunk);
    const pageStart = (trunk - 1) * pageSize;
    const leafCount = Math.min(readU32(bytes, pageStart + 4), Math.floor((pageSize - 8) / 4));
    for (let index = 0; index < leafCount; index += 1) {
      const leaf = readU32(bytes, pageStart + 8 + index * 4);
      if (leaf > 0 && leaf <= pageCount && !trunks.has(leaf)) leaves.add(leaf);
    }
    trunk = readU32(bytes, pageStart);
  }
  return { trunks, leaves };
}

function extractAscii(bytes: Uint8Array, region: FragmentRegion, source: SqlitePageInfo["source"], output: SqliteRecoveredFragment[]) {
  let start = -1;
  const flush = (end: number) => {
    if (start < 0 || end - start < 6 || output.length >= maximumFragments) {
      start = -1;
      return;
    }
    const raw = bytes.subarray(start, Math.min(end, start + maximumFragmentLength));
    output.push({
      pageNumber: region.pageNumber,
      offset: start,
      source,
      area: region.area,
      encoding: "ASCII",
      text: textDecoder.decode(raw)
    });
    start = -1;
  };
  for (let offset = region.start; offset < region.end; offset += 1) {
    const value = bytes[offset];
    if (value >= 0x20 && value <= 0x7e) {
      if (start < 0) start = offset;
    } else {
      flush(offset);
    }
  }
  flush(region.end);
}

function recoverHistoricalWalCells(walBytes: Uint8Array, wal: NonNullable<SqliteForensicAnalysis["wal"]>, encoding: string) {
  const records: SqliteRecoveredRecord[] = [];
  const pageSize = wal.info.pageSize;
  for (const frame of wal.frames) {
    if (!frame.valid || frame.latestForPage || records.length >= 500) continue;
    const pageStart = frame.offset + 24;
    const pageEnd = Math.min(walBytes.length, pageStart + pageSize);
    const btreeHeader = pageStart + (frame.pageNumber === 1 ? 100 : 0);
    if (btreeHeader + 8 > pageEnd || walBytes[btreeHeader] !== 0x0d) continue;
    const cellCount = readU16(walBytes, btreeHeader + 3);
    const pointerStart = btreeHeader + 8;
    if (!cellCount || cellCount > Math.floor((pageEnd - pointerStart) / 2)) continue;
    for (let index = 0; index < cellCount && records.length < 500; index += 1) {
      const cellRelativeOffset = readU16(walBytes, pointerStart + index * 2);
      if (!cellRelativeOffset || cellRelativeOffset >= pageSize) continue;
      const cellOffset = pageStart + cellRelativeOffset;
      if (cellOffset < pageStart || cellOffset >= pageEnd) continue;
      const recovered = recoverSqliteTableLeafCell(walBytes, cellOffset, pageEnd, encoding, {
        pageNumber: frame.pageNumber,
        source: "wal",
        area: "wal-frame",
        walFrame: frame.index
      });
      if (!recovered) continue;
      recovered.notes.unshift(frame.committed
        ? `Historical committed WAL page version from frame ${frame.index}; a newer frame superseded this page.`
        : `Valid but uncommitted WAL page version from frame ${frame.index}; treat this as transaction residue rather than committed database state.`);
      records.push(recovered);
    }
  }
  return records;
}

function extractUtf16Le(bytes: Uint8Array, region: FragmentRegion, source: SqlitePageInfo["source"], output: SqliteRecoveredFragment[]) {
  let offset = region.start + (region.start % 2);
  while (offset + 1 < region.end && output.length < maximumFragments) {
    const start = offset;
    const characters: number[] = [];
    while (offset + 1 < region.end && bytes[offset] >= 0x20 && bytes[offset] <= 0x7e && bytes[offset + 1] === 0) {
      characters.push(bytes[offset]);
      offset += 2;
    }
    if (characters.length >= 6) {
      output.push({
        pageNumber: region.pageNumber,
        offset: start,
        source,
        area: region.area,
        encoding: "UTF-16LE",
        text: String.fromCharCode(...characters.slice(0, maximumFragmentLength))
      });
    }
    offset = Math.max(offset + 2, start + 2);
  }
}

export function inspectSqliteDatabase(database: Uint8Array, walBytes?: Uint8Array | null): SqliteForensicAnalysis {
  const sourcePageSize = sqliteDatabasePageSize(database);
  let wal: SqliteForensicAnalysis["wal"] = null;
  let walError: string | null = null;
  if (walBytes?.byteLength) {
    try {
      wal = inspectSqliteWal(database, walBytes);
    } catch (error) {
      walError = error instanceof Error ? error.message : String(error);
    }
  }
  const merged = wal && wal.info.committedFrames ? applySqliteWal(database, walBytes as Uint8Array).bytes : database;
  const pageSize = sqliteDatabasePageSize(merged);
  if (pageSize !== sourcePageSize) throw new Error("SQLite 主库与合并结果的页大小不一致。");

  const pageCount = Math.floor(merged.byteLength / pageSize);
  const latestWalFrame = new Map<number, number>();
  wal?.frames.forEach((frame) => {
    if (frame.latestForPage) latestWalFrame.set(frame.pageNumber, frame.index);
  });
  const freelist = collectFreelistPages(merged, pageSize);
  const pages: SqlitePageInfo[] = [];
  const fragmentRegions: FragmentRegion[] = [];

  for (let pageNumber = 1; pageNumber <= pageCount; pageNumber += 1) {
    const pageStart = (pageNumber - 1) * pageSize;
    const pageEnd = Math.min(merged.byteLength, pageStart + pageSize);
    const btreeHeader = pageStart + (pageNumber === 1 ? 100 : 0);
    let kind: SqlitePageKind = pageNumber === 1 ? "database-header" : btreeKind(merged[btreeHeader] ?? 0);
    if (freelist.trunks.has(pageNumber)) kind = "freelist-trunk";
    else if (freelist.leaves.has(pageNumber)) kind = "freelist-leaf";
    else if (kind === "unknown" && pageIsEmpty(merged, pageStart, pageEnd)) kind = "empty";

    const source = latestWalFrame.has(pageNumber) ? "wal" : "main";
    let cellCount: number | null = null;
    let firstFreeblock: number | null = null;
    let contentOffset: number | null = null;
    let freeBytes = 0;
    if (["database-header", "table-interior", "table-leaf", "index-interior", "index-leaf"].includes(kind)) {
      const flag = merged[btreeHeader] ?? 0;
      const interior = flag === 0x02 || flag === 0x05;
      const headerSize = interior ? 12 : 8;
      firstFreeblock = readU16(merged, btreeHeader + 1) || null;
      cellCount = readU16(merged, btreeHeader + 3);
      const rawContentOffset = readU16(merged, btreeHeader + 5);
      contentOffset = rawContentOffset || 65536;
      const pointerEnd = btreeHeader + headerSize + cellCount * 2;
      const contentStart = Math.min(pageEnd, pageStart + contentOffset);
      if (contentStart > pointerEnd) {
        freeBytes += contentStart - pointerEnd;
        fragmentRegions.push({ pageNumber, start: pointerEnd, end: contentStart, area: "unallocated" });
      }
      let block = firstFreeblock ?? 0;
      const seen = new Set<number>();
      while (block >= 4 && block + 4 <= pageSize && !seen.has(block)) {
        seen.add(block);
        const absolute = pageStart + block;
        const next = readU16(merged, absolute);
        const size = readU16(merged, absolute + 2);
        if (size < 4 || block + size > pageSize) break;
        freeBytes += size;
        fragmentRegions.push({ pageNumber, start: absolute + 4, end: absolute + size, area: "freeblock" });
        block = next;
      }
      freeBytes += merged[btreeHeader + 7] ?? 0;
    } else if (kind === "freelist-trunk") {
      const leafCount = Math.min(readU32(merged, pageStart + 4), Math.floor((pageSize - 8) / 4));
      const start = Math.min(pageEnd, pageStart + 8 + leafCount * 4);
      freeBytes = Math.max(0, pageEnd - start);
      fragmentRegions.push({ pageNumber, start, end: pageEnd, area: "freelist" });
    } else if (kind === "freelist-leaf") {
      freeBytes = pageEnd - pageStart;
      fragmentRegions.push({ pageNumber, start: pageStart, end: pageEnd, area: "freelist" });
    }

    pages.push({
      pageNumber,
      offset: pageStart,
      kind,
      source,
      walFrame: latestWalFrame.get(pageNumber) ?? null,
      cellCount,
      freeBytes,
      firstFreeblock,
      contentOffset
    });
  }

  const fragments: SqliteRecoveredFragment[] = [];
  for (const region of fragmentRegions) {
    if (fragments.length >= maximumFragments || region.end <= region.start) break;
    const source = pages[region.pageNumber - 1]?.source ?? "main";
    extractAscii(merged, region, source, fragments);
    extractUtf16Le(merged, region, source, fragments);
  }
  const recoveryRegions: SqliteRecoveryRegion[] = fragmentRegions.map((region) => ({
    ...region,
    source: pages[region.pageNumber - 1]?.source ?? "main",
    walFrame: pages[region.pageNumber - 1]?.walFrame ?? null
  }));
  const encoding = sqliteEncoding(readU32(merged, 56));
  const freeSpaceRecords = recoverSqliteRecords(merged, recoveryRegions, encoding);
  const historicalWalRecords = wal && walBytes?.byteLength ? recoverHistoricalWalCells(walBytes, wal, encoding) : [];
  const confidenceRank = { high: 0, medium: 1, low: 2 } as const;
  const recoveredRecords = [...historicalWalRecords, ...freeSpaceRecords]
    .sort((left, right) => confidenceRank[left.confidence] - confidenceRank[right.confidence] || left.pageNumber - right.pageNumber || (left.walFrame ?? 0) - (right.walFrame ?? 0) || left.offset - right.offset)
    .slice(0, 750);

  const uniqueFragments = Array.from(new Map(fragments.map((fragment) => [
    `${fragment.pageNumber}:${fragment.offset}:${fragment.encoding}:${fragment.text}`,
    fragment
  ])).values());

  return {
    header: {
      pageSize,
      filePages: pageCount,
      headerPages: readU32(merged, 28),
      changeCounter: readU32(merged, 24),
      schemaCookie: readU32(merged, 40),
      schemaFormat: readU32(merged, 44),
      freelistFirstPage: readU32(merged, 32),
      freelistPages: readU32(merged, 36),
      encoding: sqliteEncoding(readU32(merged, 56)),
      userVersion: readU32(merged, 60),
      applicationId: readU32(merged, 68),
      sqliteVersion: readU32(merged, 96)
    },
    pages,
    fragments: uniqueFragments,
    recoveredRecords,
    wal,
    walError
  };
}

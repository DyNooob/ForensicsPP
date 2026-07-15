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

export type SqliteWalInfo = {
  pageSize: number;
  frames: number;
  validFrames: number;
  committedFrames: number;
  databasePages: number;
  ignoredFrames: number;
  invalidFrame: number | null;
  checksumVerified: true;
};

export type SqliteWalFrameInfo = {
  index: number;
  offset: number;
  pageNumber: number;
  commitPages: number;
  valid: boolean;
  committed: boolean;
  latestForPage: boolean;
  reason: string;
};

export type SqliteWalInspection = {
  info: SqliteWalInfo;
  frames: SqliteWalFrameInfo[];
  trailingBytes: number;
};

function readU32(bytes: Uint8Array, offset: number) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

function databasePageSize(database: Uint8Array) {
  if (database.byteLength < 100 || new TextDecoder("ascii").decode(database.subarray(0, 16)) !== "SQLite format 3\0") {
    throw new Error("不是有效的 SQLite 数据库文件。");
  }
  const raw = new DataView(database.buffer, database.byteOffset, database.byteLength).getUint16(16, false);
  return raw === 1 ? 65536 : raw;
}

function updateChecksum(bytes: Uint8Array, offset: number, length: number, littleEndian: boolean, state: [number, number]): [number, number] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let [s0, s1] = state;
  for (let cursor = offset; cursor < offset + length; cursor += 8) {
    const first = view.getUint32(cursor, littleEndian);
    const second = view.getUint32(cursor + 4, littleEndian);
    s0 = (s0 + first + s1) >>> 0;
    s1 = (s1 + second + s0) >>> 0;
  }
  return [s0, s1];
}

export function inspectSqliteWal(database: Uint8Array, wal: Uint8Array): SqliteWalInspection {
  if (wal.byteLength < 32) throw new Error("WAL 文件头不完整。");
  const magic = readU32(wal, 0);
  if (magic !== 0x377f0682 && magic !== 0x377f0683) throw new Error("不是有效的 SQLite WAL 文件。");
  if (readU32(wal, 4) !== 3007000) throw new Error("WAL 格式版本不受支持。");
  const rawPageSize = readU32(wal, 8);
  const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
  if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0) throw new Error("WAL 页大小无效。");
  if (databasePageSize(database) !== pageSize) throw new Error("数据库与 WAL 的页大小不一致。");

  const checksumLittleEndian = magic === 0x377f0682;
  let checksum = updateChecksum(wal, 0, 24, checksumLittleEndian, [0, 0]);
  if (checksum[0] !== readU32(wal, 24) || checksum[1] !== readU32(wal, 28)) throw new Error("WAL 文件头校验失败。");

  const frameSize = 24 + pageSize;
  const frames = Math.floor((wal.byteLength - 32) / frameSize);
  const salt1 = readU32(wal, 16);
  const salt2 = readU32(wal, 20);
  let lastCommit = -1;
  let databasePages = 0;
  let validFrames = 0;
  let invalidFrame: number | null = null;
  const sourcePages = Math.ceil(database.byteLength / pageSize);
  const frameDetails: SqliteWalFrameInfo[] = [];

  for (let index = 0; index < frames; index += 1) {
    const offset = 32 + index * frameSize;
    const pageNumber = readU32(wal, offset);
    const commitPages = readU32(wal, offset + 4);
    let reason = "";
    if (!pageNumber || readU32(wal, offset + 8) !== salt1 || readU32(wal, offset + 12) !== salt2) {
      invalidFrame = index + 1;
      reason = !pageNumber ? "invalid page number" : "salt mismatch";
      frameDetails.push({ index: index + 1, offset, pageNumber, commitPages, valid: false, committed: false, latestForPage: false, reason });
      break;
    }
    let nextChecksum = updateChecksum(wal, offset, 8, checksumLittleEndian, checksum);
    nextChecksum = updateChecksum(wal, offset + 24, pageSize, checksumLittleEndian, nextChecksum);
    if (nextChecksum[0] !== readU32(wal, offset + 16) || nextChecksum[1] !== readU32(wal, offset + 20)) {
      invalidFrame = index + 1;
      frameDetails.push({ index: index + 1, offset, pageNumber, commitPages, valid: false, committed: false, latestForPage: false, reason: "checksum mismatch" });
      break;
    }
    checksum = nextChecksum;
    validFrames = index + 1;
    frameDetails.push({ index: index + 1, offset, pageNumber, commitPages, valid: true, committed: false, latestForPage: false, reason: "" });
    if (commitPages) {
      // Each newly allocated database page must be represented by a frame.
      // Enforcing that bound prevents crafted commit markers from forcing huge allocations.
      if (commitPages > sourcePages + validFrames) {
        invalidFrame = index + 1;
        validFrames = index;
        frameDetails[index] = { ...frameDetails[index], valid: false, reason: "commit size exceeds available pages" };
        break;
      }
      lastCommit = index;
      databasePages = commitPages;
    }
  }

  const latestFrameByPage = new Map<number, number>();
  frameDetails.forEach((frame, index) => {
    if (!frame.valid || index > lastCommit) return;
    latestFrameByPage.set(frame.pageNumber, frame.index);
  });
  frameDetails.forEach((frame, index) => {
    frame.committed = frame.valid && index <= lastCommit;
    frame.latestForPage = frame.committed && latestFrameByPage.get(frame.pageNumber) === frame.index;
  });

  return {
    info: {
      pageSize,
      frames,
      validFrames,
      committedFrames: lastCommit + 1,
      databasePages,
      ignoredFrames: Math.max(0, frames - lastCommit - 1),
      invalidFrame,
      checksumVerified: true
    },
    frames: frameDetails,
    trailingBytes: Math.max(0, wal.byteLength - 32 - frames * frameSize)
  };
}

export function applySqliteWal(database: Uint8Array, wal: Uint8Array): { bytes: Uint8Array; info: SqliteWalInfo } {
  const inspection = inspectSqliteWal(database, wal);
  const { info } = inspection;
  if (!info.committedFrames) throw new Error("WAL 中没有完整提交，数据库未合并。");

  const outputSize = info.databasePages * info.pageSize;
  const output = new Uint8Array(outputSize);
  output.set(database.subarray(0, Math.min(database.byteLength, outputSize)));
  const frameSize = 24 + info.pageSize;
  for (let index = 0; index < info.committedFrames; index += 1) {
    const offset = 32 + index * frameSize;
    const pageNumber = readU32(wal, offset);
    if (!pageNumber || pageNumber > info.databasePages) continue;
    output.set(wal.subarray(offset + 24, offset + frameSize), (pageNumber - 1) * info.pageSize);
  }

  return {
    bytes: output,
    info
  };
}

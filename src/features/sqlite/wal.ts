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

export function applySqliteWal(database: Uint8Array, wal: Uint8Array): { bytes: Uint8Array; info: SqliteWalInfo } {
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

  for (let index = 0; index < frames; index += 1) {
    const offset = 32 + index * frameSize;
    const pageNumber = readU32(wal, offset);
    if (!pageNumber || readU32(wal, offset + 8) !== salt1 || readU32(wal, offset + 12) !== salt2) {
      invalidFrame = index + 1;
      break;
    }
    let nextChecksum = updateChecksum(wal, offset, 8, checksumLittleEndian, checksum);
    nextChecksum = updateChecksum(wal, offset + 24, pageSize, checksumLittleEndian, nextChecksum);
    if (nextChecksum[0] !== readU32(wal, offset + 16) || nextChecksum[1] !== readU32(wal, offset + 20)) {
      invalidFrame = index + 1;
      break;
    }
    checksum = nextChecksum;
    validFrames = index + 1;
    const commitPages = readU32(wal, offset + 4);
    if (commitPages) {
      // Each newly allocated database page must be represented by a frame.
      // Enforcing that bound prevents crafted commit markers from forcing huge allocations.
      if (commitPages > sourcePages + validFrames) {
        invalidFrame = index + 1;
        validFrames = index;
        break;
      }
      lastCommit = index;
      databasePages = commitPages;
    }
  }
  if (lastCommit < 0) throw new Error("WAL 中没有完整提交，数据库未合并。");

  const outputSize = databasePages * pageSize;
  const output = new Uint8Array(outputSize);
  output.set(database.subarray(0, Math.min(database.byteLength, outputSize)));
  for (let index = 0; index <= lastCommit; index += 1) {
    const offset = 32 + index * frameSize;
    const pageNumber = readU32(wal, offset);
    if (!pageNumber || pageNumber > databasePages) continue;
    output.set(wal.subarray(offset + 24, offset + frameSize), (pageNumber - 1) * pageSize);
  }

  return {
    bytes: output,
    info: {
      pageSize,
      frames,
      validFrames,
      committedFrames: lastCommit + 1,
      databasePages,
      ignoredFrames: Math.max(0, frames - lastCommit - 1),
      invalidFrame,
      checksumVerified: true
    }
  };
}

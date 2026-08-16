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

import { describe, expect, it } from "vitest";
import { annotateSqliteRecoveredRecords, recoverSqliteRecords, recoverSqliteTableLeafCell } from "../src/features/sqlite/recovery";
import { inspectSqliteDatabase } from "../src/features/sqlite/forensic";

function recordPayload(name = "alice", age = 42) {
  // Header: 3 bytes total, TEXT(5) serial type 23, 1-byte INTEGER serial type 1.
  if (new TextEncoder().encode(name).length !== 5) throw new Error("Synthetic SQLite record name must be exactly 5 bytes.");
  return Uint8Array.from([3, 23, 1, ...new TextEncoder().encode(name), age]);
}

function writeBe32(bytes: Uint8Array, offset: number, value: number) {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value, false);
}

function walChecksum(bytes: Uint8Array, offset: number, length: number, state: [number, number]): [number, number] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let [s0, s1] = state;
  for (let cursor = offset; cursor < offset + length; cursor += 8) {
    s0 = (s0 + view.getUint32(cursor, true) + s1) >>> 0;
    s1 = (s1 + view.getUint32(cursor + 4, true) + s0) >>> 0;
  }
  return [s0, s1];
}

function sqliteLeafPage(name: string, age: number, rowid: number) {
  const pageSize = 512;
  const page = new Uint8Array(pageSize);
  const view = new DataView(page.buffer);
  page.set(new TextEncoder().encode("SQLite format 3\0"));
  view.setUint16(16, pageSize, false);
  writeBe32(page, 28, 1);
  writeBe32(page, 56, 1);
  const payload = recordPayload(name, age);
  const cellOffset = 480;
  page[100] = 0x0d;
  view.setUint16(101, 0, false);
  view.setUint16(103, 1, false);
  view.setUint16(105, cellOffset, false);
  view.setUint16(108, cellOffset, false);
  page.set([payload.length, rowid, ...payload], cellOffset);
  return page;
}

function sqliteWalPages(pages: Uint8Array[]) {
  const pageSize = 512;
  const frameSize = 24 + pageSize;
  const wal = new Uint8Array(32 + frameSize * pages.length);
  writeBe32(wal, 0, 0x377f0682);
  writeBe32(wal, 4, 3007000);
  writeBe32(wal, 8, pageSize);
  writeBe32(wal, 16, 11);
  writeBe32(wal, 20, 22);
  let state = walChecksum(wal, 0, 24, [0, 0]);
  writeBe32(wal, 24, state[0]);
  writeBe32(wal, 28, state[1]);
  pages.forEach((page, index) => {
    const offset = 32 + frameSize * index;
    writeBe32(wal, offset, 1);
    writeBe32(wal, offset + 4, 1);
    writeBe32(wal, offset + 8, 11);
    writeBe32(wal, offset + 12, 22);
    wal.set(page, offset + 24);
    state = walChecksum(wal, offset, 8, state);
    state = walChecksum(wal, offset + 24, pageSize, state);
    writeBe32(wal, offset + 16, state[0]);
    writeBe32(wal, offset + 20, state[1]);
  });
  return wal;
}

describe("SQLite deleted-record reconstruction", () => {
  it("recovers an intact table-leaf-cell shaped residue with rowid", () => {
    const payload = recordPayload();
    const bytes = new Uint8Array(128);
    const offset = 24;
    bytes.set([payload.length, 7, ...payload], offset);

    const records = recoverSqliteRecords(bytes, [{
      pageNumber: 3,
      start: offset,
      end: offset + 2 + payload.length,
      area: "unallocated",
      source: "main"
    }], "UTF-8");

    const record = records.find((item) => item.recovery === "cell" && item.rowid === "7");
    expect(record).toBeTruthy();
    expect(record?.confidence).toBe("high");
    expect(record?.values.map((value) => [value.kind, value.value])).toEqual([["TEXT", "alice"], ["INTEGER", "42"]]);
  });

  it("recovers a payload-only candidate and keeps rowid unknown", () => {
    const payload = recordPayload();
    const bytes = new Uint8Array(128);
    const offset = 48;
    bytes.set(payload, offset);

    const records = recoverSqliteRecords(bytes, [{
      pageNumber: 5,
      start: offset,
      end: offset + payload.length,
      area: "freeblock",
      source: "main"
    }], "UTF-8");

    const record = records.find((item) => item.recovery === "record-payload" && item.payloadOffset === offset);
    expect(record).toBeTruthy();
    expect(record?.rowid).toBeNull();
    expect(record?.notes.join(" ")).toContain("rowid is unavailable");
  });


  it("recovers superseded table-leaf rows from historical committed WAL frames", () => {
    const database = sqliteLeafPage("prior", 10, 1);
    const wal = sqliteWalPages([sqliteLeafPage("alice", 42, 7), sqliteLeafPage("bravo", 43, 8)]);
    const result = inspectSqliteDatabase(database, wal);
    const historical = result.recoveredRecords.find((record) => record.area === "wal-frame" && record.walFrame === 1 && record.rowid === "7");
    expect(historical?.values.map((value) => value.value)).toEqual(["alice", "42"]);
    expect(historical?.notes.join(" ")).toContain("newer frame superseded");
    expect(result.recoveredRecords.some((record) => record.area === "wal-frame" && record.walFrame === 2)).toBe(false);
  });

  it("reconstructs a table-leaf payload across an overflow page", () => {
    const database = new Uint8Array(1024);
    database.set(new TextEncoder().encode("SQLite format 3\0"));
    new DataView(database.buffer).setUint16(16, 512, false);
    const text = "A".repeat(600);
    const serial = 13 + text.length * 2;
    const serialVarint = Uint8Array.from([0x80 | (serial >> 7), serial & 0x7f]);
    const payload = Uint8Array.from([3, ...serialVarint, ...new TextEncoder().encode(text)]);
    const cellOffset = 200;
    database.set([0x80 | (payload.length >> 7), payload.length & 0x7f, 1], cellOffset);
    const localBytes = 95;
    database.set(payload.subarray(0, localBytes), cellOffset + 3);
    new DataView(database.buffer).setUint32(cellOffset + 3 + localBytes, 2, false);
    new DataView(database.buffer).setUint32(512, 0, false);
    database.set(payload.subarray(localBytes), 516);

    const record = recoverSqliteTableLeafCell(database, cellOffset, 512, "UTF-8", { pageNumber: 1, area: "unallocated", source: "main" });
    expect(record).toMatchObject({ recovery: "cell-overflow", rowid: "1", overflowPages: [2], overflowBytes: payload.length - localBytes });
    expect(record?.values[0].kind).toBe("TEXT");
    expect(record?.values[0].value).toBe("A".repeat(500));
  });

  it("ranks candidate tables from live schema affinity without asserting a table", () => {
    const payload = recordPayload();
    const bytes = Uint8Array.from([payload.length, 9, ...payload]);
    const records = recoverSqliteRecords(bytes, [{ pageNumber: 1, start: 0, end: bytes.length, area: "unallocated", source: "main" }], "UTF-8");
    const annotated = annotateSqliteRecoveredRecords(records, [
      { table: "users", columns: [{ name: "name", type: "TEXT" }, { name: "age", type: "INTEGER" }] },
      { table: "blobs", columns: [{ name: "a", type: "BLOB" }, { name: "b", type: "BLOB" }] }
    ]);
    const record = annotated.find((item) => item.recovery === "cell" && item.rowid === "9");
    expect(record?.tableCandidates[0]).toMatchObject({ table: "users", score: 100 });
  });
});

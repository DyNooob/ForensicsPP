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

import { describe, expect, it } from "vitest";
import * as CFB from "cfb";
import { parseMsg } from "../src/features/email/msg";
import { parsePlist } from "../src/features/plist/analyzer";
import { parseRegistryHive } from "../src/features/registry/analyzer";
import { inspectSqliteDatabase } from "../src/features/sqlite/forensic";
import { sqliteObjectRisk, sqliteSensitiveHits, sqliteValueRisk } from "../src/features/sqlite/analyzer";
import { applySqliteWal, inspectSqliteWal } from "../src/features/sqlite/wal";

function writeBe32(bytes: Uint8Array, offset: number, value: number) {
  new DataView(bytes.buffer).setUint32(offset, value, false);
}

function checksum(bytes: Uint8Array, offset: number, length: number, state: [number, number]): [number, number] {
  const view = new DataView(bytes.buffer);
  let [s0, s1] = state;
  for (let cursor = offset; cursor < offset + length; cursor += 8) {
    s0 = (s0 + view.getUint32(cursor, true) + s1) >>> 0;
    s1 = (s1 + view.getUint32(cursor + 4, true) + s0) >>> 0;
  }
  return [s0, s1];
}

function sqliteDatabase(pageSize = 512) {
  const bytes = new Uint8Array(pageSize);
  bytes.set(new TextEncoder().encode("SQLite format 3\0"));
  new DataView(bytes.buffer).setUint16(16, pageSize === 65536 ? 1 : pageSize, false);
  return bytes;
}

function sqliteWal(frameCommits: number[]) {
  const pageSize = 512;
  const frameSize = 24 + pageSize;
  const wal = new Uint8Array(32 + frameSize * frameCommits.length);
  writeBe32(wal, 0, 0x377f0682);
  writeBe32(wal, 4, 3007000);
  writeBe32(wal, 8, pageSize);
  writeBe32(wal, 16, 11);
  writeBe32(wal, 20, 22);
  let state = checksum(wal, 0, 24, [0, 0]);
  writeBe32(wal, 24, state[0]);
  writeBe32(wal, 28, state[1]);
  frameCommits.forEach((commitPages, index) => {
    const offset = 32 + frameSize * index;
    writeBe32(wal, offset, 1);
    writeBe32(wal, offset + 4, commitPages);
    writeBe32(wal, offset + 8, 11);
    writeBe32(wal, offset + 12, 22);
    wal[offset + 24] = index + 7;
    state = checksum(wal, offset, 8, state);
    state = checksum(wal, offset + 24, pageSize, state);
    writeBe32(wal, offset + 16, state[0]);
    writeBe32(wal, offset + 20, state[1]);
  });
  return wal;
}

function sqliteForensicDatabase() {
  const pageSize = 512;
  const bytes = new Uint8Array(pageSize * 3);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("SQLite format 3\0"));
  view.setUint16(16, pageSize, false);
  writeBe32(bytes, 28, 3);
  writeBe32(bytes, 32, 3);
  writeBe32(bytes, 36, 1);
  writeBe32(bytes, 56, 1);
  bytes[100] = 0x0d;
  view.setUint16(105, pageSize, false);
  bytes[pageSize] = 0x0d;
  view.setUint16(pageSize + 1, 300, false);
  view.setUint16(pageSize + 5, 280, false);
  view.setUint16(pageSize + 300, 0, false);
  view.setUint16(pageSize + 302, 32, false);
  bytes.set(new TextEncoder().encode("deleted-note-fragment"), pageSize + 304);
  bytes.set(new TextEncoder().encode("freelist-text-fragment"), pageSize * 2 + 16);
  return bytes;
}

function registryFixture(sequence2 = 1) {
  const bytes = new Uint8Array(0x2000);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("regf"));
  view.setUint32(0x04, 1, true);
  view.setUint32(0x08, sequence2, true);
  view.setUint32(0x14, 1, true);
  view.setUint32(0x18, 5, true);
  view.setUint32(0x1c, 0, true);
  view.setUint32(0x20, 1, true);
  view.setUint32(0x24, 0x20, true);
  view.setUint32(0x28, 0x1000, true);
  bytes.set(new TextEncoder().encode("hbin"), 0x1000);
  view.setUint32(0x1004, 0, true);
  view.setUint32(0x1008, 0x1000, true);
  const root = 0x1020;
  view.setInt32(root, -0x80, true);
  bytes.set(new TextEncoder().encode("nk"), root + 4);
  view.setUint16(root + 6, 0x20, true);
  view.setUint32(root + 4 + 28, 0xffffffff, true);
  view.setUint32(root + 4 + 36, 1, true);
  view.setUint32(root + 4 + 40, 0xa0, true);
  view.setUint16(root + 4 + 72, 4, true);
  bytes.set(new TextEncoder().encode("ROOT"), root + 4 + 76);
  const valueList = 0x10a0;
  view.setInt32(valueList, -0x10, true);
  view.setUint32(valueList + 4, 0xb0, true);
  const value = 0x10b0;
  view.setInt32(value, -0x28, true);
  bytes.set(new TextEncoder().encode("vk"), value + 4);
  view.setUint16(value + 6, 4, true);
  view.setUint32(value + 8, 0x80000004, true);
  view.setUint32(value + 12, 42, true);
  view.setUint32(value + 16, 4, true);
  view.setUint16(value + 20, 1, true);
  bytes.set(new TextEncoder().encode("Test"), value + 24);
  let headerChecksum = 0;
  for (let offset = 0; offset < 0x1fc; offset += 4) headerChecksum = (headerChecksum ^ view.getUint32(offset, true)) >>> 0;
  view.setUint32(0x1fc, headerChecksum, true);
  return bytes;
}

describe("SQLite WAL", () => {
  it("applies frames through the last commit", () => {
    const database = sqliteDatabase();
    const wal = sqliteWal([1, 0]);

    const result = applySqliteWal(database, wal);
    expect(result.bytes[0]).toBe(7);
    expect(result.info.committedFrames).toBe(1);
    expect(result.info.ignoredFrames).toBe(1);
    expect(result.info.validFrames).toBe(2);
    expect(result.info.checksumVerified).toBe(true);
  });

  it("ignores a corrupt tail after the last complete commit", () => {
    const wal = sqliteWal([1, 0]);
    wal[32 + 24 + 512 + 24] ^= 0xff;
    const result = applySqliteWal(sqliteDatabase(), wal);
    expect(result.bytes[0]).toBe(7);
    expect(result.info.invalidFrame).toBe(2);
    expect(result.info.validFrames).toBe(1);
  });

  it("rejects a WAL whose page size does not match the database", () => {
    expect(() => applySqliteWal(sqliteDatabase(1024), sqliteWal([1]))).toThrow(/页大小/);
  });

  it("rejects a commit size that cannot be produced by its frames", () => {
    expect(() => applySqliteWal(sqliteDatabase(), sqliteWal([1000]))).toThrow(/完整提交/);
  });

  it("lists committed and uncommitted frames without merging the tail", () => {
    const inspection = inspectSqliteWal(sqliteDatabase(), sqliteWal([1, 0]));
    expect(inspection.info.committedFrames).toBe(1);
    expect(inspection.frames).toMatchObject([
      { index: 1, pageNumber: 1, committed: true, latestForPage: true },
      { index: 2, pageNumber: 1, committed: false, latestForPage: false }
    ]);
  });
});

describe("SQLite forensic pages", () => {
  it("maps b-tree and freelist pages and keeps text hits tied to offsets", () => {
    const result = inspectSqliteDatabase(sqliteForensicDatabase());
    expect(result.header.pageSize).toBe(512);
    expect(result.pages.map((page) => page.kind)).toEqual(["database-header", "table-leaf", "freelist-trunk"]);
    expect(result.pages[1].firstFreeblock).toBe(300);
    expect(result.fragments).toEqual(expect.arrayContaining([
      expect.objectContaining({ pageNumber: 2, area: "freeblock", text: "deleted-note-fragment" }),
      expect.objectContaining({ pageNumber: 3, area: "freelist", text: "freelist-text-fragment" })
    ]));
  });

  it("keeps the main database available when an attached WAL is invalid", () => {
    const result = inspectSqliteDatabase(sqliteForensicDatabase(), new Uint8Array(64));
    expect(result.pages).toHaveLength(3);
    expect(result.wal).toBeNull();
    expect(result.walError).toMatch(/WAL/);
  });
});

describe("SQLite triage markers", () => {
  it("marks only useful high-signal values", () => {
    expect(sqliteValueRisk("password", "secret-value")).toEqual(["sensitive column name"]);
    expect(sqliteValueRisk("url", "https://example.test/path")).toContain("URL value");
    expect(sqliteValueRisk("contact", "analyst@example.test")).toContain("email value");
    expect(sqliteValueRisk("remote_ip", "192.168.1.10")).toContain("IPv4 value");
    expect(sqliteValueRisk("token", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature")).toContain("JWT-like value");
    expect(sqliteValueRisk("digest", "900150983cd24fb0d6963f7d28e17f72")).toContain("hash-like MD5-like");
    expect(sqliteValueRisk("notes", new Uint8Array([0x41, 0x42]))).toEqual([]);
  });

  it("reports sensitive rows and structural SQLite actions", () => {
    const data = {
      columns: ["id", "email", "password"],
      values: [[1, "analyst@example.test", "secret-value"]] as Array<[number, string, string]>,
      rowids: [7],
      editable: true,
      message: "1/1 rows",
      totalRows: 1
    };
    expect(sqliteSensitiveHits(data)).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: "Email", column: "email", rowid: 7 }),
      expect.objectContaining({ type: "Sensitive Column", column: "password", rowid: 7 })
    ]));
    expect(sqliteObjectRisk("trigger", "cleanup", "CREATE TRIGGER cleanup AS ATTACH DATABASE 'other.db' AS other;")).toEqual(["attaches external database"]);
    expect(sqliteObjectRisk("view", "load", "SELECT load_extension('x')")).toEqual(["loads SQLite extension"]);
  });
});

describe("binary Plist", () => {
  it("reads a simple dictionary", () => {
    const bytes = new Uint8Array(50);
    bytes.set(new TextEncoder().encode("bplist00"));
    bytes.set([0x51, 0x61, 0x51, 0x62, 0xd1, 0x00, 0x01, 8, 10, 12], 8);
    const trailer = 18;
    bytes[trailer + 6] = 1;
    bytes[trailer + 7] = 1;
    new DataView(bytes.buffer).setBigUint64(trailer + 8, 3n, false);
    new DataView(bytes.buffer).setBigUint64(trailer + 16, 2n, false);
    new DataView(bytes.buffer).setBigUint64(trailer + 24, 15n, false);
    expect(parsePlist(bytes).value).toEqual({ a: "b" });
  });
});

describe("Registry Hive", () => {
  it("reads the root NK cell and an inline DWORD value", () => {
    const result = parseRegistryHive(registryFixture());
    expect(result.keys[0].name).toBe("ROOT");
    expect(result.keys[0].values).toContainEqual({ name: "Test", type: "REG_DWORD", value: "42", size: 4 });
    expect(result.warnings).toEqual([]);
  });

  it("reports a dirty hive sequence without rejecting readable data", () => {
    const result = parseRegistryHive(registryFixture(2));
    expect(result.dirty).toBe(true);
    expect(result.warnings[0]).toMatch(/序列号/);
  });

  it("rejects a REGF header without an HBIN data block", () => {
    const bytes = registryFixture();
    bytes.fill(0, 0x1000, 0x1004);
    expect(() => parseRegistryHive(bytes)).toThrow(/HBIN/);
  });

  it("does not read cells from trailing data outside the declared HBIN area", () => {
    const source = registryFixture();
    const bytes = new Uint8Array(0x2100);
    bytes.set(source);
    new DataView(bytes.buffer).setUint32(0x24, 0x1000, true);
    expect(() => parseRegistryHive(bytes)).toThrow(/偏移越界/);
  });
});

describe("Outlook MSG", () => {
  it("maps MAPI streams into the email workbench", async () => {
    const container = CFB.utils.cfb_new();
    const utf16 = (value: string) => new Uint8Array(Array.from(new TextEncoder().encode(`${value}\0`)).flatMap((byte) => [byte, 0]));
    CFB.utils.cfb_add(container, "__substg1.0_0037001F", utf16("Fixture subject"));
    CFB.utils.cfb_add(container, "__substg1.0_0C1A001F", utf16("Sender"));
    CFB.utils.cfb_add(container, "__substg1.0_5D01001F", utf16("sender@example.test"));
    CFB.utils.cfb_add(container, "__substg1.0_0E04001F", utf16("recipient@example.test"));
    CFB.utils.cfb_add(container, "__substg1.0_1000001F", utf16("Message body"));
    CFB.utils.cfb_add(container, "__attach_version1.0_#00000000/__substg1.0_3707001F", utf16("note.txt"));
    CFB.utils.cfb_add(container, "__attach_version1.0_#00000000/__substg1.0_37010102", new TextEncoder().encode("attachment"));
    const bytes = new Uint8Array(CFB.write(container, { type: "array", fileType: "cfb" }) as number[]);
    const result = await parseMsg(bytes);
    expect(result.analysis.rows).toContainEqual(["Subject", "Fixture subject"]);
    expect(result.analysis.bodyText).toBe("Message body");
    expect(result.analysis.attachments[0].filename).toBe("note.txt");
  });

  it("rejects a generic OLE compound file without MAPI properties", async () => {
    const container = CFB.utils.cfb_new();
    CFB.utils.cfb_add(container, "Document", new TextEncoder().encode("not a message"));
    const bytes = new Uint8Array(CFB.write(container, { type: "array", fileType: "cfb" }) as number[]);
    await expect(parseMsg(bytes)).rejects.toThrow(/MSG|邮件属性流/);
  });
});

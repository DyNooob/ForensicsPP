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

import { describe, expect, it } from "vitest";
import { zipSync } from "fflate";
import { analyzeIocs } from "../src/features/ioc/analyzer";
import { parseSqlDump } from "../src/features/sql/analyzer";
import { coerceSqliteEditValue, loadSqliteTableRows, quoteSqlIdentifier, quoteSqlLiteral, sqliteFilterWhere, sqliteHexDump, sqliteInternalRowidIdentifier, sqliteRowsToCsv } from "../src/features/sqlite/analyzer";
import { parseFatPackedDateTime, parseMongoObjectIdTimestamp, parseTimestampCandidates, parseUlidTimestamp } from "../src/features/timestamp/analyzer";
import { parseArchiveEntries } from "../src/tools/ArchiveTool";

describe("forensic timestamp identifiers", () => {
  it("decodes a known ULID timestamp", () => {
    expect(parseUlidTimestamp("01ARZ3NDEKTSV4RRFFQ69G5FAV")).toBe(1469922850259);
  });

  it("decodes the timestamp prefix of a MongoDB ObjectId", () => {
    expect(parseMongoObjectIdTimestamp("507f1f77bcf86cd799439011")).toBe(1350508407000);
  });

  it("decodes a FAT packed timestamp", () => {
    const packed = ((2026 - 1980) << 25) | (7 << 21) | (12 << 16) | (14 << 11) | (35 << 5) | 14;
    expect(parseFatPackedDateTime(packed)).toBe(Date.UTC(2026, 6, 12, 14, 35, 28));
  });

  it("keeps event identity separate when two sources share the same line", () => {
    const first = parseTimestampCandidates("event at 2026-07-12T14:35:28Z", "auth.log")[0];
    const second = parseTimestampCandidates("event at 2026-07-12T14:35:28Z", "system.log")[0];

    expect(first?.source).toBe("auth.log");
    expect(second?.source).toBe("system.log");
    expect(first?.id).not.toBe(second?.id);
  });
});

describe("archive directory parsing", () => {
  it("reads names and sizes from the ZIP central directory", () => {
    const archive = zipSync({
      "folder/readme.txt": new TextEncoder().encode("hello"),
      "empty.bin": new Uint8Array()
    });
    const result = parseArchiveEntries(archive);
    expect(result.skipped).toBe(0);
    expect(result.entries.map((entry) => entry.name)).toEqual(["folder/readme.txt", "empty.bin"]);
    expect(result.entries[0].uncompressed).toBe(5);
  });
});

describe("SQL dump parsing", () => {
  it("preserves columns, escaped strings, NULL and row order", () => {
    const sql = `
      CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, note TEXT);
      INSERT INTO users (id, name, note) VALUES
        (1, 'Alice', 'first'),
        (2, 'Bob', NULL),
        (3, 'O''Brien', 'line\\nvalue');
    `;
    const result = parseSqlDump(sql, "fixture.sql", sql.length);
    expect(result.tables).toHaveLength(1);
    expect(result.tables[0].columns.map((column) => column.name)).toEqual(["id", "name", "note"]);
    expect(result.tables[0].rows).toEqual([
      { id: "1", name: "Alice", note: "first" },
      { id: "2", name: "Bob", note: "NULL" },
      { id: "3", name: "O'Brien", note: "line\nvalue" }
    ]);
  });
});

describe("SQLite value helpers", () => {
  it("quotes identifiers and literals safely", () => {
    expect(quoteSqlIdentifier('event"name')).toBe('"event""name"');
    expect(quoteSqlLiteral("O'Brien")).toBe("'O''Brien'");
  });

  it("preserves numeric and blob value types while editing", () => {
    expect(coerceSqliteEditValue(10, "42")).toBe(42);
    expect(coerceSqliteEditValue(new Uint8Array([0]), "00ff")).toEqual(new Uint8Array([0, 255]));
    expect(coerceSqliteEditValue("value", "NULL")).toBeNull();
  });

  it("escapes exported CSV values", () => {
    expect(sqliteRowsToCsv(["id", "note"], [[1, "a,b"], [2, "line\nvalue"]])).toBe('id,note\n1,"a,b"\n2,"line\nvalue"');
  });

  it("filters only a verified column and escapes LIKE wildcards", () => {
    const columns = [
      { name: "id", type: "INTEGER", notNull: true, defaultValue: "NULL", primaryKey: true },
      { name: "note", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false }
    ];
    expect(sqliteFilterWhere(columns, "50%_off", "note")).toContain('CAST("note" AS TEXT)');
    expect(sqliteFilterWhere(columns, "50%_off", "note")).toContain("%50\\%\\_off%");
    expect(sqliteFilterWhere(columns, "value", 'note\" OR 1=1')).toBe("");
  });

  it("renders a readable BLOB hex dump", () => {
    const dump = sqliteHexDump(new Uint8Array([0x41, 0x00, 0xff, 0x42]));
    expect(dump).toContain("00000000  41 00 FF 42");
    expect(dump).toContain("A..B");
  });

  it("keeps a real column named like the internal rowid alias", () => {
    const queries: string[] = [];
    const result = loadSqliteTableRows(
      {
        exec: (sql) => {
          queries.push(sql);
          if (sql.startsWith("SELECT COUNT")) return [{ columns: ["COUNT(*)"], values: [[1]] }];
          return [{ columns: ["___forensicspp_rowid__", "id", "__forensicspp_rowid__", "note"], values: [[7, 1, "real-column", "value"]] }];
        }
      },
      { name: "records", type: "table", sql: "", rows: 1, columns: 3 },
      [
        { name: "id", type: "INTEGER", notNull: true, defaultValue: "NULL", primaryKey: true },
        { name: "__forensicspp_rowid__", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false },
        { name: "note", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false }
      ],
      100,
      0,
      "",
      "",
      "asc"
    );
    expect(queries.some((query) => query.includes('AS "___forensicspp_rowid__"'))).toBe(true);
    expect(result.columns).toEqual(["id", "__forensicspp_rowid__", "note"]);
    expect(result.rowids).toEqual([7]);
    expect(result.values).toEqual([[1, "real-column", "value"]]);
  });

  it("does not treat a user rowid column as SQLite's internal rowid", () => {
    expect(sqliteInternalRowidIdentifier([
      { name: "rowid", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false },
      { name: "_rowid_", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false }
    ])).toBe("oid");
    expect(sqliteInternalRowidIdentifier([
      { name: "rowid", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false },
      { name: "_rowid_", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false },
      { name: "oid", type: "TEXT", notNull: false, defaultValue: "NULL", primaryKey: false }
    ])).toBeNull();
  });
});

describe("IOC extraction", () => {
  it("refangs, deduplicates and records sightings", () => {
    const result = analyzeIocs("hxxps://example[.]com/a\nexample.com\nexample.com\nCVE-2026-12345", "fixture");
    const domain = result.records.find((record) => record.type === "Domain" && record.normalized === "example.com");
    expect(domain).toBeDefined();
    expect(domain?.count).toBeGreaterThanOrEqual(2);
    expect(result.records.some((record) => record.type === "CVE" && record.normalized === "cve-2026-12345")).toBe(true);
  });
});

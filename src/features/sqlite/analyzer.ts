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

import { fileSignatureForBytes, hexPreview, previewText } from "../../utils/binary";
import { formatBytes, limitReportText } from "../../utils/files";
import { detectHashType } from "../../utils/hash";
import type {
  SqliteCellSelection,
  SqliteChangeLog,
  SqliteColumnInfo,
  SqliteColumnProfile,
  SqliteContentHit,
  SqliteDataSet,
  SqliteIndexInfo,
  SqliteObjectInfo,
  SqliteQueryHistoryEntry,
  SqliteQueryTemplate,
  SqliteTableInfo,
  SqliteValue
} from "../../models";

export function quoteSqlIdentifier(value: string) {
  return `"${value.replace(/"/g, "\"\"")}"`;
}

export function quoteSqlLiteral(value: string) {
  return `'${value.replace(/'/g, "''")}'`;
}

export function displaySqliteValue(value: SqliteValue) {
  if (value === null) return "NULL";
  if (value instanceof Uint8Array) return `BLOB ${formatBytes(value.byteLength)}`;
  return String(value);
}

export function editableSqliteValue(value: SqliteValue) {
  if (value === null) return "";
  if (value instanceof Uint8Array) return Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return String(value);
}

export function coerceSqliteEditValue(original: SqliteValue, value: string): SqliteValue {
  if (value.toUpperCase() === "NULL") return null;
  if (typeof original === "number" && value.trim() !== "" && Number.isFinite(Number(value))) return Number(value);
  if (original instanceof Uint8Array && /^(?:[0-9a-fA-F]{2})*$/.test(value.trim())) {
    const hex = value.trim();
    return new Uint8Array(Array.from({ length: hex.length / 2 }, (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)));
  }
  return value;
}

export function coerceSqliteColumnValue(column: SqliteColumnInfo, value: string): SqliteValue {
  const trimmed = value.trim();
  if (trimmed.toUpperCase() === "NULL") return null;
  if (!trimmed && !column.notNull) return null;
  if (/\b(INT|REAL|NUM|DEC|DOUBLE|FLOAT|BOOL)\b/i.test(column.type) && Number.isFinite(Number(trimmed))) return Number(trimmed);
  if (/\bBLOB\b/i.test(column.type) && /^(?:[0-9a-fA-F]{2})+$/.test(trimmed)) {
    return new Uint8Array(Array.from({ length: trimmed.length / 2 }, (_, index) => Number.parseInt(trimmed.slice(index * 2, index * 2 + 2), 16)));
  }
  return value;
}

export function sqliteRowsToCsv(columns: string[], values: SqliteValue[][]) {
  const escapeCell = (value: SqliteValue | string) => {
    const text = typeof value === "string" ? value : displaySqliteValue(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [columns.map(escapeCell).join(","), ...values.map((row) => row.map(escapeCell).join(","))].join("\n");
}

export function sqliteRowsToJson(columns: string[], values: SqliteValue[][]) {
  return JSON.stringify(values.map((row) => Object.fromEntries(columns.map((column, index) => [column, displaySqliteValue(row[index] ?? null)]))), null, 2);
}

export function sqliteValueKind(value: SqliteValue) {
  if (value === null) return "NULL";
  if (value instanceof Uint8Array) return "BLOB";
  if (typeof value === "number") return Number.isInteger(value) ? "INTEGER" : "REAL";
  return "TEXT";
}

export function sqliteValueSize(value: SqliteValue) {
  if (value === null) return 0;
  if (value instanceof Uint8Array) return value.byteLength;
  return new Blob([String(value)]).size;
}

export function sqliteValueBytes(value: SqliteValue) {
  if (value === null) return new Uint8Array();
  if (value instanceof Uint8Array) return value;
  return new TextEncoder().encode(String(value));
}

export function sqliteValueSignature(value: SqliteValue) {
  const bytes = sqliteValueBytes(value);
  if (!bytes.length) return "--";
  return fileSignatureForBytes(bytes)?.label ?? "Binary";
}

export function sqliteValueExportExtension(value: SqliteValue) {
  if (!(value instanceof Uint8Array)) return "txt";
  const signature = fileSignatureForBytes(value);
  if (!signature) return "bin";
  return signature.extensions[0] ?? "bin";
}

export function sqliteCellPreviewRows(value: SqliteValue): Array<[string, string]> {
  if (value === null) return [["Text preview", "NULL"], ["Hex preview", "--"]];
  const bytes = sqliteValueBytes(value);
  return [
    ["Signature", sqliteValueSignature(value)],
    ["Text preview", previewText(bytes, 1200) || "--"],
    ["Hex preview", hexPreview(bytes, 160)]
  ];
}

export function sqliteValueRisk(column: string, value: SqliteValue) {
  const text = displaySqliteValue(value);
  const risks = [
    /(pass(word)?|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|refresh[_-]?token|client[_-]?secret|session|cookie|auth|jwt|bearer|credential|salt|hash)/i.test(column) ? "sensitive column name" : "",
    /\bhttps?:\/\/[^\s"'<>]+/i.test(text) ? "URL value" : "",
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(text) ? "email value" : "",
    /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/.test(text) ? "IPv4 value" : "",
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text) ? "JWT-like value" : "",
    /(?:AKIA|ASIA)[A-Z0-9]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,}|sk-[A-Za-z0-9_-]{24,}|-----BEGIN [A-Z ]+PRIVATE KEY-----/i.test(text) ? "known secret pattern" : "",
    detectHashType(text) ? `hash-like ${detectHashType(text)}` : "",
    text.length > 512 ? "long value" : "",
    value instanceof Uint8Array && value.byteLength > 0 ? "blob value" : ""
  ].filter(Boolean);
  return Array.from(new Set(risks));
}

export function sqliteColumnProfiles(data: SqliteDataSet, columns: SqliteColumnInfo[]): SqliteColumnProfile[] {
  const columnType = new Map(columns.map((column) => [column.name, column.type || "--"]));
  return data.columns.map((column, columnIndex) => {
    const values = data.values.map((row) => row[columnIndex] ?? null);
    const distinct = new Set(values.slice(0, 1000).map(displaySqliteValue));
    const risk = new Set<string>();
    values.slice(0, 300).forEach((value) => sqliteValueRisk(column, value).forEach((item) => risk.add(item)));
    return {
      column,
      type: columnType.get(column) ?? "--",
      nulls: values.filter((value) => value === null).length,
      distinct: distinct.size,
      numeric: values.filter((value) => typeof value === "number").length,
      text: values.filter((value) => typeof value === "string").length,
      blob: values.filter((value) => value instanceof Uint8Array).length,
      risk: Array.from(risk),
      sample: values.map(displaySqliteValue).find((value) => value !== "NULL" && value !== "") ?? "--"
    };
  });
}

export function sqliteSensitiveHits(data: SqliteDataSet) {
  const hits: SqliteContentHit[] = [];
  data.values.slice(0, 500).forEach((row, rowIndex) => {
    data.columns.forEach((column, columnIndex) => {
      const value = row[columnIndex] ?? null;
      const risk = sqliteValueRisk(column, value);
      if (!risk.length) return;
      const display = displaySqliteValue(value);
      const type = risk.includes("known secret pattern")
        ? "Secret"
        : risk.some((item) => item.startsWith("hash-like"))
        ? "Hash"
        : risk.includes("URL value")
        ? "URL"
        : risk.includes("JWT-like value")
        ? "JWT"
        : risk.includes("email value")
        ? "Email"
        : risk.includes("IPv4 value")
        ? "IPv4"
        : risk.includes("sensitive column name")
        ? "Sensitive Column"
        : sqliteValueKind(value);
      hits.push({
        rowIndex,
        rowid: data.rowids[rowIndex] ?? null,
        column,
        type,
        value: display,
        risk
      });
    });
  });
  return hits.slice(0, 500);
}

export function sqliteDefaultCellSelection(data: SqliteDataSet): SqliteCellSelection | null {
  if (!data.columns.length || !data.values.length) return null;
  let best: SqliteCellSelection | null = null;
  let bestScore = -Infinity;
  data.values.slice(0, Math.min(data.values.length, 80)).forEach((row, rowIndex) => {
    data.columns.forEach((column, columnIndex) => {
      const value = row[columnIndex] ?? null;
      const text = displaySqliteValue(value);
      const lowered = column.toLowerCase();
      const risk = sqliteValueRisk(column, value);
      const score = (
        risk.length * 120
        + (/pass|token|secret|key|session|cookie|auth|jwt|credential/i.test(lowered) ? 160 : 0)
        + (/url|uri|link|host|domain|ip|email|mail|phone|path|file|name|title/i.test(lowered) ? 80 : 0)
        + (/(time|date|created|updated|modified|deleted|expires|timestamp|last)/i.test(lowered) ? 45 : 0)
        + (value instanceof Uint8Array && value.byteLength ? 70 : 0)
        + (text && text !== "NULL" ? Math.min(text.length, 80) / 8 : -80)
        + (/^(id|rowid|pk)$/i.test(column) ? -140 : 0)
      );
      if (score > bestScore) {
        bestScore = score;
        best = {
          rowIndex,
          columnIndex,
          column,
          rowid: data.rowids[rowIndex] ?? null,
          value
        };
      }
    });
  });
  if (best) return best;
  const columnIndex = Math.max(0, data.columns.findIndex((column) => !/^(id|rowid)$/i.test(column)));
  return {
    rowIndex: 0,
    columnIndex,
    column: data.columns[columnIndex],
    rowid: data.rowids[0] ?? null,
    value: data.values[0]?.[columnIndex] ?? null
  };
}

export function sqliteEmptyDataSet(message = ""): SqliteDataSet {
  return { columns: [], values: [], rowids: [], editable: false, message, totalRows: null };
}

export function getSqliteTables(db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> }) {
  const rows = db.exec("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY type, name")[0]?.values ?? [];
  return rows.map((row) => {
    const name = String(row[0] ?? "");
    const type = String(row[1] ?? "");
    const sql = String(row[2] ?? "");
    let count: number | null = null;
    let columns = 0;
    try {
      const countValue = db.exec(`SELECT COUNT(*) FROM ${quoteSqlIdentifier(name)}`)[0]?.values?.[0]?.[0];
      count = typeof countValue === "number" ? countValue : Number(countValue);
    } catch {
      count = null;
    }
    try {
      columns = db.exec(`PRAGMA table_info(${quoteSqlIdentifier(name)})`)[0]?.values.length ?? 0;
    } catch {
      columns = 0;
    }
    return { name, type, sql, rows: Number.isFinite(count) ? count : null, columns };
  });
}

export function sqliteObjectRisk(type: string, name: string, sql: string) {
  const risks = [
    /^sqlite_/i.test(name) ? "internal sqlite object" : "",
    type === "trigger" ? "trigger changes data automatically" : "",
    /\b(delete|drop|update|insert|replace)\b/i.test(sql) && type === "trigger" ? "mutating trigger" : "",
    /\b(load_extension|attach\s+database|pragma\s+writable_schema)\b/i.test(sql) ? "dangerous SQL capability" : "",
    /password|token|secret|credential|auth|session|cookie|key/i.test(`${name} ${sql}`) ? "sensitive-name marker" : ""
  ].filter(Boolean);
  return Array.from(new Set(risks));
}

export function getSqliteObjects(db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> }): SqliteObjectInfo[] {
  const rows = db.exec("SELECT name, type, tbl_name, rootpage, sql FROM sqlite_master ORDER BY type, tbl_name, name")[0]?.values ?? [];
  return rows.map((row) => {
    const name = String(row[0] ?? "");
    const type = String(row[1] ?? "");
    const tblName = String(row[2] ?? "");
    const rootpage = row[3] == null ? null : Number(row[3]);
    const sql = String(row[4] ?? "");
    return {
      name,
      type,
      tblName,
      rootpage: Number.isFinite(rootpage) ? rootpage : null,
      sql,
      risk: sqliteObjectRisk(type, name, sql)
    };
  });
}

export function getSqliteIndexInfo(db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> }, table: string): SqliteIndexInfo[] {
  const rows = db.exec(`PRAGMA index_list(${quoteSqlIdentifier(table)})`)[0]?.values ?? [];
  return rows.map((row) => {
    const name = String(row[1] ?? "");
    const detailRows = db.exec(`PRAGMA index_info(${quoteSqlIdentifier(name)})`)[0]?.values ?? [];
    return {
      name,
      unique: Number(row[2] ?? 0) === 1,
      origin: String(row[3] ?? ""),
      partial: Number(row[4] ?? 0) === 1,
      columns: detailRows.map((detail) => String(detail[2] ?? "")).filter(Boolean)
    };
  });
}

export function getSqlitePragmaRows(db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> }): Array<[string, string]> {
  const readOne = (sql: string) => {
    try {
      return displaySqliteValue(db.exec(sql)[0]?.values?.[0]?.[0] ?? null);
    } catch {
      return "--";
    }
  };
  return [
    ["SQLite version", readOne("SELECT sqlite_version()")],
    ["Page count", readOne("PRAGMA page_count")],
    ["Page size", readOne("PRAGMA page_size")],
    ["Freelist pages", readOne("PRAGMA freelist_count")],
    ["Journal mode", readOne("PRAGMA journal_mode")],
    ["Auto vacuum", readOne("PRAGMA auto_vacuum")],
    ["Encoding", readOne("PRAGMA encoding")],
    ["User version", readOne("PRAGMA user_version")],
    ["Application ID", readOne("PRAGMA application_id")],
    ["Foreign keys", readOne("PRAGMA foreign_keys")],
    ["Integrity check", readOne("PRAGMA quick_check")]
  ];
}

export function sqliteFindings(fileName: string, objects: SqliteObjectInfo[], tables: SqliteTableInfo[], pragmaRows: Array<[string, string]>) {
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  const triggers = objects.filter((object) => object.type === "trigger");
  const views = objects.filter((object) => object.type === "view");
  const indexes = objects.filter((object) => object.type === "index");
  const internal = tables.filter((table) => /^sqlite_/i.test(table.name));
  const sensitive = objects.filter((object) => /password|token|secret|credential|auth|session|cookie|key|history|message|chat|account/i.test(`${object.name} ${object.sql}`));
  const riskyObjects = objects.filter((object) => object.risk.length);
  const quickCheck = pragmaRows.find(([key]) => key === "Integrity check")?.[1] ?? "";
  if (!objects.length) findings.push({ level: "warn", title: "No sqlite_master objects", detail: "The database opened, but no schema objects were listed." });
  if (quickCheck && quickCheck !== "ok" && quickCheck !== "--") findings.push({ level: "danger", title: "SQLite quick_check anomaly", detail: quickCheck });
  if (triggers.length) findings.push({ level: "warn", title: "Triggers present", detail: triggers.slice(0, 12).map((object) => object.name).join(", ") });
  if (views.length) findings.push({ level: "info", title: "Views present", detail: views.slice(0, 12).map((object) => object.name).join(", ") });
  if (!indexes.length && tables.some((table) => table.type === "table")) findings.push({ level: "info", title: "No user indexes found", detail: "Queries on larger evidence tables may be slow; verify table row counts before broad filtering." });
  if (internal.length) findings.push({ level: "info", title: "SQLite internal tables", detail: internal.map((table) => table.name).join(", ") });
  if (sensitive.length) findings.push({ level: "warn", title: "Sensitive schema names", detail: sensitive.slice(0, 12).map((object) => `${object.type}:${object.name}`).join(", ") });
  if (riskyObjects.length) findings.push({ level: "warn", title: "Schema objects worth review", detail: riskyObjects.slice(0, 12).map((object) => `${object.type}:${object.name} (${object.risk.join(", ")})`).join("\n") });
  if (/\b(history|cache|cookies|webcache|sms|chat|message|contacts|calls|location)\b/i.test(fileName)) findings.push({ level: "info", title: "Evidence-oriented filename", detail: fileName });
  if (!findings.length) findings.push({ level: "info", title: "SQLite database opened", detail: `${tables.length} table/view object(s) available for local browsing, editing, and export.` });
  return findings;
}

export function getSqliteColumns(db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> }, table: string): SqliteColumnInfo[] {
  const values = db.exec(`PRAGMA table_info(${quoteSqlIdentifier(table)})`)[0]?.values ?? [];
  return values.map((row) => ({
    name: String(row[1] ?? ""),
    type: String(row[2] ?? ""),
    notNull: Number(row[3] ?? 0) === 1,
    defaultValue: displaySqliteValue(row[4] ?? null),
    primaryKey: Number(row[5] ?? 0) > 0
  }));
}

export function sqliteFilterWhere(columns: SqliteColumnInfo[], filter: string) {
  const value = filter.trim();
  if (!value) return "";
  const like = `%${value.replace(/[\\%_]/g, (match) => `\\${match}`)}%`;
  return columns.length
    ? ` WHERE ${columns.map((column) => `CAST(${quoteSqlIdentifier(column.name)} AS TEXT) LIKE ${quoteSqlLiteral(like)} ESCAPE '\\'`).join(" OR ")}`
    : "";
}

export function loadSqliteTableRows(
  db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> },
  table: SqliteTableInfo,
  columns: SqliteColumnInfo[],
  limit: number,
  offset: number,
  filter: string,
  sortColumn: string,
  sortDirection: "asc" | "desc"
): SqliteDataSet {
  const tableName = quoteSqlIdentifier(table.name);
  const where = sqliteFilterWhere(columns, filter);
  const orderBy = sortColumn && columns.some((column) => column.name === sortColumn)
    ? ` ORDER BY ${quoteSqlIdentifier(sortColumn)} ${sortDirection === "desc" ? "DESC" : "ASC"}`
    : "";
  const boundedLimit = Math.min(1000, Math.max(10, limit));
  const boundedOffset = Math.max(0, offset);
  let totalRows: number | null = null;
  try {
    const countValue = db.exec(`SELECT COUNT(*) FROM ${tableName}${where}`)[0]?.values?.[0]?.[0];
    totalRows = typeof countValue === "number" ? countValue : Number(countValue);
    if (!Number.isFinite(totalRows)) totalRows = null;
  } catch {
    totalRows = null;
  }
  if (table.type === "table") {
    try {
      const result = db.exec(`SELECT rowid AS __rowid__, * FROM ${tableName}${where}${orderBy} LIMIT ${boundedLimit} OFFSET ${boundedOffset}`)[0];
      if (result) {
        const rowidIndex = result.columns.indexOf("__rowid__");
        return {
          columns: result.columns.filter((_, index) => index !== rowidIndex),
          values: result.values.map((row) => row.filter((_, index) => index !== rowidIndex)),
          rowids: result.values.map((row) => {
            const rowid = row[rowidIndex];
            return typeof rowid === "number" ? rowid : rowid === null ? null : Number(rowid);
          }),
          editable: true,
          message: totalRows === null ? `${result.values.length} rows` : `${result.values.length}/${totalRows} rows`,
          totalRows
        };
      }
    } catch {
      // WITHOUT ROWID tables and some virtual tables fall through to read-only browsing.
    }
  }
  const result = db.exec(`SELECT * FROM ${tableName}${where}${orderBy} LIMIT ${boundedLimit} OFFSET ${boundedOffset}`)[0];
  return {
    columns: result?.columns ?? [],
    values: result?.values ?? [],
    rowids: [],
    editable: false,
    message: result ? (totalRows === null ? `${result.values.length} rows` : `${result.values.length}/${totalRows} rows`) : "",
    totalRows
  };
}

export function runSqliteQuery(db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> }, sql: string): SqliteDataSet {
  const trimmed = sql.trim();
  if (!trimmed) return sqliteEmptyDataSet();
  const results = db.exec(trimmed);
  const last = results[results.length - 1];
  if (last) return { columns: last.columns, values: last.values, rowids: [], editable: false, message: `${last.values.length} rows`, totalRows: last.values.length };
  return sqliteEmptyDataSet("Statement executed");
}

export function sqliteSqlIsMutating(sql: string) {
  return /\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|VACUUM|PRAGMA|ATTACH|DETACH|REINDEX)\b/i.test(sql);
}

export function sqliteQueryHistoryToCsv(rows: SqliteQueryHistoryEntry[]) {
  const escape = (value: string | number | boolean) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["at", "mutating", "rows", "columns", "message", "sql"].join(","),
    ...rows.map((row) => [row.at, row.mutating, row.rows, row.columns, row.message, row.sql].map(escape).join(","))
  ].join("\n");
}

export function sqliteQueryTemplates(table: SqliteTableInfo | null, columns: SqliteColumnInfo[]): SqliteQueryTemplate[] {
  if (!table) {
    return [
      {
        label: "List objects",
        sql: "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY type, tbl_name, name;",
        detail: "查看 sqlite_master 中的表、视图、索引和触发器。",
        level: "info"
      },
      {
        label: "Database metadata",
        sql: "PRAGMA database_list;\nPRAGMA quick_check;\nPRAGMA page_count;\nPRAGMA freelist_count;",
        detail: "快速查看数据库元信息和完整性检查结果。",
        level: "info"
      }
    ];
  }
  const tableName = quoteSqlIdentifier(table.name);
  const timeColumn = columns.find((column) => /\b(ts|time|date|created|updated|modified|deleted|last|expires)\b/i.test(column.name))?.name ?? "";
  const templates: SqliteQueryTemplate[] = [
    {
      label: "Preview current table",
      sql: `SELECT rowid, * FROM ${tableName} LIMIT 100;`,
      detail: "带 rowid 预览当前表，便于定位可编辑记录。",
      level: "info"
    },
    {
      label: "Count rows",
      sql: `SELECT COUNT(*) AS row_count FROM ${tableName};`,
      detail: "统计当前表行数，和侧栏记录数交叉核对。",
      level: "info"
    },
    {
      label: "Schema for table",
      sql: `PRAGMA table_info(${tableName});\nPRAGMA index_list(${tableName});`,
      detail: "查看当前表列、主键、索引信息。",
      level: "info"
    }
  ];
  if (timeColumn) {
    templates.push({
      label: "Timeline candidates",
      sql: `SELECT rowid, ${quoteSqlIdentifier(timeColumn)}, * FROM ${tableName} WHERE ${quoteSqlIdentifier(timeColumn)} IS NOT NULL ORDER BY ${quoteSqlIdentifier(timeColumn)} DESC LIMIT 200;`,
      detail: `按疑似时间字段 ${timeColumn} 排序，辅助时间线分析。`,
      level: "info"
    });
  }
  return templates;
}

export function loadSqliteTableRowsForExport(
  db: { exec: (sql: string) => Array<{ columns: string[]; values: SqliteValue[][] }> },
  table: SqliteTableInfo,
  columns: SqliteColumnInfo[],
  filter: string,
  sortColumn: string,
  sortDirection: "asc" | "desc",
  maxRows = 50000
): SqliteDataSet {
  const tableName = quoteSqlIdentifier(table.name);
  const where = sqliteFilterWhere(columns, filter);
  const orderBy = sortColumn && columns.some((column) => column.name === sortColumn)
    ? ` ORDER BY ${quoteSqlIdentifier(sortColumn)} ${sortDirection === "desc" ? "DESC" : "ASC"}`
    : "";
  const result = db.exec(`SELECT * FROM ${tableName}${where}${orderBy} LIMIT ${Math.max(1, maxRows)}`)[0];
  return {
    columns: result?.columns ?? [],
    values: result?.values ?? [],
    rowids: [],
    editable: false,
    message: result ? `${result.values.length} exported row(s)${table.rows && table.rows > maxRows ? `; capped at ${maxRows}` : ""}` : "",
    totalRows: result?.values.length ?? 0
  };
}

export function sqliteSelectedRowJson(data: SqliteDataSet, selectedCell: SqliteCellSelection | null) {
  if (!selectedCell) return "";
  const row = data.values[selectedCell.rowIndex];
  if (!row) return "";
  const payload = Object.fromEntries(data.columns.map((column, index) => [column, displaySqliteValue(row[index] ?? null)]));
  return JSON.stringify({ rowid: selectedCell.rowid, rowIndex: selectedCell.rowIndex + 1, values: payload }, null, 2);
}

export function sqliteSelectedRowData(data: SqliteDataSet, selectedCell: SqliteCellSelection | null): SqliteDataSet | null {
  if (!selectedCell) return null;
  const row = data.values[selectedCell.rowIndex];
  if (!row) return null;
  return {
    columns: data.columns,
    values: [row],
    rowids: [selectedCell.rowid],
    editable: false,
    message: `row ${selectedCell.rowIndex + 1}`,
    totalRows: 1
  };
}

export function sqliteReportText(info: {
  fileName: string;
  fileSize: number;
  fileSha256: string;
  tables: SqliteTableInfo[];
  objects: SqliteObjectInfo[];
  pragmaRows: Array<[string, string]>;
  findings: Array<{ level: string; title: string; detail: string }>;
  selectedTable: string;
  columns: SqliteColumnInfo[];
  indexes: SqliteIndexInfo[];
  profiles: SqliteColumnProfile[];
  contentHits: SqliteContentHit[];
  changeLog: SqliteChangeLog[];
  queryHistory: SqliteQueryHistoryEntry[];
}) {
  return [
    "# SQLite Evidence Browser Report",
    "",
    "## Database",
    `- Name: ${info.fileName || "--"}`,
    `- Size: ${info.fileSize ? formatBytes(info.fileSize) : "--"}`,
    `- Source SHA256: ${info.fileSha256 || "--"}`,
    `- Tables/views: ${info.tables.length}`,
    `- Objects: ${info.objects.length}`,
    "",
    "## PRAGMA / Metadata",
    ...info.pragmaRows.map(([key, value]) => `- ${key}: ${limitReportText(value, 600)}`),
    "",
    "## Findings",
    ...info.findings.map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 1200)}`),
    "",
    "## Objects",
    ...info.objects.slice(0, 160).map((object) => `- ${object.type} ${object.name} table=${object.tblName || "--"} rootpage=${object.rootpage ?? "--"}${object.risk.length ? ` review=${object.risk.join(", ")}` : ""}`),
    "",
    `## Current Table: ${info.selectedTable || "--"}`,
    ...info.columns.map((column) => `- ${column.name}: ${column.type || "--"} not_null=${column.notNull ? "yes" : "no"} pk=${column.primaryKey ? "yes" : "no"} default=${column.defaultValue}`),
    "",
    "## Column Profile",
    ...(info.profiles.length
      ? info.profiles.map((profile) => `- ${profile.column}: type=${profile.type} nulls=${profile.nulls} distinct=${profile.distinct} review=${profile.risk.join(", ") || "--"} sample=${limitReportText(profile.sample, 240)}`)
      : ["- --"]),
    "",
    "## Sensitive Value Hits",
    ...(info.contentHits.length
      ? info.contentHits.slice(0, 120).map((hit) => `- row=${hit.rowid ?? hit.rowIndex + 1} column=${hit.column} type=${hit.type} review=${hit.risk.join(", ")} value=${limitReportText(hit.value, 400)}`)
      : ["- --"]),
    "",
    "## Change Log",
    ...(info.changeLog.length
      ? info.changeLog.map((entry) => `- ${entry.at} [${entry.action}] table=${entry.table || "--"} rowid=${entry.rowid ?? "--"}${entry.column ? ` column=${entry.column}` : ""}: ${limitReportText(entry.detail, 800)}`)
      : ["- --"]),
    "",
    "## Query History",
    ...(info.queryHistory.length
      ? info.queryHistory.map((entry) => `- ${entry.at} ${entry.mutating ? "[MUTATING]" : "[READ]"} rows=${entry.rows} columns=${entry.columns}\n  ${limitReportText(entry.sql, 1000)}`)
      : ["- --"]),
    "",
    "## Indexes",
    ...(info.indexes.length
      ? info.indexes.map((index) => `- ${index.name}: unique=${index.unique ? "yes" : "no"} origin=${index.origin || "--"} partial=${index.partial ? "yes" : "no"} columns=${index.columns.join(", ") || "--"}`)
      : ["- --"])
  ].join("\n");
}

export function sqliteTriageCards(info: {
  fileName: string;
  fileSize: number;
  tables: SqliteTableInfo[];
  objects: SqliteObjectInfo[];
  findings: Array<{ level: string; title: string; detail: string }>;
  selectedTable: string;
  columns: SqliteColumnInfo[];
  data: SqliteDataSet;
  contentHits: SqliteContentHit[];
  dirty: boolean;
}) {
  const danger = info.findings.filter((finding) => finding.level === "danger").length;
  const warn = info.findings.filter((finding) => finding.level === "warn").length;
  const selected = info.tables.find((table) => table.name === info.selectedTable);
  const riskyObjects = info.objects.filter((object) => object.risk.length);
  return [
    {
      label: "数据库",
      value: info.fileName || "--",
      level: danger ? "danger" : warn ? "warn" : info.fileName ? "info" : "warn",
      detail: info.fileSize ? `${formatBytes(info.fileSize)}; ${info.tables.length} table/view object(s).` : "等待 SQLite 文件。"
    },
    {
      label: "当前表",
      value: selected?.name ?? "--",
      level: info.contentHits.length ? "warn" : "info",
      detail: selected ? `${selected.type}; ${selected.columns} columns; ${selected.rows ?? "?"} rows; page ${info.data.message || "--"}.` : "尚未选择表。"
    },
    {
      label: "敏感线索",
      value: `${info.contentHits.length} hit(s)`,
      level: info.contentHits.length ? "warn" : "info",
      detail: info.contentHits.slice(0, 3).map((hit) => `${hit.column}:${hit.type}`).join(" / ") || "当前页未命中敏感值。"
    },
    {
      label: "修改状态",
      value: info.dirty ? "pending export" : "clean",
      level: info.dirty ? "warn" : "info",
      detail: `${riskyObjects.length} review-marked object(s); ${info.columns.length} selected columns.`
    }
  ];
}

export function sqliteBriefing(info: {
  fileName: string;
  fileSize: number;
  fileSha256: string;
  tables: SqliteTableInfo[];
  objects: SqliteObjectInfo[];
  pragmaRows: Array<[string, string]>;
  findings: Array<{ level: string; title: string; detail: string }>;
  selectedTable: string;
  columns: SqliteColumnInfo[];
  indexes: SqliteIndexInfo[];
  profiles: SqliteColumnProfile[];
  contentHits: SqliteContentHit[];
  selectedCell: SqliteCellSelection | null;
  data: SqliteDataSet;
  dirty: boolean;
  changeLog: SqliteChangeLog[];
  queryHistory: SqliteQueryHistoryEntry[];
}) {
  const selected = info.tables.find((table) => table.name === info.selectedTable);
  return limitReportText([
    "# SQLite Evidence Browser Briefing",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Database",
    `- Name: ${info.fileName || "--"}`,
    `- Size: ${info.fileSize ? formatBytes(info.fileSize) : "--"}`,
    `- Source SHA256: ${info.fileSha256 || "--"}`,
    `- Tables/views: ${info.tables.length}`,
    `- Objects: ${info.objects.length}`,
    `- Dirty/export pending: ${info.dirty ? "yes" : "no"}`,
    `- Change log entries: ${info.changeLog.length}`,
    `- Query history entries: ${info.queryHistory.length}`,
    "",
    "## Current Table",
    selected
      ? `- Name: ${selected.name}\n- Type: ${selected.type}\n- Rows: ${selected.rows ?? "--"}\n- Columns: ${selected.columns}\n- Current page: ${info.data.message || "--"}`
      : "- --",
    "",
    "## Current Cell",
    info.selectedCell
      ? `- Row: ${info.selectedCell.rowid == null ? info.selectedCell.rowIndex + 1 : `rowid ${info.selectedCell.rowid}`}\n- Column: ${info.selectedCell.column}\n- Type: ${sqliteValueKind(info.selectedCell.value)}\n- Size: ${formatBytes(sqliteValueSize(info.selectedCell.value))}\n- Signature: ${sqliteValueSignature(info.selectedCell.value)}\n- Check markers: ${sqliteValueRisk(info.selectedCell.column, info.selectedCell.value).join(", ") || "--"}\n- Text preview: ${limitReportText(previewText(sqliteValueBytes(info.selectedCell.value), 1200) || displaySqliteValue(info.selectedCell.value), 1200)}\n- Hex preview: ${hexPreview(sqliteValueBytes(info.selectedCell.value), 160)}`
      : "- --",
    "",
    "## Findings",
    ...(info.findings.length
      ? info.findings.map((finding) => `- [${finding.level.toUpperCase()}] ${finding.title}: ${limitReportText(finding.detail, 900)}`)
      : ["- --"]),
    "",
    "## Column Profile",
    ...(info.profiles.length
      ? info.profiles.slice(0, 80).map((profile) => `- ${profile.column}: type=${profile.type} nulls=${profile.nulls} distinct=${profile.distinct} review=${profile.risk.join(", ") || "--"} sample=${limitReportText(profile.sample, 240)}`)
      : ["- --"]),
    "",
    "## Sensitive Hits",
    ...(info.contentHits.length
      ? info.contentHits.slice(0, 100).map((hit) => `- row=${hit.rowid ?? hit.rowIndex + 1} column=${hit.column} type=${hit.type} review=${hit.risk.join(", ")} value=${limitReportText(hit.value, 400)}`)
      : ["- --"]),
    "",
    "## Change Log",
    ...(info.changeLog.length
      ? info.changeLog.slice(-80).map((entry) => `- ${entry.at} [${entry.action}] table=${entry.table || "--"} rowid=${entry.rowid ?? "--"}${entry.column ? ` column=${entry.column}` : ""}: ${limitReportText(entry.detail, 600)}`)
      : ["- --"]),
    "",
    "## Query History",
    ...(info.queryHistory.length
      ? info.queryHistory.slice(0, 40).map((entry) => `- ${entry.at} ${entry.mutating ? "MUTATING" : "READ"} rows=${entry.rows} columns=${entry.columns} ${limitReportText(entry.sql, 500)}`)
      : ["- --"]),
    "",
    "## PRAGMA",
    ...info.pragmaRows.map(([key, value]) => `- ${key}: ${limitReportText(value, 600)}`)
  ].join("\n"), 30000);
}

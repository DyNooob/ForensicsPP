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

import React from "react";
import initSqlJs from "sql.js";
import type { Database, SqlJsStatic } from "sql.js";
import sqlWasmUrl from "sql.js/dist/sql-wasm.wasm?url";
import { CopyOutlined, DeleteOutlined, EditOutlined } from "@ant-design/icons";
import { Popconfirm, Switch } from "antd";
import { AButton, ASelect, ASegmentedButton, ASegmentedGroup, InfoTable, PanelTitle } from "../components/ui";
import { copy } from "../i18n";
import type {
  SqliteCellSelection,
  SqliteChangeLog,
  SqliteColumnInfo,
  SqliteDataSet,
  SqliteIndexInfo,
  SqliteObjectInfo,
  SqliteQueryHistoryEntry,
  SqliteTableInfo,
  SqliteValue
} from "../models";
import {
  coerceSqliteColumnValue,
  coerceSqliteEditValue,
  displaySqliteValue,
  editableSqliteValue,
  getSqliteColumns,
  getSqliteIndexInfo,
  getSqliteObjects,
  getSqlitePragmaRows,
  getSqliteTables,
  loadSqliteTableRows,
  quoteSqlIdentifier,
  quoteSqlLiteral,
  runSqliteQuery,
  sqliteCellPreviewRows,
  sqliteDefaultCellSelection,
  sqliteEmptyDataSet,
  sqliteFilterWhere,
  sqliteQueryTemplates,
  sqliteRowsToCsv,
  sqliteSelectedRowJson,
  sqliteSqlIsMutating,
  sqliteValueBytes,
  sqliteValueExportExtension,
  sqliteValueKind,
  sqliteValueSignature,
  sqliteValueSize
} from "../features/sqlite/analyzer";
import { previewText } from "../utils/binary";
import { downloadBlob, downloadTextFile, formatBytes, limitReportText } from "../utils/files";
import { useStoredState } from "../utils/storage";

function sqliteColumnPreferredWidth(column: string) {
  const normalized = column.toLowerCase();
  if (/^(id|rowid|pk|uid|gid|pid|sid)$/.test(normalized)) return 72;
  if (/^(is_|has_|can_|should_|enabled|active|deleted|hidden)|(_id|_no|_num|_count|_flag|_type|_status)$/.test(normalized)) return 96;
  if (/(date|time|created|updated|deleted|expires|timestamp|version|order|size|length|offset)/.test(normalized)) return 126;
  if (/(name|title|slug|key|email|phone|host|domain|ip|path|file)/.test(normalized)) return 160;
  if (/(url|uri|link|summary|description|feature|spec|sql|json|xml|html|body|content|value|data|blob|text|message|remark|note)/.test(normalized)) return 260;
  return 180;
}

function sqliteColumnWidthClass(width: number) {
  return `sqlite-col-${width}`;
}

function chooseSqliteDefaultTable(tables: SqliteTableInfo[], preferred = "") {
  if (preferred && tables.some((table) => table.name === preferred)) return preferred;
  const score = (table: SqliteTableInfo) => {
    const rows = table.rows ?? 0;
    const objectBonus = table.type === "table" ? 1000 : 0;
    const systemPenalty = /^sqlite_/i.test(table.name) ? 10000 : 0;
    const metadataPenalty = /(setting|config|schema|migration|meta)/i.test(table.name) ? 260 : 0;
    return objectBonus + rows * Math.max(table.columns, 1) + table.columns * 18 - systemPenalty - metadataPenalty;
  };
  return [...tables].sort((left, right) => score(right) - score(left))[0]?.name ?? "";
}

export function SqliteTool({ t }: { t: (typeof copy)["zh"] }) {
  const sqlRef = React.useRef<SqlJsStatic | null>(null);
  const dbRef = React.useRef<Database | null>(null);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const [fileName, setFileName] = React.useState("");
  const [fileSize, setFileSize] = React.useState(0);
  const [originalBytes, setOriginalBytes] = React.useState<Uint8Array | null>(null);
  const [tables, setTables] = React.useState<SqliteTableInfo[]>([]);
  const [objects, setObjects] = React.useState<SqliteObjectInfo[]>([]);
  const [pragmaRows, setPragmaRows] = React.useState<Array<[string, string]>>([]);
  const [selectedTable, setSelectedTable] = React.useState("");
  const [columns, setColumns] = React.useState<SqliteColumnInfo[]>([]);
  const [indexes, setIndexes] = React.useState<SqliteIndexInfo[]>([]);
  const [data, setData] = React.useState<SqliteDataSet>(() => sqliteEmptyDataSet());
  const [queryResult, setQueryResult] = React.useState<SqliteDataSet>(() => sqliteEmptyDataSet());
  const [sql, setSql] = React.useState("SELECT name, type, sql FROM sqlite_master ORDER BY type, name;");
  const [objectFilter, setObjectFilter] = React.useState("");
  const [limit, setLimit] = React.useState(100);
  const [offset, setOffset] = React.useState(0);
  const [tableSearch, setTableSearch] = React.useState("");
  const [tableFilter, setTableFilter] = React.useState("");
  const [sortColumn, setSortColumn] = React.useState("");
  const [sortDirection, setSortDirection] = React.useState<"asc" | "desc">("asc");
  const [selectedCell, setSelectedCell] = React.useState<SqliteCellSelection | null>(null);
  const [selectedCellDraft, setSelectedCellDraft] = React.useState("");
  const [cellEditOpen, setCellEditOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<{ rowIndex: number; rowid: number; values: Record<string, string> } | null>(null);
  const [creating, setCreating] = React.useState<Record<string, string> | null>(null);
  const [changeLog, setChangeLog] = React.useState<SqliteChangeLog[]>([]);
  const [queryHistory, setQueryHistory] = useStoredState<SqliteQueryHistoryEntry[]>("sqlite.queryHistory", []);
  const [dirty, setDirty] = React.useState(false);
  const [editingEnabled, setEditingEnabled] = React.useState(false);
  const [error, setError] = React.useState("");
  const [isSqliteDropActive, setSqliteDropActive] = React.useState(false);
  const [sqlitePage, setSqlitePage] = React.useState<"data" | "sql" | "schema" | "changes">("data");
  const english = t.waiting === "Waiting";

  const activeTable = tables.find((table) => table.name === selectedTable) ?? null;
  const visibleTables = React.useMemo(() => {
    const query = tableSearch.trim().toLowerCase();
    if (!query) return tables;
    return tables.filter((table) => [table.name, table.type, table.sql ?? ""].join(" ").toLowerCase().includes(query));
  }, [tableSearch, tables]);
  const visibleObjects = React.useMemo(() => {
    const query = objectFilter.trim().toLowerCase();
    if (!query) return objects;
    return objects.filter((object) => [object.name, object.type, object.tblName, object.sql, object.risk.join(" ")].join(" ").toLowerCase().includes(query));
  }, [objectFilter, objects]);
  const sqliteTemplates = React.useMemo(() => sqliteQueryTemplates(activeTable, columns), [activeTable, columns]);
  const hasSqliteDb = Boolean(fileName && dbRef.current);
  const queryMutating = React.useMemo(() => sqliteSqlIsMutating(sql.trim()), [sql]);

  const refreshTables = React.useCallback((nextSelectedTable?: string) => {
    const db = dbRef.current;
    if (!db) return;
    const nextTables = getSqliteTables(db);
    const nextObjects = getSqliteObjects(db);
    const nextPragmas = getSqlitePragmaRows(db);
    const nextName = chooseSqliteDefaultTable(nextTables, nextSelectedTable ?? selectedTable);
    setTables(nextTables);
    setObjects(nextObjects);
    setPragmaRows(nextPragmas);
    setSelectedTable(nextName);
  }, [selectedTable]);

  const refreshSelectedTable = React.useCallback(() => {
    const db = dbRef.current;
    const table = tables.find((item) => item.name === selectedTable);
    if (!db || !table) {
      setColumns([]);
      setData(sqliteEmptyDataSet());
      return;
    }
    try {
      const nextColumns = getSqliteColumns(db, table.name);
      const nextIndexes = getSqliteIndexInfo(db, table.name);
      setColumns(nextColumns);
      setIndexes(nextIndexes);
      setData(loadSqliteTableRows(db, table, nextColumns, limit, offset, tableFilter, sortColumn, sortDirection));
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setIndexes([]);
      setData(sqliteEmptyDataSet());
    }
  }, [limit, offset, selectedTable, sortColumn, sortDirection, tableFilter, tables]);

  React.useEffect(() => {
    refreshSelectedTable();
  }, [refreshSelectedTable]);

  React.useEffect(() => {
    setSelectedCellDraft(selectedCell ? editableSqliteValue(selectedCell.value) : "");
  }, [selectedCell]);

  React.useEffect(() => {
    setCellEditOpen(false);
    setEditing(null);
    setCreating(null);
  }, [limit, offset, selectedTable, sortColumn, sortDirection, tableFilter]);

  React.useEffect(() => {
    if (!data.columns.length || !data.values.length) {
      if (selectedCell) setSelectedCell(null);
      setCellEditOpen(false);
      return;
    }
    const currentCell = selectedCell;
    const currentRow = currentCell ? data.values[currentCell.rowIndex] : null;
    if (currentCell && currentRow && data.columns[currentCell.columnIndex] === currentCell.column) {
      const nextValue = currentRow[currentCell.columnIndex] ?? null;
      const nextRowid = data.rowids[currentCell.rowIndex] ?? null;
      if (nextValue !== currentCell.value || nextRowid !== currentCell.rowid) {
        setSelectedCell({ ...currentCell, rowid: nextRowid, value: nextValue });
      }
      return;
    }
    if (!currentCell) {
      setSelectedCell(sqliteDefaultCellSelection(data));
      return;
    }
    setSelectedCell(null);
  }, [data.columns, data.rowids, data.values, selectedCell]);

  React.useEffect(() => () => dbRef.current?.close(), []);

  const appendChange = React.useCallback((entry: Omit<SqliteChangeLog, "id" | "at">) => {
    setChangeLog((previous) => [
      ...previous,
      {
        ...entry,
        id: `${Date.now()}-${previous.length + 1}`,
        at: new Date().toISOString()
      }
    ]);
  }, []);

  const resetSqliteViewState = React.useCallback(() => {
    setOffset(0);
    setTableSearch("");
    setTableFilter("");
    setSortColumn("");
    setSortDirection("asc");
    setObjectFilter("");
    setEditing(null);
    setCreating(null);
    setSelectedCell(null);
    setCellEditOpen(false);
  }, []);

  const clearSqliteWorkspace = React.useCallback(() => {
    dbRef.current?.close();
    dbRef.current = null;
    setFileName("");
    setFileSize(0);
    setOriginalBytes(null);
    setTables([]);
    setObjects([]);
    setPragmaRows([]);
    setSelectedTable("");
    setColumns([]);
    setIndexes([]);
    setData(sqliteEmptyDataSet());
    setQueryResult(sqliteEmptyDataSet());
    setSql("SELECT name, type, sql FROM sqlite_master ORDER BY type, name;");
    setChangeLog([]);
    setQueryHistory([]);
    setDirty(false);
    setEditingEnabled(false);
    setError("");
    setSqliteDropActive(false);
    resetSqliteViewState();
  }, [resetSqliteViewState, setQueryHistory]);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setSqliteDropActive(false);
    try {
      const SQL = sqlRef.current ?? await initSqlJs({ locateFile: () => sqlWasmUrl });
      sqlRef.current = SQL;
      dbRef.current?.close();
      const bytes = new Uint8Array(await file.arrayBuffer());
      const sourceBytes = new Uint8Array(bytes.byteLength);
      sourceBytes.set(bytes);
      const db = new SQL.Database(bytes);
      dbRef.current = db;
      const nextTables = getSqliteTables(db);
      const nextObjects = getSqliteObjects(db);
      const nextPragmas = getSqlitePragmaRows(db);
      setFileName(file.name);
      setFileSize(file.size);
      setOriginalBytes(sourceBytes);
      setTables(nextTables);
      setObjects(nextObjects);
      setPragmaRows(nextPragmas);
      setSelectedTable(chooseSqliteDefaultTable(nextTables));
      resetSqliteViewState();
      setDirty(false);
      setChangeLog([]);
      setQueryHistory([]);
      setQueryResult(sqliteEmptyDataSet());
    setError("");
    setEditingEnabled(false);
      setSqlitePage("data");
    } catch (caught) {
      dbRef.current = null;
      setError(caught instanceof Error ? caught.message : String(caught));
      setFileName("");
      setFileSize(0);
      setTables([]);
      setObjects([]);
      setPragmaRows([]);
      setSelectedTable("");
      setData(sqliteEmptyDataSet());
      setOriginalBytes(null);
      setChangeLog([]);
      setQueryHistory([]);
      setQueryResult(sqliteEmptyDataSet());
      setDirty(false);
      resetSqliteViewState();
    }
  };

  const discardSqliteChanges = async () => {
    if (!originalBytes) return;
    try {
      const SQL = sqlRef.current ?? await initSqlJs({ locateFile: () => sqlWasmUrl });
      sqlRef.current = SQL;
      dbRef.current?.close();
      const sourceBytes = new Uint8Array(originalBytes.byteLength);
      sourceBytes.set(originalBytes);
      const db = new SQL.Database(sourceBytes);
      dbRef.current = db;
      const nextTables = getSqliteTables(db);
      const nextObjects = getSqliteObjects(db);
      const nextPragmas = getSqlitePragmaRows(db);
      const nextSelected = chooseSqliteDefaultTable(nextTables, selectedTable);
      setTables(nextTables);
      setObjects(nextObjects);
      setPragmaRows(nextPragmas);
      setSelectedTable(nextSelected);
      resetSqliteViewState();
      setSelectedTable(nextSelected);
      setDirty(false);
      setChangeLog([]);
      setQueryResult(sqliteEmptyDataSet("Reverted to original database"));
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const startEdit = (rowIndex: number) => {
    const rowid = data.rowids[rowIndex];
    if (!data.editable || typeof rowid !== "number") return;
    setEditing({
      rowIndex,
      rowid,
      values: Object.fromEntries(data.columns.map((column, index) => [column, editableSqliteValue(data.values[rowIndex]?.[index] ?? null)]))
    });
  };

  const saveEdit = () => {
    const db = dbRef.current;
    if (!db || !activeTable || !editing) return;
    try {
      const assignments = data.columns.map((column) => `${quoteSqlIdentifier(column)} = ?`).join(", ");
      const before = Object.fromEntries(data.columns.map((column, index) => [column, displaySqliteValue(data.values[editing.rowIndex]?.[index] ?? null)]));
      const after = Object.fromEntries(data.columns.map((column) => [column, editing.values[column] ?? ""]));
      const changedColumns = data.columns.filter((column) => before[column] !== after[column]);
      const params = data.columns.map((column, index) => coerceSqliteEditValue(data.values[editing.rowIndex]?.[index] ?? null, editing.values[column] ?? ""));
      db.run(`UPDATE ${quoteSqlIdentifier(activeTable.name)} SET ${assignments} WHERE rowid = ?`, [...params, editing.rowid]);
      appendChange({
        action: "row-update",
        table: activeTable.name,
        rowid: editing.rowid,
        before: JSON.stringify(before),
        after: JSON.stringify(after),
        detail: changedColumns.length ? `Updated ${changedColumns.join(", ")}` : "Saved row without visible value changes"
      });
      setEditing(null);
      setDirty(true);
      refreshTables(activeTable.name);
      refreshSelectedTable();
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const saveSelectedCell = () => {
    const db = dbRef.current;
    if (!db || !activeTable || !selectedCell || !data.editable || typeof selectedCell.rowid !== "number") return;
    try {
      const nextValue = coerceSqliteEditValue(selectedCell.value, selectedCellDraft);
      const before = displaySqliteValue(selectedCell.value);
      const after = displaySqliteValue(nextValue);
      db.run(`UPDATE ${quoteSqlIdentifier(activeTable.name)} SET ${quoteSqlIdentifier(selectedCell.column)} = ? WHERE rowid = ?`, [nextValue, selectedCell.rowid]);
      appendChange({
        action: "cell-update",
        table: activeTable.name,
        rowid: selectedCell.rowid,
        column: selectedCell.column,
        before,
        after,
        detail: `Updated ${selectedCell.column} from ${limitReportText(before, 220)} to ${limitReportText(after, 220)}`
      });
      setSelectedCell({ ...selectedCell, value: nextValue });
      setCellEditOpen(false);
      setDirty(true);
      refreshTables(activeTable.name);
      refreshSelectedTable();
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const startCreate = () => {
    if (!activeTable || activeTable.type !== "table" || !columns.length) return;
    setCreating(Object.fromEntries(columns.map((column) => [column.name, ""])));
    setEditing(null);
  };

  const saveCreate = () => {
    const db = dbRef.current;
    if (!db || !activeTable || !creating) return;
    try {
      const insertColumns = columns.filter((column) => column.name && !(column.primaryKey && !creating[column.name]?.trim()));
      const names = insertColumns.map((column) => quoteSqlIdentifier(column.name)).join(", ");
      const placeholders = insertColumns.map(() => "?").join(", ");
      const params = insertColumns.map((column) => coerceSqliteColumnValue(column, creating[column.name] ?? ""));
      db.run(
        insertColumns.length
          ? `INSERT INTO ${quoteSqlIdentifier(activeTable.name)} (${names}) VALUES (${placeholders})`
          : `INSERT INTO ${quoteSqlIdentifier(activeTable.name)} DEFAULT VALUES`,
        params
      );
      appendChange({
        action: "row-insert",
        table: activeTable.name,
        rowid: null,
        after: JSON.stringify(creating),
        detail: `Inserted row with ${insertColumns.length || 0} explicit column value(s)`
      });
      setCreating(null);
      setDirty(true);
      refreshTables(activeTable.name);
      refreshSelectedTable();
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const deleteRow = (rowIndex: number) => {
    const db = dbRef.current;
    const rowid = data.rowids[rowIndex];
    if (!db || !activeTable || !data.editable || typeof rowid !== "number") return;
    try {
      const before = Object.fromEntries(data.columns.map((column, index) => [column, displaySqliteValue(data.values[rowIndex]?.[index] ?? null)]));
      db.run(`DELETE FROM ${quoteSqlIdentifier(activeTable.name)} WHERE rowid = ?`, [rowid]);
      appendChange({
        action: "row-delete",
        table: activeTable.name,
        rowid,
        before: JSON.stringify(before),
        detail: `Deleted rowid ${rowid}`
      });
      setDirty(true);
      setEditing(null);
      setCreating(null);
      refreshTables(activeTable.name);
      refreshSelectedTable();
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const runQuery = () => {
    const db = dbRef.current;
    if (!db) return;
    if (queryMutating && !editingEnabled) {
      setError(english ? "Enable edit mode before running a modifying statement." : "执行修改语句前请先开启编辑模式。");
      return;
    }
    try {
      const result = runSqliteQuery(db, sql);
      const trimmedSql = sql.trim();
      const mutating = sqliteSqlIsMutating(trimmedSql);
      setQueryResult(result);
      setQueryHistory((previous) => [
        {
          id: `${Date.now()}-${previous.length + 1}`,
          at: new Date().toISOString(),
          sql: trimmedSql,
          rows: result.values.length,
          columns: result.columns.length,
          mutating,
          message: result.message
        },
        ...previous.filter((entry) => entry.sql !== trimmedSql)
      ].slice(0, 30));
      setError("");
      if (mutating) {
        setDirty(true);
        appendChange({
          action: "sql-execute",
          table: activeTable?.name ?? "",
          rowid: null,
          detail: limitReportText(trimmedSql, 1200)
        });
      }
      refreshTables(activeTable?.name);
      refreshSelectedTable();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const exportDatabase = () => {
    const db = dbRef.current;
    if (!db) return;
    const exported = db.export();
    const base = fileName.replace(/\.(db|sqlite|sqlite3)$/i, "") || "database";
    const bytes = new Uint8Array(exported.byteLength);
    bytes.set(exported);
    downloadBlob(`${base}-forensicspp.sqlite`, new Blob([bytes.buffer], { type: "application/vnd.sqlite3" }));
    const savedBytes = new Uint8Array(bytes.byteLength);
    savedBytes.set(bytes);
    setOriginalBytes(savedBytes);
    setDirty(false);
  };

  const exportChangeLog = () => {
    const db = dbRef.current;
    const exported = db ? db.export() : null;
    const currentBytes = exported ? new Uint8Array(exported) : new Uint8Array();
    const payload = {
      generatedAt: new Date().toISOString(),
      source: {
        fileName,
        fileSize
      },
      current: db ? {
        size: currentBytes.byteLength,
        dirty
      } : null,
      tables: tables.map((table) => ({
        name: table.name,
        type: table.type,
        rows: table.rows,
        columns: table.columns
      })),
      queryHistory,
      changes: changeLog
    };
    downloadTextFile(`sqlite-change-log-${Date.now()}.json`, JSON.stringify(payload, null, 2), "application/json;charset=utf-8");
  };

  const copyDataCsv = (target: SqliteDataSet) => void navigator.clipboard.writeText(sqliteRowsToCsv(target.columns, target.values));
  const downloadDataCsv = (target: SqliteDataSet, name: string) => downloadTextFile(`${name}-${Date.now()}.csv`, sqliteRowsToCsv(target.columns, target.values), "text/csv;charset=utf-8");
  const copySqliteRow = (target: SqliteDataSet, row: SqliteValue[]) => {
    const payload = Object.fromEntries(target.columns.map((column, index) => [column, displaySqliteValue(row[index] ?? null)]));
    void navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
  };
  const copySelectedRow = () => {
    const rowJson = sqliteSelectedRowJson(data, selectedCell);
    if (rowJson) void navigator.clipboard.writeText(rowJson);
  };
  const downloadSelectedCell = () => {
    if (!selectedCell || !activeTable) return;
    const safeColumn = selectedCell.column.replace(/[^\w.-]+/g, "_") || "cell";
    const rowPart = selectedCell.rowid == null ? `row-${selectedCell.rowIndex + 1}` : `rowid-${selectedCell.rowid}`;
    if (selectedCell.value instanceof Uint8Array) {
      const copy = new Uint8Array(selectedCell.value.byteLength);
      copy.set(selectedCell.value);
      const extension = sqliteValueExportExtension(selectedCell.value);
      downloadBlob(`${activeTable.name}-${rowPart}-${safeColumn}.${extension}`, new Blob([copy.buffer], { type: "application/octet-stream" }));
      return;
    }
    downloadTextFile(`${activeTable.name}-${rowPart}-${safeColumn}.txt`, displaySqliteValue(selectedCell.value), "text/plain;charset=utf-8");
  };
  const canGoNext = data.totalRows == null ? data.values.length >= limit : offset + limit < data.totalRows;
  const pageEnd = data.totalRows == null ? offset + data.values.length : Math.min(offset + limit, data.totalRows);
  const sqliteColumnWidths = React.useMemo(() => data.columns.map((column) => sqliteColumnPreferredWidth(column)), [data.columns]);
  const sqliteQueryColumnWidths = React.useMemo(() => queryResult.columns.map((column) => sqliteColumnPreferredWidth(column)), [queryResult.columns]);
  const sqliteDataMinWidth = Math.max(760, 96 + sqliteColumnWidths.reduce((sum, width) => sum + width, 0));
  const sqliteQueryMinWidth = Math.max(720, sqliteQueryColumnWidths.reduce((sum, width) => sum + width, 0));
  const selectedCellDisplay = selectedCell ? displaySqliteValue(selectedCell.value) : "";
  const selectedCellTextPreview = selectedCell ? previewText(sqliteValueBytes(selectedCell.value), 8000) || selectedCellDisplay : "";
  const sqliteRowActions = t.waiting === "Waiting"
    ? { edit: "Edit", copy: "Copy", delete: "Del" }
    : { edit: "改", copy: "复制", delete: "删" };
  const sqliteLabels = React.useMemo(() => ({
    name: english ? "Name" : "名称",
    type: english ? "Type" : "类型",
    table: english ? "Table" : "当前表",
    totalRows: english ? `${t.rows} Total` : `${t.rows}总数`,
    page: english ? "Page" : "分页",
    changes: english ? "Changes" : "修改",
    rows: english ? "rows" : "行",
    time: english ? "Time" : "时间",
    action: english ? "Action" : "操作",
    row: english ? "Row" : "行",
    column: english ? "Column" : "列",
    detail: english ? "Detail" : "详情",
    yes: english ? "yes" : "是",
    no: english ? "no" : "否",
    unique: english ? "Unique" : "唯一",
    notNull: english ? "Not null" : "非空",
    defaultValue: english ? "Default" : "默认值"
  }), [english, t.rows]);
  const sqliteObjectType = React.useCallback((type: string) => {
    if (english) return type;
    if (type === "table") return "表";
    if (type === "view") return "视图";
    if (type === "index") return "索引";
    if (type === "trigger") return "触发器";
    return type;
  }, [english]);
  const sqlitePageStatus = data.values.length
    ? `${data.values.length}${data.totalRows == null ? "" : `/${data.totalRows}`} ${sqliteLabels.rows}`
    : "--";
  return (
    <div className={`tool-grid sqlite-browser-grid sqlite-browser-simple ${hasSqliteDb ? "has-sqlite" : "empty-sqlite"}`}>
      <div className="tool-panel wide-panel sqlite-source-panel">
        <PanelTitle title={english ? "SQLite database" : "SQLite 数据库"} />
        <input ref={inputRef} type="file" accept=".db,.sqlite,.sqlite3" onChange={(event) => void handleFile(event.target.files?.[0])} />
        <div className={`desktop-drop-zone ${isSqliteDropActive ? "active" : ""}`} role="button" tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setSqliteDropActive(true); }} onDragLeave={() => setSqliteDropActive(false)}
          onDrop={(event) => { event.preventDefault(); setSqliteDropActive(false); void handleFile(event.dataTransfer.files?.[0]); }}>
          <strong>{fileName || t.dropFileTitle}</strong>
          <span>{hasSqliteDb ? `${formatBytes(fileSize)} · ${tables.length} ${t.sqliteTables}` : t.sqliteDropHint}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.sqliteOpenFile}</AButton>
          <AButton variant="outlined" disabled={!dbRef.current} onClick={exportDatabase}>{t.sqliteExportDb}</AButton>
          <AButton variant="text" disabled={!hasSqliteDb && !error} onClick={clearSqliteWorkspace}>{t.clear}</AButton>
          {hasSqliteDb && <label className="sqlite-edit-mode"><span>{english ? "Edit mode" : "编辑模式"}</span><Switch checked={editingEnabled} onChange={(checked) => { setEditingEnabled(checked); if (!checked) { setEditing(null); setCreating(null); setCellEditOpen(false); } }} /></label>}
        </div>
        {error && <div className="empty-state error-state">{error}</div>}
      </div>

      {hasSqliteDb && <div className="sqlite-admin-shell wide-panel">
        <aside className="tool-panel sqlite-table-browser-panel">
          <div className="panel-heading-row"><PanelTitle title={fileName || t.sqliteTables} /><span className="status-pill">{visibleTables.length}/{tables.length}</span></div>
          <input className="text-input" aria-label={english ? "Search tables and views" : "搜索表或视图"} value={tableSearch} onChange={(event) => setTableSearch(event.currentTarget.value)} placeholder={english ? "Search tables" : "搜索表或视图"} />
          <div className="sqlite-simple-table-list">{visibleTables.map((table) => <button className={table.name === selectedTable ? "active" : ""} type="button" key={`${table.type}-${table.name}`} onClick={() => { setSelectedTable(table.name); setOffset(0); }}><strong>{table.name}</strong><span>{sqliteObjectType(table.type)} · {table.rows ?? "--"} {t.rows}</span></button>)}</div>
        </aside>

        <div className="sqlite-admin-main">
        <ASegmentedGroup className="sqlite-page-tabs" value={sqlitePage} selects="single" aria-label={english ? "SQLite workspace pages" : "SQLite 页面"}>
          <ASegmentedButton value="data" onClick={() => setSqlitePage("data")}>{english ? "Browse" : "浏览"}</ASegmentedButton>
          <ASegmentedButton value="schema" onClick={() => setSqlitePage("schema")}>{english ? "Structure" : "结构"}</ASegmentedButton>
          <ASegmentedButton value="sql" onClick={() => setSqlitePage("sql")}>SQL</ASegmentedButton>
          <ASegmentedButton value="changes" onClick={() => setSqlitePage("changes")}>{english ? "Changes" : "修改"}{dirty ? " *" : ""}</ASegmentedButton>
        </ASegmentedGroup>

        {sqlitePage === "data" && <div className="sqlite-data-workspace">
          <div className="tool-panel sqlite-main-data-panel">
            <div className="panel-heading-row"><PanelTitle title={activeTable ? `${activeTable.name}` : t.sqliteData} /><span className="status-pill">{sqlitePageStatus}</span></div>
            <div className="sqlite-simple-controls">
              <input className="text-input" aria-label={english ? "Filter current table rows" : "筛选当前表记录"} value={tableFilter} onChange={(event) => { setTableFilter(event.currentTarget.value); setOffset(0); }} placeholder={english ? "Filter rows" : "筛选当前表"} />
              <label className="sqlite-page-size-control"><span>{english ? "Rows" : "每页"}</span><ASelect aria-label={english ? "Rows per page" : "每页行数"} value={limit} onChange={(value) => { setLimit(Number(value)); setOffset(0); }} options={[50, 100, 250, 500].map((value) => ({ value, label: String(value) }))} /></label>
              <AButton variant="outlined" disabled={!data.values.length} onClick={() => copyDataCsv(data)}>{t.copyCsv}</AButton>
              <AButton variant="outlined" disabled={!data.values.length} onClick={() => downloadDataCsv(data, activeTable?.name || "sqlite-table")}>{t.exportCsv}</AButton>
              <AButton variant="outlined" disabled={!editingEnabled || !data.editable} onClick={startCreate}>{t.sqliteNewRow}</AButton>
            </div>
            <div className="table-scroll sqlite-data-scroll">
              {data.columns.length ? <table className="data-table sqlite-data-table sqlite-browse-table" style={{ "--sqlite-table-width": `${sqliteDataMinWidth}px` } as React.CSSProperties}>
                <colgroup><col className="sqlite-action-col" />{data.columns.map((column, index) => <col className={`sqlite-value-col ${sqliteColumnWidthClass(sqliteColumnWidths[index])}`} key={column} />)}</colgroup>
                <thead><tr><th className="sqlite-action-cell">{english ? "Actions" : "操作"}</th>{data.columns.map((column) => <th key={column} title={column}>{column}</th>)}</tr></thead>
                <tbody>{data.values.map((row, rowIndex) => <tr key={`${data.rowids[rowIndex] ?? rowIndex}`}>
                  <td className="sqlite-action-cell"><div className="button-row compact-buttons sqlite-row-action-buttons">{editingEnabled && data.editable && <AButton variant="text" icon={<EditOutlined aria-hidden="true" />} aria-label={sqliteRowActions.edit} title={sqliteRowActions.edit} onClick={() => startEdit(rowIndex)} />}<AButton variant="text" icon={<CopyOutlined aria-hidden="true" />} aria-label={sqliteRowActions.copy} title={sqliteRowActions.copy} onClick={() => copySqliteRow(data, row)} />{editingEnabled && data.editable && <Popconfirm title={`${t.sqliteDeleteRow}: rowid ${data.rowids[rowIndex] ?? rowIndex + 1}?`} okText={t.sqliteDeleteRow} cancelText={t.cancelEdit} okButtonProps={{ danger: true }} onConfirm={() => deleteRow(rowIndex)}><AButton variant="text" danger icon={<DeleteOutlined aria-hidden="true" />} aria-label={sqliteRowActions.delete} title={sqliteRowActions.delete} /></Popconfirm>}</div></td>
                  {data.columns.map((column, columnIndex) => { const value = row[columnIndex] ?? null; const active = selectedCell?.rowIndex === rowIndex && selectedCell.columnIndex === columnIndex; return <td className={active ? "active-cell" : ""} key={column} title={displaySqliteValue(value)} onClick={() => setSelectedCell({ rowIndex, columnIndex, column, rowid: data.rowids[rowIndex] ?? null, value })} onDoubleClick={() => { setSelectedCell({ rowIndex, columnIndex, column, rowid: data.rowids[rowIndex] ?? null, value }); if (editingEnabled && data.editable && typeof data.rowids[rowIndex] === "number") setCellEditOpen(true); }}>{displaySqliteValue(value)}</td>; })}
                </tr>)}</tbody>
              </table> : <div className="empty-state">--</div>}
            </div>
            <div className="sqlite-pagination-row"><AButton variant="outlined" disabled={offset <= 0} onClick={() => setOffset(Math.max(0, offset - limit))}>{english ? "Previous" : "上一页"}</AButton><span>{data.values.length ? `${offset + 1}-${pageEnd}` : "0"}</span><AButton variant="outlined" disabled={!canGoNext} onClick={() => setOffset(offset + limit)}>{english ? "Next" : "下一页"}</AButton></div>
          </div>

          {selectedCell && <div className="tool-panel sqlite-simple-cell-panel">
            <div className="panel-heading-row"><PanelTitle title={`${selectedCell.column}`} /><span className="status-pill">{selectedCell.rowid == null ? `row ${selectedCell.rowIndex + 1}` : `rowid ${selectedCell.rowid}`}</span></div>
            <InfoTable rows={[[english ? "Type" : "类型", sqliteValueKind(selectedCell.value)], [t.fileSize, formatBytes(sqliteValueSize(selectedCell.value))], [english ? "Value" : "值", selectedCellDisplay || "--"]]} />
            <textarea aria-label={english ? "Selected cell value" : "选中单元格值"} className="single-textarea sqlite-cell-value" value={cellEditOpen ? selectedCellDraft : selectedCellTextPreview} readOnly={!cellEditOpen} onChange={(event) => setSelectedCellDraft(event.currentTarget.value)} />
            <div className="action-row"><AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(selectedCellDisplay)}>{t.copy}</AButton><AButton variant="outlined" onClick={copySelectedRow}>{english ? "Copy row JSON" : "复制行 JSON"}</AButton><AButton variant="outlined" onClick={downloadSelectedCell}>{t.sqliteDownloadCell}</AButton>{editingEnabled && data.editable && typeof selectedCell.rowid === "number" && !cellEditOpen && <AButton variant="filled" onClick={() => setCellEditOpen(true)}>{english ? "Edit cell" : "编辑单元格"}</AButton>}{cellEditOpen && <><AButton variant="filled" onClick={saveSelectedCell}>{t.saveChanges}</AButton><AButton variant="text" onClick={() => { setCellEditOpen(false); setSelectedCellDraft(editableSqliteValue(selectedCell.value)); }}>{t.cancelEdit}</AButton></>}</div>
          </div>}

          {editing && <div className="tool-panel sqlite-row-editor-panel"><PanelTitle title={`${t.editRow}: rowid ${editing.rowid}`} /><div className="sqlite-editor-fields">{data.columns.map((column) => <label key={column}>{column}<textarea className="single-textarea compact-textarea" value={editing.values[column] ?? ""} onChange={(event) => setEditing({ ...editing, values: { ...editing.values, [column]: event.currentTarget.value } })} /></label>)}</div><div className="action-row"><AButton variant="filled" onClick={saveEdit}>{t.saveChanges}</AButton><AButton variant="text" onClick={() => setEditing(null)}>{t.cancelEdit}</AButton></div></div>}
          {creating && <div className="tool-panel sqlite-row-editor-panel"><PanelTitle title={t.sqliteNewRow} /><div className="sqlite-editor-fields">{columns.map((column) => <label key={column.name}>{column.name}<textarea className="single-textarea compact-textarea" value={creating[column.name] ?? ""} onChange={(event) => setCreating({ ...creating, [column.name]: event.currentTarget.value })} /></label>)}</div><div className="action-row"><AButton variant="filled" onClick={saveCreate}>{t.saveChanges}</AButton><AButton variant="text" onClick={() => setCreating(null)}>{t.cancelEdit}</AButton></div></div>}
        </div>}

        {sqlitePage === "sql" && <div className="tool-panel wide-panel sqlite-simple-sql-panel">
          <div className="panel-heading-row"><PanelTitle title={t.sqliteSql} />{queryMutating ? <Popconfirm disabled={!editingEnabled} title={english ? "Run this modifying SQL statement?" : "确认执行这条修改型 SQL？"} okText={english ? "Run" : "执行"} cancelText={t.cancelEdit} onConfirm={runQuery}><AButton variant="filled" danger disabled={!sql.trim() || !editingEnabled}>{t.runSql}</AButton></Popconfirm> : <AButton variant="filled" disabled={!sql.trim()} onClick={runQuery}>{t.runSql}</AButton>}</div>
          <details className="sqlite-query-examples">
            <summary>{english ? "Query examples" : "常用查询"}</summary>
            <div className="sqlite-template-list">{sqliteTemplates.slice(0, 6).map((template) => <button className="sqlite-template-item" type="button" key={template.label} onClick={() => setSql(template.sql)}><strong>{template.label}</strong><span>{template.detail}</span></button>)}</div>
          </details>
          <textarea className="single-textarea sqlite-query-input" value={sql} onChange={(event) => setSql(event.currentTarget.value)} />
          <div className="panel-heading-row"><PanelTitle title={t.sqliteQueryResult} /><div className="button-row compact-buttons"><AButton variant="outlined" disabled={!queryResult.values.length} onClick={() => copyDataCsv(queryResult)}>{t.copyCsv}</AButton><AButton variant="outlined" disabled={!queryResult.values.length} onClick={() => downloadDataCsv(queryResult, "sqlite-query")}>{t.exportCsv}</AButton></div></div>
          <div className="table-scroll sqlite-query-scroll">{queryResult.columns.length ? <table className="data-table sqlite-data-table sqlite-query-table" style={{ "--sqlite-table-width": `${sqliteQueryMinWidth}px` } as React.CSSProperties}><colgroup>{queryResult.columns.map((column, index) => <col className={`sqlite-value-col ${sqliteColumnWidthClass(sqliteQueryColumnWidths[index])}`} key={column} />)}</colgroup><thead><tr>{queryResult.columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{queryResult.values.map((row, rowIndex) => <tr key={rowIndex}>{queryResult.columns.map((column, columnIndex) => <td key={column}>{displaySqliteValue(row[columnIndex] ?? null)}</td>)}</tr>)}</tbody></table> : <div className="empty-state">{queryResult.message || "--"}</div>}</div>
        </div>}

        {sqlitePage === "schema" && <div className="tool-panel wide-panel sqlite-simple-schema-panel">
          <PanelTitle title={t.sqliteSchema} />
          <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{sqliteLabels.name}</th><th>{sqliteLabels.type}</th><th>{sqliteLabels.notNull}</th><th>{sqliteLabels.defaultValue}</th><th>PK</th></tr></thead><tbody>{columns.map((column) => <tr key={column.name}><td>{column.name}</td><td>{column.type || "--"}</td><td>{column.notNull ? sqliteLabels.yes : sqliteLabels.no}</td><td>{column.defaultValue}</td><td>{column.primaryKey ? sqliteLabels.yes : sqliteLabels.no}</td></tr>)}</tbody></table></div>
          {activeTable?.sql && <pre className="result-box">{activeTable.sql}</pre>}
          <PanelTitle title={t.sqliteIndexes} />
          <div className="table-scroll compact-scroll">{indexes.length ? <table className="data-table"><thead><tr><th>{sqliteLabels.name}</th><th>{sqliteLabels.unique}</th><th>{t.columns}</th></tr></thead><tbody>{indexes.map((index) => <tr key={index.name}><td>{index.name}</td><td>{index.unique ? sqliteLabels.yes : sqliteLabels.no}</td><td>{index.columns.join(", ") || "--"}</td></tr>)}</tbody></table> : <div className="empty-state">--</div>}</div>
          <PanelTitle title={t.sqliteObjects} />
          <div className="table-scroll sqlite-object-scroll"><table className="data-table"><thead><tr><th>{sqliteLabels.type}</th><th>{sqliteLabels.name}</th><th>SQL</th></tr></thead><tbody>{visibleObjects.map((object) => <tr key={`${object.type}-${object.name}`}><td>{sqliteObjectType(object.type)}</td><td>{object.name}</td><td><code>{object.sql || "--"}</code></td></tr>)}</tbody></table></div>
          <PanelTitle title={t.sqlitePragmas} /><InfoTable rows={pragmaRows} />
        </div>}

        {sqlitePage === "changes" && <div className="tool-panel wide-panel sqlite-simple-changes-panel">
          <div className="panel-heading-row"><PanelTitle title={t.sqliteChangeLog} /><div className="button-row compact-buttons"><AButton variant="filled" onClick={exportDatabase}>{t.sqliteExportDb}</AButton><AButton variant="outlined" disabled={!dirty || !originalBytes} onClick={() => void discardSqliteChanges()}>{t.sqliteDiscardChanges}</AButton><AButton variant="outlined" disabled={!changeLog.length} onClick={exportChangeLog}>{t.sqliteExportChangeLog}</AButton></div></div>
          {changeLog.length ? <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{sqliteLabels.time}</th><th>{sqliteLabels.action}</th><th>{sqliteLabels.table}</th><th>{sqliteLabels.row}</th><th>{sqliteLabels.column}</th><th>{sqliteLabels.detail}</th></tr></thead><tbody>{changeLog.slice().reverse().map((entry) => <tr key={entry.id}><td>{entry.at}</td><td>{entry.action}</td><td>{entry.table || "--"}</td><td>{entry.rowid ?? "--"}</td><td>{entry.column ?? "--"}</td><td>{entry.detail}</td></tr>)}</tbody></table></div> : <div className="empty-state">{english ? "No local changes." : "暂无本地修改。"}</div>}
        </div>}
        </div>
      </div>}
    </div>
  );

}

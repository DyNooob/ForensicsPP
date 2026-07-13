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
import {
  CaretDownOutlined,
  CaretUpOutlined,
  CopyOutlined,
  DeleteOutlined,
  DoubleLeftOutlined,
  DoubleRightOutlined,
  EditOutlined,
  LeftOutlined,
  RightOutlined,
  SearchOutlined,
  UndoOutlined
} from "@ant-design/icons";
import { message, Modal, Popconfirm, Switch } from "antd";
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
  sqliteDefaultCellSelection,
  sqliteEmptyDataSet,
  sqliteHexDump,
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
import { applySqliteWal, type SqliteWalInfo } from "../features/sqlite/wal";
import { downloadBlob, downloadTextFile, formatBytes, limitReportText } from "../utils/files";

function sqliteColumnPreferredWidth(column: string) {
  const normalized = column.toLowerCase();
  if (/^(id|rowid|pk|uid|gid|pid|sid)$/.test(normalized)) return 72;
  if (/^(is_|has_|can_|should_|enabled|active|deleted|hidden)|(_id|_no|_num|_count|_flag|_type|_status)$/.test(normalized)) return 96;
  if (/(date|time|created|updated|deleted|expires|timestamp|version|order|size|length|offset)/.test(normalized)) return 126;
  if (/(name|title|slug|key|email|phone|host|domain|ip|path|file)/.test(normalized)) return 160;
  if (/(url|uri|link|summary|description|feature|spec|sql|json|xml|html|body|content|value|data|blob|text|message|remark|note)/.test(normalized)) return 260;
  return 180;
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

const SQLITE_UNDO_SNAPSHOT_LIMIT = 32 * 1024 * 1024;

type SqliteUndoState = {
  bytes: Uint8Array;
  dirty: boolean;
  changeLogLength: number;
  queryHistory: SqliteQueryHistoryEntry[];
  selectedTable: string;
};

export function SqliteTool({ t, onDirtyChange }: { t: (typeof copy)["zh"]; onDirtyChange?: (dirty: boolean) => void }) {
  const [messageApi, messageContextHolder] = message.useMessage();
  const [modalApi, modalContextHolder] = Modal.useModal();
  const sqlRef = React.useRef<SqlJsStatic | null>(null);
  const dbRef = React.useRef<Database | null>(null);
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const [fileName, setFileName] = React.useState("");
  const [fileSize, setFileSize] = React.useState(0);
  const [walInfo, setWalInfo] = React.useState<SqliteWalInfo | null>(null);
  const [hasShm, setHasShm] = React.useState(false);
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
  const [tableFilterDraft, setTableFilterDraft] = React.useState("");
  const [tableFilterColumn, setTableFilterColumn] = React.useState("");
  const [sortColumn, setSortColumn] = React.useState("");
  const [sortDirection, setSortDirection] = React.useState<"asc" | "desc">("asc");
  const [selectedCell, setSelectedCell] = React.useState<SqliteCellSelection | null>(null);
  const [selectedCellDraft, setSelectedCellDraft] = React.useState("");
  const [selectedCellPreviewMode, setSelectedCellPreviewMode] = React.useState<"text" | "hex">("text");
  const [cellEditOpen, setCellEditOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<{ rowIndex: number; rowid: number; values: Record<string, string> } | null>(null);
  const [creating, setCreating] = React.useState<Record<string, string> | null>(null);
  const [changeLog, setChangeLog] = React.useState<SqliteChangeLog[]>([]);
  const [queryHistory, setQueryHistory] = React.useState<SqliteQueryHistoryEntry[]>([]);
  const [dirty, setDirty] = React.useState(false);
  const [editingEnabled, setEditingEnabled] = React.useState(false);
  const [undoState, setUndoState] = React.useState<SqliteUndoState | null>(null);
  const [columnWidths, setColumnWidths] = React.useState<Record<string, number>>({});
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
  const sqliteColumnKey = React.useCallback((column: string) => `${selectedTable}\u0000${column}`, [selectedTable]);
  const queryMutating = React.useMemo(() => sqliteSqlIsMutating(sql.trim()), [sql]);

  React.useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  React.useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);

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
      setData(loadSqliteTableRows(db, table, nextColumns, limit, offset, tableFilter, sortColumn, sortDirection, tableFilterColumn));
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setIndexes([]);
      setData(sqliteEmptyDataSet());
    }
  }, [limit, offset, selectedTable, sortColumn, sortDirection, tableFilter, tableFilterColumn, tables]);

  React.useEffect(() => {
    refreshSelectedTable();
  }, [refreshSelectedTable]);

  React.useEffect(() => {
    setSelectedCellDraft(selectedCell ? editableSqliteValue(selectedCell.value) : "");
    setSelectedCellPreviewMode("text");
  }, [selectedCell]);

  React.useEffect(() => {
    setCellEditOpen(false);
    setEditing(null);
    setCreating(null);
  }, [limit, offset, selectedTable, sortColumn, sortDirection, tableFilter, tableFilterColumn]);

  React.useEffect(() => {
    setTableFilter("");
    setTableFilterDraft("");
    setTableFilterColumn("");
    setOffset(0);
  }, [selectedTable]);

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
    setTableFilterDraft("");
    setTableFilterColumn("");
    setSortColumn("");
    setSortDirection("asc");
    setObjectFilter("");
    setEditing(null);
    setCreating(null);
    setSelectedCell(null);
    setCellEditOpen(false);
    setUndoState(null);
  }, []);

  const createUndoSnapshot = React.useCallback((): SqliteUndoState | null => {
    const db = dbRef.current;
    if (!db || fileSize > SQLITE_UNDO_SNAPSHOT_LIMIT) return null;
    const exported = db.export();
    if (exported.byteLength > SQLITE_UNDO_SNAPSHOT_LIMIT) return null;
    const bytes = new Uint8Array(exported.byteLength);
    bytes.set(exported);
    return {
      bytes,
      dirty,
      changeLogLength: changeLog.length,
      queryHistory: queryHistory.slice(),
      selectedTable
    };
  }, [changeLog.length, dirty, fileSize, queryHistory, selectedTable]);

  const undoLastChange = React.useCallback(() => {
    const SQL = sqlRef.current;
    const snapshot = undoState;
    if (!SQL || !snapshot) return;
    try {
      dbRef.current?.close();
      const bytes = new Uint8Array(snapshot.bytes.byteLength);
      bytes.set(snapshot.bytes);
      const db = new SQL.Database(bytes);
      dbRef.current = db;
      const nextTables = getSqliteTables(db);
      const nextSelected = chooseSqliteDefaultTable(nextTables, snapshot.selectedTable);
      setTables(nextTables);
      setObjects(getSqliteObjects(db));
      setPragmaRows(getSqlitePragmaRows(db));
      setSelectedTable(nextSelected);
      setChangeLog((previous) => previous.slice(0, snapshot.changeLogLength));
      setQueryHistory(snapshot.queryHistory);
      setDirty(snapshot.dirty);
      setUndoState(null);
      setQueryResult(sqliteEmptyDataSet(english ? "Last change undone" : "已撤销上一步修改"));
      setEditing(null);
      setCreating(null);
      setSelectedCell(null);
      setCellEditOpen(false);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }, [english, undoState]);

  const resizeSqliteColumn = React.useCallback((column: string, width: number) => {
    setColumnWidths((current) => ({
      ...current,
      [sqliteColumnKey(column)]: Math.max(64, Math.min(560, Math.round(width)))
    }));
  }, [sqliteColumnKey]);

  const beginSqliteColumnResize = React.useCallback((event: React.PointerEvent<HTMLSpanElement>, column: string, width: number) => {
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const move = (pointerEvent: PointerEvent) => resizeSqliteColumn(column, width + pointerEvent.clientX - startX);
    const finish = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      document.body.classList.remove("sqlite-column-resizing");
    };
    document.body.classList.add("sqlite-column-resizing");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish, { once: true });
  }, [resizeSqliteColumn]);

  const clearSqliteWorkspace = React.useCallback(() => {
    dbRef.current?.close();
    dbRef.current = null;
    setFileName("");
    setFileSize(0);
    setWalInfo(null);
    setHasShm(false);
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
    setUndoState(null);
    setColumnWidths({});
    setError("");
    setSqliteDropActive(false);
    resetSqliteViewState();
  }, [resetSqliteViewState, setQueryHistory]);

  const confirmDiscardBefore = React.useCallback((action: () => void) => {
    if (!dirty) {
      action();
      return;
    }
    modalApi.confirm({
      title: english ? "Discard unexported changes?" : "放弃尚未导出的修改？",
      content: english ? "The current SQLite changes cannot be recovered after continuing." : "继续后，当前 SQLite 修改将无法恢复。",
      okText: english ? "Continue" : "继续",
      cancelText: t.cancelEdit,
      okButtonProps: { danger: true },
      onOk: action
    });
  }, [dirty, english, modalApi, t.cancelEdit]);

  const handleFiles = async (files: File[]) => {
    if (!files.length) return;
    const databaseFile = files.find((file) => !/(?:-wal|-shm|\.wal|\.shm)$/i.test(file.name));
    if (!databaseFile) { setError(english ? "Select the SQLite database together with its WAL/SHM files." : "请同时选择 SQLite 数据库主文件。"); return; }
    const baseName = databaseFile.name.replace(/\.(?:db|sqlite|sqlite3)$/i, "");
    const walFile = files.find((file) => /(?:-wal|\.wal)$/i.test(file.name) && (file.name.startsWith(databaseFile.name) || file.name.startsWith(baseName))) ?? files.find((file) => /(?:-wal|\.wal)$/i.test(file.name));
    const shmFile = files.find((file) => /(?:-shm|\.shm)$/i.test(file.name) && (file.name.startsWith(databaseFile.name) || file.name.startsWith(baseName))) ?? files.find((file) => /(?:-shm|\.shm)$/i.test(file.name));
    setSqliteDropActive(false);
    try {
      const SQL = sqlRef.current ?? await initSqlJs({ locateFile: () => sqlWasmUrl });
      sqlRef.current = SQL;
      dbRef.current?.close();
      let bytes: Uint8Array<ArrayBufferLike> = new Uint8Array(await databaseFile.arrayBuffer());
      let nextWalInfo: SqliteWalInfo | null = null;
      if (walFile) {
        const merged = applySqliteWal(bytes, new Uint8Array(await walFile.arrayBuffer()));
        bytes = merged.bytes;
        nextWalInfo = merged.info;
      }
      const sourceBytes = new Uint8Array(bytes.byteLength);
      sourceBytes.set(bytes);
      const db = new SQL.Database(bytes);
      dbRef.current = db;
      const nextTables = getSqliteTables(db);
      const nextObjects = getSqliteObjects(db);
      const nextPragmas = getSqlitePragmaRows(db);
      setFileName(databaseFile.name);
      setFileSize(files.reduce((total, file) => total + file.size, 0));
      setWalInfo(nextWalInfo);
      setHasShm(Boolean(shmFile));
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
      setWalInfo(null);
      setHasShm(false);
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

  const requestFiles = (files: File[]) => {
    if (inputRef.current) inputRef.current.value = "";
    confirmDiscardBefore(() => void handleFiles(files));
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
      const undo = createUndoSnapshot();
      const assignments = data.columns.map((column) => `${quoteSqlIdentifier(column)} = ?`).join(", ");
      const before = Object.fromEntries(data.columns.map((column, index) => [column, displaySqliteValue(data.values[editing.rowIndex]?.[index] ?? null)]));
      const after = Object.fromEntries(data.columns.map((column) => [column, editing.values[column] ?? ""]));
      const changedColumns = data.columns.filter((column) => before[column] !== after[column]);
      const params = data.columns.map((column, index) => coerceSqliteEditValue(data.values[editing.rowIndex]?.[index] ?? null, editing.values[column] ?? ""));
      db.run(`UPDATE ${quoteSqlIdentifier(activeTable.name)} SET ${assignments} WHERE rowid = ?`, [...params, editing.rowid]);
      setUndoState(undo);
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
      const undo = createUndoSnapshot();
      const nextValue = coerceSqliteEditValue(selectedCell.value, selectedCellDraft);
      const before = displaySqliteValue(selectedCell.value);
      const after = displaySqliteValue(nextValue);
      db.run(`UPDATE ${quoteSqlIdentifier(activeTable.name)} SET ${quoteSqlIdentifier(selectedCell.column)} = ? WHERE rowid = ?`, [nextValue, selectedCell.rowid]);
      setUndoState(undo);
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
      const undo = createUndoSnapshot();
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
      setUndoState(undo);
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
      const undo = createUndoSnapshot();
      const before = Object.fromEntries(data.columns.map((column, index) => [column, displaySqliteValue(data.values[rowIndex]?.[index] ?? null)]));
      db.run(`DELETE FROM ${quoteSqlIdentifier(activeTable.name)} WHERE rowid = ?`, [rowid]);
      setUndoState(undo);
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
      const undo = queryMutating ? createUndoSnapshot() : null;
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
        setUndoState(undo);
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
    setUndoState(null);
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
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = data.totalRows == null ? null : Math.max(1, Math.ceil(data.totalRows / limit));
  const applyTableFilter = () => {
    setTableFilter(tableFilterDraft.trim());
    setOffset(0);
  };
  const clearTableFilter = () => {
    setTableFilterDraft("");
    setTableFilter("");
    setOffset(0);
  };
  const toggleSqliteSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection((current) => current === "asc" ? "desc" : "asc");
    } else {
      setSortColumn(column);
      setSortDirection("asc");
    }
    setOffset(0);
  };
  const sqliteColumnWidths = React.useMemo(
    () => data.columns.map((column) => columnWidths[sqliteColumnKey(column)] ?? sqliteColumnPreferredWidth(column)),
    [columnWidths, data.columns, sqliteColumnKey]
  );
  const sqliteQueryColumnWidths = React.useMemo(() => queryResult.columns.map((column) => sqliteColumnPreferredWidth(column)), [queryResult.columns]);
  const sqliteDataMinWidth = Math.max(760, 96 + sqliteColumnWidths.reduce((sum, width) => sum + width, 0));
  const sqliteQueryMinWidth = Math.max(720, sqliteQueryColumnWidths.reduce((sum, width) => sum + width, 0));
  const selectedCellDisplay = selectedCell ? displaySqliteValue(selectedCell.value) : "";
  const selectedCellTextPreview = selectedCell ? previewText(sqliteValueBytes(selectedCell.value), 8000) || selectedCellDisplay : "";
  const selectedCellPreview = selectedCell && selectedCellPreviewMode === "hex"
    ? sqliteHexDump(selectedCell.value)
    : selectedCellTextPreview;
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
      {messageContextHolder}
      {modalContextHolder}
      <div className="tool-panel wide-panel sqlite-source-panel">
        <PanelTitle title={english ? "SQLite database" : "SQLite 数据库"} />
        <input className="hidden-file-input" ref={inputRef} type="file" multiple aria-hidden="true" tabIndex={-1} onChange={(event) => { const files = Array.from(event.currentTarget.files ?? []); event.currentTarget.value = ""; requestFiles(files); }} />
        <div className={`desktop-drop-zone ${isSqliteDropActive ? "active" : ""}`} role="button" tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inputRef.current?.click(); } }}
          onDragOver={(event) => { event.preventDefault(); setSqliteDropActive(true); }} onDragLeave={() => setSqliteDropActive(false)}
          onDrop={(event) => { event.preventDefault(); setSqliteDropActive(false); requestFiles(Array.from(event.dataTransfer.files ?? [])); }}>
          <strong>{fileName || t.dropFileTitle}</strong>
          <span>{hasSqliteDb ? `${formatBytes(fileSize)} · ${tables.length} ${t.sqliteTables}${walInfo ? ` · WAL ${walInfo.committedFrames}/${walInfo.frames}, ${english ? "checksum verified" : "校验通过"}${walInfo.invalidFrame ? `, ${english ? `frame ${walInfo.invalidFrame} ignored` : `第 ${walInfo.invalidFrame} 帧已忽略`}` : ""}` : ""}${hasShm ? ` · ${english ? "SHM detected (not used for recovery)" : "已检测 SHM（恢复不使用）"}` : ""}` : (english ? "Select the database and optional -wal/-shm files together" : "可同时选择数据库及对应的 -wal/-shm 文件")}</span>
        </div>
        <div className="action-row">
          <AButton variant="filled" onClick={() => inputRef.current?.click()}>{t.sqliteOpenFile}</AButton>
          <AButton variant="outlined" disabled={!dbRef.current} onClick={exportDatabase}>{t.sqliteExportDb}</AButton>
          <AButton variant="text" disabled={!hasSqliteDb && !error} onClick={() => confirmDiscardBefore(clearSqliteWorkspace)}>{t.clear}</AButton>
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
        <div className="sqlite-workspace-tabs-row">
          <ASegmentedGroup className="sqlite-page-tabs" value={sqlitePage} selects="single" aria-label={english ? "SQLite workspace pages" : "SQLite 页面"}>
            <ASegmentedButton value="data" onClick={() => setSqlitePage("data")}>{english ? "Browse" : "浏览"}</ASegmentedButton>
            <ASegmentedButton value="schema" onClick={() => setSqlitePage("schema")}>{english ? "Structure" : "结构"}</ASegmentedButton>
            <ASegmentedButton value="sql" onClick={() => setSqlitePage("sql")}>SQL</ASegmentedButton>
            <ASegmentedButton value="changes" onClick={() => setSqlitePage("changes")}>{english ? "Changes" : "修改"}{dirty ? " *" : ""}</ASegmentedButton>
          </ASegmentedGroup>
          <div className={`sqlite-edit-mode ${editingEnabled ? "active" : ""}`}><span><EditOutlined aria-hidden="true" />{english ? "Edit mode" : "编辑模式"}</span><Switch size="small" aria-label={english ? "Toggle edit mode" : "切换编辑模式"} checked={editingEnabled} onChange={(checked) => { setEditingEnabled(checked); if (!checked) { setEditing(null); setCreating(null); setCellEditOpen(false); } }} /></div>
        </div>

        {sqlitePage === "data" && <div className="sqlite-data-workspace">
          <div className="tool-panel sqlite-main-data-panel">
            <div className="panel-heading-row"><PanelTitle title={activeTable ? `${activeTable.name}` : t.sqliteData} /><span className="status-pill">{sqlitePageStatus}</span></div>
            <div className="sqlite-simple-controls">
              <div className="sqlite-filter-control">
                <ASelect
                  className="sqlite-filter-column-select"
                  aria-label={english ? "Filter column" : "筛选列"}
                  value={tableFilterColumn}
                  onChange={(value) => { setTableFilterColumn(String(value)); if (tableFilter) setOffset(0); }}
                  options={[
                    { value: "", label: english ? "All columns" : "全部列" },
                    ...columns.map((column) => ({ value: column.name, label: column.name }))
                  ]}
                />
                <input className="text-input" aria-label={english ? "Filter current table rows" : "筛选当前表记录"} value={tableFilterDraft} onChange={(event) => setTableFilterDraft(event.currentTarget.value)} onKeyDown={(event) => { if (event.key === "Enter") applyTableFilter(); }} placeholder={english ? "Filter rows" : "筛选当前表"} />
                <AButton variant="filled" icon={<SearchOutlined aria-hidden="true" />} disabled={!tableFilterDraft.trim() && !tableFilter} onClick={applyTableFilter}>{english ? "Filter" : "筛选"}</AButton>
                {tableFilter && <AButton variant="text" onClick={clearTableFilter}>{t.clear}</AButton>}
              </div>
              <label className="sqlite-page-size-control"><span>{english ? "Rows" : "每页"}</span><ASelect aria-label={english ? "Rows per page" : "每页行数"} value={limit} onChange={(value) => { setLimit(Number(value)); setOffset(0); }} options={[50, 100, 250, 500].map((value) => ({ value, label: String(value) }))} /></label>
              <AButton variant="outlined" disabled={!data.values.length} onClick={() => copyDataCsv(data)}>{t.copyCsv}</AButton>
              <AButton variant="outlined" disabled={!data.values.length} onClick={() => downloadDataCsv(data, activeTable?.name || "sqlite-table")}>{t.exportCsv}</AButton>
              <AButton variant="outlined" disabled={!editingEnabled || !data.editable} onClick={startCreate}>{t.sqliteNewRow}</AButton>
            </div>
            <div className="table-scroll sqlite-data-scroll">
              {data.columns.length ? <table className="data-table sqlite-data-table sqlite-browse-table" style={{ "--sqlite-table-width": `${sqliteDataMinWidth}px` } as React.CSSProperties}>
                <colgroup><col className="sqlite-action-col" />{data.columns.map((column, index) => <col className="sqlite-value-col" style={{ width: sqliteColumnWidths[index] }} key={column} />)}</colgroup>
                <thead><tr><th className="sqlite-action-cell">{english ? "Actions" : "操作"}</th>{data.columns.map((column, index) => <th className={sortColumn === column ? "is-sorted" : ""} key={column} title={column}><button className="sqlite-column-sort" type="button" onClick={() => toggleSqliteSort(column)} aria-label={`${english ? "Sort by" : "按列排序"} ${column}${sortColumn === column ? `, ${sortDirection}` : ""}`}><span className="sqlite-column-label">{column}</span>{sortColumn === column ? (sortDirection === "asc" ? <CaretUpOutlined aria-hidden="true" /> : <CaretDownOutlined aria-hidden="true" />) : null}</button><span className="sqlite-column-resizer" role="separator" aria-label={`${english ? "Resize" : "调整列宽"} ${column}`} aria-orientation="vertical" tabIndex={0} onPointerDown={(event) => beginSqliteColumnResize(event, column, sqliteColumnWidths[index])} onDoubleClick={(event) => { event.stopPropagation(); resizeSqliteColumn(column, sqliteColumnPreferredWidth(column)); }} onKeyDown={(event) => { if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return; event.preventDefault(); resizeSqliteColumn(column, sqliteColumnWidths[index] + (event.key === "ArrowRight" ? 12 : -12) * (event.shiftKey ? 3 : 1)); }} /></th>)}</tr></thead>
                <tbody>{data.values.map((row, rowIndex) => <tr key={`${data.rowids[rowIndex] ?? rowIndex}`}>
                  <td className="sqlite-action-cell"><div className="button-row compact-buttons sqlite-row-action-buttons">{editingEnabled && data.editable && <AButton variant="text" icon={<EditOutlined aria-hidden="true" />} aria-label={sqliteRowActions.edit} title={sqliteRowActions.edit} onClick={() => startEdit(rowIndex)} />}<AButton variant="text" icon={<CopyOutlined aria-hidden="true" />} aria-label={sqliteRowActions.copy} title={sqliteRowActions.copy} onClick={() => copySqliteRow(data, row)} />{editingEnabled && data.editable && <Popconfirm title={`${t.sqliteDeleteRow}: rowid ${data.rowids[rowIndex] ?? rowIndex + 1}?`} okText={t.sqliteDeleteRow} cancelText={t.cancelEdit} okButtonProps={{ danger: true }} onConfirm={() => deleteRow(rowIndex)}><AButton variant="text" danger icon={<DeleteOutlined aria-hidden="true" />} aria-label={sqliteRowActions.delete} title={sqliteRowActions.delete} /></Popconfirm>}</div></td>
                  {data.columns.map((column, columnIndex) => {
                    const value = row[columnIndex] ?? null;
                    const active = selectedCell?.rowIndex === rowIndex && selectedCell.columnIndex === columnIndex;
                    const inlineEditing = active && cellEditOpen;
                    return <td className={`${active ? "active-cell" : ""} ${inlineEditing ? "editing-cell" : ""}`} key={column} title={inlineEditing ? undefined : displaySqliteValue(value)} onClick={() => { if (!inlineEditing) setCellEditOpen(false); setSelectedCell({ rowIndex, columnIndex, column, rowid: data.rowids[rowIndex] ?? null, value }); }} onDoubleClick={() => {
                      setSelectedCell({ rowIndex, columnIndex, column, rowid: data.rowids[rowIndex] ?? null, value });
                      if (!editingEnabled) { messageApi.info(english ? "Enable edit mode first" : "请先开启编辑模式"); return; }
                      if (!data.editable || typeof data.rowids[rowIndex] !== "number") { messageApi.warning(english ? "This table or view cannot be edited directly" : "当前表或视图不支持直接编辑"); return; }
                      setSelectedCellDraft(editableSqliteValue(value));
                      setCellEditOpen(true);
                    }}>{inlineEditing ? <input autoFocus className="sqlite-inline-cell-editor" aria-label={`${english ? "Edit" : "编辑"} ${column}`} value={selectedCellDraft} onChange={(event) => setSelectedCellDraft(event.currentTarget.value)} onClick={(event) => event.stopPropagation()} onDoubleClick={(event) => event.stopPropagation()} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); saveSelectedCell(); } else if (event.key === "Escape") { event.preventDefault(); setCellEditOpen(false); setSelectedCellDraft(editableSqliteValue(value)); } }} /> : displaySqliteValue(value)}</td>;
                  })}
                </tr>)}</tbody>
              </table> : <div className="empty-state">--</div>}
            </div>
            <div className="sqlite-pagination-row">
              <div className="sqlite-pagination-buttons">
                <AButton variant="outlined" icon={<DoubleLeftOutlined aria-hidden="true" />} aria-label={english ? "First page" : "第一页"} title={english ? "First page" : "第一页"} disabled={offset <= 0} onClick={() => setOffset(0)} />
                <AButton variant="outlined" icon={<LeftOutlined aria-hidden="true" />} aria-label={english ? "Previous page" : "上一页"} title={english ? "Previous page" : "上一页"} disabled={offset <= 0} onClick={() => setOffset(Math.max(0, offset - limit))} />
              </div>
              <span>{data.values.length ? `${offset + 1}-${pageEnd}` : "0"} · {english ? "Page" : "第"} {currentPage}{totalPages ? ` / ${totalPages}` : ""}{english ? "" : " 页"}</span>
              <div className="sqlite-pagination-buttons">
                <AButton variant="outlined" icon={<RightOutlined aria-hidden="true" />} aria-label={english ? "Next page" : "下一页"} title={english ? "Next page" : "下一页"} disabled={!canGoNext} onClick={() => setOffset(offset + limit)} />
                <AButton variant="outlined" icon={<DoubleRightOutlined aria-hidden="true" />} aria-label={english ? "Last page" : "最后一页"} title={english ? "Last page" : "最后一页"} disabled={!totalPages || currentPage >= totalPages} onClick={() => totalPages && setOffset((totalPages - 1) * limit)} />
              </div>
            </div>
          </div>

          {selectedCell && <div className="tool-panel sqlite-simple-cell-panel">
            <div className="panel-heading-row"><PanelTitle title={`${selectedCell.column}`} /><div className="button-row compact-buttons"><span className="status-pill">{selectedCell.rowid == null ? `row ${selectedCell.rowIndex + 1}` : `rowid ${selectedCell.rowid}`}</span>{selectedCell.value instanceof Uint8Array && <ASegmentedGroup value={selectedCellPreviewMode} selects="single" aria-label={english ? "Cell preview format" : "单元格预览格式"}><ASegmentedButton value="text" onClick={() => setSelectedCellPreviewMode("text")}>{english ? "Text" : "文本"}</ASegmentedButton><ASegmentedButton value="hex" onClick={() => setSelectedCellPreviewMode("hex")}>Hex</ASegmentedButton></ASegmentedGroup>}</div></div>
            <InfoTable rows={[[english ? "Type" : "类型", sqliteValueKind(selectedCell.value)], [t.fileSize, formatBytes(sqliteValueSize(selectedCell.value))], ...(selectedCell.value instanceof Uint8Array ? [[english ? "Signature" : "文件特征", sqliteValueSignature(selectedCell.value)] as [string, string]] : [[english ? "Value" : "值", selectedCellDisplay || "--"] as [string, string]])]} />
            <textarea aria-label={english ? "Selected cell value" : "选中单元格值"} className="single-textarea sqlite-cell-value" value={selectedCellPreview} readOnly />
            <div className="action-row"><AButton variant="outlined" onClick={() => void navigator.clipboard.writeText(selectedCellPreview)}>{t.copy}</AButton><AButton variant="outlined" onClick={copySelectedRow}>{english ? "Copy row JSON" : "复制行 JSON"}</AButton><AButton variant="outlined" onClick={downloadSelectedCell}>{t.sqliteDownloadCell}</AButton></div>
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
          <div className="table-scroll sqlite-query-scroll">{queryResult.columns.length ? <table className="data-table sqlite-data-table sqlite-query-table" style={{ "--sqlite-table-width": `${sqliteQueryMinWidth}px` } as React.CSSProperties}><colgroup>{queryResult.columns.map((column, index) => <col className="sqlite-value-col" style={{ width: sqliteQueryColumnWidths[index] }} key={column} />)}</colgroup><thead><tr>{queryResult.columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{queryResult.values.map((row, rowIndex) => <tr key={rowIndex}>{queryResult.columns.map((column, columnIndex) => <td key={column}>{displaySqliteValue(row[columnIndex] ?? null)}</td>)}</tr>)}</tbody></table> : <div className="empty-state">{queryResult.message || "--"}</div>}</div>
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
          <div className="panel-heading-row"><PanelTitle title={t.sqliteChangeLog} /><div className="button-row compact-buttons"><AButton variant="outlined" icon={<UndoOutlined aria-hidden="true" />} disabled={!undoState} onClick={undoLastChange}>{english ? "Undo last" : "撤销上一步"}</AButton><AButton variant="filled" onClick={exportDatabase}>{t.sqliteExportDb}</AButton><Popconfirm disabled={!dirty || !originalBytes} title={english ? "Discard all changes since the last export?" : "放弃上次导出后的全部修改？"} okText={t.sqliteDiscardChanges} cancelText={t.cancelEdit} okButtonProps={{ danger: true }} onConfirm={() => void discardSqliteChanges()}><AButton variant="outlined" disabled={!dirty || !originalBytes}>{t.sqliteDiscardChanges}</AButton></Popconfirm><AButton variant="outlined" disabled={!changeLog.length} onClick={exportChangeLog}>{t.sqliteExportChangeLog}</AButton></div></div>
          {changeLog.length ? <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{sqliteLabels.time}</th><th>{sqliteLabels.action}</th><th>{sqliteLabels.table}</th><th>{sqliteLabels.row}</th><th>{sqliteLabels.column}</th><th>{sqliteLabels.detail}</th></tr></thead><tbody>{changeLog.slice().reverse().map((entry) => <tr key={entry.id}><td>{entry.at}</td><td>{entry.action}</td><td>{entry.table || "--"}</td><td>{entry.rowid ?? "--"}</td><td>{entry.column ?? "--"}</td><td>{entry.detail}</td></tr>)}</tbody></table></div> : <div className="empty-state">{english ? "No local changes." : "暂无本地修改。"}</div>}
        </div>}
        </div>
      </div>}
    </div>
  );

}

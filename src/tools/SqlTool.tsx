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
import { AButton, ASelect, InfoTable, PanelTitle, ToolFactGrid, ToolPanelHeader, ToolStageFeatures } from "../components/ui";
import { filterSqlRows, minifySqlText, parseSqlDump, sqlRowsToCsv, sqlTableToJson } from "../features/sql/analyzer";
import type { Translation } from "../i18n";
import type { SqlParseResult } from "../models";
import { downloadTextFile, formatBytes } from "../utils/files";
import { useStoredState } from "../utils/storage";

export function SqlTool({ t }: { t: Translation }) {
  const english = t.waiting === "Waiting";
  const [result, setResult] = React.useState<SqlParseResult | null>(null);
  const [selectedTable, setSelectedTable] = React.useState("");
  const [tableFilter, setTableFilter] = React.useState("");
  const [error, setError] = React.useState("");
  const [formatInput, setFormatInput] = useStoredState("sql.formatInput", "");
  const [formatOutput, setFormatOutput] = useStoredState("sql.formatOutput", "");
  const [dialect, setDialect] = useStoredState("sql.dialect", "mysql");
  const [dropActive, setDropActive] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement | null>(null);

  const labels = React.useMemo(() => ({
    statements: english ? "Statements" : "语句数",
    currentTable: english ? "Current Table" : "当前表",
    analyzeInput: english ? "Analyze Input" : "解析输入",
    name: english ? "Name" : "名称",
    details: english ? "Details" : "详细信息",
    export: english ? "Export" : "导出",
    noRows: english ? "No matching rows" : "没有匹配的数据行",
    source: english ? "SQL dump source" : "SQL Dump 来源",
    overview: english ? "Dump overview" : "Dump 概览"
  }), [english]);

  const table = result?.tables.find((item) => item.name === selectedTable) ?? result?.tables[0] ?? null;
  const previewColumns = table
    ? table.columns.length
      ? table.columns.map((column) => column.name)
      : Object.keys(table.rows[0] ?? {})
    : [];
  const filteredRows = React.useMemo(() => filterSqlRows(table, tableFilter), [table, tableFilter]);
  const visibleRows = filteredRows.slice(0, 250);
  const totalRows = result?.tables.reduce((sum, item) => sum + item.insertRows, 0) ?? 0;
  const totalColumns = result?.tables.reduce((sum, item) => sum + item.columns.length, 0) ?? 0;

  const applyResult = (text: string, name: string, size: number) => {
    const parsed = parseSqlDump(text, name, size);
    setResult(parsed);
    setSelectedTable(parsed.tables[0]?.name ?? "");
    setTableFilter("");
    setFormatInput(text.slice(0, 20000));
    setFormatOutput("");
    setError("");
  };

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setDropActive(false);
    try {
      const text = await file.text();
      applyResult(text, file.name, file.size);
    } catch (caught) {
      setResult(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const analyzeInput = () => {
    const text = formatInput.trim();
    if (!text) return;
    try {
      applyResult(text, "pasted-sql.sql", new TextEncoder().encode(text).byteLength);
    } catch (caught) {
      setResult(null);
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  const runFormatter = async (mode: "format" | "minify") => {
    try {
      if (mode === "minify") {
        setFormatOutput(minifySqlText(formatInput));
        return;
      }
      const formatter = await import("sql-formatter");
      setFormatOutput(formatter.format(formatInput, { language: dialect as never }));
    } catch (caught) {
      setFormatOutput(`${t.parseError}: ${caught instanceof Error ? caught.message : String(caught)}`);
    }
  };

  const clear = () => {
    setResult(null);
    setSelectedTable("");
    setTableFilter("");
    setError("");
    setDropActive(false);
  };

  const factRows = React.useMemo<Array<[string, string]>>(() => [
    [labels.statements, result ? String(result.statementCount) : "--"],
    [t.tables, result ? String(result.tables.length) : "--"],
    [t.rows, result ? String(totalRows) : "--"],
    [labels.currentTable, table?.name ?? "--"]
  ], [labels.currentTable, labels.statements, result, t.rows, t.tables, table?.name, totalRows]);

  const stageFeatures = english
    ? [
        { label: "Schema", value: "Tables / Columns", detail: "Summarize CREATE TABLE definitions and field layouts." },
        { label: "Rows", value: "INSERT review", detail: "Browse INSERT rows and filter current-table samples." },
        { label: "Workspace", value: "Format / Export", detail: "Format SQL and export parsed tables." }
      ]
    : [
        { label: "表结构", value: "表 / 字段", detail: "汇总 CREATE TABLE 定义和字段布局。" },
        { label: "数据行", value: "INSERT 复核", detail: "浏览 INSERT 数据并筛选当前表。" },
        { label: "工作区", value: "格式化 / 导出", detail: "格式化 SQL 并导出解析结果。" }
      ];

  return (
    <div className={`sql-workbench ${result ? "has-sql" : "empty-sql"}`}>
      <div className="tool-panel upload-zone sql-upload">
        <PanelTitle title={labels.source} />
        <input ref={inputRef} type="file" aria-hidden="true" tabIndex={-1} accept=".sql,.txt,text/plain,application/sql" onChange={(event) => void handleFile(event.target.files?.[0])} />
        <p>{t.physicalMysqlHint}</p>
        <div
          className={`desktop-drop-zone ${dropActive ? "active" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => { event.preventDefault(); setDropActive(true); }}
          onDragLeave={() => setDropActive(false)}
          onDrop={(event) => { event.preventDefault(); void handleFile(event.dataTransfer.files?.[0]); }}
        >
          <strong>{result?.name ?? t.dropFileTitle}</strong>
          <span>{result ? `${result.tables.length} ${t.tables} · ${totalRows} ${t.rows} · ${totalColumns} ${t.columns}` : t.dropFileHint}</span>
          <em>{result ? `${result.statementCount} ${labels.statements} · ${formatBytes(result.size)}` : ".sql / .txt"}</em>
        </div>
        <div className="action-row">
          <AButton onClick={() => inputRef.current?.click()}>{t.selectFile}</AButton>
          <AButton variant="outlined" disabled={!formatInput.trim()} onClick={analyzeInput}>{labels.analyzeInput}</AButton>
          <AButton variant="text" disabled={!result && !error} onClick={clear}>{t.clear}</AButton>
        </div>
        {!result && <ToolStageFeatures items={stageFeatures} />}
        {error && <pre className="result-box">{error}</pre>}
      </div>

      {result && (
        <>
          <div className="tool-panel wide-panel sql-facts-panel">
            <ToolPanelHeader
              title={labels.overview}
              actions={
                <>
                <AButton variant="text" onClick={() => void navigator.clipboard.writeText(JSON.stringify(result, null, 2))}>JSON</AButton>
                <AButton variant="text" disabled={!table} onClick={() => table && void navigator.clipboard.writeText(table.name)}>{t.copy}</AButton>
                </>
              }
            />
            <ToolFactGrid className="sql-facts-grid" items={factRows.map(([label, value]) => ({ label, value, copyValue: value }))} />
          </div>

          <div className="tool-panel sql-table-panel">
            <PanelTitle title={t.tables} />
            <div className="sql-table-list">
              {result.tables.map((item) => (
                <AButton
                  className={item.name === table?.name ? "active" : ""}
                  key={item.name}
                  variant={item.name === table?.name ? "tonal" : "outlined"}
                  onClick={() => { setSelectedTable(item.name); setTableFilter(""); }}
                >
                  <strong>{item.name}</strong>
                  <span>{item.columns.length} {t.columns} / {item.insertRows} {t.rows}</span>
                </AButton>
              ))}
            </div>
          </div>

          <div className="tool-panel wide-panel sql-preview-panel">
            <ToolPanelHeader
              className="sql-preview-header"
              title={table?.name ?? t.dataPreview}
              subtitle={`${filteredRows.length}/${table?.rows.length ?? 0} ${t.rows}`}
              actions={
                <>
                <AButton variant="outlined" disabled={!table || !filteredRows.length} onClick={() => void navigator.clipboard.writeText(sqlRowsToCsv(previewColumns, filteredRows))}>{t.copyCsv}</AButton>
                <AButton variant="outlined" disabled={!table || !filteredRows.length} onClick={() => void navigator.clipboard.writeText(sqlTableToJson(table, filteredRows))}>{t.copyJson}</AButton>
                <AButton variant="text" disabled={!table || !filteredRows.length} onClick={() => table && downloadTextFile(`sql-${table.name}-${Date.now()}.csv`, sqlRowsToCsv(previewColumns, filteredRows), "text/csv;charset=utf-8")}>{t.exportCsv}</AButton>
                </>
              }
            />
            <label className="stack-label sql-filter-label">{t.search}<input className="text-input full-input" value={tableFilter} onChange={(event) => setTableFilter(event.target.value)} placeholder={t.search} /></label>
            {visibleRows.length ? (
              <div className="table-scroll sql-preview-scroll">
                <table className="data-table sql-preview-table">
                  <thead><tr>{previewColumns.map((column) => <th key={column}>{column}</th>)}</tr></thead>
                  <tbody>{visibleRows.map((row, rowIndex) => <tr key={rowIndex}>{previewColumns.map((column) => <td key={column}>{row[column] ?? ""}</td>)}</tr>)}</tbody>
                </table>
              </div>
            ) : <div className="empty-state">{labels.noRows}</div>}
          </div>

          <details className="image-advanced-shell sql-advanced-shell wide-panel">
            <summary>{labels.details}</summary>
            <div className="sql-advanced-stack">
              <div className="tool-panel wide-panel sql-export-panel">
                <ToolPanelHeader
                  title={labels.export}
                  actions={
                    <>
                    <AButton variant="outlined" onClick={() => downloadTextFile(`sql-dump-${Date.now()}.json`, JSON.stringify(result, null, 2), "application/json;charset=utf-8")}>{t.exportJson}</AButton>
                    <AButton variant="text" disabled={!table} onClick={() => table && downloadTextFile(`sql-${table.name}-${Date.now()}.json`, sqlTableToJson(table, filteredRows), "application/json;charset=utf-8")}>{t.exportJson}</AButton>
                    </>
                  }
                />
              </div>
              <div className="tool-panel advanced-panel">
                <PanelTitle title={t.sqlSummary} />
                <InfoTable rows={[[labels.name, result.name], [t.fileSize, formatBytes(result.size)], [labels.statements, String(result.statementCount)], [t.tables, String(result.tables.length)], [t.rows, String(totalRows)], [t.sensitiveFields, String(result.findings.length)]]} />
              </div>
              <div className="tool-panel wide-panel advanced-panel">
                <PanelTitle title={t.tableStructure} />
                {table?.columns.length ? <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.columns}</th><th>{t.detectedType}</th><th>{t.sampleValue}</th></tr></thead><tbody>{table.columns.map((column) => <tr key={column.name}><td>{column.name}</td><td>{column.type}</td><td>{table.rows.find((row) => row[column.name] && row[column.name] !== "NULL")?.[column.name] ?? "--"}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}
              </div>
              <div className="tool-panel wide-panel advanced-panel">
                <PanelTitle title={t.sensitiveFields} />
                {result.findings.length ? <div className="table-scroll compact-scroll"><table className="data-table"><thead><tr><th>{t.tables}</th><th>{t.columns}</th><th>{t.detectedType}</th><th>{t.sampleValue}</th></tr></thead><tbody>{result.findings.map((finding, index) => <tr key={`${finding.table}-${finding.column}-${finding.type}-${index}`}><td>{finding.table}</td><td>{finding.column}</td><td>{finding.type}</td><td>{finding.sample}</td></tr>)}</tbody></table></div> : <div className="empty-state">--</div>}
              </div>
            </div>
          </details>

          <details className="tool-panel wide-panel sql-format-details" open>
            <summary><strong>{t.sqlFormatter}</strong></summary>
            <div className="control-bar">
              <label>{t.sqlDialect}<ASelect aria-label={t.sqlDialect} value={dialect} onChange={(value) => setDialect(String(value))} options={["mysql", "postgresql", "sqlite", "transactsql", "mariadb", "plsql", "spark"].map((item) => ({ value: item, label: item }))} /></label>
              <AButton onClick={() => void runFormatter("format")}>{t.formatSql}</AButton>
              <AButton variant="outlined" onClick={() => void runFormatter("minify")}>{t.minifySql}</AButton>
              <AButton variant="text" disabled={!formatOutput} onClick={() => void navigator.clipboard.writeText(formatOutput)}>{t.copyOutput}</AButton>
            </div>
            <div className="text-columns sql-format-columns">
              <textarea className="single-textarea" aria-label={english ? "SQL input" : "SQL 输入"} value={formatInput} onChange={(event) => setFormatInput(event.target.value)} />
              <textarea className="single-textarea" aria-label={english ? "Formatted SQL output" : "格式化 SQL 输出"} value={formatOutput} readOnly />
            </div>
          </details>
        </>
      )}
    </div>
  );
}

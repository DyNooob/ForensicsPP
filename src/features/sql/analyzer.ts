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

import type { SqlColumn, SqlFinding, SqlParseResult, SqlTable } from "../../models";
import { detectHashType } from "../../utils/hash";

export function stripSqlComments(sql: string) {
  return sql
    .replace(/\/\*![\s\S]*?\*\//g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*--.*$/gm, "")
    .replace(/^\s*#.*$/gm, "");
}

export function minifySqlText(value: string) {
  return stripSqlComments(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .join(" ")
    .replace(/\s*;\s*/g, "; ")
    .trim();
}

function splitSqlStatements(sql: string) {
  const statements: string[] = [];
  let current = "";
  let quote: "'" | '"' | "`" | null = null;

  for (let index = 0; index < sql.length; index += 1) {
    const char = sql[index];
    current += char;
    if (quote) {
      if (char === "\\") {
        index += 1;
        current += sql[index] ?? "";
      } else if (char === quote) {
        if ((quote === "'" || quote === '"') && sql[index + 1] === quote) {
          index += 1;
          current += sql[index];
        } else quote = null;
      }
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === ";") {
      const statement = current.trim();
      if (statement) statements.push(statement);
      current = "";
    }
  }
  const tail = current.trim();
  if (tail) statements.push(tail);
  return statements;
}

function splitTopLevelComma(text: string) {
  const parts: string[] = [];
  let current = "";
  let depth = 0;
  let quote: "'" | '"' | "`" | null = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    current += char;
    if (quote) {
      if (char === "\\") {
        index += 1;
        current += text[index] ?? "";
      } else if (char === quote) {
        if ((quote === "'" || quote === '"') && text[index + 1] === quote) {
          index += 1;
          current += text[index];
        } else quote = null;
      }
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") depth = Math.max(0, depth - 1);
    if (char === "," && depth === 0) {
      parts.push(current.slice(0, -1).trim());
      current = "";
    }
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function normalizeSqlIdentifier(raw: string) {
  return raw.trim().replace(/\s+/g, "").replace(/[`"\[\]]/g, "").split(".").filter(Boolean).pop() ?? raw.trim();
}

function getCreateBody(statement: string) {
  const start = statement.indexOf("(");
  if (start < 0) return "";
  let depth = 0;
  let quote: "'" | '"' | "`" | null = null;
  for (let index = start; index < statement.length; index += 1) {
    const char = statement[index];
    if (quote) {
      if (char === "\\") index += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") {
      depth -= 1;
      if (depth === 0) return statement.slice(start + 1, index);
    }
  }
  return "";
}

function parseSqlColumn(definition: string): SqlColumn | null {
  const trimmed = definition.trim();
  if (/^(PRIMARY|UNIQUE|KEY|INDEX|CONSTRAINT|FOREIGN|FULLTEXT|SPATIAL|CHECK)\b/i.test(trimmed)) return null;
  const match = trimmed.match(/^`([^`]+)`\s+(.+)$/) ?? trimmed.match(/^"([^"]+)"\s+(.+)$/) ?? trimmed.match(/^([A-Za-z_][\w$]*)\s+(.+)$/);
  if (!match) return null;
  const rest = match[2].trim();
  const type = rest.split(/\s+(?:CHARACTER|COLLATE|NOT|NULL|DEFAULT|COMMENT|PRIMARY|UNIQUE|KEY|AUTO_INCREMENT|GENERATED|REFERENCES)\b/i)[0];
  return { name: match[1], type: type || rest };
}

function parseCreateTable(statement: string) {
  const match = statement.match(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(.+?)\s*\(/i);
  if (!match) return null;
  const name = normalizeSqlIdentifier(match[1]);
  const columns = splitTopLevelComma(getCreateBody(statement)).map(parseSqlColumn).filter(Boolean) as SqlColumn[];
  return { name, columns };
}

function unescapeSqlString(value: string) {
  return value
    .replace(/\\0/g, "\0")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\b/g, "\b")
    .replace(/\\Z/g, "\x1a")
    .replace(/\\'/g, "'")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\")
    .replace(/''/g, "'");
}

function sqlValueToString(raw: string) {
  const value = raw.trim();
  if (/^NULL$/i.test(value)) return "NULL";
  if (/^x'[0-9a-f]+'$/i.test(value)) return value.toUpperCase();
  if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) return unescapeSqlString(value.slice(1, -1));
  return value;
}

function forEachSqlTuple(values: string, onTuple: (items: string[]) => void) {
  let current = "";
  let depth = 0;
  let quote: "'" | '"' | "`" | null = null;
  for (let index = 0; index < values.length; index += 1) {
    const char = values[index];
    if (quote) {
      current += char;
      if (char === "\\") {
        index += 1;
        current += values[index] ?? "";
      } else if (char === quote) {
        if ((quote === "'" || quote === '"') && values[index + 1] === quote) {
          index += 1;
          current += values[index];
        } else quote = null;
      }
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      current += char;
      continue;
    }
    if (char === "(") {
      if (depth > 0) current += char;
      depth += 1;
      continue;
    }
    if (char === ")") {
      depth -= 1;
      if (depth === 0) {
        onTuple(splitTopLevelComma(current).map(sqlValueToString));
        current = "";
      } else current += char;
      continue;
    }
    if (depth > 0) current += char;
  }
}

function parseInsertStatement(statement: string) {
  const match = statement.match(/INSERT\s+(?:IGNORE\s+)?INTO\s+((?:`[^`]+`|"[^"]+"|\[[^\]]+\]|[\w$]+)(?:\s*\.\s*(?:`[^`]+`|"[^"]+"|\[[^\]]+\]|[\w$]+))?)\s*(?:\(([\s\S]*?)\))?\s+VALUES\s*([\s\S]*?);?$/i);
  if (!match) return null;
  return {
    table: normalizeSqlIdentifier(match[1]),
    columns: match[2] ? splitTopLevelComma(match[2]).map(normalizeSqlIdentifier) : [],
    values: match[3]
  };
}

function analyzeSqlFindings(tables: SqlTable[]) {
  const findings: SqlFinding[] = [];
  const sensitiveColumn = /(pass(word)?|pwd|token|secret|api[_-]?key|access[_-]?key|salt|hash|mail|email|phone|mobile|user(name)?|login|auth|session)/i;
  const seen = new Set<string>();
  const push = (finding: SqlFinding) => {
    const key = `${finding.table}:${finding.column}:${finding.type}:${finding.sample}`;
    if (seen.has(key) || findings.length >= 100) return;
    seen.add(key);
    findings.push(finding);
  };
  tables.forEach((table) => {
    table.columns.forEach((column) => {
      if (!sensitiveColumn.test(column.name)) return;
      const sample = table.rows.find((row) => row[column.name] && row[column.name] !== "NULL")?.[column.name] ?? "--";
      push({ table: table.name, column: column.name, type: "sensitive column", sample });
    });
    table.rows.slice(0, 250).forEach((row) => {
      Object.entries(row).forEach(([column, value]) => {
        const hashType = detectHashType(value);
        if (hashType) push({ table: table.name, column, type: hashType, sample: value });
      });
    });
  });
  return findings;
}

export function sqlRowsToCsv(columns: string[], rows: Array<Record<string, string>>) {
  const escape = (value: string) => `"${String(value ?? "").replace(/"/g, '""')}"`;
  return [columns.map(escape).join(","), ...rows.map((row) => columns.map((column) => escape(row[column] ?? "")).join(","))].join("\n");
}

export function filterSqlRows(table: SqlTable | null, query: string) {
  if (!table) return [];
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) return table.rows;
  return table.rows.filter((row) => Object.entries(row).some(([column, value]) => `${column} ${value}`.toLowerCase().includes(trimmed)));
}

export function sqlTableToJson(table: SqlTable | null, rows: Array<Record<string, string>>) {
  if (!table) return "{}";
  return JSON.stringify({ table: table.name, columns: table.columns, sampledRows: rows, parsedRows: table.rows.length, insertRows: table.insertRows }, null, 2);
}

export function parseSqlDump(sql: string, name: string, size: number): SqlParseResult {
  const statements = splitSqlStatements(stripSqlComments(sql));
  const tableMap = new Map<string, SqlTable>();
  const ensureTable = (name: string) => {
    const existing = tableMap.get(name);
    if (existing) return existing;
    const table: SqlTable = { name, columns: [], rows: [], insertRows: 0 };
    tableMap.set(name, table);
    return table;
  };
  statements.forEach((statement) => {
    const create = parseCreateTable(statement);
    if (create) {
      ensureTable(create.name).columns = create.columns;
      return;
    }
    const insert = parseInsertStatement(statement);
    if (!insert) return;
    const table = ensureTable(insert.table);
    const fallbackColumns = table.columns.map((column) => column.name);
    forEachSqlTuple(insert.values, (items) => {
      table.insertRows += 1;
      if (table.rows.length >= 500) return;
      const columns = insert.columns.length ? insert.columns : fallbackColumns.length ? fallbackColumns : items.map((_, index) => `col_${index + 1}`);
      const row: Record<string, string> = {};
      items.forEach((item, index) => { row[columns[index] ?? `col_${index + 1}`] = item; });
      table.rows.push(row);
    });
  });
  const tables = Array.from(tableMap.values()).sort((a, b) => a.name.localeCompare(b.name));
  return { name, size, statementCount: statements.length, tables, findings: analyzeSqlFindings(tables) };
}

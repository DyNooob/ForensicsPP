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

export type JsonBasicPath = {
  path: string;
  type: string;
  value: string;
  length: number;
};

export type JsonBasicParsed = {
  ok: boolean;
  value: unknown;
  kind: string;
  error: string;
  normalized: string;
  minified: string;
  jsonl: string;
};

export type JsonBasicResult = {
  parsed: JsonBasicParsed;
  paths: JsonBasicPath[];
};

function valueType(value: unknown) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function displayValue(value: unknown) {
  if (Array.isArray(value)) return `Array(${value.length})`;
  if (value && typeof value === "object") return `Object(${Object.keys(value).length})`;
  if (typeof value === "string") return value;
  if (value === undefined) return "undefined";
  return JSON.stringify(value);
}

function childPath(parent: string, key: string) {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`;
}

export function parseBasicJson(input: string): JsonBasicParsed {
  if (!input.trim()) return { ok: false, value: null, kind: "", error: "", normalized: "", minified: "", jsonl: "" };
  try {
    const value: unknown = JSON.parse(input);
    return {
      ok: true,
      value,
      kind: "JSON",
      error: "",
      normalized: JSON.stringify(value, null, 2),
      minified: JSON.stringify(value),
      jsonl: Array.isArray(value) ? value.map((item) => JSON.stringify(item)).join("\n") : JSON.stringify(value)
    };
  } catch (jsonError) {
    const lines = input.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length > 1) {
      try {
        const value = lines.map((line) => JSON.parse(line) as unknown);
        return {
          ok: true,
          value,
          kind: "JSONL",
          error: "",
          normalized: JSON.stringify(value, null, 2),
          minified: JSON.stringify(value),
          jsonl: value.map((item) => JSON.stringify(item)).join("\n")
        };
      } catch {
        // Keep the original JSON parser error because it includes the useful offset.
      }
    }
    return {
      ok: false,
      value: null,
      kind: "",
      error: jsonError instanceof Error ? jsonError.message : String(jsonError),
      normalized: "",
      minified: "",
      jsonl: ""
    };
  }
}

export function collectBasicJsonPaths(root: unknown) {
  const rows: JsonBasicPath[] = [];
  const visit = (value: unknown, path: string) => {
    if (rows.length >= 5000) return;
    const rendered = displayValue(value);
    rows.push({ path, type: valueType(value), value: rendered, length: rendered.length });
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${path}[${index}]`));
    } else if (value && typeof value === "object") {
      Object.entries(value as Record<string, unknown>).forEach(([key, item]) => visit(item, childPath(path, key)));
    }
  };
  visit(root, "$");
  return rows;
}

export function analyzeBasicJson(input: string): JsonBasicResult {
  const parsed = parseBasicJson(input);
  return { parsed, paths: parsed.ok ? collectBasicJsonPaths(parsed.value) : [] };
}

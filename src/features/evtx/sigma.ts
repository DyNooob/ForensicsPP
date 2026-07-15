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

import { parseAllDocuments } from "yaml";
import type { EvtxEvent } from "./analyzer";

type SigmaScalar = string | number | boolean | null;
type SigmaSelection = Record<string, SigmaScalar | SigmaScalar[]> | Array<Record<string, SigmaScalar | SigmaScalar[]> | SigmaScalar> | SigmaScalar;

export type SigmaRule = {
  title: string;
  id: string;
  level: string;
  tags: string[];
  logsource: Record<string, string>;
  condition: string;
  selections: Record<string, SigmaSelection>;
};

export type SigmaMatch = {
  ruleTitle: string;
  ruleId: string;
  level: string;
  tags: string[];
  event: EvtxEvent;
};

export type SigmaParseResult = {
  rules: SigmaRule[];
  errors: string[];
};

const SUPPORTED_MODIFIERS = new Set(["contains", "startswith", "endswith", "re", "all"]);

function object(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function scalar(value: unknown): value is SigmaScalar {
  return value == null || ["string", "number", "boolean"].includes(typeof value);
}

function validSelection(value: unknown): value is SigmaSelection {
  if (scalar(value)) return true;
  if (Array.isArray(value)) return value.every((item) => scalar(item) || (object(item) && Object.values(item).every((entry) => scalar(entry) || (Array.isArray(entry) && entry.every(scalar)))));
  return object(value) && Object.values(value).every((entry) => scalar(entry) || (Array.isArray(entry) && entry.every(scalar)));
}

export function parseSigmaRules(yamlText: string): SigmaParseResult {
  const rules: SigmaRule[] = [];
  const errors: string[] = [];
  const documents = parseAllDocuments(yamlText);
  documents.forEach((document, index) => {
    if (document.errors.length) {
      errors.push(`Document ${index + 1}: ${document.errors[0].message}`);
      return;
    }
    const raw = document.toJS() as unknown;
    if (!object(raw)) {
      errors.push(`Document ${index + 1}: rule must be a mapping.`);
      return;
    }
    if (raw.correlation) {
      errors.push(`Document ${index + 1}: correlation rules are not supported locally.`);
      return;
    }
    if (!object(raw.detection) || typeof raw.detection.condition !== "string") {
      errors.push(`Document ${index + 1}: detection.condition is required.`);
      return;
    }
    if (/[|]\s*(?:count|sum|min|max|avg|near)\b/i.test(raw.detection.condition)) {
      errors.push(`Document ${index + 1}: aggregation conditions are not supported locally.`);
      return;
    }
    const selections: Record<string, SigmaSelection> = {};
    let invalid = "";
    for (const [name, value] of Object.entries(raw.detection)) {
      if (name === "condition" || name === "timeframe") continue;
      if (!validSelection(value)) {
        invalid = `selection '${name}' uses an unsupported structure`;
        break;
      }
      if (object(value)) {
        for (const field of Object.keys(value)) {
          const modifiers = field.split("|").slice(1);
          const unsupported = modifiers.find((modifier) => !SUPPORTED_MODIFIERS.has(modifier.toLowerCase()));
          if (unsupported) {
            invalid = `selection '${name}' uses unsupported modifier '${unsupported}'`;
            break;
          }
        }
      }
      selections[name] = value;
    }
    if (invalid) {
      errors.push(`Document ${index + 1}: ${invalid}.`);
      return;
    }
    if (!Object.keys(selections).length) {
      errors.push(`Document ${index + 1}: no selections found.`);
      return;
    }
    rules.push({
      title: typeof raw.title === "string" ? raw.title : `Rule ${index + 1}`,
      id: typeof raw.id === "string" ? raw.id : "",
      level: typeof raw.level === "string" ? raw.level : "",
      tags: Array.isArray(raw.tags) ? raw.tags.map(String) : [],
      logsource: object(raw.logsource) ? Object.fromEntries(Object.entries(raw.logsource).map(([key, value]) => [key, String(value)])) : {},
      condition: raw.detection.condition,
      selections
    });
  });
  return { rules, errors };
}

function fieldValue(event: EvtxEvent, field: string) {
  const aliases: Record<string, unknown> = {
    EventID: event.eventId,
    EventRecordID: event.recordId,
    Provider_Name: event.provider,
    ProviderName: event.provider,
    Channel: event.channel,
    Computer: event.computer,
    Level: event.level,
    LevelName: event.levelName,
    UserID: event.userId,
    ProcessID: event.processId,
    ThreadID: event.threadId
  };
  const entries = [...Object.entries(aliases), ...Object.entries(event.data)];
  return entries.find(([name]) => name.toLowerCase() === field.toLowerCase())?.[1];
}

function wildcardPattern(value: string) {
  let pattern = "";
  let escaped = false;
  for (const char of value) {
    if (escaped) {
      pattern += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      escaped = false;
    } else if (char === "\\") escaped = true;
    else if (char === "*") pattern += ".*";
    else if (char === "?") pattern += ".";
    else pattern += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  if (escaped) pattern += "\\\\";
  return pattern;
}

function matchScalar(actual: unknown, expected: SigmaScalar, modifiers: string[]) {
  if (expected == null) return actual == null || actual === "";
  if (actual == null) return false;
  const source = String(actual);
  const wanted = String(expected);
  const lower = source.toLowerCase();
  const target = wanted.toLowerCase();
  if (modifiers.includes("re")) {
    if (wanted.length > 1024) return false;
    try { return new RegExp(wanted, "i").test(source); } catch { return false; }
  }
  if (modifiers.includes("contains")) return lower.includes(target);
  if (modifiers.includes("startswith")) return lower.startsWith(target);
  if (modifiers.includes("endswith")) return lower.endsWith(target);
  if (wanted.includes("*") || wanted.includes("?")) return new RegExp(`^${wildcardPattern(wanted)}$`, "i").test(source);
  return lower === target;
}

function matchMap(event: EvtxEvent, selection: Record<string, SigmaScalar | SigmaScalar[]>) {
  return Object.entries(selection).every(([fieldExpression, expected]) => {
    const [field, ...rawModifiers] = fieldExpression.split("|");
    const modifiers = rawModifiers.map((modifier) => modifier.toLowerCase());
    const values = Array.isArray(expected) ? expected : [expected];
    const matches = values.map((value) => matchScalar(fieldValue(event, field), value, modifiers));
    return modifiers.includes("all") ? matches.every(Boolean) : matches.some(Boolean);
  });
}

function matchSelection(event: EvtxEvent, selection: SigmaSelection) {
  if (object(selection)) return matchMap(event, selection as Record<string, SigmaScalar | SigmaScalar[]>);
  if (Array.isArray(selection)) return selection.some((item) => object(item)
    ? matchMap(event, item as Record<string, SigmaScalar | SigmaScalar[]>)
    : Object.values(event.data).some((value) => matchScalar(value, item as SigmaScalar, [])));
  return Object.values(event.data).some((value) => matchScalar(value, selection, []));
}

type Token = { type: "word" | "number" | "left" | "right"; value: string };

function conditionTokens(condition: string): Token[] {
  const values = condition.match(/\(|\)|\d+|[A-Za-z_][\w*?.-]*/g) ?? [];
  return values.map((value) => value === "(" ? { type: "left", value } : value === ")" ? { type: "right", value } : /^\d+$/.test(value) ? { type: "number", value } : { type: "word", value });
}

function evaluateCondition(condition: string, selectionResults: Record<string, boolean>) {
  const tokens = conditionTokens(condition);
  let cursor = 0;
  const names = Object.keys(selectionResults);
  const consume = () => tokens[cursor++];
  const peek = () => tokens[cursor];
  const selected = (pattern: string) => pattern.toLowerCase() === "them"
    ? names
    : names.filter((name) => new RegExp(`^${wildcardPattern(pattern)}$`, "i").test(name));
  const primary = (): boolean => {
    const token = consume();
    if (!token) throw new Error("Unexpected end of Sigma condition.");
    if (token.type === "left") {
      const result = or();
      if (consume()?.type !== "right") throw new Error("Unclosed Sigma condition group.");
      return result;
    }
    if (token.type === "number" || token.value.toLowerCase() === "all") {
      const amount = token.type === "number" ? Number(token.value) : Number.POSITIVE_INFINITY;
      if (consume()?.value.toLowerCase() !== "of") throw new Error("Expected 'of' in Sigma condition.");
      const pattern = consume()?.value;
      if (!pattern) throw new Error("Expected a selection pattern after 'of'.");
      const matched = selected(pattern).filter((name) => selectionResults[name]).length;
      return amount === Number.POSITIVE_INFINITY ? matched === selected(pattern).length && matched > 0 : matched >= amount;
    }
    return selectionResults[token.value] ?? false;
  };
  const unary = (): boolean => peek()?.value.toLowerCase() === "not" ? (consume(), !unary()) : primary();
  const and = (): boolean => {
    let value = unary();
    while (peek()?.value.toLowerCase() === "and") { consume(); value = unary() && value; }
    return value;
  };
  const or = (): boolean => {
    let value = and();
    while (peek()?.value.toLowerCase() === "or") { consume(); value = and() || value; }
    return value;
  };
  const result = or();
  if (cursor !== tokens.length) throw new Error(`Unsupported Sigma condition near '${tokens[cursor].value}'.`);
  return result;
}

function logsourceMatches(rule: SigmaRule, event: EvtxEvent) {
  const service = rule.logsource.service?.toLowerCase();
  const product = rule.logsource.product?.toLowerCase();
  if (product && product !== "windows") return false;
  if (!service) return true;
  const channel = event.channel.toLowerCase();
  const aliases: Record<string, string[]> = {
    security: ["security"],
    system: ["system"],
    application: ["application"],
    sysmon: ["microsoft-windows-sysmon/operational"],
    powershell: ["powershell", "microsoft-windows-powershell/operational"]
  };
  return (aliases[service] ?? [service]).some((value) => channel === value || channel.includes(value));
}

export function runSigmaRules(events: EvtxEvent[], rules: SigmaRule[], maxMatches = 10_000) {
  const matches: SigmaMatch[] = [];
  const errors: string[] = [];
  outer:
  for (const rule of rules) {
    try {
      for (const event of events) {
        if (!logsourceMatches(rule, event)) continue;
        const results = Object.fromEntries(Object.entries(rule.selections).map(([name, selection]) => [name, matchSelection(event, selection)]));
        if (evaluateCondition(rule.condition, results)) {
          matches.push({ ruleTitle: rule.title, ruleId: rule.id, level: rule.level, tags: rule.tags, event });
          if (matches.length >= maxMatches) break outer;
        }
      }
    } catch (caught) {
      errors.push(`${rule.title}: ${caught instanceof Error ? caught.message : String(caught)}`);
    }
  }
  return { matches, errors };
}

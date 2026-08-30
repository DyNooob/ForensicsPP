#!/usr/bin/env node
/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.forensicspp.com
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

import { createRequire } from "module";
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, dirname, resolve } from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const ts = require("typescript");

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TOOLS_DIR = join(ROOT, "src", "tools");
const I18N_PATH = join(ROOT, "src", "i18n.ts");
const WRITE = process.argv.includes("--write");

function walk(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".tsx")) out.push(p);
  }
  return out;
}

function slugify(s) {
  let slug = s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  if (!slug) slug = "s";
  if (/^[0-9]/.test(slug)) slug = "k_" + slug;
  return slug;
}

// ---- Parse i18n.ts for existing zh/en objects + keys ----
function loadI18n() {
  const src = readFileSync(I18N_PATH, "utf8");
  const sf = ts.createSourceFile("i18n.ts", src, ts.ScriptTarget.Latest, true);
  let zhObj = null;
  let enObj = null;
  function findCopy(node) {
    if (
      ts.isVariableDeclaration(node) &&
      node.name.getText &&
      node.name.getText() === "copy" &&
      node.initializer &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      for (const prop of node.initializer.properties) {
        if (ts.isPropertyAssignment(prop) && ts.isObjectLiteralExpression(prop.initializer)) {
          if (prop.name.getText() === "zh") zhObj = prop.initializer;
          if (prop.name.getText() === "en") enObj = prop.initializer;
        }
      }
    }
    ts.forEachChild(node, findCopy);
  }
  findCopy(sf);

  const existingKeys = new Set();
  const enByValue = new Map();
  for (const prop of zhObj.properties) {
    if (ts.isPropertyAssignment(prop)) existingKeys.add(prop.name.getText());
  }
  for (const prop of enObj.properties) {
    if (ts.isPropertyAssignment(prop) && ts.isStringLiteral(prop.initializer)) {
      enByValue.set(prop.initializer.text, prop.name.getText());
    }
  }
  return { src, zhObj, enObj, existingKeys, enByValue };
}

// ---- Collect english-conditioned string-literal ternaries ----
function collectCandidates(src) {
  const sf = ts.createSourceFile("f.tsx", src, ts.ScriptTarget.Latest, true);
  const cands = [];
  function visit(node) {
    if (ts.isConditionalExpression(node)) {
      const cond = node.condition;
      if (ts.isIdentifier(cond) && cond.text === "english") {
        if (ts.isStringLiteral(node.whenTrue) && ts.isStringLiteral(node.whenFalse)) {
          if (node.whenTrue.text !== node.whenFalse.text) {
            cands.push({
              start: node.getStart(sf),
              end: node.getEnd(),
              en: node.whenTrue.text,
              zh: node.whenFalse.text,
            });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  return cands;
}

function hasNesting(cands) {
  for (let i = 0; i < cands.length; i++) {
    for (let j = 0; j < cands.length; j++) {
      if (i !== j && cands[j].start >= cands[i].start && cands[j].end <= cands[i].end) {
        return true;
      }
    }
  }
  return false;
}

// ---- Global key map with dedup + reuse of existing translations ----
function makeKeyMap(i18n) {
  const used = new Set(i18n.existingKeys);
  const keyByEn = new Map();
  const entries = [];
  function getKey(en, zh) {
    if (keyByEn.has(en)) return keyByEn.get(en);
    if (i18n.enByValue.has(en)) {
      const k = i18n.enByValue.get(en);
      keyByEn.set(en, k);
      return k;
    }
    let base = slugify(en);
    let key = base;
    let i = 2;
    while (used.has(key)) {
      key = base + "_" + i;
      i++;
    }
    used.add(key);
    keyByEn.set(en, key);
    entries.push({ key, en, zh });
    return key;
  }
  return { keyByEn, entries, getKey };
}

function main() {
  const i18n = loadI18n();
  const files = walk(TOOLS_DIR);
  const keyMap = makeKeyMap(i18n);

  const report = [];
  let totalCandidates = 0;
  let totalRemaining = 0;
  const allEntries = keyMap.entries;

  for (const file of files) {
    const src = readFileSync(file, "utf8");
    const cands = collectCandidates(src);
    const nested = hasNesting(cands);
    for (const c of cands) keyMap.getKey(c.en, c.zh);

    if (WRITE && !nested) {
      let text = src;
      const sorted = [...cands].sort((a, b) => b.start - a.start);
      for (const c of sorted) {
        const key = keyMap.keyByEn.get(c.en);
        text = text.slice(0, c.start) + `t.${key}` + text.slice(c.end);
      }
      const occ = (text.match(/\benglish\b/g) || []).length;
      if (occ === 1) {
        text = text.replace(/\s*const english = t\.waiting === "Waiting";\s*\n/, "");
      }
      writeFileSync(file, text);
    }

    if (cands.length) {
      totalCandidates += cands.length;
      report.push({
        file: file.replace(ROOT + "/", ""),
        candidates: cands.length,
        nested,
        remaining: nested ? cands.length : 0,
      });
      totalRemaining += nested ? cands.length : 0;
    }
  }

  // ---- Insert new keys into i18n.ts (write mode only) ----
  if (WRITE && allEntries.length) {
    let text = i18n.src;
    // Never re-insert a key that already exists in i18n.ts (defensive against
    // clobbering committed translations such as aboutProjectDesc).
    const toInsert = allEntries.filter((e) => !i18n.existingKeys.has(e.key));
    const makeBlock = (lang) =>
      toInsert.map((e) => `    ${e.key}: ${JSON.stringify(e[lang])},`).join("\n");

    // Insert sequentially. enObj is later in the file than zhObj, so inserting
    // it first leaves zhObj's close position (getEnd()-1) unchanged — no delta
    // math needed. Using getEnd()-1 (the position of the closing '}') is
    // reliable here; getLastToken() is NOT (returns the file's last token).
    const insertAt = (obj, block) => {
      const closePos = obj.getEnd() - 1; // the closing '}'
      const before = text.slice(0, closePos);
      const lastChar = before.trimEnd().slice(-1);
      const sep = lastChar === "," ? "\n" : ",\n";
      text = before + sep + block + "\n" + text.slice(closePos);
    };
    insertAt(i18n.enObj, makeBlock("en")); // later in file first
    insertAt(i18n.zhObj, makeBlock("zh")); // earlier, position unaffected
    writeFileSync(I18N_PATH, text);
  }

  // ---- Report ----
  console.log(`\n=== i18n-extract (${WRITE ? "WRITE" : "DRY-RUN"}) ===`);
  console.log(`Files scanned : ${files.length}`);
  console.log(`Candidates    : ${totalCandidates} english-conditioned string-literal ternaries`);
  console.log(`New keys      : ${allEntries.length} (deduped; existing translations reused where EN matched)`);
  console.log(`Remaining     : ${totalRemaining} in ${report.filter((r) => r.nested).length} nested file(s) — manual review`);
  console.log("\nPer-file:");
  for (const r of report.sort((a, b) => b.candidates - a.candidates)) {
    const tag = r.nested ? " [NESTED->skip]" : "";
    console.log(`  ${String(r.candidates).padStart(3)}  ${r.file}${tag}`);
  }
  if (allEntries.length) {
    console.log("\nNew key map (en -> key):");
    for (const e of allEntries) console.log(`  ${e.key.padEnd(28)} ${JSON.stringify(e.en)} | ${JSON.stringify(e.zh)}`);
  }
  if (WRITE) {
    console.log("\nWrote tool files + i18n.ts. Run `npm run typecheck` and `node scripts/i18n-check.mjs` to verify.");
  } else {
    console.log("\n(re-run with --write to apply; nesting files will be skipped)");
  }
}

main();

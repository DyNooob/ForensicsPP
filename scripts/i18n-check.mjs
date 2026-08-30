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
import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, dirname, resolve } from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const ts = require("typescript");

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TOOLS_DIR = join(ROOT, "src", "tools");

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

const violations = [];
for (const file of walk(TOOLS_DIR)) {
  const src = readFileSync(file, "utf8");
  const sf = ts.createSourceFile("f.tsx", src, ts.ScriptTarget.Latest, true);
  function visit(node) {
    if (ts.isConditionalExpression(node)) {
      const cond = node.condition;
      if (ts.isIdentifier(cond) && cond.text === "english") {
        if (
          ts.isStringLiteral(node.whenTrue) &&
          ts.isStringLiteral(node.whenFalse) &&
          node.whenTrue.text !== node.whenFalse.text
        ) {
          violations.push({
            file: file.replace(ROOT + "/", ""),
            en: node.whenTrue.text,
            zh: node.whenFalse.text,
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
}

if (violations.length) {
  console.error(`\n[i18n-check] FAILED: ${violations.length} inline english-ternary display string(s) remain:\n`);
  for (const v of violations) {
    console.error(`  ${v.file}: english ? ${JSON.stringify(v.en)} : ${JSON.stringify(v.zh)}`);
  }
  process.exit(1);
} else {
  console.log("[i18n-check] OK: no inline english-conditioned string-literal ternaries in src/tools.");
  process.exit(0);
}

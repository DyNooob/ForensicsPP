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

import { readdir, readFile, access } from "node:fs/promises";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const documents = [];
async function walk(folder) {
  for (const entry of await readdir(folder, { withFileTypes: true })) {
    const path = join(folder, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (entry.name.endsWith(".md")) documents.push(path);
  }
}
await walk(join(root, "docs"));
await walk(join(root, ".github"));
for (const entry of await readdir(root)) if (entry.endsWith(".md")) documents.push(join(root, entry));
documents.push(join(root, "public/README.md"), join(root, "tests/fixtures/README.md"));
const failures = [];
let links = 0;
for (const path of documents) {
  const source = await readFile(path, "utf8");
  const prose = source.replace(/^```[^\n]*\n[\s\S]*?^```\s*$/gm, "").replace(/`[^`\n]+`/g, "");
  for (const match of prose.matchAll(/!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)/g)) {
    let target = match[1].replace(/^<|>$/g, "");
    if (/^(?:[a-z][a-z\d+.-]*:|#|\/\/)/i.test(target)) continue;
    target = target.split("#")[0].split("?")[0];
    if (!target) continue;
    links++;
    try { await access(resolve(dirname(path), decodeURIComponent(target))); }
    catch { failures.push(`${path.slice(root.length + 1)}: missing link ${target}`); }
  }
  // Deployment secrets are never useful documentation, including historical records.
  if (/\bgh[pousr]_[A-Za-z\d]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|export\s+SSHPASS\s*=\s*['"][^'"]+['"]/.test(source)) failures.push(`${path.slice(root.length + 1)}: credential-like content`);
}
if (failures.length) throw new Error(`Documentation checks failed:\n${failures.join("\n")}`);
console.log(`Documentation verified: ${documents.length} Markdown files, ${links} local links, no matching deployment-secret patterns.`);

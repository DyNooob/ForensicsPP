#!/usr/bin/env node
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

import { readdir, readFile, writeFile } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const writeMode = process.argv.includes("--write");
const projectMarker = "Forensics++ (ForensicsPP.com)";

const lines = [
  projectMarker,
  "Local-first browser forensics workbench",
  "",
  "Copyright (c) 2026 DyNooob. All rights reserved.",
  "Author: DyNooob",
  "Website: https://www.loken.cn",
  "Platform: DigiForensics.cn",
  "Project: https://git.loken.cn/dynooob/ForensicsPP",
  "",
  "Forensics++ is an open-source, browser-side toolkit for CTF/MISC,",
  "lightweight forensic triage, encoding/decoding, metadata inspection,",
  "hashes, archive parsing, and local analysis.",
  "",
  "Do not use this project for unauthorized access, intrusion,",
  "privacy infringement, or unlawful activity.",
  "",
  "Released under the MIT License.",
  "Full source code: https://git.loken.cn/dynooob/ForensicsPP"
];

const cHeader = `/**\n${lines.map((line) => ` *${line ? ` ${line}` : ""}`).join("\n")}\n */\n\n`;
const htmlHeader = `<!--\n${lines.map((line) => line ? `  ${line}` : "").join("\n")}\n-->\n`;
const hashHeader = `${lines.map((line) => `#${line ? ` ${line}` : ""}`).join("\n")}\n\n`;

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else files.push(path);
  }
  return files;
}

function splitPreamble(content, style) {
  if (content.startsWith("#!")) {
    const newline = content.indexOf("\n");
    return newline === -1
      ? { preamble: `${content}\n`, body: "" }
      : { preamble: content.slice(0, newline + 1), body: content.slice(newline + 1).replace(/^\n/, "") };
  }
  if (style === "html" && /^<!doctype html>\n/i.test(content)) {
    const lineEnd = content.indexOf("\n") + 1;
    return { preamble: content.slice(0, lineEnd), body: content.slice(lineEnd) };
  }
  return { preamble: "", body: content };
}

function stripExistingHeader(body, style) {
  if (style === "c" && (body.startsWith("/*!") || body.startsWith("/**"))) {
    const end = body.indexOf("*/");
    if (end !== -1 && body.slice(0, end).includes(projectMarker)) {
      return body.slice(end + 2).replace(/^\s*\n/, "");
    }
  }
  if (style === "html" && body.startsWith("<!--")) {
    const end = body.indexOf("-->");
    if (end !== -1 && body.slice(0, end).includes(projectMarker)) {
      return body.slice(end + 3).replace(/^\s*\n/, "");
    }
  }
  if (style === "hash" && body.startsWith(`# ${projectMarker}`)) {
    const sourceLines = [
      "# Full source code: https://git.loken.cn/dynooob/ForensicsPP"
    ];
    for (const sourceLine of sourceLines) {
      const end = body.indexOf(sourceLine);
      if (end !== -1) return body.slice(end + sourceLine.length).replace(/^\s*\n/, "");
    }
  }
  return body;
}

function withHeader(content, style) {
  const { preamble, body } = splitPreamble(content, style);
  const cleanBody = stripExistingHeader(body, style);
  const header = style === "html" ? htmlHeader : style === "hash" ? hashHeader : cHeader;
  return `${preamble}${header}${cleanBody}`;
}

const srcFiles = (await walk(join(projectRoot, "src")))
  .filter((path) => [".ts", ".tsx", ".css"].includes(extname(path)));
const testFiles = (await walk(join(projectRoot, "tests")))
  .filter((path) => [".ts", ".tsx"].includes(extname(path)));
const scriptFiles = (await walk(join(projectRoot, "scripts")))
  .filter((path) => [".mjs", ".py"].includes(extname(path)));
const githubYamlFiles = (await walk(join(projectRoot, ".github")))
  .filter((path) => [".yml", ".yaml"].includes(extname(path)));
const targets = [
  ...srcFiles.map((path) => ({ path, style: "c" })),
  ...testFiles.map((path) => ({ path, style: "c" })),
  ...scriptFiles.map((path) => ({ path, style: extname(path) === ".py" ? "hash" : "c" })),
  { path: join(projectRoot, "vite.config.ts"), style: "c" },
  { path: join(projectRoot, "vitest.config.ts"), style: "c" },
  { path: join(projectRoot, "index.html"), style: "html" },
  { path: join(projectRoot, "public", "404.html"), style: "html" },
  { path: join(projectRoot, "public", "legal.html"), style: "html" },
  { path: join(projectRoot, "public", "favicon.svg"), style: "html" },
  { path: join(projectRoot, "public", "og-image.svg"), style: "html" },
  { path: join(projectRoot, "public", "sw.js"), style: "c" },
  ...githubYamlFiles.map((path) => ({ path, style: "hash" }))
];

const changed = [];
for (const target of targets) {
  const content = await readFile(target.path, "utf8");
  const expected = withHeader(content, target.style);
  if (content === expected) continue;
  changed.push(relative(projectRoot, target.path));
  if (writeMode) await writeFile(target.path, expected, "utf8");
}

if (writeMode) {
  console.log(`Updated copyright headers in ${changed.length} files.`);
} else if (changed.length) {
  console.error(`Missing or outdated copyright headers:\n${changed.map((path) => `- ${path}`).join("\n")}`);
  process.exitCode = 1;
} else {
  console.log(`Copyright headers verified in ${targets.length} files.`);
}

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

import { seoPages } from "../src/seo/seoPages.mjs";
import { SLUG_TO_TOOL, TOOL_SLUG } from "../src/seo/toolRoutes.mjs";
import { findForbidden } from "../src/seo/forbiddenWords.mjs";

const CANONICAL_SLUGS = new Set(Object.values(TOOL_SLUG));
const ALIAS_SLUGS = new Set(
  Object.keys(SLUG_TO_TOOL).filter((s) => !CANONICAL_SLUGS.has(s))
);

let hardFailures = 0;
const warnings = [];

function fail(msg) {
  hardFailures += 1;
  console.error(`  ✗ ${msg}`);
}
function warn(msg) {
  warnings.push(msg);
  console.warn(`  ! ${msg}`);
}

console.log("Capability Truth Audit — SEO / static layer\n");

// Group pages by slug for per-tool checks.
const bySlug = new Map();
for (const p of seoPages) {
  if (!bySlug.has(p.slug)) bySlug.set(p.slug, []);
  bySlug.get(p.slug).push(p);
}

console.log(`Canonical (indexable) slugs: ${[...CANONICAL_SLUGS].length}`);
console.log(`Alias (supplementary) slugs: ${[...ALIAS_SLUGS].length} → ${[...ALIAS_SLUGS].join(", ")}\n`);

// 1. Every SEO page maps to a real tool.
for (const p of seoPages) {
  if (!SLUG_TO_TOOL[p.slug]) fail(`SEO page slug "${p.slug}" is not in SLUG_TO_TOOL`);
}

// 2. Every canonical tool has both en + zh pages, non-empty H1, no brand string.
const h1ByTool = new Map();
for (const slug of CANONICAL_SLUGS) {
  const pages = bySlug.get(slug) || [];
  const en = pages.find((p) => p.locale === "en");
  const zh = pages.find((p) => p.locale === "zh-CN");
  if (!en) fail(`canonical slug "${slug}" has no EN page`);
  if (!zh) fail(`canonical slug "${slug}" has no ZH page`);
  for (const p of pages) {
    if (!p.h1 || !p.h1.trim()) fail(`empty H1 on ${slug} (${p.locale})`);
    const probe = [p.title, p.description, p.h1, p.intro, p.what, ...(p.extracts || []), ...(p.useCases || []), ...(p.limitations || [])].join(" ");
    if (/Forensics\+\+\s*ForensicsPP|ForensicsPP\s*Forensics\+\+/.test(probe)) {
      fail(`dual-brand string "Forensics++ ForensicsPP" on ${slug} (${p.locale})`);
    }
    const bad = findForbidden(probe);
    if (bad.length) fail(`forbidden words ${JSON.stringify(bad)} on ${slug} (${p.locale})`);
    if (p.h1) {
      if (!h1ByTool.has(p.toolId)) h1ByTool.set(p.toolId, []);
      h1ByTool.get(p.toolId).push({ slug, locale: p.locale, h1: p.h1 });
    }
  }
}

// 3. Duplicate H1 across distinct canonical slugs (duplicate-content risk).
const h1toSlugs = new Map();
for (const slug of CANONICAL_SLUGS) {
  const pages = bySlug.get(slug) || [];
  for (const p of pages) {
    if (!p.h1) continue;
    if (!h1toSlugs.has(p.h1)) h1toSlugs.set(p.h1, new Set());
    h1toSlugs.get(p.h1).add(slug);
  }
}
for (const [h1, slugs] of h1toSlugs) {
  if (slugs.size > 1) warn(`same H1 across ${[...slugs].join(", ")} → "${h1}" (possible duplicate content)`);
}

// 4. Alias pages are supplementary (we expect them to be noindex + canonical
//    to their sibling; the build script enforces that). Flag for visibility.
for (const slug of ALIAS_SLUGS) {
  const pages = bySlug.get(slug) || [];
  if (!pages.length) warn(`alias slug "${slug}" has no SEO page (runtime resolves it; static page may 404 without fallback)`);
  else warn(`alias slug "${slug}" → tool "${SLUG_TO_TOOL[slug]}" (supplementary; must be noindex + canonical to sibling)`);
}

// 5. declared inputs summary table.
console.log("\nDeclared inputs per canonical tool page:");
for (const slug of CANONICAL_SLUGS) {
  const en = (bySlug.get(slug) || []).find((p) => p.locale === "en");
  if (en) console.log(`  ${slug.padEnd(22)} ${JSON.stringify(en.input || [])}`);
}

console.log("");
if (warnings.length) {
  console.log(`Warnings (${warnings.length}) — surfaced, not failing the run:`);
  for (const w of warnings) console.log(`  ! ${w}`);
}
if (hardFailures) {
  console.error(`\nAUDIT FAILED: ${hardFailures} hard failure(s).`);
  process.exit(1);
}
console.log("AUDIT PASSED: SEO/static capability copy is internally consistent.");
process.exit(0);

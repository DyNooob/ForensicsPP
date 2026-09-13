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

// Generates the Static Search Discovery + Pretty-URL routing layer into dist/.
//
// Strategy (pre-release hardening):
//   For every indexable tool we emit  dist/tools/<slug>/index.html  that is a
//   CLONE OF THE SPA SHELL (dist/index.html) with route-specific <head> meta
//   injected. Because it is the real SPA, opening /tools/evtx-viewer/ directly
//   200s AND hydrates into the workbench with that tool active. This fixes the
//   "pretty URL 404" release blocker without breaking the offline/standalone
//   single-file build (build:standalone does NOT invoke this script).
//
// Slug → tool mapping is imported from src/seo/toolRoutes.mjs — the single
// source of truth shared with the runtime router (src/core/routeAdapter.ts).
// Descriptive titles/descriptions come from the hand-written seoPages copy.

import { mkdir, writeFile, rm, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { seoPages, SITE } from "../src/seo/seoPages.mjs";
import { SLUG_TO_TOOL, TOOL_SLUG } from "../src/seo/toolRoutes.mjs";
import { findForbidden } from "../src/seo/forbiddenWords.mjs";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const distRoot = join(projectRoot, "dist");
const REPO = "https://github.com/DyNooob/ForensicsPP";
const VERSION = JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8")).version;

const isPreview = process.env.VITE_PREVIEW === "1" || process.env.VITE_PREVIEW === "true";

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function jsonLd(obj) {
  return JSON.stringify(obj).replace(/</g, "\\u003c");
}

// Real static semantics for a tool route (#7). This is what a no-JS visitor —
// or a crawler reading the raw HTML before hydration — sees for /tools/<slug>/.
// It replaces the homepage preboot so a tool URL never shows home content
// (which also removes the pre-hydration home-flash on direct tool navigation).
function renderToolPreboot(en) {
  if (!en) return "";
  const inputs = (en.input ?? []).map((i) => `<li>${esc(i)}</li>`).join("");
  return `<main class="preboot">
    <header class="pb-brand">
    <span class="pb-name">Forensics++</span>
    <span class="pb-tag">${esc(en.h1 || "")}</span>
  </header>
  <h1>${esc(en.h1 || "")}</h1>
  <p class="pb-lede">${esc(en.description || "")}</p>
  <p class="pb-privacy"><strong>No upload.</strong> Evidence files are processed locally in your browser.</p>
  ${inputs ? `<h2>Supported input</h2>\n  <ul class="pb-tools">${inputs}</ul>` : ""}
  <p class="pb-note">Enable JavaScript to open the workbench and analyze evidence.</p>
</main>`;
}

// No-JS fallback for a tool route. Deliberately a <p>, NOT an <h1> (#20):
// a no-JS page must not present "requires JavaScript" as its document H1.
function renderToolNoscript(en) {
  const h1 = en?.h1 || "Forensics++ tool";
  return `<main class="noscript-fallback">
  <strong>F++</strong>
  <p>${esc(h1)} — this tool runs entirely in your browser. Enable JavaScript to analyze evidence locally; files are not uploaded.</p>
</main>`;
}

// Canonical (own-page, indexable) slugs — exactly the TOOL_SLUG values.
// Alias/legacy slugs (e.g. sqlite-wal-recovery, wal) resolve to the same
// workbench as their canonical sibling and MUST NOT be emitted as a separate
// physical page (duplicate-content guard): search engines consolidate them via
// the canonical <link> on the canonical tool page, and the SPA runtime still
// routes them through src/core/routeAdapter.ts.
const CANONICAL_SLUGS = new Set(Object.values(TOOL_SLUG));

function seoFor(toolId, locale) {
  return seoPages.find((p) => p.toolId === toolId && p.locale === locale);
}

// Build the per-route SPA shell: clone dist/index.html, inject meta, make
// asset references root-absolute so the file works when served from
// /tools/<slug>/.
async function renderRouteShell(slug, toolId) {
  const distIndex = await readFile(join(distRoot, "index.html"), "utf8");
  const en = seoFor(toolId, "en");
  const zh = seoFor(toolId, "zh-CN");
  const title = en?.title || `${SITE.name} — ${toolId}`;
  const description = en?.description || SITE.tagline;
  const isAlias = !CANONICAL_SLUGS.has(slug);
  const canonicalSlug = isAlias ? TOOL_SLUG[toolId] : slug;
  const canonical = `${SITE.base}/tools/${canonicalSlug}/`;
  // Preview builds noindex everything; alias (non-canonical) slugs are always
  // noindex so search engines consolidate them onto the canonical tool page.
  const robots = isPreview || isAlias ? "noindex,nofollow,noarchive" : "index,follow";

  const jsonLdBlocks = [
    {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      name: "Forensics++",
      alternateName: "ForensicsPP",
      applicationCategory: "SecurityApplication",
      operatingSystem: "Any modern browser",
      softwareVersion: VERSION,
      url: canonical,
      description,
      author: { "@type": "Person", name: "DyNooob", url: SITE.base },
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      itemListElement: [
        { "@type": "ListItem", position: 1, name: "Forensics++", item: `${SITE.base}/` },
        { "@type": "ListItem", position: 2, name: en?.h1 || toolId, item: canonical },
      ],
    },
  ]
    .map((o) => `<script type="application/ld+json">${jsonLd(o)}</script>`)
    .join("\n");

  const meta = [
    `<meta name="robots" content="${robots}" />`,
    `<title>${esc(title)}</title>`,
    `<meta name="description" content="${esc(description)}" />`,
    `<link rel="canonical" href="${canonical}" />`,
    `<meta property="og:type" content="website" />`,
    `<meta property="og:site_name" content="Forensics++" />`,
    `<meta property="og:title" content="${esc(title)}" />`,
    `<meta property="og:description" content="${esc(description)}" />`,
    `<meta property="og:url" content="${canonical}" />`,
    `<meta name="twitter:card" content="summary_large_image" />`,
    `<meta name="twitter:title" content="${esc(title)}" />`,
    `<meta name="twitter:description" content="${esc(description)}" />`,
    jsonLdBlocks,
  ].join("\n");

  let html = distIndex;
  // Replace the document title.
  html = html.replace(/<title>[\s\S]*?<\/title>/, `<title>${esc(title)}</title>`);
  // Strip the meta the shell already declares so we don't duplicate/conflict.
  html = html.replace(/<meta name="robots"[^>]*>/g, "");
  html = html.replace(/<meta name="description"[^>]*>/g, "");
  html = html.replace(/<link rel="canonical"[^>]*>/g, "");
  html = html.replace(/<meta property="og:[^>]*>/g, "");
  html = html.replace(/<meta name="twitter:[^>]*>/g, "");
  // Replace the homepage preboot body and the no-JS fallback with TOOL-SPECIFIC
  // static content, so a tool route shows the tool's identity (not home) both
  // pre-hydration and with JavaScript disabled (#7, #31).
  html = html.replace(/<main class="preboot">[\s\S]*?<\/main>/, renderToolPreboot(en));
  html = html.replace(/<main class="noscript-fallback">[\s\S]*?<\/main>/, renderToolNoscript(en));
  // Inject our route meta right before </head>.
  html = html.replace("</head>", `${meta}\n</head>`);
  // Make asset references root-absolute so the page works under /tools/<slug>/.
  html = html.replace(/="\.\//g, '="/');
  return html;
}

function buildSitemap() {
  const bySlug = new Map();
  for (const slug of CANONICAL_SLUGS) {
    const tool = SLUG_TO_TOOL[slug];
    if (!bySlug.has(slug)) bySlug.set(slug, { tool, slug });
  }
  const urls = [];
  for (const { slug, tool } of bySlug.values()) {
    const en = seoFor(tool, "en");
    const loc = `${SITE.base}/tools/${slug}/`;
    urls.push(`  <url>
    <loc>${loc}</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${loc}" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${loc}" />
  </url>`);
    void en;
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>${SITE.base}/</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${SITE.base}/" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${SITE.base}/" />
  </url>
  <url>
    <loc>${SITE.base}/legal.html</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${SITE.base}/legal.html" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${SITE.base}/legal.html" />
  </url>
${urls.join("\n")}
</urlset>
`;
}

async function main() {
  // Guard: refuse to emit marketing copy.
  for (const p of seoPages) {
    const probe = [p.title, p.description, p.h1, p.intro, p.what, ...p.extracts, ...p.useCases, ...p.limitations].join(" ");
    const bad = findForbidden(probe);
    if (bad.length) {
      console.error(`SEO copy guard failed for ${p.slug} (${p.locale}): forbidden words -> ${bad.join(", ")}`);
      process.exit(1);
    }
  }

  // Clean stale SEO output, then regenerate.
  await rm(join(distRoot, "tools"), { recursive: true, force: true });
  await rm(join(distRoot, "zh"), { recursive: true, force: true });

  for (const slug of CANONICAL_SLUGS) {
    const tool = SLUG_TO_TOOL[slug];
    const outDir = join(distRoot, "tools", slug);
    await mkdir(outDir, { recursive: true });
    await writeFile(join(outDir, "index.html"), await renderRouteShell(slug, tool), "utf8");
    console.log(`wrote tools/${slug}/index.html (-> ${tool})`);
  }

  await writeFile(join(distRoot, "sitemap.xml"), buildSitemap(), "utf8");
  console.log(`wrote sitemap.xml (${CANONICAL_SLUGS.size} canonical tool routes + home + legal)`);
  console.log(isPreview ? "preview mode: noindex injected into route pages" : "production mode: route pages indexable");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

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

// Generates the Static Search Discovery Layer (B6-SEO) into dist/.
// Run AFTER `vite build` (web distribution only). Standalone build does NOT
// invoke this script, so the offline single-file app stays free of SEO pages.

import { mkdir, writeFile, rm } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { seoPages, SITE, SLUG_TO_TOOL } from "../src/seo/seoPages.mjs";
import { findForbidden } from "../src/seo/forbiddenWords.mjs";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const distRoot = join(projectRoot, "dist");
const REPO = "https://github.com/DyNooob/ForensicsPP";
const VERSION = JSON.parse(await (await import("node:fs/promises")).readFile(join(projectRoot, "package.json"), "utf8")).version;

const HEADINGS = {
  en: {
    what: "What it analyzes",
    extracts: "What Forensics++ extracts",
    input: "Supported input",
    useCases: "Relevant forensic use cases",
    limitations: "Known limitations",
    maturity: "Maturity and validation",
    privacy: "Privacy and local processing",
    usage: "How to use",
    relatedArtifacts: "Related artifacts",
    relatedTools: "Related Forensics++ tools",
  },
  "zh-CN": {
    what: "分析对象",
    extracts: "Forensics++ 提取的内容",
    input: "支持的输入",
    useCases: "相关取证场景",
    limitations: "已知限制",
    maturity: "成熟度与校验",
    privacy: "隐私与本地处理",
    usage: "使用方式",
    relatedArtifacts: "相关工件",
    relatedTools: "相关 Forensics++ 工具",
  },
};

const PRIVACY = {
  en: "All processing happens in your browser. The evidence file stays on your device and is never uploaded to a server.",
  "zh-CN": "所有处理均在你的浏览器内进行。检材文件保留在你的设备上，不会被上传到任何服务器。",
};

const USAGE = {
  en: "Open the workbench, load your file, and review the results. No installation or account is required.",
  "zh-CN": "打开工作台，载入文件，查看结果。无需安装，无需账号。",
};

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function jsonLd(obj) {
  return JSON.stringify(obj).replace(/</g, "\\u003c");
}

// toolId -> first slug that documents it (for related-tool links)
const toolToSlug = {};
for (const [slug, tool] of Object.entries(SLUG_TO_TOOL)) {
  if (!(tool in toolToSlug)) toolToSlug[tool] = slug;
}

function relatedToolHref(toolId, locale) {
  const slug = toolToSlug[toolId];
  const prefix = locale === "zh-CN" ? "/zh" : "";
  if (slug) return `${prefix}/tools/${slug}/`;
  return `/#${toolId}`;
}

function renderPage(p) {
  const isZh = p.locale === "zh-CN";
  const lang = isZh ? "zh-CN" : "en";
  const enUrl = `${SITE.base}/tools/${p.slug}/`;
  const zhUrl = `${SITE.base}/zh/tools/${p.slug}/`;
  const canonical = isZh ? zhUrl : enUrl;
  const h = HEADINGS[p.locale];

  const ogUrl = canonical;
  const ogTitle = p.title;
  const ogDesc = p.description;

  const relatedLinks = p.relatedTools
    .map((t) => `<li><a href="${relatedToolHref(t, p.locale)}">${esc(toolLabel(t, p.locale))}</a></li>`)
    .join("\n");

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
      description: p.description,
      author: { "@type": "Person", name: "DyNooob", url: SITE.base },
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      itemListElement: [
        { "@type": "ListItem", position: 1, name: "Forensics++", item: `${SITE.base}/` },
        { "@type": "ListItem", position: 2, name: p.h1, item: canonical },
      ],
    },
  ]
    .map((o) => `<script type="application/ld+json">${jsonLd(o)}</script>`)
    .join("\n");

  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${esc(p.title)}</title>
<meta name="description" content="${esc(p.description)}" />
<meta name="author" content="DyNooob" />
<meta name="license" content="MIT" />
<link rel="canonical" href="${canonical}" />
<link rel="alternate" hreflang="en" href="${enUrl}" />
<link rel="alternate" hreflang="zh-CN" href="${zhUrl}" />
<link rel="alternate" hreflang="x-default" href="${enUrl}" />
<meta property="og:type" content="website" />
<meta property="og:site_name" content="Forensics++" />
<meta property="og:title" content="${esc(ogTitle)}" />
<meta property="og:description" content="${esc(ogDesc)}" />
<meta property="og:url" content="${ogUrl}" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${esc(ogTitle)}" />
<meta name="twitter:description" content="${esc(ogDesc)}" />
${jsonLdBlocks}
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", "Noto Sans SC", sans-serif;
    color: #162130; background: #f5f7fa; line-height: 1.6;
  }
  .wrap { max-width: 760px; margin: 0 auto; padding: 32px 20px 64px; }
  header.brand { border-bottom: 1px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 8px; }
  header.brand .name { font-weight: 800; font-size: 18px; letter-spacing: .02em; }
  header.brand .tag { color: #66768a; font-size: 13px; }
  h1 { font-size: 28px; line-height: 1.25; margin: 24px 0 8px; }
  h2 { font-size: 18px; margin: 32px 0 8px; border-left: 3px solid #245F73; padding-left: 10px; }
  p { margin: 8px 0; }
  ul { margin: 8px 0; padding-left: 20px; }
  li { margin: 4px 0; }
  .intro { font-size: 16px; color: #2b3a4d; }
  .meta { display: inline-block; font-size: 13px; color: #66768a; background: #eef2f7; border: 1px solid #dde5ee; border-radius: 6px; padding: 4px 10px; margin-top: 4px; }
  .cta {
    display: inline-block; margin: 28px 0 8px; padding: 12px 22px; border-radius: 8px;
    background: #245F73; color: #fff; font-weight: 700; text-decoration: none; font-size: 15px;
  }
  .cta:hover { background: #1d4e5e; }
  .note { font-size: 14px; color: #66768a; }
  footer { margin-top: 48px; border-top: 1px solid #e2e8f0; padding-top: 16px; font-size: 13px; color: #66768a; }
  a { color: #245F73; }
  @media (prefers-color-scheme: dark) {
    body { background: #0f1822; color: #dbe4ee; }
    header.brand { border-color: #243240; }
    header.brand .tag, .meta, .note, footer { color: #93a4b8; }
    h2 { border-color: #4a8aa0; }
    .meta { background: #18242f; border-color: #2a3a49; }
    a { color: #7fb6cc; }
    .cta { background: #2f7d96; }
    .cta:hover { background: #256378; }
    footer { border-color: #243240; }
  }
</style>
</head>
<body>
<main class="wrap">
  <header class="brand">
    <div class="name">${esc(SITE.name)}</div>
    <div class="tag">${esc(SITE.tagline)}</div>
  </header>

  <h1>${esc(p.h1)}</h1>
  <p class="intro">${esc(p.intro)}</p>

  <h2>${esc(h.what)}</h2>
  <p>${esc(p.what)}</p>

  <h2>${esc(h.extracts)}</h2>
  <ul>
${p.extracts.map((x) => `    <li>${esc(x)}</li>`).join("\n")}
  </ul>

  <h2>${esc(h.input)}</h2>
  <ul>
${p.input.map((x) => `    <li>${esc(x)}</li>`).join("\n")}
  </ul>

  <h2>${esc(h.useCases)}</h2>
  <ul>
${p.useCases.map((x) => `    <li>${esc(x)}</li>`).join("\n")}
  </ul>

  <h2>${esc(h.limitations)}</h2>
  <ul>
${p.limitations.map((x) => `    <li>${esc(x)}</li>`).join("\n")}
  </ul>

  <h2>${esc(h.maturity)}</h2>
  <p><span class="meta">Maturity: ${esc(p.maturity)} · Validation: ${esc(p.validation)}</span></p>

  <h2>${esc(h.privacy)}</h2>
  <p>${esc(PRIVACY[p.locale])}</p>

  <h2>${esc(h.usage)}</h2>
  <p>${esc(USAGE[p.locale])}</p>

  <h2>${esc(h.relatedArtifacts)}</h2>
  <ul>
${p.relatedArtifacts.map((x) => `    <li>${esc(x)}</li>`).join("\n")}
  </ul>

  <h2>${esc(h.relatedTools)}</h2>
  <ul>
${relatedLinks}
  </ul>

  <a class="cta" href="/#${esc(p.toolId)}">${esc(p.ctaLabel)}</a>
  <p class="note">${esc(isZh ? "该页面用于让搜索引擎与用户了解此能力；实际分析在工作台内进行。" : "This page helps search engines and users understand the capability. The actual analysis happens in the workbench.")}</p>

  <footer>
    ${esc(SITE.name)} is open source under the MIT License. Full source: <a href="${REPO}">${REPO}</a>
  </footer>
</main>
</body>
</html>
`;
}

// ---- Home / language landing pages ---------------------------------------
// The English root `/` is owned by the React SPA (index.html), which carries
// its own no-JS preboot content + hreflang. We only generate the `/zh/`
// discovery landing here (lightweight static page, no app payload).
const HOME_TOOLS = [
  { slug: "evtx-viewer", en: "Windows Event Logs (EVTX)", zh: "Windows 事件日志 (EVTX)" },
  { slug: "sqlite-forensics", en: "SQLite Forensics", zh: "SQLite 取证" },
  { slug: "sqlite-wal-recovery", en: "SQLite WAL Recovery", zh: "SQLite WAL 恢复" },
  { slug: "apk-signature-analyzer", en: "APK Signature Analysis", zh: "APK 签名分析" },
  { slug: "pcap-analyzer", en: "PCAP / Network Analysis", zh: "PCAP / 网络分析" },
  { slug: "registry-forensics", en: "Registry Forensics", zh: "注册表取证" },
  { slug: "firmware-analyzer", en: "Firmware Analysis", zh: "固件分析" },
  { slug: "binary-file-analyzer", en: "Binary / Unknown File Analysis", zh: "二进制 / 未知文件分析" },
  { slug: "windows-artifacts", en: "Windows Artifacts", zh: "Windows 工件" },
  { slug: "image-forensics", en: "Image Forensics", zh: "图像取证" },
];

function renderZhHome() {
  const items = HOME_TOOLS.map(
    (t) => `          <li><a href="/zh/tools/${t.slug}/">${esc(t.zh)}</a></li>`
  ).join("\n");
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Forensics++ — 本地优先的数字取证工作台 | Forensics++</title>
<meta name="description" content="Forensics++ 是一个开源的 DFIR 工作台。检材在浏览器中本地解析，不会上传到服务器。包含 EVTX、SQLite、APK 签名、PCAP、注册表、固件、二进制、Windows 工件与图像取证。" />
<meta name="author" content="DyNooob" />
<meta name="license" content="MIT" />
<link rel="canonical" href="${SITE.base}/zh/" />
<link rel="alternate" hreflang="en" href="${SITE.base}/" />
<link rel="alternate" hreflang="zh-CN" href="${SITE.base}/zh/" />
<link rel="alternate" hreflang="x-default" href="${SITE.base}/" />
<meta property="og:type" content="website" />
<meta property="og:site_name" content="Forensics++" />
<meta property="og:title" content="Forensics++ — 本地优先的数字取证工作台" />
<meta property="og:description" content="开源 DFIR 工作台，检材本地解析，不上传服务器。" />
<meta property="og:url" content="${SITE.base}/zh/" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="Forensics++ — 本地优先的数字取证工作台" />
<meta name="twitter:description" content="开源 DFIR 工作台，检材本地解析，不上传服务器。" />
<script type="application/ld+json">${jsonLd({
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: "Forensics++",
    alternateName: "ForensicsPP",
    url: `${SITE.base}/zh/`,
  })}</script>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", "Noto Sans SC", sans-serif; color: #162130; background: #f5f7fa; line-height: 1.6; }
  .wrap { max-width: 760px; margin: 0 auto; padding: 40px 20px 64px; }
  .pb-brand { border-bottom: 1px solid #e2e8f0; padding-bottom: 14px; margin-bottom: 8px; }
  .pb-name { font-weight: 800; font-size: 18px; letter-spacing: .02em; }
  .pb-tag { display: block; color: #66768a; font-size: 13px; margin-top: 2px; }
  h1 { font-size: 27px; line-height: 1.3; margin: 24px 0 8px; }
  h2 { font-size: 18px; margin: 32px 0 8px; border-left: 3px solid #245F73; padding-left: 10px; }
  .pb-lede { font-size: 16px; color: #2b3a4d; }
  .pb-privacy { font-size: 14px; color: #245F73; }
  .pb-tools { padding-left: 20px; line-height: 1.9; }
  .pb-tools a { color: #245F73; text-decoration: none; }
  .pb-tools a:hover { text-decoration: underline; }
  .pb-note { font-size: 14px; color: #66768a; margin-top: 24px; }
  a { color: #245F73; }
  @media (prefers-color-scheme: dark) {
    body { background: #0f1822; color: #dbe4ee; }
    .pb-brand { border-color: #243240; }
    .pb-tag, .pb-note { color: #93a4b8; }
    h2 { border-color: #4a8aa0; }
    .pb-lede { color: #c2cedb; }
    .pb-privacy { color: #7fb6cc; }
    .pb-tools a { color: #7fb6cc; }
    a { color: #7fb6cc; }
  }
</style>
</head>
<body>
<main class="wrap">
  <header class="pb-brand">
    <span class="pb-name">Forensics++</span>
    <span class="pb-tag">ForensicsPP · 本地优先的数字取证工作台</span>
  </header>
  <h1>在浏览器中运行的 DFIR 工具，分析过程全部在本地完成</h1>
  <p class="pb-lede">Forensics++ 是一个开源的数字取证与事件响应工作台。检材在你的浏览器中本地解析，不会被上传到服务器。</p>
  <p class="pb-privacy"><strong>不上传。</strong>文件保留在你的设备上。载入后可离线使用。</p>
  <h2>核心工作台</h2>
  <ul class="pb-tools">
${items}
  </ul>
  <p class="pb-note">启用 JavaScript 以打开工作台并分析检材。English: <a href="/">Forensics++ (English)</a>。</p>
</main>
</body>
</html>
`;
}

// Human-readable label for a related tool id (used in related-tools lists).
function toolLabel(toolId, locale) {
  const map = {
    evtx: { en: "EVTX Viewer", "zh-CN": "EVTX 查看器" },
    sqlite: { en: "SQLite Forensics", "zh-CN": "SQLite 取证" },
    "sqlite-wal-recovery": { en: "SQLite WAL Recovery", "zh-CN": "SQLite WAL 恢复" },
    android: { en: "APK Signature Analyzer", "zh-CN": "APK 签名分析器" },
    pcap: { en: "PCAP Analyzer", "zh-CN": "PCAP 分析器" },
    registry: { en: "Registry Forensics", "zh-CN": "注册表取证" },
    firmware: { en: "Firmware Analyzer", "zh-CN": "固件分析器" },
    binary: { en: "Binary File Analyzer", "zh-CN": "二进制文件分析器" },
    windows: { en: "Windows Artifacts", "zh-CN": "Windows 工件" },
    image: { en: "Image Forensics", "zh-CN": "图像取证" },
    browserartifacts: { en: "Browser Artifacts", "zh-CN": "浏览器工件" },
    ioc: { en: "IOC Extraction", "zh-CN": "IOC 提取" },
    archive: { en: "Archive Unpacker", "zh-CN": "归档解包器" },
    disk: { en: "Disk Image Loader", "zh-CN": "磁盘镜像加载器" },
    timeline: { en: "Timeline Tool", "zh-CN": "时间线工具" },
  };
  return map[toolId]?.[locale] || toolId;
}

function buildSitemap() {
  const bySlug = new Map();
  for (const p of seoPages) {
    if (!bySlug.has(p.slug)) bySlug.set(p.slug, {});
    bySlug.get(p.slug)[p.locale] = p;
  }
  const urls = [];
  for (const [slug, locales] of bySlug) {
    const en = locales.en;
    const zh = locales["zh-CN"];
    const enUrl = `${SITE.base}/tools/${slug}/`;
    const zhUrl = `${SITE.base}/zh/tools/${slug}/`;
    if (en) {
      urls.push(`  <url>
    <loc>${enUrl}</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${enUrl}" />
    <xhtml:link rel="alternate" hreflang="zh-CN" href="${zhUrl}" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${enUrl}" />
  </url>`);
    }
    if (zh) {
      urls.push(`  <url>
    <loc>${zhUrl}</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${enUrl}" />
    <xhtml:link rel="alternate" hreflang="zh-CN" href="${zhUrl}" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${enUrl}" />
  </url>`);
    }
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>${SITE.base}/</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${SITE.base}/" />
    <xhtml:link rel="alternate" hreflang="zh-CN" href="${SITE.base}/zh/" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${SITE.base}/" />
  </url>
  <url>
    <loc>${SITE.base}/zh/</loc>
    <xhtml:link rel="alternate" hreflang="en" href="${SITE.base}/" />
    <xhtml:link rel="alternate" hreflang="zh-CN" href="${SITE.base}/zh/" />
    <xhtml:link rel="alternate" hreflang="x-default" href="${SITE.base}/" />
  </url>
  <url>
    <loc>${SITE.base}/legal.html</loc>
    <lastmod>2026-07-13</lastmod>
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
  for (const dir of [join(distRoot, "tools"), join(distRoot, "zh")]) {
    await rm(dir, { recursive: true, force: true });
  }

  for (const p of seoPages) {
    const prefix = p.locale === "zh-CN" ? join(distRoot, "zh") : distRoot;
    const outDir = join(prefix, "tools", p.slug);
    await mkdir(outDir, { recursive: true });
    await writeFile(join(outDir, "index.html"), renderPage(p), "utf8");
    console.log(`wrote ${p.locale} ${join("tools", p.slug, "index.html")}`);
  }

  await writeFile(join(distRoot, "sitemap.xml"), buildSitemap(), "utf8");
  console.log(`wrote sitemap.xml (${seoPages.length / 2} tool pages, ${seoPages.length} locale pages)`);

  // Language landing: only /zh/ is generated (the English `/` is the React SPA).
  const zhHomeDir = join(distRoot, "zh");
  await mkdir(zhHomeDir, { recursive: true });
  await writeFile(join(zhHomeDir, "index.html"), renderZhHome(), "utf8");
  console.log("wrote zh/index.html (Chinese discovery landing)");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

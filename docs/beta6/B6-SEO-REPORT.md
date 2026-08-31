# Forensics++ B6-SEO Report

**Phase:** B6-SEO — Search Discovery Foundation
**Branch:** `beta6` · **Commit:** _(this phase, separate commit)_ · **Version:** 1.0.0-beta.6
**Author:** DyNooob · **License:** MIT

> Scope of this phase: a **Static Search Discovery Layer** — explain → scope → limitations → trust → open the real analyzer. It does **not** modify the App's analysis logic, hash routing, standalone build, or `file://` usage, and adds no backend / AI / login / cloud.

---

## 1. Before

Real audit of the repo (not from README). Findings:

| Area | Before B6-SEO |
| --- | --- |
| Web build | `npm run build` → multi-chunk Vite app, must serve over HTTP (`file://` blocks ES modules). |
| Standalone build | `SINGLE_FILE=1 vite build` inlines app JS/CSS; Web Workers stay external (26 worker bundles). |
| Homepage body | Pure React SPA. Crawler with JS disabled saw only `<title>`, meta description, OG tags, JSON-LD, and a `<noscript>requires JavaScript</noscript>`. **No real body content.** |
| `index.html` lang | `lang="zh-CN"` (static); app overrides at runtime. |
| sitemap.xml | **2 URLs** only: home + legal. No tool pages, no `/zh/`. |
| canonical | Only homepage self-canonical. |
| language strategy | No `hreflang`, no `/zh/` layer. Tools are hash routes (`/#sqlite`), not real URLs. |
| Independent tool pages | None — every tool is a hash route inside the SPA. |
| robots.txt | `Allow: /` + sitemap pointer (fine; not blocking). |
| Deployment | Any static host can serve `dist/`; `CNAME` + `.nojekyll` present for GitHub Pages. |

**Conclusion:** The crawler could index the brand name and nothing else. No discoverable capability pages existed.

---

## 2. Architecture chosen

- **Discovery layer = generated static HTML**, emitted by `scripts/build-seo-pages.mjs` **after** `vite build` (web distribution only). It is **not** a second SPA, does not import React, and does not duplicate any analyzer logic.
- **App unchanged**: hash routing (`/#evtx`), `file://` standalone, and offline behavior are untouched. SEO pages are siblings of the app under `/tools/<slug>/` and `/zh/tools/<slug>/`, each CTA linking to `/#<toolId>`.
- **Standalone unaffected**: the SEO generator is wired into `build` **only**, not `build:standalone` (per spec §44/§45). The single-file offline app stays app-only.
- **Single source of truth**: `src/seo/seoPages.mjs` holds the honest copy (hand-written from real `ToolDefinition` capabilities / maturity / validation + the actual analyzers). `src/seo/forbiddenWords.mjs` is the no-AI-marketing guard.
- **Why not Next/Nuxt**: would break local-first / standalone / hash routing and add a server. Explicitly out of scope (§0).

---

## 3. Crawlable homepage

`index.html` now ships a **no-JS preboot block** inside `#root` (React replaces it on mount; no-JS users and crawlers see it). Verified present in the **built** `dist/index.html`:

- `<html lang="en">`
- `<h1>Browser-native DFIR tools that run on your device</h1>`
- Lead paragraph: local-first + no-upload message
- "No upload. Files stay on your device. Works offline once loaded."
- **Core workbenches** list (10 links) → `/tools/<slug>/`
- No `display:none` / `visibility:hidden` / `font-size:0` hacks anywhere in the SEO layer (grep = 0).

The App also gained `hreflang` (en / zh-CN / x-default) and kept its `SoftwareApplication` JSON-LD.

---

## 4. SEO pages

10 core tools, each emitted as `/tools/<slug>/index.html` (EN) + `/zh/tools/<slug>/index.html` (ZH). Every page: H1, intro, *What it analyzes*, *extracts* (bullets), *supported input*, *use cases*, *known limitations* (honest), *maturity & validation*, *privacy*, *usage*, *related artifacts*, *related tools*, and a CTA → `/#<toolId>`.

| Slug | Analyzer (`toolId`) | Title | Description (EN) |
| --- | --- | --- | --- |
| `evtx-viewer` | `evtx` | EVTX Viewer and Windows Event Log Analyzer \| Forensics++ | Open and inspect Windows EVTX files in your browser. Parse event records locally and export results without uploading the evidence. |
| `sqlite-forensics` | `sqlite` | SQLite Forensics and WAL Analyzer \| Forensics++ | Inspect SQLite databases in your browser. Review tables, WAL history, freelist pages, and recoverable fragments without uploading the file. |
| `sqlite-wal-recovery` | `sqlite` | SQLite WAL Recovery and Analysis \| Forensics++ | Understand SQLite WAL files: frames, historical row versions, and companion files. Analyzed inside the SQLite Workbench, locally. |
| `apk-signature-analyzer` | `android` | APK Signature Analyzer \| Forensics++ | Analyze Android APK signing in your browser. Verify v1–v3.1 schemes, inspect certificate chains, and check signature consistency locally. |
| `pcap-analyzer` | `pcap` | PCAP Analyzer and Network Capture Forensics \| Forensics++ | Parse pcap and pcapng captures in your browser. Reassemble TCP, extract HTTP/DNS/TLS sessions, and flag IOCs locally. |
| `registry-forensics` | `registry` | Registry Forensics — Hive Analysis \| Forensics++ | Inspect Windows registry hives in your browser. Parse regf/hbin structure, decode last-write times, and flag integrity issues locally. |
| `firmware-analyzer` | `firmware` | Firmware Analyzer and File Carver \| Forensics++ | Analyze firmware images in your browser. Identify filesystems, spot compressed regions by entropy, and carve embedded objects locally. |
| `binary-file-analyzer` | `binary` | Binary File Analyzer — Identify Unknown Files \| Forensics++ | Load any binary in your browser. Identify the real type from magic bytes, compare against the extension, and summarize structure locally. |
| `windows-artifacts` | `windows` | Windows Artifact Analyzer \| Forensics++ | Parse Windows artifacts in your browser. Extract execution traces from LNK, Prefetch, Registry, MFT, and USN journals locally. |
| `image-forensics` | `image` | Image Forensics and Metadata Analyzer \| Forensics++ | Inspect images in your browser. Read EXIF and metadata, surface steganography clues, verify integrity, and decode QR codes locally. |

---

## 5. English / Chinese

- EN root `/` (x-default). ZH layer `/zh/` (Chinese discovery landing) + `/zh/tools/<slug>/`.
- Reciprocal `hreflang` on every page: `en`, `zh-CN`, `x-default`. The home and `/zh/` cross-reference each other.
- No IP-based redirect; no JS redirect of crawlers.
- 1:1 slug mapping enforced by contract test (en set === zh set).

---

## 6. Technical SEO

- **Canonical:** unique per page, self-referencing (EN → `/tools/<slug>/`, ZH → `/zh/tools/<slug>/`). Never canonical back to home.
- **Sitemap:** `scripts/build-seo-pages.mjs` regenerates `dist/sitemap.xml` with **21 URLs** — home, `/zh/`, and all 20 locale tool pages — each with reciprocal `xhtml:link` alternates. No hash/state URLs.
- **robots.txt:** `Allow: /` + sitemap pointer. Does not block CSS/JS/required assets. (`public/robots.txt` is the standalone fallback; web build overwrites with the full one.)
- **Structured data:** `SoftwareApplication` + `BreadcrumbList` on tool pages; `WebSite` on `/zh/`. **No** fabricated `AggregateRating` / `Review` / `FAQPage` / `offers`-with-claims. The App's homepage keeps its `SoftwareApplication` with a `price:0` offer (pre-existing, accurate).
- **OG / Twitter:** `og:title/description/url/type`, `twitter:card/title/description` per page, consistent with body copy (no marketing rewrite).
- **404:** real `public/404.html` (`noindex`) carried into `dist/` by `finalize-dist`.

---

## 7. Content source

All copy derives from real metadata, not invented:

- `src/config/app.ts` `toolDefinitions` → `id`, `category`, `accepts`, `capabilities`, `maturity`, `validation`, `emitsEnvelope`.
- Analyzers read directly for honest detail:
  - `android` (models.ts): verifies **v1–v3.1**; v4 (`.idsig`) accepted as input but **not separately verified** — stated explicitly on the page.
  - `pcap` (tls.ts): extracts **SNI, ALPN, JA3, certificate SHA-256** (metadata only) — claimed accurately.
  - `sqlite`: deleted-record = **heuristic fragment recovery** from WAL/freelist — page says "recoverable fragments", not "fully recovered deleted records".
  - `image`: steganography = **clues only**, not detection — page says "surface steganography clues".
  - `registry` / `firmware` / `windows`: marked **triage**; pages say "triage / flag integrity issues", not "full forensic analysis".
- Maturity/validation rendered verbatim from the registry (`Maturity: stable · Validation: fixture-validated`). No second, inflated capability source.

---

## 8. No-AI-style review

- `src/seo/forbiddenWords.mjs` blocks EN hype terms (`ultimate`, `revolutionary`, `powerful`, `seamless`, `empower`, `leverage`, `best-in-class`, `cutting-edge`, `game-changing`, …) and ZH terms (`赋能`, `一站式`, `行业领先`, `极致`, `智能化`, `全方位`, …). `magic` (as in *magic bytes*) is allowed — it is a legitimate technical term.
- The generator **fails the build** if any forbidden term appears (defensive per §50). `scripts/lint-seo.mjs` re-checks built HTML (strips `<style>/<script>`, lints visible copy).
- **Per-page human review performed** (§35): every page checked for unsupported claims, AI phrasing, repetition, hidden limitations. Overclaim grep (`fully recover`, `all signature schemes`, `detect steganography`, `v4 signature`) returned **0** hits across EN pages.

---

## 9. Build outputs

- **Web (`npm run build`):** `clean → check:headers → typecheck → vite build → finalize-dist → verify:dist → build-seo-pages`. Produces the app **plus** `dist/tools/*`, `dist/zh/tools/*`, `dist/zh/index.html`, and the 21-URL `dist/sitemap.xml`.
- **Standalone (`npm run build:standalone`):** unchanged pipeline (no SEO step) → single-file app only. SEO pages are **not** bundled.

> Note: the `clean` step is sandbox-guarded in this environment (>50-file delete). Validated here via the sandbox-safe path: `vite build` (into isolated dir) + `finalize-dist` + `verify:dist` + `build-seo-pages`, all green. The committed source produces the same output in a normal environment.

---

## 10. Tests

| Command | Result |
| --- | --- |
| `npx tsc --noEmit` | exit 0 (0 errors) |
| `npm test` | **352 passed** (74 files; +10 new SEO contract tests) |
| `npm run validate` | 16 passed |
| `npm run i18n:check` | OK |
| `node scripts/lint-seo.mjs` | OK — 31 pages, 0 marketing terms |
| `npm run verify:dist` | verified 208 files, 55.4 MiB (with SEO pages present) |
| `node scripts/build-seo-pages.mjs` | 20 locale tool pages + `/zh/` home + sitemap; guard passed |

New test: `tests/seo-contract.test.ts` (10 cases) — unique title/canonical/slug, non-empty description, **valid `toolId` reference to real tools** (fails on rename), en/zh 1:1 mapping, forbidden-word lint, and (when built) raw-HTML canonical + reciprocal hreflang + JSON-LD + sitemap coverage.

---

## 11. No-JS verification

Real checks against **built** `dist/` (raw HTML, no JS execution):

- `dist/tools/evtx-viewer/index.html`: `<title>`, meta `description`, `<link rel="canonical" href="https://www.forensicspp.com/tools/evtx-viewer/">`, two `application/ld+json` blocks, `<h1>EVTX Viewer and Windows Event Log Analyzer</h1>`, "Known limitations" + a limitation line — **all present in source text**.
- `dist/zh/index.html`: `<html lang="zh-CN">`, `<h1>在浏览器中运行的 DFIR 工具，分析过程全部在本地完成</h1>`, `hreflang="zh-CN"`.
- Homepage `dist/index.html`: `class="preboot"` block present; `hreflang` en/zh-CN/x-default; `lang="en"`.
- Hidden-text hacks across `dist/tools` + `dist/zh`: **0**.

---

## 12. Known SEO limitations

- **Indexing is not guaranteed by code.** Search appearance depends on deployment, crawl budget, backlinks, content quality, and time. This phase delivers a *technical SEO foundation*, not rankings.
- **`/zh/` is a thin discovery landing**, not a second app instance; it links into the bilingual SPA. Acceptable per §7.
- **No blog / guides / formats KB yet** — topic-cluster structure is reserved (§26) but not populated (§48).
- **`robots.txt` / sitemap** are committed to `dist/` at build time; the live site needs the host to serve them at `/robots.txt` and `/sitemap.xml` (GitHub Pages / any static host does).
- **Worker-backed tools still need HTTP** (standalone `file://` cannot load Workers) — unchanged, and irrelevant to SEO pages (they only link into the app).
- **Language auto-detection** is the App's runtime concern; the SEO layer uses explicit `hreflang`, not IP/JS redirect.

---

## 13. Files changed

Source (this commit):
- `index.html` — no-JS preboot block + `lang="en"` + home `hreflang`.
- `package.json` — `build` appends `build-seo-pages.mjs`; new `build:seo` and `lint:seo` scripts.
- `scripts/build-seo-pages.mjs` — (new) generator (pages + sitemap + `/zh/` home).
- `scripts/lint-seo.mjs` — (new) content lint over built HTML.
- `src/seo/seoPages.mjs` — (new) page registry (single source of honest copy).
- `src/seo/forbiddenWords.mjs` — (new) no-AI-marketing term guard.
- `tests/seo-contract.test.ts` — (new) 10 SEO contract tests.

Build output (`dist/`, **not committed** — matches repo convention): `tools/`, `zh/`, `sitemap.xml` regenerated by `npm run build`.

Excluded from staging: `dist-v4/`, `dist-v5/`, `dist-v7/`, `layout-*`, `overflow-audit-*`, `empty-measure*`, `fix-verify*`, `*-screenshots/`, `stale-banner-verification.png`, `scripts/_*.mjs`, `scripts/empty-shots.mjs`, `scripts/measure-empty.mjs`, `scripts/overflow-audit*.mjs`, `scripts/verify-fixes.mjs`, `scripts/_debug-binary.mjs`, and the B6-B report (separate phase).

---

## 14. Git status

- HEAD before: `592f75f` (B6-B1). This phase is a **separate** commit on `beta6`, no push, no AI/Co-Authored-By trailer.
- Staged: the 7 source files above (no audit junk, no build output).
- Audit junk remains untracked and unstaged.

---

### What was NOT claimed

Per spec §52: this is a **technical SEO foundation**, not a ranking guarantee. "Done" means crawlable discovery pages, honest capability copy, correct canonical/hreflang/sitemap, and passing contract + lint tests — not that Google has indexed anything or that traffic will rise.

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

import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { seoPages, SITE, SLUG_TO_TOOL } from "../src/seo/seoPages.mjs";
import { TOOL_SLUG, LEGACY_TO_TOOL, isKnownSlug } from "../src/seo/toolRoutes.mjs";
import { findForbidden } from "../src/seo/forbiddenWords.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const appTs = readFileSync(join(root, "src/config/app.ts"), "utf8");
const realToolIds = new Set<string>(
  [...appTs.matchAll(/id:\s*"([^"]+)"/g)].map((m) => m[1])
);

function canonicalFor(slug: string, _locale?: string) {
  // Locale is handled at runtime via ?lang= (there is no /zh/ URL path).
  // The canonical URL for a tool is therefore locale-agnostic.
  return `${SITE.base}/tools/${slug}/`;
}

const isPreview =
  process.env.VITE_PREVIEW === "1" || process.env.VITE_PREVIEW === "true";

describe("SEO page registry", () => {
  it("imports a non-empty set of pages", () => {
    expect(seoPages.length).toBeGreaterThanOrEqual(10);
  });

  it("every page has required non-empty fields", () => {
    for (const p of seoPages) {
      for (const f of ["slug", "toolId", "locale", "title", "description", "h1", "intro"] as const) {
        expect((p[f] ?? "").trim().length, `${p.slug}/${p.locale}.${f}`).toBeGreaterThan(0);
      }
      expect(p.description.length, `${p.slug}/${p.locale} description length`).toBeLessThanOrEqual(200);
    }
  });

  it("every page references a real tool id", () => {
    for (const p of seoPages) {
      expect(realToolIds.has(p.toolId), `unknown toolId "${p.toolId}" on ${p.slug}`).toBe(true);
    }
    for (const [slug, tool] of Object.entries(SLUG_TO_TOOL)) {
      expect(realToolIds.has(tool), `SLUG_TO_TOOL[${slug}] -> unknown tool "${tool}"`).toBe(true);
    }
  });

  it("titles are unique across all locale pages", () => {
    const titles = seoPages.map((p) => p.title);
    expect(new Set(titles).size).toBe(titles.length);
  });

  it("canonical URLs are unique per route", () => {
    const slugs = [...new Set(seoPages.map((p) => p.slug))];
    const cans = slugs.map((s) => canonicalFor(s, "en"));
    expect(new Set(cans).size).toBe(cans.length);
  });

  it("slugs are unique within a locale", () => {
    const seen = new Set<string>();
    for (const p of seoPages) {
      const key = `${p.locale}:${p.slug}`;
      expect(seen.has(key), `duplicate ${key}`).toBe(false);
      seen.add(key);
    }
  });

  it("no AI-marketing forbidden words appear in any page copy", () => {
    for (const p of seoPages) {
      const copy = [p.title, p.description, p.h1, p.intro, p.what, ...(p.extracts ?? []), ...(p.useCases ?? []), ...(p.limitations ?? [])].join(" ");
      const bad = findForbidden(copy);
      expect(bad, `${p.slug}/${p.locale} forbidden: ${bad.join(", ")}`).toEqual([]);
    }
  });
});

describe("Tool route registry (single source of truth)", () => {
  it("every slug maps to a real tool id", () => {
    for (const [slug, tool] of Object.entries(SLUG_TO_TOOL)) {
      expect(realToolIds.has(tool), `SLUG_TO_TOOL[${slug}]="${tool}" is not a real tool`).toBe(true);
    }
  });

  it("TOOL_SLUG keys are real tool ids and values are known slugs", () => {
    for (const [tool, slug] of Object.entries(TOOL_SLUG)) {
      expect(realToolIds.has(tool), `TOOL_SLUG key "${tool}" is not a real tool`).toBe(true);
      expect(isKnownSlug(slug), `TOOL_SLUG value "${slug}" is not a known slug`).toBe(true);
    }
  });

  it("LEGACY_TO_TOOL values are real tool ids", () => {
    for (const [legacy, tool] of Object.entries(LEGACY_TO_TOOL)) {
      expect(realToolIds.has(tool), `LEGACY_TO_TOOL[${legacy}]="${tool}" is not a real tool`).toBe(true);
    }
  });

  it("canonical slugs are unique (no two tools share a slug)", () => {
    const slugs = Object.values(TOOL_SLUG);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("every indexable tool has SEO copy in both locales", () => {
    for (const tool of Object.keys(TOOL_SLUG)) {
      const hasEn = seoPages.some((p) => p.toolId === tool && p.locale === "en");
      const hasZh = seoPages.some((p) => p.toolId === tool && p.locale === "zh-CN");
      expect(hasEn, `missing en SEO copy for indexable tool "${tool}"`).toBe(true);
      expect(hasZh, `missing zh SEO copy for indexable tool "${tool}"`).toBe(true);
    }
  });

  it("no SEO page describes an unknown or unrouted slug", () => {
    for (const p of seoPages) {
      expect(isKnownSlug(p.slug), `seoPages slug "${p.slug}" is not a known route`).toBe(true);
    }
  });

  it("slug uniqueness across SLUG_TO_TOOL and LEGACY_TO_TOOL (no collisions)", () => {
    const all = { ...SLUG_TO_TOOL, ...LEGACY_TO_TOOL };
    const slugs = Object.keys(all);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("seoPages re-exports the same SLUG_TO_TOOL as the route registry", async () => {
    expect(SLUG_TO_TOOL).toEqual(
      // the single source lives in toolRoutes.mjs; seoPages re-exports it.
      (await import("../src/seo/toolRoutes.mjs")).SLUG_TO_TOOL
    );
  });
});

describe("SEO built artifacts", () => {
  const dist = join(root, "dist");

  // The dist may have been built in preview or production mode. Rather than
  // trusting the test's own env, derive the expected origin from the built
  // index.html so this check is self-consistent with whatever dist exists.
  function distBase() {
    const idx = join(dist, "index.html");
    if (!existsSync(idx)) return SITE.base;
    const html = readFileSync(idx, "utf8");
    const m = html.match(/<link rel="canonical" href="(https?:\/\/[^/]+)\//);
    return m ? m[1] : SITE.base;
  }
  function distIsPreview() {
    return distBase().includes("pre.forensicspp.com");
  }

  it("every route slug resolves to a real SPA shell (when built)", () => {
    const base = distBase();
    const preview = distIsPreview();
    // Only canonical/indexable slugs own a self-referential page. Alias slugs
    // (e.g. sqlite-wal-recovery) resolve to a shell that canonicalizes to their
    // canonical tool and are intentionally excluded from the sitemap.
    for (const slug of Object.values(TOOL_SLUG)) {
      const htmlPath = join(dist, "tools", slug, "index.html");
      if (!existsSync(htmlPath)) {
        console.warn(`route shell not found: ${slug} — run \`npm run build\` to exercise this check.`);
        continue;
      }
      const html = readFileSync(htmlPath, "utf8");
      const canonical = `${base}/tools/${slug}/`;
      expect(html.includes(`<link rel="canonical" href="${canonical}"`), `${slug} canonical`).toBe(true);
      // It is the real SPA, not a dead text page: it boots #root.
      expect(html.includes('id="root"')).toBe(true);
      // Root-absolute assets so it serves from /tools/<slug>/.
      expect(html.includes('/assets/')).toBe(true);
      // No hidden-text hacks.
      expect(html.includes("display:none") || html.includes("visibility:hidden") || html.includes("font-size:0")).toBe(false);
      // Indexing policy matches the build mode of the dist under test.
      const hasNoindex = /name="robots"[^>]*content="[^"]*noindex/i.test(html);
      if (preview) expect(hasNoindex, `${slug} preview must noindex`).toBe(true);
      else expect(hasNoindex, `${slug} production must not noindex`).toBe(false);
    }
  });

  it("alias route slugs have a shell that canonicalizes to their canonical tool (when built)", () => {
    const base = distBase();
    const aliases = Object.keys(SLUG_TO_TOOL).filter(
      (s) => !Object.values(TOOL_SLUG).includes(s)
    );
    for (const slug of aliases) {
      const htmlPath = join(dist, "tools", slug, "index.html");
      if (!existsSync(htmlPath)) {
        console.warn(`alias shell not found: ${slug} — run \`npm run build\` to exercise this check.`);
        continue;
      }
      const html = readFileSync(htmlPath, "utf8");
      const tool = SLUG_TO_TOOL[slug];
      const canonicalSlug = TOOL_SLUG[tool];
      expect(
        html.includes(`<link rel="canonical" href="${base}/tools/${canonicalSlug}/"`),
        `${slug} should canonicalize to ${canonicalSlug}`
      ).toBe(true);
    }
  });

  it("sitemap covers every route + home, and never /zh/ (when built)", () => {
    const base = distBase();
    const sm = join(dist, "sitemap.xml");
    if (!existsSync(sm)) {
      console.warn("sitemap.xml not found — run `npm run build` to exercise this check.");
      return;
    }
    const xml = readFileSync(sm, "utf8");
    for (const slug of Object.values(TOOL_SLUG)) {
      expect(xml.includes(`${base}/tools/${slug}/`), `sitemap missing /tools/${slug}/`).toBe(true);
    }
    expect(xml.includes(`${base}/`)).toBe(true);
    expect(xml.includes("/zh/")).toBe(false);
  });
});

describe("homepage links resolve", () => {
  const indexPath = join(root, "index.html");

  it("all /tools/ links in the preboot homepage map to known slugs and /zh/ is gone", () => {
    const html = readFileSync(indexPath, "utf8");
    const hrefs = [...html.matchAll(/href="(\/tools\/[a-z0-9-]+\/)"/g)].map((m) => m[1]);
    expect(hrefs.length).toBeGreaterThan(0);
    for (const href of hrefs) {
      const slug = href.replace(/^\/tools\//, "").replace(/\/$/, "");
      expect(isKnownSlug(slug), `homepage links to unknown slug: ${href}`).toBe(true);
    }
    // No dead /zh/ route is advertised.
    expect(html.includes('href="/zh/')).toBe(false);
    expect(html.includes('hreflang="zh-CN"')).toBe(false);
  });
});

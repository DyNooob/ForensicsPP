/**
 * Forensics++ (ForensicsPP.com) — B6-SEO contract tests
 *
 * Enforces the Static Search Discovery Layer invariants:
 *  - every page references a real tool id (fails if a tool is renamed)
 *  - titles / descriptions / canonicals are unique
 *  - English and Chinese pages map 1:1 (hreflang reciprocity at source)
 *  - no AI-marketing forbidden words
 *  - when built, raw HTML carries canonical + hreflang + JSON-LD and the
 *    sitemap covers every locale page.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { seoPages, SITE, SLUG_TO_TOOL } from "../src/seo/seoPages.mjs";
import { findForbidden } from "../src/seo/forbiddenWords.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const appTs = readFileSync(join(root, "src/config/app.ts"), "utf8");
const realToolIds = new Set<string>(
  [...appTs.matchAll(/id:\s*"([^"]+)"/g)].map((m) => m[1])
);

function canonicalOf(p: { slug: string; locale: string }) {
  return p.locale === "zh-CN"
    ? `${SITE.base}/zh/tools/${p.slug}/`
    : `${SITE.base}/tools/${p.slug}/`;
}

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

  it("canonical URLs are unique", () => {
    const cans = seoPages.map(canonicalOf);
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

  it("English and Chinese map 1:1 (hreflang reciprocity at source)", () => {
    const en = new Set(seoPages.filter((p) => p.locale === "en").map((p) => p.slug));
    const zh = new Set(seoPages.filter((p) => p.locale === "zh-CN").map((p) => p.slug));
    expect([...en].sort()).toEqual([...zh].sort());
  });

  it("no AI-marketing forbidden words appear in any page copy", () => {
    for (const p of seoPages) {
      const copy = [p.title, p.description, p.h1, p.intro, p.what, ...(p.extracts ?? []), ...(p.useCases ?? []), ...(p.limitations ?? [])].join(" ");
      const bad = findForbidden(copy);
      expect(bad, `${p.slug}/${p.locale} forbidden: ${bad.join(", ")}`).toEqual([]);
    }
  });
});

describe("SEO built artifacts", () => {
  const dist = join(root, "dist");

  it("raw landing HTML carries canonical + reciprocal hreflang + JSON-LD (when built)", () => {
    const sample = join(dist, "tools", "evtx-viewer", "index.html");
    if (!existsSync(sample)) {
      console.warn("SEO build not found — run `npm run build` to exercise raw-HTML checks.");
      return;
    }
    for (const p of seoPages) {
      const html = readFileSync(
        join(dist, p.locale === "zh-CN" ? "zh" : "", "tools", p.slug, "index.html"),
        "utf8"
      );
      const can = canonicalOf(p);
      expect(html.includes(`<link rel="canonical" href="${can}"`), `${p.slug}/${p.locale} canonical`).toBe(true);
      expect(html.includes('hreflang="en"')).toBe(true);
      expect(html.includes('hreflang="zh-CN"')).toBe(true);
      expect(html.includes('hreflang="x-default"')).toBe(true);
      expect(html.includes("application/ld+json")).toBe(true);
      // No hidden-text hacks used to stuff keywords.
      expect(html.includes("display:none") || html.includes("visibility:hidden") || html.includes("font-size:0")).toBe(false);
    }
  });

  it("sitemap covers every locale page + home + /zh/ (when built)", () => {
    const sm = join(dist, "sitemap.xml");
    if (!existsSync(sm)) {
      console.warn("sitemap.xml not found — run `npm run build` to exercise sitemap coverage.");
      return;
    }
    const xml = readFileSync(sm, "utf8");
    for (const p of seoPages) {
      expect(xml.includes(canonicalOf(p)), `sitemap missing ${canonicalOf(p)}`).toBe(true);
    }
    expect(xml.includes(`${SITE.base}/`)).toBe(true);
    expect(xml.includes(`${SITE.base}/zh/`)).toBe(true);
  });
});

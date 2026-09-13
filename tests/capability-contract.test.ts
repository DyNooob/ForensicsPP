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

/**
 * Forensics++ — Capability Contract consistency gate.
 *
 * Hard gates from the Capability Truth Audit (spec §40). These must FAIL the
 * build/test run, not be downgraded to warnings:
 *   - every indexable (canonical) tool has acceptedInput + description
 *   - every canonical slug has both en + zh SEO pages
 *   - no empty static H1
 *   - no duplicate H1 across distinct canonical tools (duplicate content)
 *   - the dual-brand string "Forensics++ ForensicsPP" never appears
 *   - alias slugs are supplementary (sqlite-wal-recovery resolves to sqlite
 *     and must NOT be a separately indexed canonical page)
 *   - no forbidden marketing words in SEO copy
 */

import { describe, it, expect } from "vitest";
import { tools, getToolDefinitionById, type ToolId } from "../src/config/app";
import { seoPages, SLUG_TO_TOOL } from "../src/seo/seoPages.mjs";
import { TOOL_SLUG, LEGACY_TO_TOOL } from "../src/seo/toolRoutes.mjs";
import { findForbidden } from "../src/seo/forbiddenWords.mjs";

const CANONICAL_SLUGS = new Set(Object.values(TOOL_SLUG));

function pagesFor(slug: string) {
  return seoPages.filter((p) => p.slug === slug);
}

describe("Capability Contract — indexable tool registry", () => {
  it("every canonical tool has acceptedInput and a description", () => {
    for (const slug of CANONICAL_SLUGS) {
      const toolId = SLUG_TO_TOOL[slug] as ToolId;
      const def = getToolDefinitionById(toolId);
      expect(def, `registry entry for ${toolId}`).toBeTruthy();
      expect(Array.isArray(def.accepts) && def.accepts.length > 0, `accepts for ${toolId}`).toBe(true);
      expect(typeof def.desc === "string" && def.desc.length > 0, `desc for ${toolId}`).toBe(true);
    }
  });

  it("every tool id referenced by SEO/route maps to a real registry tool", () => {
    for (const toolId of Object.values(SLUG_TO_TOOL)) {
      expect(getToolDefinitionById(toolId as ToolId), `tool ${toolId}`).toBeTruthy();
    }
    for (const toolId of Object.values(LEGACY_TO_TOOL)) {
      expect(getToolDefinitionById(toolId as ToolId), `legacy tool ${toolId}`).toBeTruthy();
    }
  });
});

describe("Capability Contract — SEO static pages", () => {
  it("every canonical slug has both en and zh pages", () => {
    for (const slug of CANONICAL_SLUGS) {
      const pages = pagesFor(slug);
      expect(pages.find((p) => p.locale === "en"), `EN page for ${slug}`).toBeTruthy();
      expect(pages.find((p) => p.locale === "zh-CN"), `ZH page for ${slug}`).toBeTruthy();
    }
  });

  it("no empty H1 (would emit an empty static <h1>)", () => {
    for (const p of seoPages) {
      expect(p.h1 && p.h1.trim().length > 0, `H1 on ${p.slug} (${p.locale})`).toBe(true);
    }
  });

  it("no duplicate H1 across distinct canonical tools", () => {
    const seen = new Map<string, string[]>();
    for (const slug of CANONICAL_SLUGS) {
      for (const p of pagesFor(slug)) {
        if (!p.h1) continue;
        if (!seen.has(p.h1)) seen.set(p.h1, []);
        seen.get(p.h1)!.push(slug);
      }
    }
    for (const [h1, slugs] of seen) {
      expect(slugs.length, `duplicate H1 "${h1}" across ${slugs.join(", ")}`).toBe(1);
    }
  });

  it("dual-brand string 'Forensics++ ForensicsPP' never appears", () => {
    for (const p of seoPages) {
      const probe = [p.title, p.description, p.h1, p.intro, p.what, ...(p.extracts || []), ...(p.useCases || []), ...(p.limitations || [])].join(" ");
      expect(/Forensics\+\+\s*ForensicsPP|ForensicsPP\s*Forensics\+\+/.test(probe)).toBe(false);
    }
  });

  it("no forbidden marketing words in SEO copy", () => {
    for (const p of seoPages) {
      const probe = [p.title, p.description, p.h1, p.intro, p.what, ...(p.extracts || []), ...(p.useCases || []), ...(p.limitations || [])].join(" ");
      expect(findForbidden(probe), `forbidden words on ${p.slug} (${p.locale})`).toEqual([]);
    }
  });
});

describe("Capability Contract — SQLite / WAL identity", () => {
  it("sqlite-wal-recovery is a supplementary alias, not a separately indexed canonical page", () => {
    expect(CANONICAL_SLUGS.has("sqlite-wal-recovery")).toBe(false);
    expect(SLUG_TO_TOOL["sqlite-wal-recovery"]).toBe("sqlite");
    expect(TOOL_SLUG["sqlite"]).toBe("sqlite-forensics");
  });

  it("sqlite tool no longer claims a non-existent timeline capability", () => {
    const def = getToolDefinitionById("sqlite")!;
    expect(def.capabilities).toBeTruthy();
    expect((def.capabilities as readonly string[]).includes("timeline")).toBe(false);
  });
});

describe("Capability Contract — registry accepts accuracy", () => {
  it("registry tool does not advertise .reg as a hive (concept error fixed)", () => {
    const def = getToolDefinitionById("registry")!;
    expect((def.accepts as readonly string[]).includes(".reg")).toBe(false);
  });

  it("firmware help / copy does not claim an unimplemented cramfs detector", () => {
    const def = getToolDefinitionById("firmware")!;
    const help = `${def.help?.en ?? ""} ${def.help?.zh ?? ""}`;
    expect(/cramfs/i.test(help)).toBe(false);
  });
});

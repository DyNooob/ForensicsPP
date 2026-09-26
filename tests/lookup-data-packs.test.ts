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

import { afterEach, describe, expect, it, vi } from "vitest";
import { inspectLookupDataPacks, LOOKUP_DATA_CACHE, LOOKUP_DATA_PACKS } from "../src/features/lookup/dataPacks";

const originalCaches = Object.getOwnPropertyDescriptor(globalThis, "caches");

afterEach(() => {
  if (originalCaches) Object.defineProperty(globalThis, "caches", originalCaches);
  else delete (globalThis as { caches?: unknown }).caches;
});

describe("lookup data-pack manifest", () => {
  it("pins every remote pack to an immutable revision", () => {
    for (const pack of Object.values(LOOKUP_DATA_PACKS)) {
      expect(pack.url).toMatch(/githubusercontent|jsdelivr/);
      expect(pack.url).toMatch(/@[a-f0-9]{7,40}\//);
      expect(pack.version).toBeTruthy();
      expect(pack.source).toBeTruthy();
    }
  });

  it("reports current packs as on-demand before the cache exists", async () => {
    const has = vi.fn(async () => false);
    Object.defineProperty(globalThis, "caches", { configurable: true, value: { has } });
    const statuses = await inspectLookupDataPacks();
    expect(has).toHaveBeenCalledWith(LOOKUP_DATA_CACHE);
    expect(statuses).toHaveLength(3);
    expect(statuses.every((status) => status.cacheSupported && !status.cached)).toBe(true);
  });

  it("checks cached responses against the current manifest URLs", async () => {
    const match = vi.fn(async (url: string) => url === LOOKUP_DATA_PACKS.phone.url ? new Response("cached") : undefined);
    const open = vi.fn(async () => ({ match }));
    Object.defineProperty(globalThis, "caches", { configurable: true, value: { has: async () => true, open } });
    const statuses = await inspectLookupDataPacks();
    expect(open).toHaveBeenCalledWith(LOOKUP_DATA_CACHE);
    expect(statuses.find((status) => status.id === "phone")?.cached).toBe(true);
    expect(statuses.filter((status) => status.id !== "phone").every((status) => !status.cached)).toBe(true);
  });
});

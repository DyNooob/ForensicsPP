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
import { DataPackError, fetchLookupDataPack, inspectLookupDataPacks, LOOKUP_DATA_CACHE, LOOKUP_DATA_PACKS } from "../src/features/lookup/dataPacks";

const originalCaches = Object.getOwnPropertyDescriptor(globalThis, "caches");

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  if (originalCaches) Object.defineProperty(globalThis, "caches", originalCaches);
  else delete (globalThis as { caches?: unknown }).caches;
});

function mockCache(failPut = false) {
  const entries = new Map<string, Response>();
  const key = (request: Request | string) => typeof request === "string" ? request : request.url;
  const match = vi.fn(async (request: Request | string) => entries.get(key(request))?.clone());
  const put = vi.fn(async (request: Request | string, response: Response) => {
    if (failPut) throw new DOMException("Quota", "QuotaExceededError");
    entries.set(key(request), response);
  });
  vi.stubGlobal("caches", { has: async () => entries.size > 0, open: async () => ({ match, put }) });
  return { entries, match, put };
}

describe("proactive lookup localization", () => {
  const areaPack = JSON.stringify({ areas: { "110105": [{ name: "朝阳区" }] } });

  it("persists a complete download that a later offline lookup reuses", async () => {
    const cache = mockCache();
    const fetch = vi.fn(async () => new Response(areaPack));
    vi.stubGlobal("fetch", fetch);
    const progress = vi.fn();
    await fetchLookupDataPack("id", { requireCache: true, onProgress: progress });
    expect(cache.put).toHaveBeenCalledOnce();
    expect(progress).toHaveBeenLastCalledWith({ received: new TextEncoder().encode(areaPack).length, total: new TextEncoder().encode(areaPack).length });
    expect((await inspectLookupDataPacks()).find((pack) => pack.id === "id")?.cached).toBe(true);
    fetch.mockImplementation(async () => { throw new Error("offline"); });
    expect(await (await fetchLookupDataPack("id")).json()).toEqual(JSON.parse(areaPack));
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("refuses localization without storage before requesting network data", async () => {
    vi.stubGlobal("caches", undefined);
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(fetchLookupDataPack("id", { requireCache: true })).rejects.toMatchObject({ code: "unavailable" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not claim success on quota failure but permits a normal lookup", async () => {
    mockCache(true);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(areaPack)));
    await expect(fetchLookupDataPack("id", { requireCache: true })).rejects.toMatchObject({ code: "storage" });
    expect((await inspectLookupDataPacks()).every((pack) => !pack.cached)).toBe(true);
    expect(await (await fetchLookupDataPack("id")).json()).toEqual(JSON.parse(areaPack));
  });

  it.each(["<html>CDN error</html>", '{"areas": []}', '{"areas":{}}'])("rejects invalid content without poisoning the cache: %s", async (body) => {
    const cache = mockCache();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(body)));
    await expect(fetchLookupDataPack("id", { requireCache: true })).rejects.toBeInstanceOf(DataPackError);
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("rejects truncated binary packs and unsuccessful HTTP responses", async () => {
    const cache = mockCache();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new Uint8Array(4))));
    await expect(fetchLookupDataPack("phone", { requireCache: true })).rejects.toMatchObject({ code: "invalid" });
    await expect(fetchLookupDataPack("ip", { requireCache: true })).rejects.toMatchObject({ code: "invalid" });
    vi.stubGlobal("fetch", vi.fn(async () => new Response("error", { status: 503 })));
    await expect(fetchLookupDataPack("id", { requireCache: true })).rejects.toMatchObject({ code: "network" });
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("cancels a pending download without saving a partial response", async () => {
    const cache = mockCache();
    vi.stubGlobal("fetch", vi.fn((_request, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));
    const controller = new AbortController();
    const download = fetchLookupDataPack("id", { requireCache: true, signal: controller.signal });
    const assertion = expect(download).rejects.toMatchObject({ name: "AbortError" });
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled());
    controller.abort();
    await assertion;
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("bounds an unresponsive download and exposes a timeout for retry", async () => {
    vi.useFakeTimers();
    mockCache();
    vi.stubGlobal("fetch", vi.fn((_request, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));
    const download = fetchLookupDataPack("id", { requireCache: true });
    const assertion = expect(download).rejects.toMatchObject({ code: "timeout" });
    await vi.advanceTimersByTimeAsync(60_001);
    await assertion;
  });
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

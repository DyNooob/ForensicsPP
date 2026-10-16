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
 * Static lookup packs have their own cache namespace. App-shell releases can
 * rotate independently without forcing users to download these larger packs
 * again; changing this version deliberately invalidates every lookup pack.
 */
export const LOOKUP_DATA_CACHE = "forensicspp-lookup-data-v1";

export const LOOKUP_DATA_PACKS = {
  ip: {
    url: "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@c1a1fc7d5941760db3f8431dc05c48cf7f0e30a1/data/ip2region_v4.xdb",
    version: "ip2region@c1a1fc7",
    source: "ip2region (Apache-2.0)"
  },
  phone: {
    url: "https://cdn.jsdelivr.net/gh/pangongzi/phone@a0076a7cdfb5b44c53e70fac0bc46ef3ebb8bd80/src/data/phone.dat",
    version: "2025-02 / a0076a7",
    source: "pangongzi/phone community data"
  },
  id: {
    url: "https://cdn.jsdelivr.net/gh/xihan123/gb2260@aa9f31b3a8b1dff06e815b7612f4a9e5c02a5bff/site/public/downloads/areas.json",
    version: "gb2260@aa9f31b",
    source: "xihan123/gb2260 (CC0; upstream terms apply)"
  }
} as const;

export type LookupDataPackId = keyof typeof LOOKUP_DATA_PACKS;

export type LookupDataPackStatus = {
  id: LookupDataPackId;
  version: string;
  source: string;
  cached: boolean;
  cacheSupported: boolean;
};

export async function inspectLookupDataPacks(): Promise<LookupDataPackStatus[]> {
  const packs = Object.entries(LOOKUP_DATA_PACKS) as Array<[LookupDataPackId, (typeof LOOKUP_DATA_PACKS)[LookupDataPackId]]>;
  if (typeof caches === "undefined") {
    return packs.map(([id, pack]) => ({ id, version: pack.version, source: pack.source, cached: false, cacheSupported: false }));
  }
  try {
    const cacheExists = await caches.has(LOOKUP_DATA_CACHE);
    if (!cacheExists) {
      return packs.map(([id, pack]) => ({ id, version: pack.version, source: pack.source, cached: false, cacheSupported: true }));
    }
    const cache = await caches.open(LOOKUP_DATA_CACHE);
    return Promise.all(packs.map(async ([id, pack]) => ({
      id,
      version: pack.version,
      source: pack.source,
      cached: Boolean((await cache.match(pack.url))?.ok),
      cacheSupported: true
    })));
  } catch {
    return packs.map(([id, pack]) => ({ id, version: pack.version, source: pack.source, cached: false, cacheSupported: false }));
  }
}

export type PackDownloadProgress = { received: number; total: number };
export class DataPackError extends Error {
  constructor(public code: "unavailable" | "network" | "invalid" | "storage" | "timeout") {
    super(`lookup data pack: ${code}`);
  }
}

/** Shared by Settings and the lookup Worker: only complete packs enter the cache. */
export async function fetchLookupDataPack(id: LookupDataPackId, options: {
  requireCache?: boolean;
  signal?: AbortSignal;
  onProgress?: (progress: PackDownloadProgress) => void;
} = {}): Promise<Response> {
  const request = new Request(LOOKUP_DATA_PACKS[id].url, { mode: "cors", credentials: "omit" });
  let cache: Cache | null = null;
  try {
    if (typeof caches !== "undefined") cache = await caches.open(LOOKUP_DATA_CACHE);
    const cached = await cache?.match(request);
    if (cached?.ok) return cached;
  } catch { cache = null; }
  if (options.requireCache && !cache) throw new DataPackError("unavailable");

  const controller = new AbortController();
  let timedOut = false;
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) abort();
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, 60_000);
  try {
    const response = await fetch(request, { cache: "force-cache", signal: controller.signal });
    if (!response.ok || !response.body) throw new DataPackError("network");
    const total = Number(response.headers.get("content-length")) || 0;
    const limit = 64 * 1024 * 1024;
    if (total > limit) throw new DataPackError("invalid");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    let lastProgress = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > limit) throw new DataPackError("invalid");
        chunks.push(value);
        if (Date.now() - lastProgress > 100) {
          options.onProgress?.({ received, total });
          lastProgress = Date.now();
        }
      }
    } finally { await reader.cancel().catch(() => undefined); }
    const bytes = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    if (controller.signal.aborted) throw new DOMException("Aborted", "AbortError");
    // Reject CDN error documents and truncated packs before persisting them.
    if (id === "id") {
      try {
        const payload = JSON.parse(new TextDecoder().decode(bytes));
        if (!payload.areas || typeof payload.areas !== "object" || Array.isArray(payload.areas) || !Object.keys(payload.areas).length) throw new Error();
      } catch { throw new DataPackError("invalid"); }
    } else if (id === "ip" ? bytes.length < 256 + 65536 * 8 : bytes.length < 17 || new DataView(bytes.buffer).getUint32(4, true) < 8 || new DataView(bytes.buffer).getUint32(4, true) >= bytes.length) {
      throw new DataPackError("invalid");
    }
    const complete = new Response(bytes, { headers: { "Content-Type": id === "id" ? "application/json" : "application/octet-stream" } });
    if (cache) {
      try {
        await cache.put(request, complete.clone());
        if (options.requireCache && !(await cache.match(request))?.ok) throw new Error();
      } catch { if (options.requireCache) throw new DataPackError("storage"); }
    }
    options.onProgress?.({ received, total: received });
    return complete;
  } catch (caught) {
    if (timedOut) throw new DataPackError("timeout");
    if (caught instanceof DataPackError || options.signal?.aborted) throw caught;
    throw new DataPackError("network");
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
}

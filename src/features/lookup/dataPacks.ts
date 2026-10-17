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

import dataSources from "./dataSources.json";

/**
 * Static lookup packs have their own cache namespace. App-shell releases can
 * rotate independently without forcing users to download these larger packs
 * again; changing this version deliberately invalidates every lookup pack.
 */
export const LOOKUP_DATA_CACHE = "forensicspp-lookup-data-v1";

const resourceBase = (import.meta.env as { VITE_ASSET_CDN_URL?: string }).VITE_ASSET_CDN_URL;

export function lookupDataPackUrl(pack: { path: string; upstream: string }, base = resourceBase): string {
  return base ? `${base.replace(/\/releases\/[^/]+$/, "")}/${pack.path}` : pack.upstream;
}

export const LOOKUP_DATA_PACKS = Object.fromEntries(Object.entries(dataSources).map(([id, pack]) => [id, {
  ...pack,
  // Content-addressed data URLs stay stable across application releases.
  url: lookupDataPackUrl(pack)
}])) as Record<keyof typeof dataSources, (typeof dataSources)[keyof typeof dataSources] & { url: string }>;

export function lookupDataPackMessage(message: string, lang: "zh" | "en"): string {
  const code = /^lookup data pack: (network|timeout|invalid|storage|unavailable)$/.exec(message)?.[1];
  if (!code) return message;
  const messages: Record<string, [string, string]> = {
    network: ["查询数据包下载失败，请重试；也可在设置中预先下载数据包。", "Could not download the lookup data. Retry, or download the data pack in Settings."],
    timeout: ["查询数据包下载超时，请重试。", "Lookup data download timed out. Please retry."],
    invalid: ["查询数据包不完整或格式无效，请在设置中清除数据包后重新下载。", "Lookup data is incomplete or invalid. Remove it in Settings, then download again."],
    storage: ["数据包无法保存，请检查浏览器存储空间。", "Could not save the data pack. Check browser storage space."],
    unavailable: ["浏览器暂不支持保存数据包，请直接查询或更换浏览器。", "Data-pack storage is unavailable. Run the lookup directly or use another browser."]
  };
  return messages[code][lang === "zh" ? 0 : 1];
}

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

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
      cached: Boolean(await cache.match(pack.url)),
      cacheSupported: true
    })));
  } catch {
    return packs.map(([id, pack]) => ({ id, version: pack.version, source: pack.source, cached: false, cacheSupported: false }));
  }
}

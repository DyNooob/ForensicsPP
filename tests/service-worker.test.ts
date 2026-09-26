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

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

const projectRoot = join(__dirname, "..");
const serviceWorkerSource = readFileSync(join(projectRoot, "public/sw.js"), "utf8");
const registrationSource = readFileSync(join(projectRoot, "src/app/useServiceWorker.ts"), "utf8");

const SCOPE = "http://127.0.0.1:4173/";

type FetchListener = (event: unknown) => void;

class FakeCache {
  private readonly entries = new Map<string, Response>();

  private static key(input: unknown): string {
    return typeof input === "string" ? input : String((input as { url: string }).url);
  }

  async match(input: unknown): Promise<Response | undefined> {
    return this.entries.get(FakeCache.key(input));
  }

  async put(input: unknown, response: Response): Promise<void> {
    this.entries.set(FakeCache.key(input), response);
  }

  async addAll(urls: string[]): Promise<void> {
    for (const url of urls) this.entries.set(new URL(url, SCOPE).href, new Response(""));
  }

  async delete(input: unknown): Promise<boolean> {
    return this.entries.delete(FakeCache.key(input));
  }

  seed(url: string, body: string): void {
    this.entries.set(new URL(url, SCOPE).href, new Response(body));
  }
}

/**
 * Evaluates public/sw.js against a stubbed Service Worker global scope and
 * returns the registered fetch listener plus the cache it writes through, so the
 * offline fallback can be exercised for real instead of pattern-matched.
 */
function loadServiceWorker(): { dispatchFetch: (request: unknown) => Promise<Response>; cache: FakeCache } {
  const cache = new FakeCache();
  const listeners = new Map<string, FetchListener>();
  const sandbox = {
    self: {
      addEventListener: (type: string, listener: FetchListener) => listeners.set(type, listener),
      location: { origin: "http://127.0.0.1:4173" },
      registration: { scope: SCOPE },
      skipWaiting: () => undefined,
      clients: { claim: () => undefined }
    },
    caches: {
      open: async () => cache,
      keys: async () => [] as string[],
      delete: async () => true,
      match: async (input: unknown) => cache.match(input)
    },
    // Offline: every network attempt rejects, which is exactly the state that
    // produced the reported synthetic 504 storm.
    fetch: async () => {
      throw new TypeError("Failed to fetch");
    },
    Response,
    URL,
    console
  };
  runInNewContext(serviceWorkerSource, sandbox);
  const fetchListener = listeners.get("fetch");
  if (!fetchListener) throw new Error("sw.js registered no fetch listener");
  return {
    cache,
    dispatchFetch: (request: unknown) =>
      new Promise<Response>((resolve, reject) => {
        let settled = false;
        fetchListener({
          request,
          respondWith: (value: Promise<Response> | Response) => {
            settled = true;
            Promise.resolve(value).then(resolve, reject);
          }
        });
        if (!settled) reject(new Error("sw.js did not respond to the request"));
      })
  };
}

const navigateRequest = {
  method: "GET",
  url: SCOPE,
  mode: "navigate",
  destination: "document"
};

describe("service worker cache version contract", () => {
  it("keeps the marker that scripts/finalize-dist.mjs rewrites at build time", () => {
    expect(/const CACHE_VERSION = "[^"]+";/.test(serviceWorkerSource)).toBe(true);
  });

  it("never hardcodes a release version in the source sentinel", () => {
    const declared = /const CACHE_VERSION = "([^"]+)";/.exec(serviceWorkerSource)?.[1];
    expect(declared).toBeTruthy();
    // A literal release version here would let the source SW share a cache
    // namespace with a shipped build and replay its chunks.
    expect(declared).not.toMatch(/^forensicspp-v\d/);
    // The activate handler purges by this prefix, so the sentinel must keep it.
    expect(declared?.startsWith("forensicspp-")).toBe(true);
  });

  it("preserves versioned data packs when the app-shell cache rotates", () => {
    expect(serviceWorkerSource).toContain('"forensicspp-lookup-data-"');
    expect(serviceWorkerSource).toContain("!PERSISTENT_CACHE_PREFIXES.some");
  });
});

describe("service worker offline shell fallback", () => {
  it("serves the cached shell offline when every asset it references is replayable", async () => {
    const { cache, dispatchFetch } = loadServiceWorker();
    cache.seed(
      "./index.html",
      '<script type="module" src="./assets/index-a-hDq85W.js"></script>' +
        '<link rel="stylesheet" href="./assets/index-BR9Bo5zW.css">'
    );
    cache.seed("./assets/index-a-hDq85W.js", "//entry");
    cache.seed("./assets/index-BR9Bo5zW.css", "/*css*/");

    const response = await dispatchFetch(navigateRequest);
    expect(response.status).toBe(200);
    await expect(response.clone().text()).resolves.toContain("index-a-hDq85W.js");
  });

  it("refuses a cached shell that points at chunks from a build that no longer exists", async () => {
    const { cache, dispatchFetch } = loadServiceWorker();
    // Exactly the reported failure: the shell survives in cache but its entry
    // chunk hash is dead, so booting it only yields synthetic 504s per chunk.
    cache.seed("./index.html", '<script type="module" src="./assets/index-M6rkVCJp.js"></script>');

    const response = await dispatchFetch(navigateRequest);
    expect(response.status).toBe(504);
    expect(response.headers.get("content-type")).toContain("text/plain");
  });

  it("answers a missing asset with a neutral offline response instead of hanging", async () => {
    const { dispatchFetch } = loadServiceWorker();
    const response = await dispatchFetch({
      method: "GET",
      url: `${SCOPE}assets/index-M6rkVCJp.js`,
      mode: "cors",
      destination: "script"
    });
    expect(response.status).toBe(504);
  });
});

describe("service worker registration gate", () => {
  it("registers only for production bundles", () => {
    expect(registrationSource).toContain("import.meta.env.PROD");
    const registerIndex = registrationSource.indexOf("serviceWorker.register");
    const gateIndex = registrationSource.indexOf("import.meta.env.PROD");
    expect(gateIndex).toBeGreaterThan(-1);
    expect(registerIndex).toBeGreaterThan(gateIndex);
  });

  it("drops leftover dev registrations so a stale cache cannot keep booting", () => {
    expect(registrationSource).toContain("getRegistrations");
    expect(registrationSource).toContain("unregister");
  });
});

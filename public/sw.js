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

// Development sentinel only. scripts/finalize-dist.mjs rewrites this at build
// time to `forensicspp-v<package version>-<asset fingerprint>`, and
// scripts/verify-dist.mjs fails the build if it was not rewritten. Never
// hardcode a release version here: a stale literal would make the source SW
// share a cache namespace with a shipped build.
const CACHE_VERSION = "forensicspp-dev";
// Build-time list of the entry JS, modulepreloads and CSS required to boot.
const BUILD_ASSETS = [];
const PERSISTENT_CACHE_PREFIXES = ["forensicspp-data-", "forensicspp-lookup-data-"];
const CORE_ASSETS = [
  "./",
  "./index.html",
  "./legal.html",
  "./404.html",
  "./favicon.svg",
  "./og-image.png",
  "./site.webmanifest",
  "./robots.txt",
  "./sitemap.xml"
];
// NOTE: The CyberChef static bundle (~12MB+) is intentionally NOT pre-cached here.
// It is loaded on demand (runtime cache) only when the user opens the CyberChef tool,
// keeping first-paint fast. See src/tools/CyberChefTool.tsx.

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_VERSION)
      .then((cache) => cache.addAll([...CORE_ASSETS, ...BUILD_ASSETS]))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys
        .filter((key) => key.startsWith("forensicspp-") && key !== CACHE_VERSION)
        .filter((key) => !PERSISTENT_CACHE_PREFIXES.some((prefix) => key.startsWith(prefix)))
        .map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

function offlineResponse() {
  return new Response("Service temporarily unavailable", {
    status: 504,
    headers: { "Content-Type": "text/plain; charset=utf-8" }
  });
}

// A content hash identifies immutable bytes, so a cached build asset never
// needs a network round trip. Unversioned files still use network-first.
function isCdnVendorAsset(url) {
  const allAssets = BUILD_ASSETS.some((asset) => /\/releases\/[^/]+\/assets\//.test(asset));
  const resourcePattern = allAssets ? /\/assets\/[^/]+\.(?:js|css|wasm)$/ : /\/assets\/vendor-[\w-]+\.(?:js|css)$/;
  if (!resourcePattern.test(url.pathname)) return false;
  return BUILD_ASSETS.some((asset) => {
    const bootstrap = new URL(asset, self.registration.scope);
    return bootstrap.origin !== self.location.origin && bootstrap.origin === url.origin &&
      resourcePattern.test(bootstrap.pathname) &&
      bootstrap.pathname.slice(0, bootstrap.pathname.lastIndexOf("/") + 1) === url.pathname.slice(0, url.pathname.lastIndexOf("/") + 1);
  });
}

function isImmutableAsset(url) {
  const assetPath = new URL("./assets/", self.registration.scope).pathname;
  return (url.pathname.startsWith(assetPath) || isCdnVendorAsset(url)) && /-[\w-]{8}\.(?:js|css|wasm)$/.test(url.pathname);
}

// A cached app shell is only worth serving offline when every build asset it
// references can still be replayed from cache. After a rebuild the shell held in
// cache may point at content hashes that no longer exist on disk or on the
// network; serving it then paints a page that can never boot and answers each
// dead chunk with a synthetic 504. Refusing the unbootable shell surfaces one
// honest offline response instead of a broken app.
async function bootableShell(cache) {
  const shellUrl = new URL("./index.html", self.registration.scope).href;
  const shell = await cache.match(shellUrl);
  if (!shell) return undefined;
  let html;
  try {
    html = await shell.clone().text();
  } catch {
    return undefined;
  }
  const references = new Set();
  const pattern = /(?:src|href)="([^"]*assets\/[^"]+\.(?:js|css))"/g;
  let match;
  const markup = html.replace(/(<script\b[^>]*>)[\s\S]*?<\/script>/gi, "$1</script>");
  while ((match = pattern.exec(markup))) references.add(match[1]);
  for (const reference of references) {
    if (!(await cache.match(new URL(reference, shellUrl).href))) return undefined;
  }
  return shell;
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  // Only the resource CDN directory declared by this build may enter the cache.
  // Lookup data packs and unrelated external requests keep their own handling.
  if (url.origin !== self.location.origin && !isCdnVendorAsset(url)) return;

  const embeddedDocument = url.pathname.startsWith(new URL("./cyberchef/", self.registration.scope).pathname);
  if (request.mode === "navigate" && !embeddedDocument) {
    event.respondWith(
      (async () => {
        let timer;
        try {
          const network = fetch(request);
          // Handle rejection while CacheStorage is being inspected too.
          const networkResult = network.then((response) => ({ response }), () => ({ response: null }));
          const cache = await caches.open(CACHE_VERSION).catch(() => null);
          const shell = cache ? await bootableShell(cache).catch(() => undefined) : undefined;
          if (shell) {
            const result = await Promise.race([
              networkResult,
              new Promise((resolve) => { timer = setTimeout(() => resolve({ response: shell }), 3000); })
            ]);
            return result.response || shell;
          }
          return (await networkResult).response || offlineResponse();
        } catch (networkError) {
          try {
            const cache = await caches.open(CACHE_VERSION);
            return (await bootableShell(cache)) || offlineResponse();
          } catch {
            return offlineResponse();
          }
        } finally {
          if (timer !== undefined) clearTimeout(timer);
        }
      })()
    );
    return;
  }

  // Reuse immutable build assets immediately. All other URLs remain
  // network-first with an offline fallback in this build's cache.
  event.respondWith(
    (async () => {
      if (isImmutableAsset(url)) {
        try {
          const cache = await caches.open(CACHE_VERSION);
          const cached = await cache.match(request);
          if (cached?.ok) return cached;
        } catch {
          // A storage failure must not prevent the network request.
        }
      }
      try {
        const response = await fetch(request);
        if (response && response.ok) {
          // A quota/policy failure must never discard a successful response.
          const copy = response.clone();
          const save = caches.open(CACHE_VERSION)
            .then((cache) => cache.put(request, copy))
            .catch(() => undefined);
          event.waitUntil(save);
        }
        return response;
      } catch (networkError) {
        try {
          const cache = await caches.open(CACHE_VERSION);
          const cached = await cache.match(request);
          if (cached) return cached;
          // Embedded documents must never receive the Forensics++ shell.
          // A missing CyberChef build gets the same neutral failure as assets.
        } catch {
          // CacheStorage can be unavailable in private/restricted sessions.
        }
        return offlineResponse();
      }
    })()
  );
});

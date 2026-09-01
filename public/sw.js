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
      .then((cache) => cache.addAll(CORE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key.startsWith("forensicspp-") && key !== CACHE_VERSION).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

function offlineResponse() {
  return new Response("Service temporarily unavailable", {
    status: 504,
    headers: { "Content-Type": "text/plain; charset=utf-8" }
  });
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
  while ((match = pattern.exec(html))) references.add(match[1]);
  for (const reference of references) {
    if (!(await cache.match(new URL(reference, shellUrl).href))) return undefined;
  }
  return shell;
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          return await fetch(request);
        } catch (networkError) {
          const cache = await caches.open(CACHE_VERSION);
          const shell = await bootableShell(cache);
          return shell || offlineResponse();
        }
      })()
    );
    return;
  }

  // Network-first for app assets (JS/CSS/fonts/wasm). This guarantees a
  // rebuilt app always fetches current chunks instead of stale cached ones
  // whose content hash no longer matches index.html. Cache is only a fallback
  // for offline use, so the local-first promise still holds.
  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE_VERSION);
      try {
        const response = await fetch(request);
        if (response && response.ok) cache.put(request, response.clone());
        return response;
      } catch (networkError) {
        const cached = await cache.match(request);
        if (cached) return cached;
        // Not cached and offline: answer embedded documents with the app shell
        // when it is still bootable, other missing assets with a neutral 504 so
        // the caller can recover.
        if (request.destination === "document") {
          const shell = await bootableShell(cache);
          if (shell) return shell;
        }
        return offlineResponse();
      }
    })()
  );
});

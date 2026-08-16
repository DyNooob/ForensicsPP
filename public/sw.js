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

const CACHE_VERSION = "forensicspp-v1.0.0-beta.3";
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

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() => caches.match(new URL("./index.html", self.registration.scope).href))
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
        // Not cached and offline: answer navigations with the app shell,
        // other missing assets with a neutral 504 so the caller can recover.
        if (request.destination === "document") {
          const shell = await caches.match(new URL("./index.html", self.registration.scope).href);
          if (shell) return shell;
        }
        return new Response("Service temporarily unavailable", {
          status: 504,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }
    })()
  );
});

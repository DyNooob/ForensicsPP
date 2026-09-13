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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

// ─────────────────────────────────────────────────────────────────────────
// AUTHORITATIVE TOOL ↔ SLUG REGISTRY
//
// This is the single source of truth for the public URL slugs. Both the
// runtime router (src/core/routeAdapter.ts) and the SEO build scripts
// (scripts/build-seo-pages.mjs, src/seo/seoPages.mjs) import from here, so a
// slug can never drift between routing, the sidebar, the sitemap, and the
// generated landing HTML.
//
// `toolId` values MUST match the `id:` fields in src/config/app.ts. The
// seo-contract test fails the build if any mapping points at a non-existent
// tool.
//
// Slugs are kebab-case, stable, and English-only (locale is handled at
// runtime, not via URL path — see pre-release hardening notes). `home` is a
// system launcher and intentionally has no slug (it maps to `/`).
// ─────────────────────────────────────────────────────────────────────────

// toolId -> canonical, indexable slug (used for copy-link / canonical URLs).
export const TOOL_SLUG = {
  evtx: "evtx-viewer",
  sqlite: "sqlite-forensics",
  android: "apk-signature-analyzer",
  pcap: "pcap-analyzer",
  registry: "registry-forensics",
  firmware: "firmware-analyzer",
  binary: "binary-file-analyzer",
  windows: "windows-artifacts",
  image: "image-forensics",
};

// Every slug (including legacy/alias slugs) -> toolId. Used to resolve an
// incoming `/tools/<slug>/` request. `sqlite-wal-recovery` is an alias that
// resolves to the same `sqlite` workbench (it documents a sub-capability).
export const SLUG_TO_TOOL = {
  "evtx-viewer": "evtx",
  "sqlite-forensics": "sqlite",
  "sqlite-wal-recovery": "sqlite",
  "apk-signature-analyzer": "android",
  "pcap-analyzer": "pcap",
  "registry-forensics": "registry",
  "firmware-analyzer": "firmware",
  "binary-file-analyzer": "binary",
  "windows-artifacts": "windows",
  "image-forensics": "image",
};

// Legacy ids / paths that older links or bookmarks may still use. They are
// canonicalized to the current tool so old URLs never 404 into a dead end.
// (Hidden merged aliases such as qr/png/fileid/strings/entropy/yara are
//  canonicalized separately by `canonicalToolId` in config/app.ts.)
export const LEGACY_TO_TOOL = {
  "evtx-viewer": "evtx",
  "sqlite-forensics": "sqlite",
  "sqlite-wal-recovery": "sqlite",
  "apk-signature-analyzer": "android",
  "pcap-analyzer": "pcap",
  "registry-forensics": "registry",
  "firmware-analyzer": "firmware",
  "binary-file-analyzer": "binary",
  "windows-artifacts": "windows",
  "image-forensics": "image",
  wal: "sqlite",
  apk: "android",
  pe: "binary",
  "event-logs": "evtx",
};

// The set of toolIds that own a public, indexable slug.
export const INDEXABLE_TOOLS = new Set(Object.values(TOOL_SLUG));

// Online pretty-URL prefix. Keep trailing slash semantics consistent:
// `/tools/<slug>/`.
export const TOOLS_PREFIX = "/tools/";

/** True when a slug string is a known (current or legacy) tool route. */
export function isKnownSlug(slug) {
  const s = String(slug || "").toLowerCase();
  return Boolean(SLUG_TO_TOOL[s] || LEGACY_TO_TOOL[s]);
}

/** Resolve any known slug (current or legacy) to a canonical toolId. */
export function toolIdForSlug(slug) {
  const s = String(slug || "").toLowerCase();
  return SLUG_TO_TOOL[s] || LEGACY_TO_TOOL[s] || null;
}

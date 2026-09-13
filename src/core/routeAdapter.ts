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

// ─────────────────────────────────────────────────────────────────────────
// Unified Route Adapter
//
// One contract maps:  URL (path | hash)  ⇄  canonical toolId  ⇄  registry
// and back:  canonical toolId  ⇄  online pretty URL  |  standalone hash URL
//
// Online (http/https):  `/tools/<slug>/`  is the real, shareable,
//   server-direct-navigable URL. Back/Forward uses the History API.
// Standalone (file://)  or any environment without history routing:
//   `#<toolId>`  stays the compatible fallback (does not break the offline
//   single-file build).
//
// All legacy tool ids / slugs are canonicalized so old links never dead-end.
// ─────────────────────────────────────────────────────────────────────────

import {
  canonicalToolId,
  isToolId,
  toolIdFromHash,
  type ToolId,
} from "../config/app";
import {
  LEGACY_TO_TOOL,
  SLUG_TO_TOOL,
  TOOL_SLUG,
  TOOLS_PREFIX,
} from "../seo/toolRoutes.mjs";

export type RouteVia = "path" | "hash" | "legacy" | "none";

export interface RouteResolution {
  /** Canonical toolId, or null when the URL names no tool (or a bad one). */
  toolId: ToolId | null;
  /** True only when the URL *explicitly* named a tool route that does not exist
   *  (e.g. `/tools/not-a-real-tool/`). Distinguishes "home" from "404". */
  unknown: boolean;
  via: RouteVia;
  /** The raw slug (online) or hash value (standalone) that was resolved. */
  raw: string;
}

// `/tools/<slug>/` or `/tools/<slug>` — locale-agnostic (no /zh/ routes).
const PATH_RE = /^\/tools\/([a-z0-9]+(?:-[a-z0-9]+)*)\/?$/i;

export interface LocationLike {
  pathname?: string;
  hash?: string;
  protocol?: string;
}

export function isStandalone(loc?: LocationLike): boolean {
  const protocol =
    loc?.protocol ?? (typeof window !== "undefined" ? window.location.protocol : undefined);
  return protocol === "file:";
}

/** Resolve a `/tools/<slug>/` pathname. Pure: safe in node tests. */
export function resolveToolPath(
  pathname: string
): { toolId: ToolId; unknown: false } | { toolId: null; unknown: true } | { toolId: null; unknown: false } {
  const match = PATH_RE.exec(pathname || "");
  if (!match) return { toolId: null, unknown: false };
  const slug = match[1].toLowerCase();
  const tool = SLUG_TO_TOOL[slug] ?? LEGACY_TO_TOOL[slug];
  if (tool && isToolId(tool)) {
    return { toolId: canonicalToolId(tool as ToolId), unknown: false };
  }
  return { toolId: null, unknown: true };
}

/** Full resolution from a location: pathname first (online), then hash. */
export function resolveRoute(loc: LocationLike): RouteResolution {
  const pathname = loc.pathname ?? "";
  const hash = loc.hash ?? "";
  const protocol = loc.protocol;

  if (protocol !== "file:") {
    const pr = resolveToolPath(pathname);
    if (pr.unknown) return { toolId: null, unknown: true, via: "path", raw: pathname };
    if (pr.toolId) return { toolId: pr.toolId, unknown: false, via: "path", raw: pathname };
  }

  const fromHash = toolIdFromHash(hash);
  if (fromHash) {
    const legacy = hash.replace(/^#/, "").toLowerCase();
    const isLegacy = Boolean(LEGACY_TO_TOOL[legacy]) && !SLUG_TO_TOOL[legacy];
    return { toolId: fromHash, unknown: false, via: isLegacy ? "legacy" : "hash", raw: hash };
  }

  return { toolId: null, unknown: false, via: "none", raw: pathname };
}

/** Convenience: resolve from the live window (SSR-safe). */
export function resolveCurrentRoute(): RouteResolution {
  if (typeof window === "undefined") {
    return { toolId: null, unknown: false, via: "none", raw: "" };
  }
  return resolveRoute({
    pathname: window.location.pathname,
    hash: window.location.hash,
    protocol: window.location.protocol,
  });
}

/** Canonical online pretty URL for a tool (no origin). Home → `/`. */
export function toolToPrettyUrl(toolId: ToolId): string {
  const canonical = canonicalToolId(toolId);
  if (canonical === "home") return "/";
  const slug = TOOL_SLUG[canonical];
  if (slug) return `${TOOLS_PREFIX}${slug}/`;
  // Fallback for indexable-but-slugless tools (should not happen for the
  // 9 public tools); keep it a working path rather than a dead slug.
  return `${TOOLS_PREFIX}${canonical}/`;
}

/** Standalone-compatible hash URL. */
export function toolToHashUrl(toolId: ToolId): string {
  return `#${canonicalToolId(toolId)}`;
}

/** Shareable URL: pretty (online) or hash (standalone). */
export function toolToShareUrl(toolId: ToolId, origin?: string): string {
  if (isStandalone()) return toolToHashUrl(toolId);
  const base = origin ?? (typeof window !== "undefined" ? window.location.origin : "");
  return `${base}${toolToPrettyUrl(toolId)}`;
}

/** Write the current route for a tool. Online → History API; else → hash. */
export function writeRoute(toolId: ToolId, opts: { replace?: boolean } = {}): void {
  if (typeof window === "undefined") return;
  const canonical = canonicalToolId(toolId);

  if (isStandalone()) {
    const next = `#${canonical}`;
    if (window.location.hash !== next) {
      if (opts.replace) {
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${next}`);
      } else {
        window.location.hash = canonical;
      }
    }
    return;
  }

  const url = toolToPrettyUrl(canonical) + window.location.search;
  if (opts.replace) window.history.replaceState({ tool: canonical }, "", url);
  else window.history.pushState({ tool: canonical }, "", url);
}

/** Preview detection. Mirror of the build-time VITE_PREVIEW flag. */
export function isPreview(): boolean {
  const v = (import.meta.env as { VITE_PREVIEW?: string }).VITE_PREVIEW;
  return v === "1" || v === "true";
}

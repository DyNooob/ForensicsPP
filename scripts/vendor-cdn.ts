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

import type { Plugin } from "vite";
import { posix } from "node:path";

export function normalizeVendorCdn(value: string | undefined): string {
  if (!value?.trim()) return "";
  const url = new URL(value.trim());
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("VENDOR_CDN_URL must be an HTTPS URL without credentials, query or fragment");
  }
  return url.href.replace(/\/+$/, "");
}

export function isVendorAsset(filename: string): boolean {
  return /^assets\/vendor-[\w-]+\.(?:js|css)$/.test(filename);
}

export function vendorAssetUrl(base: string, filename: string): string | undefined {
  return base && isVendorAsset(filename) ? `${base}/${filename}` : undefined;
}

// Rollup's imports are relative chunk references; Vite's renderBuiltUrl handles
// asset/preload URLs but does not rewrite these ES module specifiers. Parse the
// module syntax so strings in source code or user samples are never rewritten.
export function vendorCdnPlugin(base: string): Plugin {
  return {
    name: "forensicspp-vendor-cdn",
    apply: "build",
    enforce: "post",
    augmentChunkHash: () => base,
    generateBundle(_options, bundle) {
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== "chunk") continue;
        const edits: Array<{ start: number; end: number; value: string }> = [];
        const visit = (node: any) => {
          if (!node || typeof node !== "object") return;
          if (["ImportDeclaration", "ExportNamedDeclaration", "ExportAllDeclaration", "ImportExpression"].includes(node.type)) {
            const source = node.source;
            if (source?.type === "Literal" && typeof source.value === "string" && source.value.startsWith(".")) {
              const filename = posix.normalize(posix.join(posix.dirname(chunk.fileName), source.value));
              const url = vendorAssetUrl(base, filename);
              if (url) edits.push({ start: source.start, end: source.end, value: JSON.stringify(url) });
            }
          }
          for (const value of Object.values(node)) {
            if (Array.isArray(value)) value.forEach(visit);
            else if (value && typeof value === "object") visit(value);
          }
        };
        visit(this.parse(chunk.code));
        for (const edit of edits.sort((a, b) => b.start - a.start)) {
          chunk.code = chunk.code.slice(0, edit.start) + edit.value + chunk.code.slice(edit.end);
        }
      }
    }
  };
}

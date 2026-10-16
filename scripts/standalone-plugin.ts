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

/** Inline only the scripts/styles actually referenced by the main HTML shell. */
export function standalonePlugin(): Plugin {
  return {
    name: "forensicspp-standalone",
    enforce: "post",
    config: () => ({
      base: "./",
      build: {
        // After inlining, import.meta.url is index.html rather than a script
        // under assets/. Keep Worker URLs beside the HTML they now resolve from.
        assetsDir: "",
        assetsInlineLimit: () => true,
        cssCodeSplit: false,
        chunkSizeWarningLimit: 20_000,
        rollupOptions: { output: { inlineDynamicImports: true } }
      }
    }),
    generateBundle(_options, bundle) {
      const html = bundle["index.html"];
      if (!html || html.type !== "asset" || typeof html.source !== "string") throw new Error("Missing standalone HTML");
      html.source = html.source.replace(/<script[^>]*\bsrc="([^"\s]+)"[^>]*><\/script>/g, (tag, url: string) => {
        const key = url.replace(/^\.\//, "");
        const chunk = bundle[key];
        if (!chunk || chunk.type !== "chunk") throw new Error(`Missing standalone entry: ${key}`);
        // Vite resolves this placeholder in a later hook. The referenced
        // chunk is removed here, so remove its now-unneeded preload list too.
        const code = chunk.code.replace(/"?__VITE_PRELOAD__"?/g, "void 0")
          .replace(/<(\/script|!--)/gi, "\\x3C$1");
        delete bundle[key];
        return `<script type="module">${code}</script>`;
      });
      html.source = html.source.replace(/<link[^>]*\brel="stylesheet"[^>]*>/g, (tag) => {
        const key = /\bhref="([^"\s]+)"/.exec(tag)?.[1]?.replace(/^\.\//, "");
        const css = key ? bundle[key] : undefined;
        if (!key || !css || css.type !== "asset" || typeof css.source !== "string") throw new Error("Missing standalone stylesheet");
        delete bundle[key];
        return `<style>${css.source.replace(/<\/style/gi, "\\3C /style")}</style>`;
      });
      html.source = html.source.replace(/<link[^>]*\brel="modulepreload"[^>]*>/g, "");
    }
  };
}

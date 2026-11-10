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
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

/** Bundle analyzers as self-contained Blob workers, including nested PDF workers. */
export function offlineRuntimePlugin(): Plugin {
  return {
    name: "forensicspp-offline-runtime",
    enforce: "pre",
    transform(source, id) {
      if (!/\.[cm]?[jt]sx?$/.test(id) || id.includes("node_modules")) return;
      let code = source;
      const imports: string[] = [];
      code = code.replace(/new Worker\(new URL\((['"])([^'"]+\.worker\.ts)\1, import\.meta\.url\),\s*\{\s*type:\s*['"]module['"]\s*\}\)/g,
        (_match, _quote, path: string) => {
          const name = `OfflineWorker${imports.length}`;
          imports.push(`import ${name} from ${JSON.stringify(`${path}?worker&inline`)};`);
          return `new ${name}()`;
        });
      if (id.endsWith("/features/document/pdfjs.worker.ts")) {
        // With inlineDynamicImports the PDF engine initializes in a microtask
        // before the worker receives requests; classic workers cannot use TLA.
        code = code.replace('await import("pdfjs-dist/build/pdf.worker.mjs")', 'void import("pdfjs-dist/build/pdf.worker.mjs")');
      }
      if (id.endsWith("/features/document/pdf.ts")) {
        code = code.replace('import pdfWorkerUrl from "./pdfjs.worker.ts?worker&url";', 'import OfflinePdfWorker from "./pdfjs.worker.ts?worker&inline";');
        code = code.replace('pdfjs.GlobalWorkerOptions.workerSrc = typeof window === "undefined"', 'if (typeof Worker !== "undefined") pdfjs.GlobalWorkerOptions.workerPort = new OfflinePdfWorker();\n    else pdfjs.GlobalWorkerOptions.workerSrc = typeof window === "undefined"');
        code = code.replace(': pdfWorkerUrl;', ': "";');
      }
      if (id.endsWith("/features/lookup/dataPacks.ts")) {
        const root = new URL("../", import.meta.url);
        const packs = JSON.parse(readFileSync(new URL("src/features/lookup/dataSources.json", root), "utf8"));
        const embedded: Record<string, string> = {};
        for (const [key, pack] of Object.entries(packs) as Array<[string, { sha256: string; bytes: number }]>) {
          const bytes = readFileSync(fileURLToPath(new URL(`release/lookup-data/${pack.sha256}`, root)));
          if (bytes.length !== pack.bytes || createHash("sha256").update(bytes).digest("hex") !== pack.sha256) throw new Error(`Offline lookup checksum mismatch: ${key}`);
          embedded[key] = `data:application/octet-stream;base64,${gzipSync(bytes, { level: 9 }).toString("base64")}`;
        }
        code = code.replace('const response = await fetch(request, { cache: "force-cache", signal: controller.signal });', 'const packedResponse = await fetch(request, { signal: controller.signal }); const response = new Response(packedResponse.body!.pipeThrough(new DecompressionStream("gzip")));');
        imports.push(`const offlineLookupPacks = ${JSON.stringify(embedded)};`);
        code = code.replace('url: lookupDataPackUrl(pack)', 'url: offlineLookupPacks[id as keyof typeof offlineLookupPacks]');
      }
      return code === source ? undefined : { code: imports.join("\n") + "\n" + code, map: null };
    }
  };
}

/** Inline only the scripts/styles actually referenced by the main HTML shell. */
export function standalonePlugin(): Plugin {
  return {
    name: "forensicspp-standalone",
    enforce: "post",
    config: () => ({
      base: "./",
      build: {
        // Keep remaining static resources beside index.html. Worker payloads
        // are embedded separately by offlineRuntimePlugin and run as Blobs.
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
      html.source = html.source.replace(/<link[^>]*\brel="(?:modulepreload|manifest)"[^>]*>/g, "");
    }
  };
}

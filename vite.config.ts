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

import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { standalonePlugin } from "./scripts/standalone-plugin";
import { normalizeVendorCdn, vendorAssetUrl, vendorCdnPlugin } from "./scripts/vendor-cdn";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Browser shim for node's `crypto` builtin. Several dependencies (notably
// bcryptjs' ESM entry) import node `crypto` at module top level. bcryptjs
// declares `browser: { "crypto": false }`, but that hint is dead because the
// package also ships an `exports` map, which Vite honors instead — so the node
// builtin leaks into the browser bundle and the bundler emits a runtime
// "Could not dynamically require 'crypto'" throw. Aliasing the *exact* specifier
// `crypto` to a Web-Crypto-backed shim fixes it without touching node-side code.
const browserCryptoShim = fileURLToPath(new URL("./src/shims/node-crypto-browser.ts", import.meta.url));

// Build identity (commit hash + branch) for the Preview notice. Computed at
// build time so a forensic examiner can tell exactly which build is running.
// Falls back to "dev" when git is unavailable (e.g. sandboxed/standalone build).
function readBuildInfo(): { hash: string; branch: string } {
  try {
    const hash = execSync("git rev-parse --short HEAD").toString().trim();
    const branch = process.env.RELEASE_BRANCH || process.env.GITHUB_REF_NAME || execSync("git rev-parse --abbrev-ref HEAD").toString().trim();
    return { hash: hash || "unknown", branch: branch || "unknown" };
  } catch {
    return { hash: "dev", branch: "dev" };
  }
}
const buildInfo = readBuildInfo();

const copyrightBanner = `/*!
 * Forensics++ (ForensicsPP.com)
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob | Website: https://www.forensicspp.com | Platform: DigiForensics.cn
 * Project: https://github.com/DyNooob/ForensicsPP
 * Licensed under the MIT License. Use only for lawful and authorized purposes.
 */`;

function copyrightCssPlugin(): Plugin {
  return {
    name: "forensicspp-copyright-css",
    enforce: "post",
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type !== "asset" || !/^assets\/index-.*\.css$/.test(output.fileName)) continue;
        const source = typeof output.source === "string" ? output.source : new TextDecoder().decode(output.source);
        output.source = `${copyrightBanner}\n${source}`;
      }
    }
  };
}

// Opt-in standalone build (SINGLE_FILE=1). Inlines the main-thread app
// JS/CSS into a single index.html, but Web Workers (per-tool analyzers) are
// still emitted as separate *.worker-*.js files. Browsers refuse to load
// Workers from file:// (origin "null"), so worker-backed forensic tools
// require serving over HTTP (npm run preview or any static server). This is
// an offline distribution, NOT a single self-contained file.
// Inlining forces inlineDynamicImports=true, which conflicts
// with manualChunks, so we drop manualChunks in this mode. The default
// `npm run build` stays multi-chunk and is unaffected.
const singleFileBuild = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.SINGLE_FILE === "1";
// Opt in only after uploading the matching vendor package. Offline/standalone
// releases always keep their dependencies local.
const vendorCdn = singleFileBuild ? "" : normalizeVendorCdn(process.env.VENDOR_CDN_URL);
const assetCdn = singleFileBuild ? "" : normalizeVendorCdn(process.env.ASSET_CDN_URL);
const resourceBase = assetCdn ? `${assetCdn}/releases/${buildInfo.hash}` : "";

export default defineConfig({
  resolve: {
    alias: [
      // Match the exact "crypto" specifier only (anchored regex), so
      // "crypto-js" / "crypto.subtle" are never rewritten.
      { find: /^crypto$/, replacement: browserCryptoShim }
    ]
  },
  // Web build uses root-absolute asset URLs so the SPA fallback (Nginx
  // `try_files ... /index.html`) and any /tools/<slug>/ deep-link boot the
  // app correctly from a sub-path. The standalone build inlines everything
  // (SINGLE_FILE=1) and keeps relative "./" so file:// works offline.
  base: singleFileBuild ? "./" : "/",
  define: {
    "import.meta.env.VITE_BUILD_HASH": JSON.stringify(buildInfo.hash),
    "import.meta.env.VITE_BUILD_BRANCH": JSON.stringify(buildInfo.branch),
    "import.meta.env.VITE_ASSET_CDN_URL": JSON.stringify(resourceBase),
    // Mirrors the build-time preview flag so the runtime (routeAdapter.isPreview,
    // the Preview banner, and the belt-and-suspenders noindex effect) agrees
    // with the build mode. Missing before — the banner silently never showed.
    "import.meta.env.VITE_PREVIEW": JSON.stringify(process.env.VITE_PREVIEW === "1" || process.env.VITE_PREVIEW === "true" ? "1" : "0")
  },
  plugins: [react(), copyrightCssPlugin(), ...(resourceBase || vendorCdn ? [vendorCdnPlugin(resourceBase || vendorCdn, Boolean(resourceBase))] : []), ...(singleFileBuild ? [standalonePlugin()] : [])],
  experimental: resourceBase || vendorCdn ? {
    renderBuiltUrl(filename, { hostType }) {
      if (resourceBase && filename.startsWith("assets/")) {
        // Worker constructors must stay on the page origin even when their
        // importing module is served by the CDN. The local file is a small
        // module bridge; its analyzer payload is imported from the CDN.
        if (/\.worker-[\w-]+\.js$/.test(filename) && hostType === "js") {
          return { runtime: `self.location.origin + ${JSON.stringify(`/${filename}?release=${buildInfo.hash}`)}` };
        }
        return `${resourceBase}/${filename}`;
      }
      return vendorAssetUrl(vendorCdn, filename);
    }
  } : undefined,
  build: {
    target: "es2022",
    rollupOptions: {
      output: {
        banner: copyrightBanner,
        ...(!singleFileBuild && {
          manualChunks(id: string) {
            if (id.includes("node_modules/react") || id.includes("node_modules/react-dom")) return "vendor-react";
            if (id.includes("node_modules/antd") || id.includes("node_modules/@ant-design") || id.includes("node_modules/rc-")) return "vendor-antd";
            if (id.includes("node_modules/crypto-js") || id.includes("node_modules/bcryptjs")) return "vendor-crypto";
            if (id.includes("node_modules/exifr")) return "vendor-exifr";
            if (id.includes("node_modules/jsqr")) return "vendor-jsqr";
            if (id.includes("node_modules/fflate")) return "vendor-fflate";
            if (id.includes("node_modules/postal-mime")) return "vendor-email";
            if (id.includes("node_modules/sql-formatter") || id.includes("node_modules/sql.js")) return "vendor-sql";
          }
        })
      }
    }
  },
  worker: {
    format: "es",
    rollupOptions: {
      output: {
        banner: copyrightBanner
      }
    }
  },
  server: {
    port: 5173
  }
});

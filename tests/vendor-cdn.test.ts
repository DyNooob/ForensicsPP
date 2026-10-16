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

import { describe, expect, it } from "vitest";
import { build } from "vite";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { normalizeVendorCdn, vendorAssetUrl, vendorCdnPlugin } from "../scripts/vendor-cdn";

const base = "https://static.digiforensics.cn";

describe("vendor CDN build", () => {
  it("validates the deployment base and leaves application assets local", () => {
    expect(normalizeVendorCdn(undefined)).toBe("");
    expect(normalizeVendorCdn(`${base}/`)).toBe(base);
    expect(normalizeVendorCdn(`${base}/fpp/`)).toBe(`${base}/fpp`);
    for (const value of ["http://static.example.com", `${base}?key=1`, "https://user:pass@static.example.com", `${base}#hash`]) {
      expect(() => normalizeVendorCdn(value)).toThrow();
    }
    expect(vendorAssetUrl(base, "assets/vendor-react-12345678.js")).toBe(`${base}/assets/vendor-react-12345678.js`);
    for (const asset of ["assets/index-12345678.js", "assets/hash.worker-12345678.js", "sw.js"]) {
      expect(vendorAssetUrl(base, asset)).toBeUndefined();
    }
  });

  it("rewrites static imports, lazy imports and preload links while keeping workers on the app origin", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "fpp-vendor-cdn-")));
    try {
      await writeFile(join(root, "index.html"), '<script type="module" src="/entry.js"></script>');
      await writeFile(join(root, "entry.js"), `import { value } from './vendor.js'; console.log(value); window.loadVendor = () => import('./lazy-vendor.js'); window.worker = new Worker(new URL('./sample.worker.js', import.meta.url), { type: 'module' });`);
      await writeFile(join(root, "vendor.js"), 'export const value = "vendor fixture";');
      await writeFile(join(root, "lazy-vendor.js"), 'export const lazy = 42;');
      await writeFile(join(root, "sample.worker.js"), 'self.onmessage = () => self.postMessage("worker result");');
      const result = await build({
        root, configFile: false, logLevel: "silent", base: "/",
        plugins: [vendorCdnPlugin(base)],
        experimental: { renderBuiltUrl: (name) => vendorAssetUrl(base, name) },
        build: { write: false, minify: false, rollupOptions: { output: { manualChunks(id) {
          if (id.endsWith("/vendor.js")) return "vendor-shared";
          if (id.endsWith("/lazy-vendor.js")) return "vendor-lazy";
        } } } }
      });
      if (Array.isArray(result) || !("output" in result)) throw new Error("Expected one bundle");
      const entry = result.output.find((item) => item.type === "chunk" && item.isEntry);
      if (!entry || entry.type !== "chunk") throw new Error("Missing entry");
      expect(entry.code).toMatch(/from "https:\/\/static\.digiforensics\.cn\/assets\/vendor-shared-/);
      expect(entry.code).toMatch(/import\("https:\/\/static\.digiforensics\.cn\/assets\/vendor-lazy-/);
      expect(entry.code).toContain('"/assets/sample.worker-');
      expect(entry.code).not.toMatch(/https:[^"\s]+sample\.worker/);
      const html = result.output.find((item) => item.fileName === "index.html");
      expect(html && html.type === "asset" && String(html.source)).toContain(`${base}/assets/vendor-shared-`);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

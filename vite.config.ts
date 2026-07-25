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

function cspMetaPlugin(): Plugin {
  return {
    name: "forensicspp-csp-meta",
    apply: "build",
    transformIndexHtml(html) {
      const csp =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
        "font-src 'self' data:; connect-src 'self' https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-src 'self'";
      return html.replace("<head>", `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp}">`);
    }
  };
}

export default defineConfig({
  base: "./",
  plugins: [react(), copyrightCssPlugin(), cspMetaPlugin()],
  build: {
    target: "es2022",
    // antd core is shell-required and inherently large (~700 kB); the chunk-size
    // warning is noise once we deliberately split vendors, so raise the threshold
    // above antd's size. NOTE: @ant-design/icons must stay merged with antd — they
    // have a mutual dependency that would create a circular chunk if split apart.
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: {
        banner: copyrightBanner,
        manualChunks(id) {
          if (id.includes("node_modules/react") || id.includes("node_modules/react-dom") || id.includes("node_modules/scheduler")) return "vendor-react";
          if (id.includes("node_modules/antd") || id.includes("node_modules/@ant-design") || id.includes("node_modules/rc-")) return "vendor-antd";
          if (id.includes("node_modules/crypto-js") || id.includes("node_modules/bcryptjs") || id.includes("node_modules/sm-crypto")) return "vendor-crypto";
          if (id.includes("node_modules/pdfjs-dist")) return "vendor-pdf";
          if (id.includes("node_modules/exifr")) return "vendor-exifr";
          if (id.includes("node_modules/jsqr")) return "vendor-jsqr";
          if (id.includes("node_modules/fflate")) return "vendor-fflate";
          if (id.includes("node_modules/postal-mime")) return "vendor-email";
          if (id.includes("node_modules/sql-formatter") || id.includes("node_modules/sql.js")) return "vendor-sql";
          if (id.includes("node_modules/@ts-evtx") || id.includes("node_modules/@virustotal/yara-x") || id.includes("node_modules/cfb") || id.includes("node_modules/yaml")) return "vendor-forensic";
        }
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

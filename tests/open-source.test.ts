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

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { openSourceProjects } from "../src/config/openSource";

const packageToProject = {
  "@ant-design/icons": "Ant Design Icons",
  "@ant-design/v5-patch-for-react-19": "Ant Design React 19 Patch",
  "@rc-component/qrcode": "rc-component QRCode",
  "@ts-evtx/core": "TS-EVTX",
  "@types/crypto-js": "DefinitelyTyped: CryptoJS",
  "@types/react": "DefinitelyTyped: React",
  "@types/react-dom": "DefinitelyTyped: React DOM",
  "@virustotal/yara-x": "YARA-X",
  "@vitejs/plugin-react": "Vite React Plugin",
  antd: "Ant Design",
  bcryptjs: "bcrypt.js",
  cfb: "CFB",
  "crypto-js": "CryptoJS",
  exifr: "exifr",
  fflate: "fflate",
  jsqr: "jsQR",
  "pdfjs-dist": "PDF.js",
  "postal-mime": "postal-mime",
  react: "React",
  "react-dom": "React DOM",
  "sm-crypto": "sm-crypto",
  "sql-formatter": "sql-formatter",
  "sql.js": "sql.js",
  "typescript": "TypeScript",
  "vite": "Vite",
  vitest: "Vitest",
  yaml: "YAML"
} as const;

describe("open-source project inventory", () => {
  it("lists every declared dependency in the About page inventory", () => {
    const packageJson = JSON.parse(readFileSync(resolve(process.cwd(), "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const listed = new Set(openSourceProjects.map((project) => project.name));
    const declared = Object.keys({ ...packageJson.dependencies, ...packageJson.devDependencies });
    const missingMappings = declared.filter((name) => !(name in packageToProject));
    const missingProjects = declared
      .map((name) => packageToProject[name as keyof typeof packageToProject])
      .filter((name): name is string => Boolean(name && !listed.has(name)));

    expect(missingMappings).toEqual([]);
    expect(missingProjects).toEqual([]);
  });
});

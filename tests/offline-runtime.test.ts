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
import { offlineRuntimePlugin } from "../scripts/standalone-plugin";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function transform(source: string, id: string) {
  const plugin = offlineRuntimePlugin();
  const hook = plugin.transform as (code: string, id: string) => { code: string } | undefined;
  return hook(source, id)?.code ?? source;
}

function sources(folder: string): string[] {
  return readdirSync(folder, { withFileTypes: true }).flatMap((entry) => {
    const path = `${folder}/${entry.name}`;
    return entry.isDirectory() ? sources(path) : /\.tsx?$/.test(entry.name) ? [resolve(path)] : [];
  });
}

describe("direct-file offline runtime", () => {
  it("converts every application worker constructor to an inline worker", () => {
    const files = sources("src").filter((file) => /new Worker\(new URL/.test(readFileSync(file, "utf8")));
    expect(files.length).toBeGreaterThan(20);
    for (const file of files) {
      const code = transform(readFileSync(file, "utf8"), file);
      expect(code, file).not.toMatch(/new Worker\(new URL/);
      expect(code, file).toContain("?worker&inline");
    }
  });

  it("uses an embedded PDF worker port instead of a local module URL", () => {
    const file = resolve("src/features/document/pdf.ts");
    const code = transform(readFileSync(file, "utf8"), file);
    expect(code).toContain("workerPort = new OfflinePdfWorker()");
    expect(code).not.toContain("?worker&url");
    const worker = resolve("src/features/document/pdfjs.worker.ts");
    expect(transform(readFileSync(worker, "utf8"), worker)).not.toContain('await import("pdfjs-dist/build/pdf.worker.mjs")');
  });

  it("leaves unrelated source untouched", () => {
    expect(transform('export const text = "file://";', resolve("src/utils/example.ts"))).toBe('export const text = "file://";');
  });
});

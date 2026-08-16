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

import { strToU8, unzipSync, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { buildCasePackage, readCasePackageBytes } from "../src/features/reporter/casePackage";
import { sha256Bytes } from "../src/utils/hash";

const source = {
  generatedAt: "2026-08-16T00:00:00.000Z",
  project: "https://github.com/DyNooob/ForensicsPP",
  meta: { caseName: "Case 001", examiner: "Examiner", organization: "Lab", evidenceId: "E-1", timezone: "UTC", classification: "", remarks: "" },
  notes: [{ id: "n1", tool: "SQLite", title: "Recovered row", content: "rowid=7", createdAt: "2026-08-16T00:00:00.000Z" }],
  timeline: [], evidenceFiles: [], analysisResults: [{ toolId: "firmware", result: { schemaVersion: "1", id: "a1", analyzer: { id: "firmware", version: "test" }, source: [], run: { startedAt: "2026-08-16T00:00:00.000Z", completedAt: "2026-08-16T00:00:01.000Z" }, summary: { title: "Firmware", text: "1 object" }, findings: [], indicators: [], artifacts: [], timeline: [], limitations: [], data: {} } }], markdown: "# Report\n"
};

describe(".fppcase", () => {
  it("round-trips a reference-only case package", () => {
    const bytes = buildCasePackage(source);
    const imported = readCasePackageBytes(bytes);
    expect(imported.notes).toHaveLength(1);
    expect(imported.notes[0].title).toBe("Recovered row");
    expect(imported.meta.caseName).toBe("Case 001");
    expect(imported.analysisResults).toHaveLength(1);
  });


  it("still imports schema 1.0 packages without analysis.json", () => {
    const entries: Record<string, Uint8Array> = {
      "case.json": strToU8(JSON.stringify({ generatedAt: source.generatedAt, project: source.project, meta: source.meta, integrity: null })),
      "notes.json": strToU8(JSON.stringify(source.notes)),
      "timeline.json": strToU8("[]"),
      "evidence.json": strToU8("[]"),
      "reports/report.md": strToU8(source.markdown)
    };
    const manifest = {
      format: "Forensics++ Case Package",
      schemaVersion: "1.0",
      appVersion: "1.0.0-beta.2",
      createdAt: source.generatedAt,
      project: source.project,
      evidenceEmbedded: false,
      files: Object.entries(entries).map(([path, bytes]) => ({ path, size: bytes.length, sha256: sha256Bytes(bytes) }))
    };
    const legacy = zipSync({ "manifest.json": strToU8(JSON.stringify(manifest)), ...entries });
    const imported = readCasePackageBytes(legacy);
    expect(imported.notes[0].title).toBe("Recovered row");
    expect(imported.analysisResults ?? []).toHaveLength(0);
  });

  it("rejects content changed without updating the manifest hash", () => {
    const entries = unzipSync(buildCasePackage(source)) as Record<string, Uint8Array>;
    entries["notes.json"] = strToU8("[]\n");
    const tampered = zipSync(entries);
    expect(() => readCasePackageBytes(tampered)).toThrow(/size mismatch|integrity check failed/i);
  });
});

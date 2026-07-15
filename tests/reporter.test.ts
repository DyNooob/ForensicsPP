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

import { File } from "node:buffer";
import { describe, expect, it } from "vitest";
import { buildReportHtml, buildReportMarkdown, caseNoteRiskLevel } from "../src/features/reporter/CaseReporter";
import { rememberedTimelineEvents, rememberTimelineEvents, timelineBounds } from "../src/features/reporter/timeline";
import { normalizeCaseBundle } from "../src/features/reporter/importer";
import { verifyEvidenceRegister } from "../src/features/reporter/verification";
import { copy } from "../src/i18n";
import { evidenceFileKey, fingerprintEvidenceFiles } from "../src/features/reporter/evidence";

describe("report evidence registration", () => {
  it("does not promote ordinary evidence text to a review item", () => {
    const note = {
      id: "note-risk-normal",
      tool: "邮件解析",
      title: "邮件内容",
      content: "The message mentions a password and a token, but contains no failed check.",
      createdAt: "2026-07-14T10:00:00.000Z"
    } satisfies Parameters<typeof caseNoteRiskLevel>[0];

    expect(caseNoteRiskLevel(note)).toBe("normal");
    expect(caseNoteRiskLevel({ ...note, content: "DKIM=fail; DMARC=fail" })).toBe("review");
  });

  it("deduplicates selected files and records a deliberate SHA-256 fingerprint", async () => {
    const first = new File([new TextEncoder().encode("evidence")], "sample.bin", { type: "application/octet-stream", lastModified: 1_700_000_000_000 });
    const duplicate = new File([new TextEncoder().encode("evidence")], "sample.bin", { type: "application/octet-stream", lastModified: 1_700_000_000_000 });

    expect(evidenceFileKey(first)).toBe(evidenceFileKey(duplicate));
    const records = await fingerprintEvidenceFiles([first, duplicate]);

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      name: "sample.bin",
      size: 8,
      type: "application/octet-stream",
      lastModified: "2023-11-14T22:13:20.000Z"
    });
    expect(records[0].sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("stops fingerprinting when the report flow is cancelled", async () => {
    const file = new File([new TextEncoder().encode("evidence")], "sample.bin");
    const controller = new AbortController();
    controller.abort();

    await expect(fingerprintEvidenceFiles([file], { signal: controller.signal }))
      .rejects.toMatchObject({ name: "AbortError" });
  });

  it("puts source file metadata into the report register", () => {
    const markdown = buildReportMarkdown([
      {
        id: "note-1",
        tool: "文件哈希计算",
        title: "文件哈希计算 · 2026-07-14",
        content: "SHA-256 result",
        evidenceFiles: [{ name: "sample.bin", size: 8, type: "application/octet-stream", sha256: "a".repeat(64) }],
        createdAt: "2026-07-14T10:00:00.000Z"
      }
    ], copy.zh);

    expect(markdown).toContain("## Evidence Register");
    expect(markdown).toContain("sample.bin");
    expect(markdown).toContain("a".repeat(64));
  });

  it("builds a self-contained HTML report and escapes evidence text", () => {
    const html = buildReportHtml([{
      id: "note-html",
      tool: "HTML 工具",
      title: "<script>not code</script>",
      content: "<img src=x onerror=alert(1)>\nEvidence content",
      summary: "<b>summary</b>",
      createdAt: "2026-07-14T10:00:00.000Z"
    }], copy.zh, { caseName: "Case <001>", examiner: "Analyst", organization: "", evidenceId: "", timezone: "UTC", classification: "", remarks: "" });

    expect(html).toContain("<!doctype html>");
    expect(html).toContain("<style>");
    expect(html).toContain("&lt;script&gt;not code&lt;/script&gt;");
    expect(html).not.toContain("<script>not code</script>");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("Evidence content");
  });

  it("keeps parsed timeline events attached to the report item", () => {
    const target = {};
    rememberTimelineEvents(target, [{
      id: "event-1",
      iso: "2026-07-14T10:20:30.000Z",
      local: "2026/7/14 18:20:30",
      raw: "1720952430",
      format: "Unix seconds",
      line: 4,
      source: "auth.log",
      context: "user login from 192.0.2.10",
      epochMs: 1_752_503_230_000
    }]);

    expect(rememberedTimelineEvents(target)).toEqual([expect.objectContaining({
      iso: "2026-07-14T10:20:30.000Z",
      source: "auth.log",
      context: "user login from 192.0.2.10"
    })]);

    const markdown = buildReportMarkdown([{
      id: "note-2",
      tool: "时间线构建",
      title: "时间线构建 · 2026-07-14",
      content: "user login from 192.0.2.10",
      timelineEvents: rememberedTimelineEvents(target),
      createdAt: "2026-07-14T10:21:00.000Z"
    }], copy.zh);

    expect(markdown).toContain("## Parsed Timeline Events");
    expect(markdown).toContain("user login from 192.0.2.10");
  });

  it("calculates timeline bounds by event time rather than source order", () => {
    const late = { id: "late", iso: "2026-07-14T12:00:00.000Z", local: "", raw: "", format: "", line: 1, source: "a.log", context: "", epochMs: 2_000 };
    const early = { id: "early", iso: "2026-07-14T08:00:00.000Z", local: "", raw: "", format: "", line: 2, source: "b.log", context: "", epochMs: 1_000 };
    const bounds = timelineBounds([late, early]);

    expect(bounds.first?.id).toBe("early");
    expect(bounds.last?.id).toBe("late");
  });

  it("validates and restores an exported bundle without trusting derived fields", () => {
    const bundle = normalizeCaseBundle({
      meta: { caseName: "Case 001", examiner: "Analyst", remarks: "Review" },
      integrity: { evidenceSetSha256: "not-used-for-import" },
      notes: [{
        id: "note-1",
        tool: "时间线构建",
        title: "Timeline snapshot",
        content: "login event",
        createdAt: "2026-07-14T10:00:00.000Z",
        evidenceFiles: [{ name: "auth.log", size: 12, type: "text/plain", sha256: "b".repeat(64) }],
        timelineEvents: [{
          iso: "2026-07-14T09:59:00.000Z",
          local: "2026/7/14 17:59:00",
          raw: "1752487140",
          format: "Unix seconds",
          line: 3,
          source: "auth.log",
          context: "login event"
        }],
        digest: "ignored"
      }]
    });

    expect(bundle.meta.caseName).toBe("Case 001");
    expect(bundle.notes).toHaveLength(1);
    expect(bundle.notes[0].evidenceFiles?.[0].sha256).toBe("b".repeat(64));
    expect(bundle.notes[0].timelineEvents?.[0].context).toBe("login event");
    expect(bundle.notes[0]).not.toHaveProperty("digest");
  });

  it("rejects a non-bundle JSON value", () => {
    expect(() => normalizeCaseBundle({ notes: [{ id: "only-id" }] })).toThrow("no content");
    expect(() => normalizeCaseBundle({})).toThrow("Bundle JSON");
  });

  it("verifies registered source files by name, size, and SHA-256", () => {
    const registered = [
      { name: "case/evidence.bin", size: 4, type: "application/octet-stream", sha256: "a".repeat(64) },
      { name: "notes.txt", size: 5, type: "text/plain", sha256: "b".repeat(64) }
    ];
    const result = verifyEvidenceRegister(registered, [
      { name: "evidence.bin", size: 4, type: "application/octet-stream", sha256: "a".repeat(64) },
      { name: "notes.txt", size: 5, type: "text/plain", sha256: "c".repeat(64) },
      { name: "extra.bin", size: 1, type: "application/octet-stream", sha256: "d".repeat(64) }
    ]);

    expect(result.matchedCount).toBe(1);
    expect(result.mismatchCount).toBe(1);
    expect(result.unregisteredCount).toBe(1);
    expect(result.rows.map((row) => row.status)).toEqual(["match", "mismatch"]);
  });
});

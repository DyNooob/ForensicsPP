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
import {
  buildEvidenceIdentity,
  deriveEvidenceId,
  evidenceKeyFromSources,
  isResolvedEvidenceId
} from "../src/core/evidence/identity";
import type { CaseEvidenceFile } from "../src/models";

describe("evidence identity (beta.6 P0-3)", () => {
  it("derives a stable object identity (evid:<uuid>) and never uses the digest as the id", () => {
    const id = deriveEvidenceId({ name: "a.bin", size: 10, sha256: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789" });
    expect(id.startsWith("evid:")).toBe(true);
    expect(id).not.toContain("abcdef0123456789");
    expect(id.length).toBe("evid:".length + 36);
  });

  it("assigns an object identity even when no digest is available (large evidence can enter flow before hashing)", () => {
    const id = deriveEvidenceId({ name: "a.bin", size: 10 });
    expect(id.startsWith("evid:")).toBe(true);
    expect(id.length).toBe("evid:".length + 36);
  });

  it("assigns a unique object identity per acquisition even for identical content (id != hash)", () => {
    const same = { name: "a.bin", size: 10, sha256: "A".repeat(64) };
    const first = deriveEvidenceId(same);
    const second = deriveEvidenceId(same);
    expect(first).not.toBe(second);
    expect(first.startsWith("evid:")).toBe(true);
    expect(second.startsWith("evid:")).toBe(true);
  });

  it("treats only evid:<uuid> as a resolved object identity", () => {
    expect(isResolvedEvidenceId("evid:" + "a".repeat(8) + "-" + "a".repeat(4) + "-" + "a".repeat(4) + "-" + "a".repeat(4) + "-" + "a".repeat(12))).toBe(true);
    expect(isResolvedEvidenceId("sha256:" + "a".repeat(64))).toBe(false);
    expect(isResolvedEvidenceId("pending:" + "a".repeat(36))).toBe(false);
    expect(isResolvedEvidenceId(undefined)).toBe(false);
  });

  it("builds an identity without mutating the input record", () => {
    const input: CaseEvidenceFile = { name: "a.bin", size: 10, type: "application/octet-stream", sha256: "B".repeat(64) };
    const identity = buildEvidenceIdentity(input, { source: "upload", verification: "unverified" });
    expect(identity.id?.startsWith("evid:")).toBe(true);
    expect(identity.sha256).toBe("b".repeat(64));
    expect(identity.source).toBe("upload");
    expect(identity.verification).toBe("unverified");
    expect(input.id).toBeUndefined();
  });

  it("computes a stable store key from object ids, then raw hashes, then legacy dedup key", () => {
    const resolvedA = buildEvidenceIdentity({ name: "a.bin", size: 10, type: "application/octet-stream", sha256: "A".repeat(64) });
    const resolvedB = buildEvidenceIdentity({ name: "b.bin", size: 20, type: "application/octet-stream", sha256: "B".repeat(64) });
    expect(evidenceKeyFromSources([resolvedA, resolvedB])).toBe(`${resolvedA.id}|${resolvedB.id}`);

    const raw = { name: "c.bin", size: 30, type: "application/octet-stream", sha256: "C".repeat(64) };
    expect(evidenceKeyFromSources([raw])).toBe(`sha256:${"c".repeat(64)}`);

    const legacy = { name: "d.bin", size: 40, type: "application/octet-stream", lastModified: "2026-01-01T00:00:00.000Z" };
    expect(evidenceKeyFromSources([legacy])).toBe("d.bin:40:2026-01-01T00:00:00.000Z");

    expect(evidenceKeyFromSources([])).toBe("__unkeyed__");
  });
});

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
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import { describe, expect, it } from "vitest";
import {
  buildDerivedEvidenceFile,
  dispatchToolHandoff,
  takeToolHandoff,
  clearToolHandoffs,
  type ToolHandoffLineage
} from "../src/core/toolHandoff";
import { isResolvedEvidenceId } from "../src/core/evidence/identity";
import { normalizeCaseBundle } from "../src/features/reporter/importer";
import type { CaseEvidenceFile } from "../src/models";

const makeFile = (name: string, size: number) =>
  new File([new Uint8Array(Math.min(size, 1)).buffer], name, { type: "application/octet-stream" });

const EVIDENCE_ID_RE = /^evid:[0-9a-f-]{36}$/;

describe("tool handoff lineage (beta.6 §5.4 / §5.5)", () => {
  it("builds a Derived Artifact with handoff source + origin lineage from the handoff", () => {
    const lineage: ToolHandoffLineage = {
      sourceEvidenceId: "evid:origin-mail",
      sourceRunId: "run-1",
      sourceResultId: "env-1",
      artifactId: "att-1",
      artifactType: "attachment",
      artifactLabel: "invoice.exe"
    };
    const handoff = dispatchToolHandoff({
      sourceTool: "email",
      targetTool: "binary",
      label: "invoice.exe",
      file: makeFile("invoice.exe", 4096),
      lineage
    });
    const derived = buildDerivedEvidenceFile(handoff, handoff.file);

    expect(derived.source).toBe("handoff");
    expect(derived.id).toMatch(EVIDENCE_ID_RE);
    expect(isResolvedEvidenceId(derived.id)).toBe(true);
    // The derived artifact gets its OWN identity — never collapses to the origin.
    expect(derived.id).not.toBe("evid:origin-mail");
    expect(derived.lineage).toEqual({
      originEvidenceId: "evid:origin-mail",
      originRunId: "run-1",
      originResultId: "env-1",
      originArtifactId: "att-1"
    });
  });

  it("preserves lineage across an in-memory handoff dispatch/take cycle", () => {
    clearToolHandoffs();
    const lineage: ToolHandoffLineage = {
      sourceEvidenceId: "evid:e1",
      sourceRunId: "run-r1",
      artifactId: "embedded-0-4096"
    };
    dispatchToolHandoff({
      sourceTool: "binary",
      targetTool: "image",
      label: "payload",
      file: makeFile("payload.bin", 2048),
      lineage
    });
    const taken = takeToolHandoff("image");
    expect(taken).not.toBeNull();
    expect(taken?.lineage?.sourceEvidenceId).toBe("evid:e1");
    expect(taken?.lineage?.sourceRunId).toBe("run-r1");
    expect(taken?.lineage?.artifactId).toBe("embedded-0-4096");
    const derived = buildDerivedEvidenceFile(taken!, taken!.file);
    expect(derived.lineage?.originEvidenceId).toBe("evid:e1");
    expect(derived.lineage?.originArtifactId).toBe("embedded-0-4096");
    clearToolHandoffs();
  });

  it("does not fabricate lineage when a handoff carries none", () => {
    const handoff = dispatchToolHandoff({
      sourceTool: "firmware",
      targetTool: "binary",
      label: "object",
      file: makeFile("obj.bin", 512)
    });
    const derived = buildDerivedEvidenceFile(handoff, handoff.file);
    expect(derived.source).toBe("handoff");
    expect(derived.lineage).toBeUndefined();
    clearToolHandoffs();
  });
});

describe("case import preserves derived-artifact identity + lineage (beta.6 §5.4 / §10)", () => {
  it("keeps id, source, verification and lineage on a handoff-derived evidence file", () => {
    const derived: CaseEvidenceFile = {
      name: "payload.exe",
      size: 4096,
      type: "application/x-msdownload",
      id: "evid:derived-1",
      source: "handoff",
      verification: "unverified",
      lineage: {
        originEvidenceId: "evid:mail-1",
        originRunId: "run-mail-1",
        originArtifactId: "att-1"
      }
    };
    const bundle = {
      meta: {},
      notes: [
        {
          id: "n1",
          title: "Email attachment analysis",
          tool: "binary",
          createdAt: new Date().toISOString(),
          content: "Extracted payload analyzed.",
          evidenceFiles: [derived]
        }
      ]
    };
    const imported = normalizeCaseBundle(bundle);
    const evidenceFiles = imported.notes[0].evidenceFiles;
    expect(evidenceFiles).toBeDefined();
    expect(evidenceFiles!.length).toBe(1);
    const restored = evidenceFiles![0];
    expect(restored.id).toBe("evid:derived-1");
    expect(restored.source).toBe("handoff");
    expect(restored.verification).toBe("unverified");
    expect(restored.lineage).toEqual({
      originEvidenceId: "evid:mail-1",
      originRunId: "run-mail-1",
      originArtifactId: "att-1"
    });
  });

  it("strips an invalid source/verification enum but keeps a valid identity", () => {
    const bundle = {
      meta: {},
      notes: [
        {
          id: "n1",
          title: "t",
          tool: "binary",
          createdAt: new Date().toISOString(),
          content: "c",
          evidenceFiles: [
            {
              name: "x.bin",
              size: 10,
              type: "application/octet-stream",
              id: "evid:abc",
              source: "not-a-real-source",
              verification: "probably-fine",
              lineage: { originEvidenceId: "evid:origin" }
            }
          ]
        }
      ]
    };
    const restored = normalizeCaseBundle(bundle).notes[0].evidenceFiles![0];
    expect(restored.id).toBe("evid:abc");
    // Invalid enum values must not be trusted on import.
    expect(restored.source).toBeUndefined();
    expect(restored.verification).toBeUndefined();
    expect(restored.lineage?.originEvidenceId).toBe("evid:origin");
  });
});

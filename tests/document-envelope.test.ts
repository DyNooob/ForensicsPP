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
import { buildDocumentForensicsEnvelope } from "../src/features/document/envelope";
import type { DocumentAnalysis, DocumentFinding } from "../src/features/document/analyzer";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeFinding(overrides: Partial<DocumentFinding> = {}): DocumentFinding {
  return { category: "metadata", label: "Has metadata", detail: "dc:title present", location: "docProps/core.xml", ...overrides };
}

function makeAnalysis(overrides: Partial<DocumentAnalysis> = {}): DocumentAnalysis {
  return {
    name: "report.docx",
    size: 4096,
    kind: "OOXML",
    subtype: "Word OOXML",
    metadata: [["Title", "Quarterly Report"]],
    findings: [makeFinding()],
    entries: [{ name: "word/document.xml", size: 2000, kind: "XML" }],
    extracts: [],
    pages: 0,
    revisions: 0,
    encrypted: false,
    notes: [],
    ...overrides
  };
}

describe("buildDocumentForensicsEnvelope", () => {
  it("maps document checks to findings with correct severity", () => {
    const envelope = buildDocumentForensicsEnvelope(makeAnalysis({
      findings: [
        makeFinding({ category: "external", label: "External hyperlink", detail: "https://example.com", location: "[Content_Types].xml" }),
        makeFinding({ category: "macro", label: "VBA project", detail: "vbaProject.bin present", location: "word/vbaProject.bin" }),
        makeFinding({ category: "metadata", label: "Has metadata", detail: "dc:title present", location: "docProps/core.xml" })
      ]
    }));
    const external = envelope.findings.find((finding) => finding.category === "doc-external");
    expect(external?.level).toBe("warn");
    const macro = envelope.findings.find((finding) => finding.category === "doc-macro");
    expect(macro?.level).toBe("warn");
    const metadata = envelope.findings.find((finding) => finding.category === "doc-metadata");
    expect(metadata?.level).toBe("info");
    expect(envelope.analyzer.id).toBe("documentforensics");
  });

  it("reports encryption as an error finding", () => {
    const envelope = buildDocumentForensicsEnvelope(makeAnalysis({ encrypted: true }));
    expect(envelope.findings.some((finding) => finding.title === "Document encrypted" && finding.level === "error")).toBe(true);
  });

  it("extracts external-relationship URLs and domains as indicators", () => {
    const envelope = buildDocumentForensicsEnvelope(makeAnalysis({
      findings: [makeFinding({ category: "external", label: "External link", detail: "Downloaded from https://evil.example.io/payload over plain HTTP", location: "rels" })]
    }));
    const types = envelope.indicators.map((indicator) => indicator.type);
    expect(types).toContain("url");
    expect(types).toContain("domain");
    expect(envelope.indicators.some((indicator) => indicator.type === "domain" && indicator.value === "evil.example.io")).toBe(true);
  });

  it("maps embedded extracts to artifacts", () => {
    const envelope = buildDocumentForensicsEnvelope(makeAnalysis({
      extracts: [
        { id: "e1", name: "oleObject1.bin", size: 512, kind: "Embedded object", bytes: new Uint8Array(8) },
        { id: "e2", name: "vbaProject.bin", size: 1024, kind: "VBA project", bytes: new Uint8Array(8) }
      ]
    }));
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "document-extract")).toHaveLength(2);
    expect(envelope.data.extractCount).toBe(2);
  });
});

describe("document envelope result store integration", () => {
  it("publishes under the documentforensics tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("documentforensics", buildDocumentForensicsEnvelope(makeAnalysis({ name: "a.docx", size: 1 })));
    expect(currentAnalysisResult("documentforensics")).not.toBeNull();
    clearAnalysisResults();
  });
});

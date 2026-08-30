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
import { buildImageEnvelope } from "../src/features/image/envelope";
import type { ImageInfo } from "../src/models";
import { clearAnalysisResults, currentAnalysisResult, publishAnalysisResult } from "../src/features/analysis/resultStore";

function makeImageInfo(overrides: Partial<ImageInfo> = {}): ImageInfo {
  return {
    name: "evidence.png",
    size: 2048,
    type: "image/png",
    decoded: true,
    width: 64,
    height: 64,
    dataUrl: "data:image/png;base64,",
    repairedDataUrl: "",
    repairedContainerBytes: null,
    repairStatus: "Image opened successfully.",
    recoveryRows: [],
    exif: { Make: "ACME" },
    structureRows: [["Format", "PNG"]],
    hiddenRows: [],
    trailerBytes: new Uint8Array(0),
    trailerPreview: "",
    trailerText: "",
    lsbCandidates: [],
    hiddenPayloads: [],
    repairDownloads: [],
    pngTextEntries: [],
    pngChunks: [],
    autoRevealPreviews: [],
    repairPreviewItems: [],
    channelDataUrls: {
      red: "", green: "", blue: "", alpha: "", lsb: "", lsbRed: "", lsbGreen: "", lsbBlue: "",
      lowBitHeatmap: "", noiseMap: "", bitPlanes: []
    },
    ...overrides
  };
}

describe("buildImageEnvelope", () => {
  it("reports decode status and EXIF metadata as findings", () => {
    const envelope = buildImageEnvelope(makeImageInfo());
    expect(envelope.findings.some((finding) => finding.title === "Image decoded")).toBe(true);
    expect(envelope.findings.some((finding) => finding.title === "EXIF / metadata present")).toBe(true);
    expect(envelope.findings.every((finding) => finding.code)).toBe(true);
    expect(envelope.indicators).toHaveLength(0);
    expect(envelope.timeline).toHaveLength(0);
  });

  it("flags embedded payloads as review findings and artifacts", () => {
    const payload = { label: "zip", source: "IDAT", offset: 128, size: 4096, extension: "zip", mime: "application/zip", preview: "PK", bytes: new Uint8Array([0x50, 0x4b]) };
    const envelope = buildImageEnvelope(makeImageInfo({ hiddenPayloads: [payload] }));
    const finding = envelope.findings.find((item) => item.title === "Embedded payloads extracted");
    expect(finding?.level).toBe("warn");
    expect(finding?.review).toBe(true);
    expect(envelope.artifacts.filter((artifact) => artifact.kind === "image-hidden-payload")).toHaveLength(1);
    expect(envelope.artifacts[0].offset).toBe(128);
  });

  it("publishes under the image tool key", () => {
    clearAnalysisResults();
    publishAnalysisResult("image", buildImageEnvelope(makeImageInfo()));
    const stored = currentAnalysisResult("image");
    expect(stored).not.toBeNull();
    expect(stored?.run.sequence).toBe(1);
    expect(stored?.summary.metrics.some((metric) => metric.label === "EXIF fields")).toBe(true);
    clearAnalysisResults();
  });
});

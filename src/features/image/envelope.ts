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

import { appVersion } from "../../config/app";
import type { CaseEvidenceFile } from "../../models";
import type { AnalysisArtifact, AnalysisEnvelope, AnalysisFinding, AnalysisLimitation } from "../analysis/result";
import type { ImageInfo } from "../../models";

export type ImageEnvelopeMeta = {
  startedAt?: string;
  completedAt?: string;
};

const ARTIFACT_CAP = 200;

/**
 * Map an image analysis to a unified AnalysisEnvelope (beta.6 P0-2, C-B4).
 *
 * Image forensics surfaces container structure (PNG chunk CRC / risk chunks),
 * EXIF metadata, hidden data (LSB / trailer / embedded payloads), and repair
 * viability. Each extracted embedded payload becomes an artifact; structural
 * anomalies become review findings.
 */
export function buildImageEnvelope(image: ImageInfo, meta: ImageEnvelopeMeta = {}): AnalysisEnvelope {
  const startedAt = meta.startedAt ?? new Date().toISOString();
  const completedAt = meta.completedAt ?? new Date().toISOString();
  const pngBadCrc = image.pngChunks.filter((chunk) => !chunk.ok);
  const pngRiskChunks = image.pngChunks.filter((chunk) => chunk.risk.length);

  const findings: AnalysisFinding[] = [];
  findings.push({
    level: image.decoded ? "info" : "warn",
    title: image.decoded ? "Image decoded" : "Image not decoded",
    detail: image.decoded
      ? "Pixel data decoded successfully; full analysis is available."
      : "Container opened but pixel data could not be decoded. Run Repair to attempt container recovery; QR / channel analysis are unavailable until decode succeeds.",
    category: "image-decode",
    confidence: "high"
  });
  if (pngBadCrc.length) {
    findings.push({
      level: "warn",
      title: "PNG CRC mismatch",
      detail: `${pngBadCrc.length} PNG chunk(s) failed CRC validation; the file may be tampered or corrupted.`,
      category: "image-png-crc",
      review: true,
      confidence: "high"
    });
  }
  if (pngRiskChunks.length) {
    findings.push({
      level: "warn",
      title: "Risky / private PNG chunks",
      detail: `${pngRiskChunks.length} PNG chunk(s) carry risk flags (${pngRiskChunks.slice(0, 8).map((chunk) => `${chunk.type}@0x${chunk.offset.toString(16).toUpperCase()}`).join(", ")}${pngRiskChunks.length > 8 ? " …" : ""}).`,
      category: "image-png-risk",
      review: true,
      confidence: "medium"
    });
  }
  if (image.hiddenPayloads.length) {
    findings.push({
      level: "warn",
      title: "Embedded payloads extracted",
      detail: `${image.hiddenPayloads.length} embedded file(s) carved from the image (${image.hiddenPayloads.slice(0, 6).map((payload) => payload.label).join(", ")}${image.hiddenPayloads.length > 6 ? " …" : ""}).`,
      category: "image-hidden-payload",
      review: true,
      confidence: "high"
    });
  }
  if (image.lsbCandidates.length) {
    findings.push({
      level: "warn",
      title: "LSB steganography candidates",
      detail: `${image.lsbCandidates.length} LSB plane(s) produced readable text; review for hidden messages.`,
      category: "image-lsb",
      review: true,
      confidence: "medium"
    });
  }
  if (image.trailerBytes.length) {
    findings.push({
      level: "info",
      title: "Trailer data present",
      detail: `${image.trailerBytes.length.toLocaleString()} byte(s) follow the declared image end; may contain appended data.`,
      category: "image-trailer",
      confidence: "high"
    });
  }
  if (Object.keys(image.exif).length) {
    findings.push({
      level: "info",
      title: "EXIF / metadata present",
      detail: `${Object.keys(image.exif).length} metadata field(s) extracted.`,
      category: "image-exif",
      confidence: "high"
    });
  }

  const artifacts: AnalysisArtifact[] = image.hiddenPayloads
    .slice(0, ARTIFACT_CAP)
    .map((payload, index) => ({
      id: `payload-${index}`,
      label: `${payload.label} @ 0x${payload.offset.toString(16).toUpperCase()}`,
      kind: "image-hidden-payload",
      offset: payload.offset,
      size: payload.size,
      extension: payload.extension,
      mime: payload.mime,
      confidence: "high" as const
    }));

  const limitations: AnalysisLimitation[] = [
    { code: "IMAGE_TRIAGE_SCOPE", detail: "Analysis covers container structure, EXIF, PNG chunks, LSB/trailer/hidden-payload scans, and container repair; it does not perform full steganalysis or decrypt password-protected containers." }
  ];
  if (!image.decoded) {
    limitations.push({ code: "IMAGE_NOT_DECODED", detail: "Pixel-dependent analysis (QR, channel planes) was skipped because the image could not be decoded." });
  }

  const source: CaseEvidenceFile = {
    name: image.name,
    size: image.size,
    type: image.type,
    lastModified: ""
  };

  return {
    schemaVersion: "1",
    id: `image-${startedAt}-${Math.random().toString(36).slice(2, 8)}`,
    analyzer: { id: "image", version: appVersion },
    source: [source],
    run: { startedAt, completedAt, parameters: { format: image.type } },
    summary: {
      title: "Image analysis",
      text: `${image.type} · ${image.width && image.height ? `${image.width} × ${image.height}` : "--"} · ${image.decoded ? "decoded" : "not decoded"} · ${image.hiddenPayloads.length} embedded payload(s), ${Object.keys(image.exif).length} EXIF field(s), ${image.trailerBytes.length.toLocaleString()} trailer byte(s).`,
      metrics: [
        { label: "Name", value: image.name },
        { label: "Type", value: image.type },
        { label: "Size", value: `${image.size.toLocaleString()} B` },
        { label: "Dimensions", value: image.width && image.height ? `${image.width} × ${image.height}` : "--" },
        { label: "Decoded", value: image.decoded ? "yes" : "no" },
        { label: "EXIF fields", value: String(Object.keys(image.exif).length) },
        { label: "Embedded payloads", value: String(image.hiddenPayloads.length) },
        { label: "PNG chunks", value: String(image.pngChunks.length) },
        { label: "PNG bad CRC", value: String(pngBadCrc.length) },
        { label: "PNG risk chunks", value: String(pngRiskChunks.length) },
        { label: "LSB candidates", value: String(image.lsbCandidates.length) },
        { label: "Trailer bytes", value: String(image.trailerBytes.length) }
      ]
    },
    findings: findings.map((finding) => ({ ...finding, code: finding.code ?? finding.category ?? "image.finding" })),
    indicators: [],
    artifacts,
    timeline: [],
    limitations,
    data: {
      name: image.name,
      type: image.type,
      size: image.size,
      decoded: image.decoded,
      width: image.width,
      height: image.height,
      exifFieldCount: Object.keys(image.exif).length,
      pngChunkCount: image.pngChunks.length,
      pngBadCrc: pngBadCrc.length,
      pngRiskChunks: pngRiskChunks.length,
      hiddenPayloadCount: image.hiddenPayloads.length,
      lsbCandidateCount: image.lsbCandidates.length,
      trailerBytes: image.trailerBytes.length,
      repairStatus: image.repairStatus
    }
  };
}

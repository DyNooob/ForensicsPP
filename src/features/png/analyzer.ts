/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import type { PngAnalysis, PngTextEntry } from "../../models";
import { findEmbeddedFileSignatures, hexPreview, previewText, shannonEntropy } from "../../utils/binary";
import { formatBytes } from "../../utils/files";
import { decodePngTextChunk } from "../image/analyzer";
import { knownPngChunks, parsePngFile } from "./parser";

function analyzePngEvidence(bytes: Uint8Array, name: string): PngAnalysis {
  const parsed = parsePngFile(bytes);
  const idatBytes = parsed.chunks.filter((chunk) => chunk.type === "IDAT").reduce((sum, chunk) => sum + chunk.length, 0);
  const textEntries = parsed.chunks.map((chunk) => decodePngTextChunk(bytes, chunk)).filter(Boolean) as PngTextEntry[];
  const badChunks = parsed.chunks.filter((chunk) => !chunk.ok);
  const unknownChunks = parsed.chunks.filter((chunk) => !knownPngChunks.has(chunk.type));
  const riskChunks = parsed.chunks.filter((chunk) => chunk.risk.length);
  const criticalOrder = parsed.chunks.map((chunk) => chunk.type).join(">");
  const trailerSha256 = "--";
  const trailerEntropy = parsed.trailer.length ? shannonEntropy(parsed.trailer) : 0;
  const trailerSignatures = parsed.trailer.length ? findEmbeddedFileSignatures(parsed.trailer, 0) : [];
  const repairNotes = [
    parsed.chunks.some((chunk) => chunk.type === "IEND") ? "Logical PNG stream reaches IEND; a viewer can normally ignore bytes after IEND." : "IEND was not found; decode may require carving or partial reconstruction.",
    parsed.trailer.length ? "Trailing bytes can be extracted as a separate evidence payload; do not delete them from the original exhibit." : "No bytes were found after IEND.",
    badChunks.length ? "CRC mismatches indicate modification, corruption, or non-standard chunk rewriting; keep both original and normalized preview." : "Chunk CRC values match computed checksums.",
    "A clean visual preview does not disprove LSB or transform-domain steganography; use the image workbench bit-plane/LSB views for pixel-level review."
  ];
  const findings = [
    parsed.chunks[0]?.type !== "IHDR" ? { level: "danger", title: "IHDR is not first", detail: "PNG critical chunk order is invalid." } : null,
    !parsed.chunks.some((chunk) => chunk.type === "IEND") ? { level: "danger", title: "Missing IEND", detail: "The logical PNG end chunk was not found." } : null,
    badChunks.length ? { level: "danger", title: "CRC mismatch", detail: badChunks.map((chunk) => `${chunk.type}@0x${chunk.offset.toString(16).toUpperCase()}`).join(", ") } : null,
    parsed.trailer.length ? { level: "danger", title: "Trailing data after IEND", detail: `${formatBytes(parsed.trailer.length)} after logical PNG end.` } : null,
    trailerSignatures.length ? { level: "danger", title: "Embedded signature in trailer", detail: trailerSignatures.map((hit) => `${hit.label}@0x${hit.offset.toString(16).toUpperCase()}`).join(", ") } : null,
    riskChunks.length ? { level: "warn", title: "Chunks worth review", detail: riskChunks.map((chunk) => `${chunk.type}@0x${chunk.offset.toString(16).toUpperCase()}: ${chunk.risk.join("; ")}`).join(" | ") } : null,
    textEntries.length ? { level: "warn", title: "Text metadata chunks", detail: textEntries.map((item) => `${item.chunk}:${item.keyword}`).join(", ") } : null,
    unknownChunks.length ? { level: "warn", title: "Unknown/private chunks", detail: unknownChunks.map((chunk) => chunk.type).join(", ") } : null,
    !/IHDR.*IDAT.*IEND/.test(criticalOrder) ? { level: "warn", title: "Unusual critical chunk order", detail: criticalOrder } : null,
    parsed.trailer.length && trailerEntropy > 7.35 ? { level: "warn", title: "High-entropy trailer", detail: `Trailer entropy is ${trailerEntropy.toFixed(4)}; it may be compressed, encrypted, or packed data.` } : null,
    idatBytes > 0 && idatBytes / bytes.length < 0.2 ? { level: "info", title: "Small IDAT ratio", detail: `IDAT is ${(idatBytes / bytes.length * 100).toFixed(1)}% of file size; metadata or appended data may dominate.` } : null
  ].filter(Boolean) as PngAnalysis["findings"];
  if (!findings.length) findings.push({ level: "info", title: "PNG structure looks consistent", detail: "CRC, critical chunk order, and trailer checks did not flag obvious issues." });
  return {
    name,
    size: bytes.length,
    rows: [
      ["Name", name],
      ["Size", formatBytes(bytes.length)],
      ...parsed.rows,
      ["IDAT bytes", formatBytes(idatBytes)],
      ["Text chunks", String(textEntries.length)],
      ["Risk chunks", String(riskChunks.length)],
      ["Trailer bytes", parsed.trailer.length ? formatBytes(parsed.trailer.length) : "0 B"],
      ["Trailer entropy", parsed.trailer.length ? trailerEntropy.toFixed(4) : "--"],
      ["Trailer signatures", trailerSignatures.length ? trailerSignatures.map((hit) => `${hit.label}@0x${hit.offset.toString(16).toUpperCase()}`).join(", ") : "--"]
    ],
    chunks: parsed.chunks,
    textEntries,
    findings,
    trailer: parsed.trailer,
    trailerPreview: parsed.trailer.length ? `${hexPreview(parsed.trailer, 256)}\n\n${previewText(parsed.trailer, 4096)}` : "--",
    trailerSha256,
    trailerEntropy,
    trailerSignatures,
    repairNotes
  };
}

export { analyzePngEvidence };

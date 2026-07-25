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

import { findEmbeddedFileSignatures, previewText } from "../../utils/binary";
import type { ImageInfo } from "../../models";
import { payloadMetaForSignature, carvePayloadBytes, normalizedEmbeddedOffset } from "./carve";

type ImagePixelData = { data: Uint8ClampedArray; width: number; height: number };

function decodeBitsToText(bits: number[], bitOrder: "msb" | "lsb", maxChars: number) {
  const bytes: number[] = [];
  for (let index = 0; index + 7 < bits.length && bytes.length < maxChars; index += 8) {
    let value = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      if (bitOrder === "msb") value = (value << 1) | bits[index + bit];
      else value |= bits[index + bit] << bit;
    }
    bytes.push(value);
  }
  const text = new TextDecoder().decode(new Uint8Array(bytes)).replace(/\u0000/g, "");
  const printable = text.match(/[\t\n\r -~\u00a0-\uffff]/g)?.join("") ?? "";
  const asciiPrintable = text.match(/[\t\n\r -~]/g)?.join("") ?? "";
  const printableRatio = text.length ? printable.length / text.length : 0;
  const asciiRatio = text.length ? asciiPrintable.length / text.length : 0;
  const replacementRatio = text.length ? (text.match(/\ufffd/g)?.length ?? 0) / text.length : 0;
  const signal = /(https?:\/\/|flag\{|ctf|password|secret|key=|PK\x03\x04|%PDF|MZ|BEGIN [A-Z ]+KEY|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i.test(printable);
  const plainTextLike = asciiPrintable.length > 96
    && asciiRatio > 0.9
    && printableRatio > 0.9
    && replacementRatio < 0.02
    && /[A-Za-z]{3,}/.test(asciiPrintable)
    && /[\s:;,.=_-]/.test(asciiPrintable);
  if (signal) return printable.slice(0, maxChars);
  if (plainTextLike) return asciiPrintable.slice(0, maxChars);
  return "";
}

function extractLsbCandidatesFromImageData(source: ImagePixelData, maxChars = 4096) {
  const channelSets: Array<{ mode: string; indexes: number[] }> = [
    { mode: "RGB", indexes: [0, 1, 2] },
    { mode: "R", indexes: [0] },
    { mode: "G", indexes: [1] },
    { mode: "B", indexes: [2] },
    { mode: "A", indexes: [3] },
    { mode: "RGBA", indexes: [0, 1, 2, 3] }
  ];
  const candidates: Array<{ mode: string; text: string }> = [];
  const seen = new Set<string>();
  const maxPixels = Math.min(source.width * source.height, Math.ceil((maxChars * 8) / 3) + 4096);
  for (const channelSet of channelSets) {
    for (const bitPlane of [0, 1] as const) {
      const bits: number[] = [];
      for (let pixel = 0; pixel < maxPixels; pixel += 1) {
        const base = pixel * 4;
        for (const channel of channelSet.indexes) bits.push((source.data[base + channel] >> bitPlane) & 1);
      }
      for (const order of ["msb", "lsb"] as const) {
        const text = decodeBitsToText(bits, order, maxChars);
        const normalized = text.replace(/\s+/g, " ").slice(0, 200);
        if (text && !seen.has(normalized)) {
          seen.add(normalized);
          candidates.push({ mode: `${channelSet.mode} bit ${bitPlane} ${order.toUpperCase()}`, text });
        }
      }
    }
  }
  return candidates.slice(0, 8);
}

function buildLsbByteStream(source: ImagePixelData, channelIndexes: number[], bitPlane: number, bitOrder: "msb" | "lsb", maxBytes = 262_144) {
  const bitLimit = Math.min(source.width * source.height * channelIndexes.length, maxBytes * 8);
  const bytes: number[] = [];
  let value = 0;
  let bitCount = 0;
  for (let pixel = 0; pixel < source.width * source.height && bitCount < bitLimit; pixel += 1) {
    const base = pixel * 4;
    for (const channel of channelIndexes) {
      const bit = (source.data[base + channel] >> bitPlane) & 1;
      if (bitOrder === "msb") value = (value << 1) | bit;
      else value |= bit << (bitCount % 8);
      bitCount += 1;
      if (bitCount % 8 === 0) {
        bytes.push(value);
        value = 0;
        if (bytes.length >= maxBytes) return new Uint8Array(bytes);
      }
    }
  }
  return new Uint8Array(bytes);
}

function collectLsbPayloadsFromImageData(source: ImagePixelData) {
  const payloads: ImageInfo["hiddenPayloads"] = [];
  const modes = [
    { label: "RGB", indexes: [0, 1, 2] },
    { label: "R", indexes: [0] },
    { label: "G", indexes: [1] },
    { label: "B", indexes: [2] },
    { label: "A", indexes: [3] }
  ];
  for (const mode of modes) {
    for (const bitPlane of [0, 1] as const) {
      for (const bitOrder of ["msb", "lsb"] as const) {
        const stream = buildLsbByteStream(source, mode.indexes, bitPlane, bitOrder);
        const hits = findEmbeddedFileSignatures(stream, 0);
        for (const hit of hits.slice(0, 3)) {
          if (hit.offset > 4096) continue;
        const label = `LSB ${mode.label} bit ${bitPlane} ${bitOrder.toUpperCase()} ${hit.label}`;
        const payloadOffset = normalizedEmbeddedOffset(hit.label, hit.offset);
        const payloadBytes = carvePayloadBytes(hit.label, stream.slice(payloadOffset));
        if (payloads.some((item) => item.label === label && item.offset === payloadOffset)) continue;
        const meta = payloadMetaForSignature(hit.label);
        payloads.push({
          label,
          source: `LSB byte stream (${mode.label} bit ${bitPlane} ${bitOrder.toUpperCase()})`,
          offset: payloadOffset,
          size: payloadBytes.length,
            extension: meta.extension,
            mime: meta.mime,
            preview: previewText(payloadBytes, 4096),
            bytes: payloadBytes
          });
        }
      }
    }
  }
  return payloads.slice(0, 12);
}

function scoreImageBitPlanes(source: ImagePixelData) {
  const rows: Array<[string, string]> = [];
  const findings: Array<{ level: string; title: string; detail: string }> = [];
  const channels = [
    { label: "R", index: 0 },
    { label: "G", index: 1 },
    { label: "B", index: 2 },
    { label: "A", index: 3 }
  ];
  const pixels = source.width * source.height;
  for (const channel of channels) {
    for (const bitPlane of [0, 1, 2, 3]) {
      let ones = 0;
      let horizontalTransitions = 0;
      let compared = 0;
      for (let y = 0; y < source.height; y += 1) {
        let previous = -1;
        for (let x = 0; x < source.width; x += 1) {
          const pixel = y * source.width + x;
          const bit = (source.data[pixel * 4 + channel.index] >> bitPlane) & 1;
          ones += bit;
          if (previous >= 0) {
            horizontalTransitions += previous === bit ? 0 : 1;
            compared += 1;
          }
          previous = bit;
        }
      }
      const oneRatio = pixels ? ones / pixels : 0;
      const transitionRatio = compared ? horizontalTransitions / compared : 0;
      const label = `${channel.label} bit ${bitPlane}`;
      rows.push([label, `ones ${(oneRatio * 100).toFixed(2)}% / transitions ${(transitionRatio * 100).toFixed(2)}%`]);
      const normalOpaqueAlpha = channel.label === "A" && oneRatio === 1 && transitionRatio === 0;
      if (!normalOpaqueAlpha && bitPlane <= 1 && (oneRatio < 0.30 || oneRatio > 0.70 || transitionRatio < 0.18 || transitionRatio > 0.82)) {
        findings.push({
          level: "info",
          title: `${label} distribution note`,
          detail: `ones ${(oneRatio * 100).toFixed(2)}%, horizontal transitions ${(transitionRatio * 100).toFixed(2)}%. Inspect the bit-plane preview only when it shows readable text, QR outlines, or regular shapes.`
        });
      }
    }
  }
  return { rows, findings };
}

export {
  decodeBitsToText,
  extractLsbCandidatesFromImageData,
  buildLsbByteStream,
  collectLsbPayloadsFromImageData,
  scoreImageBitPlanes
};

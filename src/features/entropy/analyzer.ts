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

import type { EntropyAnalysis, EntropyBlock, EntropyRange } from "../../models";
import { formatBytes } from "../../utils/files";

function byteDistribution(bytes: Uint8Array) {
  const counts = new Array(256).fill(0);
  bytes.forEach((byte) => {
    counts[byte] += 1;
  });
  return counts
    .map((count, byte) => ({ byte, count }))
    .filter((item) => item.count)
    .sort((a, b) => b.count - a.count)
    .map((item) => ({ ...item, ratio: bytes.length ? item.count / bytes.length : 0 }));
}

function classifyEntropyBlock(block: Pick<EntropyBlock, "size" | "entropy" | "asciiRatio" | "zeroRatio" | "dominantByte" | "dominantRatio">) {
  if (block.size < 64) {
    return {
      classification: "small-tail",
      level: "info",
      note: "末尾小块，熵值参考意义较弱。"
    };
  }
  if (block.zeroRatio >= 0.72 || block.entropy <= 0.7) {
    return {
      classification: "padding / sparse",
      level: "info",
      note: "大量 00 或重复字节，常见于填充、空洞、预分配区域。"
    };
  }
  if (block.asciiRatio >= 0.86 && block.entropy >= 3.0 && block.entropy <= 6.4) {
    return {
      classification: "text-heavy",
      level: "info",
      note: "可打印字符占比高，优先用字符串、IOC、时间线工具复核。"
    };
  }
  if (block.entropy >= 7.65) {
    return {
      classification: "very-high entropy",
      level: "warn",
      note: "接近随机分布，常见于加密、压缩、packed payload 或密钥材料。"
    };
  }
  if (block.entropy >= 7.25) {
    return {
      classification: "high entropy",
      level: "warn",
      note: "熵值偏高，可能是压缩、图片/媒体数据、加密片段或混淆代码。"
    };
  }
  if (block.dominantRatio >= 0.45) {
    return {
      classification: "repeated-byte",
      level: "info",
      note: `字节 0x${block.dominantByte.toString(16).padStart(2, "0").toUpperCase()} 占比高，可能是填充、表格或结构化区域。`
    };
  }
  return {
    classification: "structured binary",
    level: "info",
    note: "熵值处于常见结构化二进制范围。"
  };
}

function mergeEntropyRanges(blocks: EntropyBlock[]): EntropyRange[] {
  const ranges: EntropyRange[] = [];
  const pushRange = (group: EntropyBlock[]) => {
    if (!group.length) return;
    const size = group.reduce((sum, block) => sum + block.size, 0);
    const avgEntropy = group.reduce((sum, block) => sum + block.entropy * block.size, 0) / Math.max(size, 1);
    const avgAsciiRatio = group.reduce((sum, block) => sum + block.asciiRatio * block.size, 0) / Math.max(size, 1);
    const avgZeroRatio = group.reduce((sum, block) => sum + block.zeroRatio * block.size, 0) / Math.max(size, 1);
    ranges.push({
      start: group[0].offset,
      end: group[group.length - 1].endOffset,
      size,
      blockCount: group.length,
      classification: group[0].classification,
      level: group.some((block) => block.level === "warn") ? "warn" : "info",
      avgEntropy,
      avgAsciiRatio,
      avgZeroRatio,
      note: group[0].note
    });
  };
  let current: EntropyBlock[] = [];
  for (const block of blocks) {
    if (!current.length || current[current.length - 1].classification === block.classification) {
      current.push(block);
    } else {
      pushRange(current);
      current = [block];
    }
  }
  pushRange(current);
  return ranges;
}

export function analyzeEntropy(bytes: Uint8Array, blockSize = 1024): EntropyAnalysis {
  const blocks: EntropyBlock[] = [];
  const overallCounts = new Uint32Array(256);
  const entropyFromCounts = (counts: ArrayLike<number>, size: number) => {
    if (!size) return 0;
    let value = 0;
    for (let index = 0; index < counts.length; index += 1) {
      const count = counts[index];
      if (!count) continue;
      const probability = count / size;
      value -= probability * Math.log2(probability);
    }
    return value;
  };
  const effectiveBlockSize = Math.max(blockSize, Math.ceil(bytes.length / 8192));
  for (let offset = 0; offset < bytes.length; offset += effectiveBlockSize) {
    const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + effectiveBlockSize));
    let printable = 0;
    let zero = 0;
    const counts = new Array(256).fill(0) as number[];
    for (const byte of chunk) {
      counts[byte] += 1;
      overallCounts[byte] += 1;
      if (byte === 0) zero += 1;
      if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable += 1;
    }
    const dominantByte = counts.reduce((best, count, byte) => count > counts[best] ? byte : best, 0);
    const entropyValue = entropyFromCounts(counts, chunk.length);
    const baseBlock = {
      offset,
      endOffset: offset + chunk.length,
      size: chunk.length,
      entropy: entropyValue,
      asciiRatio: chunk.length ? printable / chunk.length : 0,
      zeroRatio: chunk.length ? zero / chunk.length : 0,
      dominantByte,
      dominantRatio: chunk.length ? counts[dominantByte] / chunk.length : 0
    };
    blocks.push({
      ...baseBlock,
      ...classifyEntropyBlock(baseBlock)
    });
  }
  const entropy = entropyFromCounts(overallCounts, bytes.length);
  const ranges = mergeEntropyRanges(blocks);
  const highBlocks = blocks.filter((block) => block.size >= 64 && /high entropy/i.test(block.classification));
  const veryHighBlocks = blocks.filter((block) => block.size >= 64 && block.classification === "very-high entropy");
  const lowBlocks = blocks.filter((block) => block.size >= 64 && block.classification === "padding / sparse");
  const textBlocks = blocks.filter((block) => block.size >= 64 && block.classification === "text-heavy");
  const repeatedBlocks = blocks.filter((block) => block.size >= 64 && block.classification === "repeated-byte");
  const suspiciousRanges = ranges.filter((range) => range.level === "warn" || ["padding / sparse", "text-heavy"].includes(range.classification));
  const classRows = Array.from(blocks.reduce((map, block) => {
    map.set(block.classification, (map.get(block.classification) ?? 0) + 1);
    return map;
  }, new Map<string, number>()).entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([label, count]) => [label, String(count)] as [string, string]);
  const findings: EntropyAnalysis["findings"] = [
    entropy >= 7.5 ? { level: "warn", title: "High overall entropy", detail: `${entropy.toFixed(4)} / 8; file may be compressed, encrypted, or packed.` } : null,
    veryHighBlocks.length ? { level: "warn", title: "Very high entropy blocks", detail: veryHighBlocks.slice(0, 12).map((block) => `0x${block.offset.toString(16).toUpperCase()}-${block.endOffset.toString(16).toUpperCase()} ${block.entropy.toFixed(3)}`).join("\n") } : null,
    highBlocks.length ? { level: "warn", title: "High entropy regions", detail: highBlocks.slice(0, 12).map((block) => `0x${block.offset.toString(16).toUpperCase()} ${block.entropy.toFixed(3)} ${block.note}`).join("\n") } : null,
    lowBlocks.length ? { level: "info", title: "Low entropy / padding regions", detail: lowBlocks.slice(0, 12).map((block) => `0x${block.offset.toString(16).toUpperCase()} zero=${(block.zeroRatio * 100).toFixed(1)}%`).join("\n") } : null,
    textBlocks.length ? { level: "info", title: "Printable text-heavy regions", detail: textBlocks.slice(0, 12).map((block) => `0x${block.offset.toString(16).toUpperCase()} printable=${(block.asciiRatio * 100).toFixed(1)}%`).join("\n") } : null,
    repeatedBlocks.length ? { level: "info", title: "Repeated-byte regions", detail: repeatedBlocks.slice(0, 12).map((block) => `0x${block.offset.toString(16).toUpperCase()} dominant=0x${block.dominantByte.toString(16).padStart(2, "0").toUpperCase()} ${(block.dominantRatio * 100).toFixed(1)}%`).join("\n") } : null,
    suspiciousRanges.length ? { level: "info", title: "Merged evidence ranges", detail: suspiciousRanges.slice(0, 12).map((range) => `0x${range.start.toString(16).toUpperCase()}-0x${range.end.toString(16).toUpperCase()} ${range.classification} ${formatBytes(range.size)}`).join("\n") } : null
  ].filter(Boolean) as EntropyAnalysis["findings"];
  if (!findings.length) findings.push({ level: "info", title: "No strong entropy marker", detail: "No high-entropy, low-entropy, or text-heavy region crossed the local heuristic thresholds." });
  return {
    rows: [
      ["Size", formatBytes(bytes.length)],
      ["Block size", formatBytes(effectiveBlockSize)],
      ["Blocks", String(blocks.length)],
      ["Entropy", `${entropy.toFixed(4)} / 8`],
      ["High entropy blocks", String(highBlocks.length)],
      ["Very high entropy blocks", String(veryHighBlocks.length)],
      ["Low entropy blocks", String(lowBlocks.length)],
      ["Text-heavy blocks", String(textBlocks.length)],
      ["Repeated-byte blocks", String(repeatedBlocks.length)],
      ["Merged ranges", String(ranges.length)]
    ],
    classRows,
    blocks,
    ranges,
    distribution: byteDistribution(bytes).slice(0, 32),
    findings
  };
}


function entropyBlocksToCsv(blocks: EntropyBlock[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["offset_dec", "offset_hex", "end_dec", "end_hex", "size", "entropy", "ascii_ratio", "zero_ratio", "dominant_byte", "dominant_ratio", "classification", "level", "note"].join(","),
    ...blocks.map((block) => [
      block.offset,
      `0x${block.offset.toString(16).toUpperCase()}`,
      block.endOffset,
      `0x${block.endOffset.toString(16).toUpperCase()}`,
      block.size,
      block.entropy.toFixed(6),
      block.asciiRatio.toFixed(6),
      block.zeroRatio.toFixed(6),
      `0x${block.dominantByte.toString(16).padStart(2, "0").toUpperCase()}`,
      block.dominantRatio.toFixed(6),
      block.classification,
      block.level,
      block.note
    ].map(escape).join(","))
  ].join("\n");
}

function entropyRangesToCsv(ranges: EntropyRange[]) {
  const escape = (value: string | number) => {
    const text = String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
  };
  return [
    ["start_dec", "start_hex", "end_dec", "end_hex", "size", "block_count", "classification", "level", "avg_entropy", "avg_ascii_ratio", "avg_zero_ratio", "note"].join(","),
    ...ranges.map((range) => [
      range.start,
      `0x${range.start.toString(16).toUpperCase()}`,
      range.end,
      `0x${range.end.toString(16).toUpperCase()}`,
      range.size,
      range.blockCount,
      range.classification,
      range.level,
      range.avgEntropy.toFixed(6),
      range.avgAsciiRatio.toFixed(6),
      range.avgZeroRatio.toFixed(6),
      range.note
    ].map(escape).join(","))
  ].join("\n");
}

function entropyBlockKey(block: EntropyBlock) {
  return `${block.offset}:${block.endOffset}:${block.classification}`;
}

export { entropyBlockKey, entropyBlocksToCsv, entropyRangesToCsv };

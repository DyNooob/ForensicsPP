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

import type { PngDimensionRecovery } from "./dimensionRecovery";
export function dimensionRecoveryMessage(result: Pick<PngDimensionRecovery, "status" | "reason" | "candidateCount" | "candidates"> | { status: string; reason: string; candidateCount: number; candidates: Array<{ width: number; height: number; crcMatch: boolean }> }, english: boolean) {
  if (result.status === "recovered") {
    const item = result.candidates[0];
    return english ? `Recovered ${item.width} × ${item.height}: original IHDR CRC and complete scanline layout match.` : `恢复尺寸 ${item.width} × ${item.height}：原 IHDR CRC 与完整扫描行布局同时匹配。`;
  }
  if (result.status === "consistent") return english ? "Declared dimensions match CRC and scanlines; no dimension change is required." : "声明尺寸与 CRC、扫描行一致，无需修改宽高。";
  if (result.status === "ambiguous") return english ? `${result.candidateCount} possible dimension(s). Original dimensions are not confirmed; compare previews.` : `找到 ${result.candidateCount} 个尺寸候选，尚不能确认原始宽高，请比较预览后选择。`;
  return ({
    "inflate-limit": ["解压数据超过 64 MiB 上限，已停止宽高恢复；不能据此判断不存在隐藏内容。", "Inflated data exceeds 64 MiB; dimension recovery stopped."],
    "invalid-idat": ["IDAT 压缩流损坏或不完整，无法用完整扫描行验证宽高。", "IDAT zlib stream is invalid or incomplete; scanlines cannot verify dimensions."],
    "unsupported-header": ["位深、颜色或编码字段无效，当前无法可靠推导宽高。", "Unsupported or invalid IHDR encoding fields prevent reliable recovery."],
    "missing-critical": ["缺少有效 IHDR 或 IDAT，无法恢复宽高。", "A valid IHDR and IDAT are required for dimension recovery."],
    "invalid-container": ["PNG 容器结构损坏，无法完整解析。", "PNG container cannot be parsed."],
    "search-limit": ["已达到扫描行验证预算，请缩小范围后使用专用工具继续分析。", "Scanline verification budget reached."],
    "no-match": ["在宽高 1–65535、5000 万像素范围内未找到匹配；可能还有其他字段或像素数据损坏。", "No match within dimensions 1–65535 and 50 megapixels; other fields or pixels may be damaged."],
  }[result.reason] ?? ["尚未完成宽高验证。", "Dimension verification is not complete."])[english ? 1 : 0];
}

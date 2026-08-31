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

// Marketing / hype words that must not appear in SEO copy.
// These are checked by scripts/content-lint.mjs and tests/seo-contract.test.ts.
// Add an entry only when there is a real risk of it creeping back in.
export const FORBIDDEN_EN = [
  "ultimate",
  "revolutionary",
  "revolutionize",
  "best-in-class",
  "cutting-edge",
  "game-changing",
  "seamless",
  "seamlessly",
  "powerful",
  "next-generation",
  "effortlessly",
  "robust",
  "comprehensive solution",
  "all-in-one solution",
  "transform your workflow",
  "empower",
  "supercharge",
  "leverage",
  "industry-leading",
  "professional-grade",
  "unlock",
  "state-of-the-art",
  "world-class",
  "bleeding-edge",
  "painless",
  "effortless",
];

export const FORBIDDEN_ZH = [
  "赋能",
  "一站式",
  "行业领先",
  "极致",
  "全方位",
  "智能化",
  "高效便捷",
  "强大",
  "领先",
  "革新",
  "全面提升",
  "专业级",
  "革命性",
  "无缝",
  "一站式解决方案",
];

// Returns the list of forbidden words found in `text`.
// EN matches are case-insensitive whole-ish words (word boundary).
// ZH matches are substring matches (Chinese has no word boundaries).
export function findForbidden(text) {
  if (!text || typeof text !== "string") return [];
  const found = [];
  const lower = text.toLowerCase();
  for (const word of FORBIDDEN_EN) {
    const pattern = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
    if (pattern.test(lower)) found.push(word);
  }
  for (const word of FORBIDDEN_ZH) {
    if (text.includes(word)) found.push(word);
  }
  return found;
}

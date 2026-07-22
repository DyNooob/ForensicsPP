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

import { themePresets } from "../config/app";

export function normalizeHexColor(value: string) {
  const normalized = value.trim().startsWith("#") ? value.trim() : `#${value.trim()}`;
  return /^#[0-9a-fA-F]{6}$/.test(normalized) ? normalized.toUpperCase() : null;
}

export function hexToRgb(value: string) {
  const normalized = normalizeHexColor(value);
  if (!normalized) return null;
  const hex = normalized.slice(1);
  return {
    r: Number.parseInt(hex.slice(0, 2), 16),
    g: Number.parseInt(hex.slice(2, 4), 16),
    b: Number.parseInt(hex.slice(4, 6), 16)
  };
}

export function mixHexColors(base: string, target: string, amount: number) {
  const from = hexToRgb(base);
  const to = hexToRgb(target);
  if (!from || !to) return base;
  const mix = (start: number, end: number) => Math.round(start + (end - start) * amount);
  const toHex = (value: number) => value.toString(16).padStart(2, "0").toUpperCase();
  return `#${toHex(mix(from.r, to.r))}${toHex(mix(from.g, to.g))}${toHex(mix(from.b, to.b))}`;
}

export function relativeLuminance(hex: string) {
  const rgb = hexToRgb(hex);
  if (!rgb) return 0;
  const channel = (value: number) => {
    const normalized = value / 255;
    return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(rgb.r) + 0.7152 * channel(rgb.g) + 0.0722 * channel(rgb.b);
}

export function contrastRatio(first: string, second: string) {
  const lighter = Math.max(relativeLuminance(first), relativeLuminance(second));
  const darker = Math.min(relativeLuminance(first), relativeLuminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

export function themeDisplayColor(hex: string, mode: "light" | "dark") {
  const normalized = normalizeHexColor(hex) ?? themePresets[0].hex;
  if (mode === "light") return normalized;
  const darkSurface = "#1D2A38";
  if (contrastRatio(normalized, darkSurface) >= 4.5) return normalized;
  for (let amount = 0.08; amount <= 0.8; amount += 0.04) {
    const candidate = mixHexColors(normalized, "#FFFFFF", amount);
    if (contrastRatio(candidate, darkSurface) >= 4.5) return candidate;
  }
  return mixHexColors(normalized, "#FFFFFF", 0.8);
}

export function themeSoftColor(hex: string, mode: "light" | "dark") {
  const rgb = hexToRgb(hex);
  if (!rgb) {
    return mode === "dark" ? "rgba(8, 126, 164, 0.15)" : "rgba(8, 126, 164, 0.08)";
  }
  return `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${mode === "dark" ? "0.15" : "0.08"})`;
}

/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
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

const toolDefinitions = [
  { id: "home", category: "featured", name: "home", desc: "homeDesc" },
  { id: "cyberchef", category: "featured", name: "cyberchef", desc: "cyberchefDesc" },
  { id: "image", category: "analysis", name: "image", desc: "imageDesc" },
  { id: "codec", category: "transform", name: "codec", desc: "codecDesc" },
  { id: "crypto", category: "transform", name: "crypto", desc: "cryptoDesc" },
  { id: "jwt", category: "analysis", name: "jwt", desc: "jwtDesc" },
  { id: "password", category: "analysis", name: "password", desc: "passwordDesc" },
  { id: "sql", category: "analysis", name: "sql", desc: "sqlDesc" },
  { id: "sqlite", category: "analysis", name: "sqlite", desc: "sqliteDesc" },
  { id: "android", category: "analysis", name: "android", desc: "androidDesc" },
  { id: "ioc", category: "analysis", name: "ioc", desc: "iocDesc" },
  { id: "email", category: "analysis", name: "email", desc: "emailDesc" },
  { id: "urltool", category: "analysis", name: "urltool", desc: "urltoolDesc" },
  { id: "http", category: "network", name: "http", desc: "httpDesc" },
  { id: "qr", category: "analysis", name: "qr", desc: "qrDesc" },
  { id: "fileid", category: "analysis", name: "fileid", desc: "fileidDesc" },
  { id: "png", category: "analysis", name: "png", desc: "pngDesc" },
  { id: "archive", category: "analysis", name: "archive", desc: "archiveDesc" },
  { id: "binary", category: "analysis", name: "binary", desc: "binaryDesc" },
  { id: "windows", category: "analysis", name: "windows", desc: "windowsDesc" },
  { id: "strings", category: "analysis", name: "strings", desc: "stringsDesc" },
  { id: "entropy", category: "analysis", name: "entropy", desc: "entropyDesc" },
  { id: "hash", category: "transform", name: "hash", desc: "hashDesc" },
  { id: "timestamp", category: "transform", name: "timestamp", desc: "timestampDesc" },
  { id: "timeline", category: "transform", name: "timeline", desc: "timelineDesc" },
  { id: "baseconvert", category: "transform", name: "baseconvert", desc: "baseconvertDesc" },
  { id: "uuid", category: "transform", name: "uuid", desc: "uuidDesc" },
  { id: "json", category: "transform", name: "json", desc: "jsonDesc" },
  { id: "regex", category: "transform", name: "regex", desc: "regexDesc" },
  { id: "pcap", category: "network", name: "pcap", desc: "pcapDesc" },
  { id: "yara", category: "analysis", name: "yara", desc: "yaraDesc" }
] as const;

export type ToolId = (typeof toolDefinitions)[number]["id"];
export type ToolCategory = (typeof toolDefinitions)[number]["category"];
export type ToolName = (typeof toolDefinitions)[number]["name"];
export type ToolDescription = (typeof toolDefinitions)[number]["desc"];
export type ToolDefinition = {
  id: ToolId;
  category: ToolCategory;
  name: ToolName;
  desc: ToolDescription;
};

export const tools: readonly ToolDefinition[] = toolDefinitions;
export const maxRecentTools = 6;

export const toolTitleOverrides: Partial<Record<ToolId, Record<"zh" | "en", string>>> = {
  home: { zh: "Forensics++ Workbench", en: "Forensics++ Workbench" }
};

export function getToolTitle(tool: ToolDefinition, lang: "zh" | "en", translations: Record<string, string>) {
  return toolTitleOverrides[tool.id]?.[lang] ?? translations[tool.name];
}

export const projectLinks = { repo: "https://github.com/DyNooob/ForensicsPP" } as const;

export const storagePrefix = "forensicspp:";
export const appVersion = "0.5";
export const projectLicense = "MIT";
export const projectRepoName = "DyNooob/ForensicsPP";
export const lastUpdated = "2026-07-12";
export const legalVersion = "2026-07-09";
export const feedbackEmail = "toolab@digiforensics.cn";

export const themePresets: ReadonlyArray<{
  id: string;
  hex: string;
  name: { zh: string; en: string };
}> = [
  { id: "forensic", hex: "#245F73", name: { zh: "工作台青灰", en: "Workbench Teal" } },
  { id: "indigo", hex: "#4457A6", name: { zh: "案卷靛", en: "Case Indigo" } },
  { id: "signal", hex: "#1E6B4B", name: { zh: "信号绿", en: "Signal Green" } },
  { id: "amber", hex: "#8A5A00", name: { zh: "警戒金", en: "Alert Amber" } },
  { id: "rose", hex: "#8F4A51", name: { zh: "证据红", en: "Evidence Red" } }
];

export function normalizeToolHash(value: string) {
  return value.replace(/^#/, "").trim().toLowerCase();
}

export function isToolId(value: string): value is ToolId {
  return tools.some((tool) => tool.id === value);
}

export function toolIdFromHash() {
  if (typeof window === "undefined") return null;
  const value = normalizeToolHash(window.location.hash);
  return isToolId(value) ? value : null;
}

export function writeToolHash(tool: ToolId, replace = false) {
  if (typeof window === "undefined") return;
  const nextHash = `#${tool}`;
  if (window.location.hash === nextHash) return;
  if (replace) window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${nextHash}`);
  else window.location.hash = tool;
}

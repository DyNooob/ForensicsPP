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

const toolDefinitions = [
  { id: "home", category: "featured", name: "home", desc: "homeDesc" },
  { id: "cyberchef", category: "featured", name: "cyberchef", desc: "cyberchefDesc" },
  { id: "image", category: "analysis", name: "image", desc: "imageDesc", accepts: [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"], capabilities: ["image", "exif", "metadata", "steganography", "repair"] },
  { id: "codec", category: "transform", name: "codec", desc: "codecDesc" },
  { id: "crypto", category: "transform", name: "crypto", desc: "cryptoDesc" },
  { id: "jwt", category: "analysis", name: "jwt", desc: "jwtDesc" },
  { id: "password", category: "analysis", name: "password", desc: "passwordDesc" },
  { id: "sql", category: "analysis", name: "sql", desc: "sqlDesc" },
  { id: "sqlite", category: "analysis", name: "sqlite", desc: "sqliteDesc", accepts: [".sqlite", ".sqlite3", ".db", "-wal"], capabilities: ["database", "deleted-record-recovery", "wal", "timeline"] },
  { id: "registry", category: "analysis", name: "registry", desc: "registryDesc" },
  { id: "plist", category: "analysis", name: "plist", desc: "plistDesc" },
  { id: "browserartifacts", category: "analysis", name: "browserartifacts", desc: "browserartifactsDesc" },
  { id: "evtx", category: "analysis", name: "evtx", desc: "evtxDesc" },
  { id: "documentforensics", category: "analysis", name: "documentforensics", desc: "documentforensicsDesc", accepts: [".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"], capabilities: ["document", "pdf", "ooxml", "ole", "metadata", "embedded-files"] },
  { id: "android", category: "analysis", name: "android", desc: "androidDesc", accepts: [".apk", ".apks", ".xapk", ".xml", ".idsig"], capabilities: ["android", "manifest", "signing", "certificate", "archive"] },
  { id: "ioc", category: "analysis", name: "ioc", desc: "iocDesc" },
  { id: "email", category: "analysis", name: "email", desc: "emailDesc" },
  { id: "urltool", category: "analysis", name: "urltool", desc: "urltoolDesc" },
  { id: "http", category: "network", name: "http", desc: "httpDesc" },
  { id: "qr", category: "analysis", name: "qr", desc: "qrDesc" },
  { id: "fileid", category: "analysis", name: "fileid", desc: "fileidDesc" },
  { id: "png", category: "analysis", name: "png", desc: "pngDesc" },
  { id: "archive", category: "analysis", name: "archive", desc: "archiveDesc", accepts: [".zip", ".jar", ".apk", ".gz", ".tar", ".cpio"], capabilities: ["archive", "zip", "extraction", "zip-bomb-guard"] },
  { id: "binary", category: "analysis", name: "binary", desc: "binaryDesc", accepts: ["*/*"], capabilities: ["binary", "pe", "elf", "mach-o", "hex", "embedded-signature"] },
  { id: "firmware", category: "analysis", name: "firmware", desc: "firmwareDesc", accepts: [".bin", ".img", ".rom", ".fw", ".trx", ".ubi", ".ubifs", ".squashfs", "*/*"], capabilities: ["firmware", "streaming", "carving", "entropy", "recursive-extraction", "analyzer-handoff"] },
  { id: "disk", category: "analysis", name: "disk", desc: "diskDesc", accepts: [".dd", ".raw", ".img", ".iso"], capabilities: ["random-access", "mbr", "gpt", "fat", "ntfs", "ext", "iso9660"] },
  { id: "windows", category: "analysis", name: "windows", desc: "windowsDesc", accepts: [".lnk", ".pf", ".reg", ".mft", ".j"], capabilities: ["windows", "mft", "usn-journal", "prefetch", "lnk", "timeline"] },
  { id: "memory", category: "analysis", name: "memory", desc: "memoryDesc", accepts: [".dmp", ".mdmp", ".raw", ".mem"], capabilities: ["minidump", "memory-triage", "pe-carving"] },
  { id: "strings", category: "analysis", name: "strings", desc: "stringsDesc" },
  { id: "bulk", category: "analysis", name: "bulk", desc: "bulkDesc", accepts: ["*/*"], capabilities: ["streaming", "ioc", "strings", "offsets"] },
  { id: "entropy", category: "analysis", name: "entropy", desc: "entropyDesc" },
  { id: "hash", category: "transform", name: "hash", desc: "hashDesc" },
  { id: "timestamp", category: "transform", name: "timestamp", desc: "timestampDesc" },
  { id: "timeline", category: "transform", name: "timeline", desc: "timelineDesc" },
  { id: "baseconvert", category: "transform", name: "baseconvert", desc: "baseconvertDesc" },
  { id: "uuid", category: "transform", name: "uuid", desc: "uuidDesc" },
  { id: "json", category: "transform", name: "json", desc: "jsonDesc" },
  { id: "regex", category: "transform", name: "regex", desc: "regexDesc" },
  { id: "pcap", category: "network", name: "pcap", desc: "pcapDesc", accepts: [".pcap", ".pcapng"], capabilities: ["network", "tcp-reassembly", "http", "dns", "tls", "ioc", "timeline"] },
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
  accepts?: readonly string[];
  capabilities?: readonly string[];
};

export const tools: readonly ToolDefinition[] = toolDefinitions;
const toolDefinitionMap = new Map<ToolId, ToolDefinition>(tools.map((tool) => [tool.id, tool]));
export function getToolDefinitionById(toolId: ToolId) { return toolDefinitionMap.get(toolId) ?? null; }
export const maxRecentTools = 6;
export const maxMountedTools = 8;

export const toolTitleOverrides: Partial<Record<ToolId, Record<"zh" | "en", string>>> = {
  home: { zh: "Forensics++ Workbench", en: "Forensics++ Workbench" }
};

export function getToolTitle(tool: ToolDefinition, lang: "zh" | "en", translations: Record<string, string>) {
  return toolTitleOverrides[tool.id]?.[lang] ?? translations[tool.name];
}

export const projectLinks = { repo: "https://github.com/DyNooob/ForensicsPP" } as const;

export const storagePrefix = "forensicspp:";
export const appVersion = "1.0.0-beta.3";
export const projectLicense = "MIT";
export const projectRepoName = "DyNooob/ForensicsPP";
export const lastUpdated = "2026-08-16";
export const legalVersion = "2026-07-13-v2";
export const feedbackEmail = "toolab@digiforensics.cn";

export const themePresets: ReadonlyArray<{
  id: string;
  hex: string;
  name: { zh: string; en: string };
}> = [
  { id: "indigo", hex: "#4457A6", name: { zh: "案卷靛", en: "Case Indigo" } },
  { id: "forensic", hex: "#245F73", name: { zh: "工作台青灰", en: "Workbench Teal" } },
  { id: "signal", hex: "#1E6B4B", name: { zh: "信号绿", en: "Signal Green" } },
  { id: "amber", hex: "#8A5A00", name: { zh: "警戒金", en: "Alert Amber" } },
  { id: "rose", hex: "#8F4A51", name: { zh: "证据红", en: "Evidence Red" } },
  { id: "blue", hex: "#1769AA", name: { zh: "蓝色", en: "Blue" } },
  { id: "violet", hex: "#7252A3", name: { zh: "紫色", en: "Violet" } },
  { id: "magenta", hex: "#A13F6F", name: { zh: "洋红", en: "Magenta" } },
  { id: "graphite", hex: "#52606D", name: { zh: "石墨", en: "Graphite" } }
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

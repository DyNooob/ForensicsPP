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
  { id: "home", category: "system", name: "home", desc: "homeDesc", featured: true, maturity: "stable", resourcePolicy: "retain" },
  { id: "cyberchef", category: "integration", name: "cyberchef", desc: "cyberchefDesc", featured: true, maturity: "stable", resourcePolicy: "retain" },
  { id: "image", category: "analysis", name: "image", desc: "imageDesc", accepts: [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"], capabilities: ["image", "png", "crc", "qr", "exif", "metadata", "steganography", "repair"], supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "分析图片（png/jpg/gif/webp/bmp）：读取 EXIF 与元数据、检测隐写线索、校验 CRC/完整性、识别二维码。内置 yara 与 strings 能力，可发现嵌入文本与异常区段。", en: "Analyze images (png/jpg/gif/webp/bmp): read EXIF and metadata, surface steganography clues, verify CRC/integrity, and decode QR codes. Built-in yara and strings help surface embedded text and anomalous regions." } },
  { id: "codec", category: "transform", name: "codec", desc: "codecDesc", maturity: "stable" },
  { id: "crypto", category: "transform", name: "crypto", desc: "cryptoDesc", maturity: "stable" },
  { id: "jwt", category: "transform", name: "jwt", desc: "jwtDesc", maturity: "stable" },
  { id: "password", category: "transform", name: "password", desc: "passwordDesc", maturity: "stable" },
  { id: "sql", category: "transform", name: "sql", desc: "sqlDesc", maturity: "stable" },
  { id: "sqlite", category: "analysis", name: "sqlite", desc: "sqliteDesc", accepts: [".sqlite", ".sqlite3", ".db", "-wal"], capabilities: ["database", "deleted-record-recovery", "wal"], resourcePolicy: "suspendable", heavy: true, supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "打开 SQLite 数据库：列出表与结构、执行查询、恢复已删除记录（WAL/回滚残留）。适用于移动端与应用数据库取证。", en: "Open SQLite databases: list tables and schema, run queries, and recover deleted records from WAL/rollback leftovers. Useful for mobile and application-database forensics." } },
  { id: "registry", category: "analysis", name: "registry", desc: "registryDesc", accepts: [".dat", ".hiv"], supportsEvidence: true, supportsHandoff: true, maturity: "triage", emitsEnvelope: true, validation: "fixture-validated" },
  { id: "plist", category: "analysis", name: "plist", desc: "plistDesc", accepts: [".plist"], supportsEvidence: true, supportsHandoff: true, maturity: "triage", emitsEnvelope: true, validation: "fixture-validated" },
  { id: "browserartifacts", category: "analysis", name: "browserartifacts", desc: "browserartifactsDesc", supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "解析浏览器痕迹（历史/下载/Cookie/自动填充等）：提取访问记录、时间线与登录信息，并跨数据源关联，重建用户浏览行为。", en: "Parse browser artifacts (history/downloads/cookies/autofill): extract visits, timelines, and login data, then correlate across data sources to reconstruct browsing behavior." } },
  { id: "evtx", category: "analysis", name: "evtx", desc: "evtxDesc", accepts: [".evtx"], capabilities: ["windows-event-log", "timeline"], supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "解析 Windows 事件日志 (.evtx)：按频道/级别/事件 ID 聚合，提取关键字段与时间线，适用于主机入侵排查与时间线重建。", en: "Parse Windows event logs (.evtx): aggregate by channel/level/event ID, extract key fields and a timeline. Useful for host intrusion triage and timeline reconstruction." } },
  { id: "documentforensics", category: "analysis", name: "documentforensics", desc: "documentforensicsDesc", accepts: [".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"], capabilities: ["document", "pdf", "ooxml", "ole", "metadata", "embedded-files"], supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "检查文档（PDF/OOXML）：提取元数据、嵌入对象、外部链接与结构异常，适用于钓鱼与恶意文档的初步筛查。", en: "Inspect documents (PDF/OOXML): extract metadata, embedded objects, external links, and structural anomalies. Good for initial triage of phishing and malicious documents." } },
  { id: "android", category: "analysis", name: "android", desc: "androidDesc", accepts: [".apk", ".apks", ".xapk", ".xml", ".idsig"], capabilities: ["android", "manifest", "signing", "certificate", "archive"], supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "分析 Android 产物（APK/APKS/XAPK/XML）：解析 Manifest（权限、组件、包名）、签名与证书链、对齐与可疑配置，适用于 APK 安全评估。", en: "Analyze Android artifacts (APK/APKS/XAPK/XML): parse the Manifest (permissions, components, package), signing and certificate chains, alignment, and suspicious config. Useful for APK security assessment." } },
  { id: "ioc", category: "analysis", name: "ioc", desc: "iocDesc", supportsEvidence: true, supportsResult: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "结构化提取 IOC：从文本、文件或报告中抽取 IP、域名、URL、哈希、邮箱等指示器，去重并按类型分类，可直接加入报告 IOC 附录。", en: "Structured IOC extraction: pull indicators (IPs, domains, URLs, hashes, emails) from text, files, or reports, dedupe and group by type. Can be added straight to the report's IOC appendix." } },
  { id: "lookup", category: "network", name: "lookup", desc: "lookupDesc", accepts: ["IP", "mobile", "Chinese ID", "bank card"], capabilities: ["ip-geolocation", "phone-attribution", "id-validation", "bank-bin", "batch"], resourcePolicy: "retain-with-cache-eviction", supportsEvidence: false, supportsResult: true, supportsHandoff: false, emitsEnvelope: true, maturity: "triage", validation: "unit-tested", help: { zh: "IP、手机号、身份证号与银行卡号查询，支持单条和批量输入。规则校验在浏览器执行；归属地数据采用固定版本数据包并按需缓存。IP 与号段结果属于静态数据库记录。", en: "IP, mobile, Chinese-ID, and bank-card lookup with single and batch input. Rule checks run in the browser; attribution uses pinned data packs cached on demand. IP and prefix results are static database records." } },
  { id: "email", category: "analysis", name: "email", desc: "emailDesc", supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "解析邮件（EML/MSG）：信封、头字段、Received 路由链、附件哈希与正文，并抽取 IOC 与时间线。", en: "Parse email (EML/MSG): envelope, header fields, the Received routing chain, attachment hashes, and body. Extracts IOCs and a timeline." } },
  { id: "urltool", category: "transform", name: "urltool", desc: "urltoolDesc", maturity: "stable" },
  { id: "http", category: "network", name: "http", desc: "httpDesc", maturity: "stable" },
  { id: "qr", category: "analysis", name: "qr", desc: "qrDesc", hidden: true, mergedInto: "image" },
  { id: "fileid", category: "analysis", name: "fileid", desc: "fileidDesc", hidden: true, mergedInto: "binary" },
  { id: "png", category: "analysis", name: "png", desc: "pngDesc", hidden: true, mergedInto: "image" },
  { id: "gif", category: "analysis", name: "gif", desc: "gifDesc", hidden: true, mergedInto: "image" },
  { id: "jpeg", category: "analysis", name: "jpeg", desc: "jpegDesc", hidden: true, mergedInto: "image" },
  { id: "webp", category: "analysis", name: "webp", desc: "webpDesc", hidden: true, mergedInto: "image" },
  { id: "bmp", category: "analysis", name: "bmp", desc: "bmpDesc", hidden: true, mergedInto: "image" },
  { id: "tiff", category: "analysis", name: "tiff", desc: "tiffDesc", hidden: true, mergedInto: "image" },
  { id: "heif", category: "analysis", name: "heif", desc: "heifDesc", hidden: true, mergedInto: "image" },
  { id: "archive", category: "analysis", name: "archive", desc: "archiveDesc", accepts: [".zip", ".jar", ".apk", ".gz", ".tar", ".cpio"], capabilities: ["archive", "zip", "extraction", "zip-bomb-guard"], supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "解包归档（zip/jar/apk/gz/tar/cpio）：递归列出条目、检测 zip 炸弹、提取文件。可 handoff 到下游分析工具继续深入。", en: "Unpack archives (zip/jar/apk/gz/tar/cpio): list entries recursively, detect zip bombs, and extract files. Can hand off to downstream analyzers for deeper inspection." } },
  { id: "binary", category: "analysis", name: "binary", desc: "binaryDesc", accepts: ["*/*"], capabilities: ["binary", "file-identification", "pe", "elf", "mach-o", "hex", "strings", "ioc", "entropy", "yara", "embedded-signature"], supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "加载任意二进制文件：自动识别真实类型（magic/签名）并与扩展名比对，给出熵、字符串与结构概览。内置 yara/strings/entropy/pe/elf/mach-o 等能力，适用于未知样本初步分类。", en: "Load any binary: auto-identify the real type (magic/signature) and compare it against the extension, then summarize entropy, strings, and structure. Built-in yara/strings/entropy/pe/elf/mach-o help with first-pass triage of unknown samples." } },
  { id: "firmware", category: "analysis", name: "firmware", desc: "firmwareDesc", accepts: [".bin", ".img", ".rom", ".fw", ".trx", ".ubi", ".ubifs", ".squashfs", "*/*"], capabilities: ["firmware", "streaming", "carving", "entropy", "recursive-extraction", "analyzer-handoff"], resourcePolicy: "dispose-on-switch", heavy: true, supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "triage", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "分析固件镜像：识别文件系统（squashfs/ubi/ubifs、ext、FAT、NTFS、exFAT、ISO9660）、入口与架构线索，用熵分布发现压缩/加密区段。支持 carving 与递归解包，可 handoff 到 archive/binary 继续深入。", en: "Analyze firmware images: identify filesystems (squashfs/ubi/ubifs, ext, FAT, NTFS, exFAT, ISO9660), entry points and architecture hints, and use entropy to spot compressed/encrypted regions. Supports carving and recursive extraction, with handoff to archive/binary." } },
  { id: "disk", category: "analysis", name: "disk", desc: "diskDesc", accepts: [".dd", ".raw", ".img", ".iso"], capabilities: ["random-access", "mbr", "gpt", "fat", "ntfs", "ext", "iso9660"], resourcePolicy: "dispose-on-switch", heavy: true, supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "triage", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "加载磁盘镜像（.dd/.raw/.img/.iso）：随机访问分区（MBR/GPT），识别 FAT/NTFS/ext/ISO9660，浏览与提取文件。重型工具，切换时自动释放资源。", en: "Load disk images (.dd/.raw/.img/.iso): random-access partitions (MBR/GPT), identify FAT/NTFS/ext/ISO9660, and browse or extract files. Heavy — resources are released when you switch tools." } },
  { id: "windows", category: "analysis", name: "windows", desc: "windowsDesc", accepts: [".lnk", ".pf", ".reg", ".mft", ".j"], capabilities: ["windows", "mft", "usn-journal", "prefetch", "lnk", "timeline"], supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "triage", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "解析 Windows 工件（LNK/Prefetch/Registry/MFT/USN）：提取执行痕迹、时间线与注册表键，重建用户行为与主机时间线。", en: "Parse Windows artifacts (LNK/Prefetch/Registry/MFT/USN): extract execution traces, timelines, and registry keys to reconstruct user behavior and a host timeline." } },
  { id: "memory", category: "analysis", name: "memory", desc: "memoryDesc", accepts: [".dmp", ".mdmp", ".raw", ".mem"], capabilities: ["minidump", "memory-triage", "pe-carving"], resourcePolicy: "dispose-on-switch", heavy: true, supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "triage", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "分析内存转储（.dmp/.raw）：minidump 与内存分类索引、PE 进程/模块 carving，适用于内存取证与恶意代码痕迹发现。", en: "Analyze memory dumps (.dmp/.raw): minidump and memory triage indexing, PE process/module carving. Useful for memory forensics and uncovering malware traces." } },
  { id: "strings", category: "analysis", name: "strings", desc: "stringsDesc", hidden: true, mergedInto: "binary" },
  { id: "bulk", category: "analysis", name: "bulk", desc: "bulkDesc", accepts: ["*/*"], capabilities: ["streaming", "ioc", "strings", "offsets"], resourcePolicy: "dispose-on-switch", heavy: true, supportsEvidence: true, supportsResult: false, supportsHandoff: true, emitsEnvelope: true, maturity: "triage", validation: "fixture-validated" },
  { id: "entropy", category: "analysis", name: "entropy", desc: "entropyDesc", hidden: true, mergedInto: "binary" },
  { id: "hash", category: "transform", name: "hash", desc: "hashDesc", maturity: "stable" },
  { id: "timestamp", category: "transform", name: "timestamp", desc: "timestampDesc", maturity: "stable" },
  { id: "timeline", category: "transform", name: "timeline", desc: "timelineDesc", maturity: "stable" },
  { id: "baseconvert", category: "transform", name: "baseconvert", desc: "baseconvertDesc", maturity: "stable" },
  { id: "uuid", category: "transform", name: "uuid", desc: "uuidDesc", maturity: "stable" },
  { id: "json", category: "transform", name: "json", desc: "jsonDesc", maturity: "stable" },
  { id: "regex", category: "transform", name: "regex", desc: "regexDesc", maturity: "stable" },
  { id: "pcap", category: "network", name: "pcap", desc: "pcapDesc", accepts: [".pcap", ".pcapng"], capabilities: ["network", "tcp-reassembly", "http", "dns", "tls", "ioc", "timeline"], resourcePolicy: "suspendable", heavy: true, supportsEvidence: true, supportsResult: true, supportsHandoff: true, maturity: "stable", validation: "fixture-validated", emitsEnvelope: true, help: { zh: "解析 pcap/pcapng 网络捕获：TCP 重组、HTTP/DNS/TLS 会话提取与会话时间线。重型流式分析，可标注 IOC，适用于流量取证与异常会话发现。", en: "Parse pcap/pcapng captures: TCP reassembly, HTTP/DNS/TLS session extraction, and a session timeline. Heavy streaming analysis that can flag IOCs — useful for network forensics and spotting anomalous sessions." } },
  { id: "yara", category: "analysis", name: "yara", desc: "yaraDesc", hidden: true, mergedInto: "binary" }
] as const;

export type ToolId = (typeof toolDefinitions)[number]["id"];
export type ToolCategory = (typeof toolDefinitions)[number]["category"];
export type ToolName = (typeof toolDefinitions)[number]["name"];
export type ToolDescription = (typeof toolDefinitions)[number]["desc"];
export type ResourcePolicy =
  | "retain"
  | "retain-with-cache-eviction"
  | "suspendable"
  | "dispose-on-switch";

export type ToolDefinition = {
  id: ToolId;
  /** Semantic domain. Orthogonal to `featured` — it is NOT a product tier.
   *  - analysis:    forensic analyzers (canonical workbench + legacy triage)
   *  - transform:   encoding / transform / utility tools
   *  - network:     network tools (pcap analyzer, http utility)
   *  - system:      launcher / navigation (home) — NOT a forensic analyzer
   *  - integration: external / embedded suites (cyberchef) — NOT a forensic analyzer
   * Replaces the old `tier: workbench|utility|featured` model where `featured`
   * was wrongly used as both a category and a semantic level (beta.6 correction). */
  category: ToolCategory;
  name: ToolName;
  desc: ToolDescription;
  accepts?: readonly string[];
  capabilities?: readonly string[];
  hidden?: boolean;
  mergedInto?: ToolId;
  resourcePolicy?: ResourcePolicy;
  heavy?: boolean;
  supportsEvidence?: boolean;
  supportsResult?: boolean;
  supportsHandoff?: boolean;
  supportsPersistence?: boolean;
  /** Per-tool usage/help text shown via the "?" button in the topbar. */
  help?: { zh: string; en: string };
  /** Display prominence. ORTHOGONAL to `category`: a tool may be featured
   *  regardless of its domain, and featured does NOT imply forensic-analyzer
   *  status. Only home and cyberchef are featured launchers/suites. */
  featured?: boolean;
  /** Product capability maturity — how finished / battle-tested the tool is.
   *  Orthogonal to `validation` (which measures evidence strength, not shipping
   *  state). `validated` was removed: it conflated maturity with validation. */
  maturity?: "stable" | "triage" | "experimental";
  /** Validation strength — how much forensic evidence backs the tool's claims.
   *  - unvalidated:        no test evidence
   *  - unit-tested:        logic covered by unit tests
   *  - fixture-validated:  known fixture -> real parser -> deterministic expected output
   *  - cross-validated:    fixture-validated PLUS comparison against a reference
   *                        implementation (EVTX<->libevtx/EvtxECmd, APK<->apksigner,
   *                        PCAP<->tshark, SQLite<->sqlite3, Firmware<->binwalk).
   *                        No reference-implementation comparison => cannot claim this. */
  validation?: "unvalidated" | "unit-tested" | "fixture-validated" | "cross-validated";
  /** True when the analyzer publishes a canonical AnalysisEnvelope. This is the
   *  single source of truth for the envelope-migration matrix (X of Y). It is
   *  set only for tools that actually call `publishAnalysisResult` with a
   *  structured envelope — NOT derived from `supportsResult`. */
  emitsEnvelope?: boolean;
};

export const tools: readonly ToolDefinition[] = toolDefinitions;
export const visibleTools: readonly ToolDefinition[] = tools.filter((tool) => !tool.hidden);
const toolDefinitionMap = new Map<ToolId, ToolDefinition>(tools.map((tool) => [tool.id, tool]));
export function getToolDefinitionById(toolId: ToolId) { return toolDefinitionMap.get(toolId) ?? null; }
export const maxRecentTools = 6;
export const maxMountedTools = 8;

/** Canonical forensic analyzers: visible tools in the analysis/network domain that
 *  expose an analyzer surface (evidence, result, heavy processing, capabilities, or
 *  accepted file types). Excludes hidden aliases, the system launcher (home), and
 *  external integration suites (cyberchef). This is the denominator (Y) for the
 *  envelope-migration metric; `emitsEnvelope === true` is the numerator (X). */
export function canonicalForensicAnalyzers(list: readonly ToolDefinition[] = tools): ToolDefinition[] {
  return list.filter((tool) =>
    !tool.hidden &&
    (tool.category === "analysis" || tool.category === "network") &&
    Boolean(
      tool.supportsEvidence ||
      tool.supportsResult ||
      tool.heavy ||
      (tool.capabilities && tool.capabilities.length > 0) ||
      (tool.accepts && tool.accepts.length > 0)
    )
  );
}

export const toolTitleOverrides: Partial<Record<ToolId, Record<"zh" | "en", string>>> = {
  home: { zh: "Forensics++ Workbench", en: "Forensics++ Workbench" }
};

export function getToolTitle(tool: ToolDefinition, lang: "zh" | "en", translations: Record<string, string>) {
  return toolTitleOverrides[tool.id]?.[lang] ?? translations[tool.name];
}

export const projectLinks = { repo: "https://github.com/DyNooob/ForensicsPP" } as const;

export const storagePrefix = "forensicspp:";
export const appVersion = "1.0.0-beta.7";
/** Date this version was published (YYYY-MM-DD). Bump together with `appVersion` on each release. */
export const appReleaseDate = "2026-09-26";
/** Where users download new releases. */
export const releaseDownloadUrl = `${projectLinks.repo}/releases`;
export const projectLicense = "MIT";
export const projectRepoName = "DyNooob/ForensicsPP";
export const lastUpdated = "2026-09-26";
export const legalVersion = "2026-07-13-v2";
export const feedbackEmail = "toolab@digiforensics.cn";

/**
 * Build identity injected at build time (see vite.config.ts). Lets the Preview
 * notice show exactly which commit/branch is running. Falls back when the
 * `VITE_BUILD_*` define is absent (dev server, or a build that skipped git).
 */
const buildEnv = import.meta.env as { VITE_BUILD_HASH?: string; VITE_BUILD_BRANCH?: string };
export const buildHash = buildEnv.VITE_BUILD_HASH || "dev";
export const buildBranch = buildEnv.VITE_BUILD_BRANCH || "dev";

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

export function canonicalToolId(tool: ToolId): ToolId {
  const definition = toolDefinitionMap.get(tool);
  return definition?.mergedInto ?? tool;
}

export function visibleToolById(tool: ToolId) {
  return toolDefinitionMap.get(canonicalToolId(tool)) ?? null;
}

export function toolIdFromHash(hash = typeof window === "undefined" ? "" : window.location.hash) {
  const value = normalizeToolHash(hash);
  return isToolId(value) ? canonicalToolId(value) : null;
}

export function writeToolHash(tool: ToolId, replace = false) {
  tool = canonicalToolId(tool);
  if (typeof window === "undefined") return;
  const nextHash = `#${tool}`;
  if (window.location.hash === nextHash) return;
  if (replace) window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${nextHash}`);
  else window.location.hash = tool;
}

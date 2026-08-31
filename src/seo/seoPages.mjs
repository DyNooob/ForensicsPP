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

// Static Search Discovery Layer — page registry.
//
// This is the single source of truth for the English / Chinese tool landing
// pages. Copy is hand-written from the real ToolDefinitions in src/config/app.ts
// (capabilities, maturity, validation) and the actual analyzers. It must NOT
// overstate capability (see B6-SEO spec §13). The `toolId` field ties each page
// back to a real tool so the contract test fails if a tool is renamed.
//
// Generator: scripts/build-seo-pages.mjs
// Contract test: tests/seo-contract.test.ts

export const SITE = {
  base: "https://www.forensicspp.com",
  name: "Forensics++",
  brand: "ForensicsPP",
  tagline: "Local-first digital forensics workbench",
};

// Maps an SEO page slug to the tool id it documents, so related-tools links
// resolve to the right landing page (or fall back to the in-app tool route).
export const SLUG_TO_TOOL = {
  "evtx-viewer": "evtx",
  "sqlite-forensics": "sqlite",
  "sqlite-wal-recovery": "sqlite",
  "apk-signature-analyzer": "android",
  "pcap-analyzer": "pcap",
  "registry-forensics": "registry",
  "firmware-analyzer": "firmware",
  "binary-file-analyzer": "binary",
  "windows-artifacts": "windows",
  "image-forensics": "image",
};

export const seoPages = [
  // ───────────────────────────── EVTX ─────────────────────────────
  {
    slug: "evtx-viewer",
    toolId: "evtx",
    locale: "en",
    title: "EVTX Viewer and Windows Event Log Analyzer | Forensics++",
    description:
      "Open and inspect Windows EVTX files in your browser. Parse event records locally and export results without uploading the evidence.",
    h1: "EVTX Viewer and Windows Event Log Analyzer",
    intro:
      "Forensics++ reads Windows event logs (.evtx) directly in the browser. Records are parsed locally; the evidence file is not uploaded to any server.",
    what: "Windows event log (.evtx) files: event records, channels, levels, event IDs, timestamps, and provider names.",
    extracts: [
      "Event records grouped by channel and level",
      "Event IDs with provider and keyword fields",
      "Timestamps normalized into a timeline",
      "Filterable and searchable record views",
      "Export of selected records",
    ],
    input: [".evtx files", "Windows event log exports from triage tools"],
    useCases: [
      "Host intrusion triage",
      "Timeline reconstruction from event IDs",
      "Spotting repeated failures, service changes, or account events",
    ],
    limitations: [
      "Focused on record parsing and triage, not a replacement for full Windows log tooling",
      "Some event-specific rendering (e.g. XML message templates) may be partial",
      "Very large logs may need filtering before full export",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["Windows event logs", "Security event IDs (e.g. 4624, 4688)"],
    relatedTools: ["registry", "windows", "timeline"],
    ctaLabel: "Open EVTX Workbench",
  },
  {
    slug: "evtx-viewer",
    toolId: "evtx",
    locale: "zh-CN",
    title: "EVTX 查看器与 Windows 事件日志分析 | Forensics++",
    description:
      "在浏览器中打开并检查 Windows EVTX 文件。在本地解析事件记录，导出结果而不上传检材。",
    h1: "EVTX 查看器与 Windows 事件日志分析",
    intro:
      "Forensics++ 直接在浏览器中读取 Windows 事件日志（.evtx）。记录在本地方析，检材文件不会上传到任何服务器。",
    what: "Windows 事件日志（.evtx）文件：事件记录、频道、级别、事件 ID、时间戳与提供程序名称。",
    extracts: [
      "按频道与级别分组的事件记录",
      "含提供程序与关键字字段的事件 ID",
      "归一化到时间线的时间戳",
      "可筛选与搜索的记录视图",
      "选定记录的导出",
    ],
    input: [".evtx 文件", "取证分诊工具导出的 Windows 事件日志"],
    useCases: ["主机入侵分诊", "基于事件 ID 的时间线重建", "发现反复失败、服务变更或账户相关事件"],
    limitations: [
      "侧重记录解析与分诊，不替代完整的 Windows 日志工具链",
      "部分事件专属渲染（如 XML 消息模板）可能不完整",
      "超大日志可能需要先筛选再完整导出",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["Windows 事件日志", "安全事件 ID（如 4624、4688）"],
    relatedTools: ["registry", "windows", "timeline"],
    ctaLabel: "打开 EVTX 工作台",
  },

  // ──────────────────────────── SQLite ───────────────────────────
  {
    slug: "sqlite-forensics",
    toolId: "sqlite",
    locale: "en",
    title: "SQLite Forensics and WAL Analyzer | Forensics++",
    description:
      "Inspect SQLite databases in your browser. Review tables, WAL history, freelist pages, and recoverable fragments without uploading the file.",
    h1: "SQLite Forensics and WAL Analyzer",
    intro:
      "Forensics++ opens SQLite databases (.sqlite, .db) and their companion -wal files directly in the browser. Parsing is local; the file is not uploaded.",
    what: "SQLite database files and WAL (-wal) companions: schema, tables, row data, freelist pages, and WAL frames.",
    extracts: [
      "Table and schema listing with column types",
      "Queryable row data",
      "Freelist pages and unallocated regions",
      "WAL frames showing historical row versions",
      "A timeline built from recovered timestamps",
    ],
    input: [".sqlite, .sqlite3, .db files", "Companion -wal files"],
    useCases: [
      "Mobile and application-database forensics",
      "Investigating deleted or changed rows",
      "Reconstructing state from WAL history",
    ],
    limitations: [
      "Deleted-record recovery is heuristic fragment recovery — residual deleted data, not guaranteed full structural records",
      "Corrupted pages may yield partial or no output",
      "Very large databases are processed within browser memory limits",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["SQLite databases", "WAL files", "Freelist pages"],
    relatedTools: ["browserartifacts", "android", "sqlite-wal-recovery"],
    ctaLabel: "Open SQLite Forensics",
  },
  {
    slug: "sqlite-forensics",
    toolId: "sqlite",
    locale: "zh-CN",
    title: "SQLite 取证与 WAL 分析 | Forensics++",
    description:
      "在浏览器中检查 SQLite 数据库。查看表、WAL 历史、空闲列表页与可恢复片段，而不上传文件。",
    h1: "SQLite 取证与 WAL 分析",
    intro:
      "Forensics++ 直接在浏览器中打开 SQLite 数据库（.sqlite、.db）及其配套 -wal 文件。解析在本地进行，文件不会被上传。",
    what: "SQLite 数据库文件及 WAL（-wal）配套文件：结构、表、行数据、空闲列表页与 WAL 帧。",
    extracts: [
      "带列类型的表与结构清单",
      "可查询的行数据",
      "空闲列表页与未分配区域",
      "反映历史行版本的 WAL 帧",
      "基于恢复出的时间戳构建的时间线",
    ],
    input: [".sqlite、.sqlite3、.db 文件", "配套的 -wal 文件"],
    useCases: ["移动端与应用数据库取证", "调查被删除或被修改的行", "依据 WAL 历史重建状态"],
    limitations: [
      "删除记录恢复属于启发式片段恢复——是残留的已删除数据，不保证完整的结构化记录",
      "损坏的页可能只产生部分或没有输出",
      "超大数据库在浏览器内存限制内处理",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["SQLite 数据库", "WAL 文件", "空闲列表页"],
    relatedTools: ["browserartifacts", "android", "sqlite-wal-recovery"],
    ctaLabel: "打开 SQLite 取证",
  },

  // ───────────────────────── SQLite WAL (sub-page) ─────────────────────────
  {
    slug: "sqlite-wal-recovery",
    toolId: "sqlite",
    locale: "en",
    title: "SQLite WAL Recovery and Analysis | Forensics++",
    description:
      "Understand SQLite WAL files: frames, historical row versions, and companion files. Analyzed inside the SQLite Workbench, locally.",
    h1: "SQLite WAL Recovery and Analysis",
    intro:
      "A Write-Ahead Log (-wal) records recent changes before they are merged into the main database. Forensics++ reads WAL frames in the SQLite Workbench, entirely in the browser.",
    what: "SQLite -wal files: WAL frames, checksums, page numbers, and committed vs. uncommitted frames.",
    extracts: [
      "WAL frames with page numbers and checksums",
      "Historical row versions not yet merged into the database",
      "Companion files (-wal, -shm) context",
      "Recoverable fragments that may contain residual deleted data",
    ],
    input: ["Companion -wal files", "The matching main .sqlite/.db file"],
    useCases: [
      "Recovering activity that was never committed",
      "Reconstructing recent changes before database compaction",
      "Correlating WAL history with application behavior",
    ],
    limitations: [
      "WAL analysis is performed inside the SQLite Workbench, not as a separate tool",
      "Recovery is heuristic fragment recovery, not guaranteed full records",
      "A missing or mismatched main database limits frame interpretation",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["WAL files", "SQLite databases", "Freelist pages"],
    relatedTools: ["sqlite-forensics", "binary"],
    ctaLabel: "Open SQLite Workbench",
  },
  {
    slug: "sqlite-wal-recovery",
    toolId: "sqlite",
    locale: "zh-CN",
    title: "SQLite WAL 恢复与分析 | Forensics++",
    description:
      "理解 SQLite WAL 文件：帧、历史行版本与配套文件。在 SQLite 工作台内本地分析。",
    h1: "SQLite WAL 恢复与分析",
    intro:
      "预写日志（-wal）会在变更合并进主数据库之前记录最近的改动。Forensics++ 在 SQLite 工作台内读取 WAL 帧，全程在浏览器中完成。",
    what: "SQLite -wal 文件：WAL 帧、校验和、页号，以及已提交与未提交帧。",
    extracts: [
      "带页号与校验和的 WAL 帧",
      "尚未合并进数据库的历史行版本",
      "配套文件（-wal、-shm）上下文",
      "可能包含残留已删除数据的可恢复片段",
    ],
    input: ["配套的 -wal 文件", "对应的主 .sqlite/.db 文件"],
    useCases: ["恢复从未提交的活动", "在数据库压缩前重建近期改动", "将 WAL 历史与应用行为关联"],
    limitations: [
      "WAL 分析在 SQLite 工作台内进行，不是独立工具",
      "恢复属于启发式片段恢复，不保证完整记录",
      "缺失或不匹配的主数据库会限制帧的解读",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["WAL 文件", "SQLite 数据库", "空闲列表页"],
    relatedTools: ["sqlite-forensics", "binary"],
    ctaLabel: "打开 SQLite 工作台",
  },

  // ───────────────────────────── APK ─────────────────────────────
  {
    slug: "apk-signature-analyzer",
    toolId: "android",
    locale: "en",
    title: "APK Signature Analyzer | Forensics++",
    description:
      "Analyze Android APK signing in your browser. Verify v1–v3.1 schemes, inspect certificate chains, and check signature consistency locally.",
    h1: "APK Signature Analyzer",
    intro:
      "Forensics++ analyzes Android packages (.apk, .apks, .xapk) and their signing directly in the browser. Nothing is uploaded.",
    what: "Android artifacts: Manifest (permissions, components, package), signing blocks, certificate chains, alignment, and suspicious configuration.",
    extracts: [
      "Manifest: package name, permissions, activities, services, receivers",
      "Signing scheme verification for v1 (JAR), v2, v3, and v3.1",
      "Per-signer certificate chains with SHA-256 fingerprints",
      "Signature / public-key / certificate consistency checks",
      "Alignment and configuration flags worth reviewing",
    ],
    input: [".apk, .apks, .xapk files", ".xml manifests", ".idsig files (accepted as input)"],
    useCases: [
      "APK security assessment",
      "Confirming signer identity and certificate chain",
      "Detecting mismatched or inconsistent signatures",
    ],
    limitations: [
      "Signature verification covers v1–v3.1; v4 (apksigner with .idsig) is accepted as input but not separately verified",
      "This is static analysis, not dynamic runtime behavior",
      "Obfuscated or packed apps may hide detail until unpacked",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["APK files", "Android manifests", "Signing certificates"],
    relatedTools: ["archive", "binary"],
    ctaLabel: "Analyze an APK",
  },
  {
    slug: "apk-signature-analyzer",
    toolId: "android",
    locale: "zh-CN",
    title: "APK 签名分析器 | Forensics++",
    description:
      "在浏览器中分析 Android APK 签名。校验 v1–v3.1 方案，检查证书链，并在本地核验签名一致性。",
    h1: "APK 签名分析器",
    intro:
      "Forensics++ 直接在浏览器中分析 Android 包（.apk、.apks、.xapk）及其签名。不会上传任何内容。",
    what: "Android 产物：Manifest（权限、组件、包名）、签名块、证书链、对齐信息与可疑配置。",
    extracts: [
      "Manifest：包名、权限、Activity、Service、Receiver",
      "v1（JAR）、v2、v3、v3.1 签名方案校验",
      "每个签名者的证书链及 SHA-256 指纹",
      "签名 / 公钥 / 证书一致性检查",
      "值得复核的对齐与配置标志",
    ],
    input: [".apk、.apks、.xapk 文件", ".xml Manifest", ".idsig 文件（作为输入接受）"],
    useCases: ["APK 安全评估", "确认签名者身份与证书链", "发现不匹配或不一致的签名"],
    limitations: [
      "签名校验覆盖 v1–v3.1；v4（配合 .idsig 的 apksigner）仅作为输入接受，不做单独校验",
      "这是静态分析，不反映运行时动态行为",
      "混淆或加壳应用需先解包才能看到细节",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["APK 文件", "Android Manifest", "签名证书"],
    relatedTools: ["archive", "binary"],
    ctaLabel: "分析 APK",
  },

  // ───────────────────────────── PCAP ─────────────────────────────
  {
    slug: "pcap-analyzer",
    toolId: "pcap",
    locale: "en",
    title: "PCAP Analyzer and Network Capture Forensics | Forensics++",
    description:
      "Parse pcap and pcapng captures in your browser. Reassemble TCP, extract HTTP/DNS/TLS sessions, and flag IOCs locally.",
    h1: "PCAP Analyzer and Network Capture Forensics",
    intro:
      "Forensics++ parses network captures (.pcap, .pcapng) directly in the browser. Sessions are rebuilt locally; the capture is not uploaded.",
    what: "Network captures: TCP sessions, HTTP, DNS, and TLS metadata, with a session timeline.",
    extracts: [
      "TCP reassembly into sessions",
      "HTTP requests, responses, and hostnames",
      "DNS queries and resolved names",
      "TLS metadata: SNI, ALPN, supported cipher suites, JA3 fingerprints, certificate SHA-256",
      "IOC tagging on suspicious endpoints",
    ],
    input: [".pcap, .pcapng files"],
    useCases: [
      "Network forensics and traffic triage",
      "Spotting anomalous or unexpected sessions",
      "Extracting hosts and indicators for follow-up",
    ],
    limitations: [
      "TLS inspection is metadata-only — payloads are not decrypted",
      "Very large captures are processed as a streaming, memory-bounded pass",
      "Some tunnelled or non-standard protocols may not be fully parsed",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["PCAP / PCAPNG captures", "TLS certificates", "DNS logs"],
    relatedTools: ["ioc", "binary"],
    ctaLabel: "Open PCAP Analyzer",
  },
  {
    slug: "pcap-analyzer",
    toolId: "pcap",
    locale: "zh-CN",
    title: "PCAP 分析与网络流量取证 | Forensics++",
    description:
      "在浏览器中解析 pcap 与 pcapng 捕获文件。重组 TCP，提取 HTTP/DNS/TLS 会话，并在本地标注 IOC。",
    h1: "PCAP 分析与网络流量取证",
    intro:
      "Forensics++ 直接在浏览器中解析网络捕获文件（.pcap、.pcapng）。会话在本地方建，捕获文件不会被上传。",
    what: "网络捕获文件：TCP 会话、HTTP、DNS 与 TLS 元数据，以及会话时间线。",
    extracts: [
      "重组为会话的 TCP 流",
      "HTTP 请求、响应与主机名",
      "DNS 查询与解析出的名称",
      "TLS 元数据：SNI、ALPN、支持的加密套件、JA3 指纹、证书 SHA-256",
      "对可疑端点的 IOC 标注",
    ],
    input: [".pcap、.pcapng 文件"],
    useCases: ["网络取证与流量分诊", "发现异常或意料之外的会话", "提取主机与指标用于后续跟进"],
    limitations: [
      "TLS 检查仅含元数据——不对载荷解密",
      "超大捕获以流式、受内存约束的方式处理",
      "部分隧道化或非标准协议可能无法完整解析",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["PCAP / PCAPNG 捕获", "TLS 证书", "DNS 日志"],
    relatedTools: ["ioc", "binary"],
    ctaLabel: "打开 PCAP 分析器",
  },

  // ──────────────────────────── Registry ───────────────────────────
  {
    slug: "registry-forensics",
    toolId: "registry",
    locale: "en",
    title: "Registry Forensics — Hive Analysis | Forensics++",
    description:
      "Inspect Windows registry hives in your browser. Parse regf/hbin structure, decode last-write times, and flag integrity issues locally.",
    h1: "Registry Forensics — Hive Analysis",
    intro:
      "Forensics++ parses Windows registry hives (.reg, .dat) directly in the browser. Structure is decoded locally; the file is not uploaded.",
    what: "Registry hive files: keys, values, types, and last-write FILETIME timestamps.",
    extracts: [
      "Registry structure (regf/hbin) parsing",
      "Keys with their value names, types, and data",
      "Last-write FILETIME decoded to ISO timestamps",
      "Integrity flags (sequence mismatch, checksum issues)",
    ],
    input: [".reg, .dat registry hive files"],
    useCases: [
      "Triage of registry-based persistence and configuration",
      "Decoding last-write times for timeline work",
      "Quick structural checks before deeper analysis",
    ],
    limitations: [
      "This is triage-level inspection, not a full registry forensic suite",
      "Transaction log replay is not performed",
      "Decoding is structural; value semantics are not interpreted for you",
    ],
    maturity: "Triage",
    validation: "Fixture-validated",
    relatedArtifacts: ["Registry hives", "Registry keys", "Last-write timestamps"],
    relatedTools: ["evtx", "windows"],
    ctaLabel: "Open Registry Workbench",
  },
  {
    slug: "registry-forensics",
    toolId: "registry",
    locale: "zh-CN",
    title: "注册表取证 — 配置单元分析 | Forensics++",
    description:
      "在浏览器中检查 Windows 注册表配置单元。解析 regf/hbin 结构，解码最后写入时间，并在本地标记完整性问题。",
    h1: "注册表取证 — 配置单元分析",
    intro:
      "Forensics++ 直接在浏览器中解析 Windows 注册表配置单元（.reg、.dat）。结构在本地方码，文件不会被上传。",
    what: "注册表配置单元文件：键、值、类型与最后写入的 FILETIME 时间戳。",
    extracts: [
      "注册表结构（regf/hbin）解析",
      "带值名称、类型与数据的键",
      "最后写入 FILETIME 解码为 ISO 时间戳",
      "完整性标记（序列不匹配、校验和问题）",
    ],
    input: [".reg、.dat 注册表配置单元文件"],
    useCases: ["基于注册表的持久化与配置分诊", "为时间线工作解码最后写入时间", "深入前快速做结构检查"],
    limitations: [
      "这是分诊级检查，不是完整的注册表取证套件",
      "不执行事务日志重放",
      "解码是结构性的，不会替你解释值的语义",
    ],
    maturity: "分诊",
    validation: "Fixture 校验",
    relatedArtifacts: ["注册表配置单元", "注册表键", "最后写入时间戳"],
    relatedTools: ["evtx", "windows"],
    ctaLabel: "打开注册表工作台",
  },

  // ──────────────────────────── Firmware ───────────────────────────
  {
    slug: "firmware-analyzer",
    toolId: "firmware",
    locale: "en",
    title: "Firmware Analyzer and File Carver | Forensics++",
    description:
      "Analyze firmware images in your browser. Identify filesystems, spot compressed regions by entropy, and carve embedded objects locally.",
    h1: "Firmware Analyzer and File Carver",
    intro:
      "Forensics++ analyzes firmware images (.bin, .img, .rom, .fw, squashfs, and more) directly in the browser. Extraction is local; the file is not uploaded.",
    what: "Firmware images: filesystems, entry points, architecture hints, and embedded objects found by carving.",
    extracts: [
      "Filesystem identification (squashfs, ubi, cramfs, and similar)",
      "Entry-point and architecture hints",
      "Entropy mapping to locate compressed or encrypted regions",
      "Carved embedded objects with handoff to archive/binary",
    ],
    input: [".bin, .img, .rom, .fw, .trx, .ubi, .ubifs, .squashfs files", "Raw firmware images"],
    useCases: [
      "IoT and embedded device triage",
      "Locating compressed or encrypted regions",
      "Recovering embedded files for deeper inspection",
    ],
    limitations: [
      "This is triage-level analysis",
      "Large images may be processed partially due to browser resource limits",
      "Deep unpacking relies on handoff to the archive and binary tools",
    ],
    maturity: "Triage",
    validation: "Fixture-validated",
    relatedArtifacts: ["Firmware images", "Embedded filesystems", "Carved objects"],
    relatedTools: ["binary", "archive", "disk"],
    ctaLabel: "Open Firmware Analyzer",
  },
  {
    slug: "firmware-analyzer",
    toolId: "firmware",
    locale: "zh-CN",
    title: "固件分析与文件雕刻 | Forensics++",
    description:
      "在浏览器中分析固件镜像。识别文件系统，用熵定位压缩区域，并在本地雕刻出嵌入对象。",
    h1: "固件分析与文件雕刻",
    intro:
      "Forensics++ 直接在浏览器中分析固件镜像（.bin、.img、.rom、.fw、squashfs 等）。提取在本地进行，文件不会被上传。",
    what: "固件镜像：文件系统、入口点、架构线索，以及通过雕刻发现的嵌入对象。",
    extracts: [
      "文件系统识别（squashfs、ubi、cramfs 等）",
      "入口点与架构线索",
      "熵映射以定位压缩或加密区域",
      "雕刻出的嵌入对象，可 handoff 到 archive/binary",
    ],
    input: [".bin、.img、.rom、.fw、.trx、.ubi、.ubifs、.squashfs 文件", "原始固件镜像"],
    useCases: ["IoT 与嵌入式设备分诊", "定位压缩或加密区域", "恢复嵌入文件以深入检查"],
    limitations: [
      "这是分诊级分析",
      "受浏览器资源限制，超大镜像可能只被部分处理",
      "深度解包依赖 handoff 到 archive 与 binary 工具",
    ],
    maturity: "分诊",
    validation: "Fixture 校验",
    relatedArtifacts: ["固件镜像", "嵌入文件系统", "雕刻对象"],
    relatedTools: ["binary", "archive", "disk"],
    ctaLabel: "打开固件分析器",
  },

  // ──────────────────────────── Binary ───────────────────────────
  {
    slug: "binary-file-analyzer",
    toolId: "binary",
    locale: "en",
    title: "Binary File Analyzer — Identify Unknown Files | Forensics++",
    description:
      "Load any binary in your browser. Identify the real type from magic bytes, compare against the extension, and summarize structure locally.",
    h1: "Binary File Analyzer — Identify Unknown Files",
    intro:
      "Forensics++ loads arbitrary binary files and identifies what they actually are, entirely in the browser. Nothing is uploaded.",
    what: "Any binary: real type from magic/signature, structure overview, entropy, strings, and embedded signatures.",
    extracts: [
      "Real file type from magic bytes and signatures, compared to the extension",
      "Entropy and structure summary",
      "Strings and embedded text",
      "PE / ELF / Mach-O parsing where applicable",
      "Embedded signatures and YARA match hints",
    ],
    input: ["Any file (*/*)"],
    useCases: [
      "First-pass triage of unknown samples",
      "Confirming or disputing a file's extension",
      "Locating embedded or overlapping content",
    ],
    limitations: [
      "Identification is signature-based and may be inconclusive for unusual formats",
      "Deep parsing depends on handing off to a specific analyzer",
      "Very large files are summarized within browser memory limits",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["Unknown binaries", "Magic-byte signatures", "Embedded PE/ELF/Mach-O"],
    relatedTools: ["firmware", "archive", "image"],
    ctaLabel: "Open Binary Analyzer",
  },
  {
    slug: "binary-file-analyzer",
    toolId: "binary",
    locale: "zh-CN",
    title: "二进制文件分析器 — 识别未知文件 | Forensics++",
    description:
      "在浏览器中加载任意二进制文件。依据魔数识别真实类型，与扩展名比对，并在本地给出结构概要。",
    h1: "二进制文件分析器 — 识别未知文件",
    intro:
      "Forensics++ 加载任意二进制文件并识别其真实类型，全程在浏览器中完成。不会上传任何内容。",
    what: "任意二进制：基于魔数/签名的真实类型、结构概要、熵、字符串与嵌入签名。",
    extracts: [
      "基于魔数与签名的真实文件类型，并与扩展名比对",
      "熵与结构概要",
      "字符串与嵌入文本",
      "适用的 PE / ELF / Mach-O 解析",
      "嵌入签名与 YARA 匹配线索",
    ],
    input: ["任意文件（*/*）"],
    useCases: ["未知样本的初步分诊", "确认或质疑文件的扩展名", "定位嵌入或重叠的内容"],
    limitations: [
      "识别基于签名，对罕见格式可能不确定",
      "深度解析依赖 handoff 到具体专用分析器",
      "超大文件在浏览器内存限制内给出概要",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["未知二进制", "魔数签名", "嵌入的 PE/ELF/Mach-O"],
    relatedTools: ["firmware", "archive", "image"],
    ctaLabel: "打开二进制分析器",
  },

  // ──────────────────────────── Windows ───────────────────────────
  {
    slug: "windows-artifacts",
    toolId: "windows",
    locale: "en",
    title: "Windows Artifact Analyzer | Forensics++",
    description:
      "Parse Windows artifacts in your browser. Extract execution traces from LNK, Prefetch, Registry, MFT, and USN journals locally.",
    h1: "Windows Artifact Analyzer",
    intro:
      "Forensics++ parses common Windows artifacts (.lnk, .pf, .reg, .mft, .j) directly in the browser. Parsing is local; files are not uploaded.",
    what: "Windows artifacts: LNK shortcuts, Prefetch, Registry, MFT, and USN journal records.",
    extracts: [
      "LNK: target paths, timestamps, and machine hints",
      "Prefetch: executed programs and accessed files",
      "Registry keys and last-write times",
      "MFT and USN journal execution and timeline traces",
    ],
    input: [".lnk, .pf, .reg, .mft, .j files"],
    useCases: [
      "Reconstructing user and program behavior on a host",
      "Building a host timeline from multiple artifact types",
      "Triage before deeper Windows forensics",
    ],
    limitations: [
      "This is targeted artifact parsing, not a complete Windows forensics platform",
      "Some artifact versions may be only partially supported",
      "Corrupted records may yield incomplete output",
    ],
    maturity: "Triage",
    validation: "Fixture-validated",
    relatedArtifacts: ["LNK files", "Prefetch", "MFT", "USN journal"],
    relatedTools: ["evtx", "registry", "image"],
    ctaLabel: "Open Windows Artifacts",
  },
  {
    slug: "windows-artifacts",
    toolId: "windows",
    locale: "zh-CN",
    title: "Windows 工件分析器 | Forensics++",
    description:
      "在浏览器中解析 Windows 工件。在本地从 LNK、Prefetch、注册表、MFT 与 USN 日志提取执行痕迹。",
    h1: "Windows 工件分析器",
    intro:
      "Forensics++ 直接在浏览器中解析常见 Windows 工件（.lnk、.pf、.reg、.mft、.j）。解析在本地进行，文件不会被上传。",
    what: "Windows 工件：LNK 快捷方式、Prefetch、注册表、MFT 与 USN 日志记录。",
    extracts: [
      "LNK：目标路径、时间戳与机器线索",
      "Prefetch：执行过的程序与访问过的文件",
      "注册表键与最后写入时间",
      "MFT 与 USN 日志的执行与时间线痕迹",
    ],
    input: [".lnk、.pf、.reg、.mft、.j 文件"],
    useCases: ["重建主机上的用户与程序行为", "从多种工件类型构建主机时间线", "深入 Windows 取证前的分诊"],
    limitations: [
      "这是针对特定工件的解析，不是完整的 Windows 取证平台",
      "部分工件版本可能仅被部分支持",
      "损坏的记录可能产生不完整的输出",
    ],
    maturity: "分诊",
    validation: "Fixture 校验",
    relatedArtifacts: ["LNK 文件", "Prefetch", "MFT", "USN 日志"],
    relatedTools: ["evtx", "registry", "image"],
    ctaLabel: "打开 Windows 工件",
  },

  // ──────────────────────────── Image ───────────────────────────
  {
    slug: "image-forensics",
    toolId: "image",
    locale: "en",
    title: "Image Forensics and Metadata Analyzer | Forensics++",
    description:
      "Inspect images in your browser. Read EXIF and metadata, surface steganography clues, verify integrity, and decode QR codes locally.",
    h1: "Image Forensics and Metadata Analyzer",
    intro:
      "Forensics++ analyzes images (png/jpg/gif/webp/bmp) directly in the browser. Metadata and content are processed locally; the file is not uploaded.",
    what: "Image files: EXIF and metadata, format structure, embedded data, QR codes, and integrity checks.",
    extracts: [
      "EXIF and embedded metadata",
      "Format structure and PNG chunk review",
      "CRC and integrity verification",
      "QR code decoding",
      "Steganography clues (not detection) via built-in YARA and strings",
    ],
    input: [".png, .jpg, .jpeg, .gif, .webp, .bmp files"],
    useCases: [
      "Metadata review of evidentiary images",
      "Spotting anomalous or hidden regions",
      "Pulling embedded text or QR codes",
    ],
    limitations: [
      "Steganography support surfaces clues only — it is not a detector",
      "Some proprietary or malformed chunks may be skipped",
      "Deep carving depends on handoff to the binary tool",
    ],
    maturity: "Stable",
    validation: "Fixture-validated",
    relatedArtifacts: ["Image metadata", "EXIF", "QR codes", "PNG chunks"],
    relatedTools: ["binary", "windows"],
    ctaLabel: "Open Image Forensics",
  },
  {
    slug: "image-forensics",
    toolId: "image",
    locale: "zh-CN",
    title: "图像取证与元数据分析器 | Forensics++",
    description:
      "在浏览器中检查图像。读取 EXIF 与元数据，呈现隐写线索，校验完整性，并在本地解码二维码。",
    h1: "图像取证与元数据分析器",
    intro:
      "Forensics++ 直接在浏览器中分析图像（png/jpg/gif/webp/bmp）。元数据与内容在本地方理，文件不会被上传。",
    what: "图像文件：EXIF 与元数据、格式结构、嵌入数据、二维码与完整性检查。",
    extracts: [
      "EXIF 与嵌入元数据",
      "格式结构与 PNG chunk 审查",
      "CRC 与完整性校验",
      "二维码解码",
      "通过内置 YARA 与 strings 呈现隐写线索（非检测）",
    ],
    input: [".png、.jpg、.jpeg、.gif、.webp、.bmp 文件"],
    useCases: ["证据图像的元数据审查", "发现异常或隐藏区域", "提取嵌入文本或二维码"],
    limitations: [
      "隐写支持仅呈现线索——并非检测器",
      "部分专有或畸形 chunk 可能被跳过",
      "深度雕刻依赖 handoff 到 binary 工具",
    ],
    maturity: "稳定",
    validation: "Fixture 校验",
    relatedArtifacts: ["图像元数据", "EXIF", "二维码", "PNG chunk"],
    relatedTools: ["binary", "windows"],
    ctaLabel: "打开图像取证",
  },
];

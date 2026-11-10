# Tool reference / 工具手册

[Documentation](README.md) · [Getting started](GETTING_STARTED.md)

This reference covers the **36 visible workspaces in the current source tree** (1.0.0 shipped 35). The catalog in [`src/config/app.ts`](../src/config/app.ts), individual workspace guards and analyzer limitations are authoritative. Browser memory and file structure can impose additional constraints. A successful parse is not an authenticity or attribution conclusion.

Use the sidebar search by name, ID or capability. Website routes use canonical slugs where defined and tool IDs otherwise. Offline links use `/#<id>`. Historical Image/Binary aliases resolve to their owning workspace.

## Evidence and analysis / 检材分析

| Workspace / ID | Input and purpose | Interpretation boundary |
| --- | --- | --- |
| Image / 图片 · `image` | Common images, TIFF, HEIC/HEIF/AVIF and image-like bytes; preview, EXIF, container checks, PNG CRC, QR, channels, hidden/trailing data and repair attempts | Current input limit 64 MiB; pixel guard 50 MP; automatic restoration only up to 8 MiB. Preview decode does not alter original analysis bytes. EXIF is declared metadata. |
| Binary / 二进制 · `binary` | Bounded arbitrary files; identification, Hex, executable structure, strings/IOC, entropy, YARA and embedded objects | Expensive pages execute on demand. Signatures and heuristic extents are leads, not proof that every carved object is complete. |
| Firmware / 固件 · `firmware` | Firmware images; chunked signatures/entropy, architecture hints, filesystem structures, extraction and manifest | Recursive expansion and object hashing have separate budgets. Large sources may receive top-level streaming analysis only. |
| Disk / 磁盘镜像 · `disk` | Raw disk/partition images; MBR/GPT and supported FAT/NTFS/exFAT/EXT/ISO9660 metadata | Metadata and supported directory exploration are scoped/read-only; this is not a complete filesystem-mounting or recovery suite. |
| SQLite / 数据库 · `sqlite` | SQLite and related WAL/SHM; tables, SQL, forensic pages, recovery candidates and export | Recovery can be heuristic or incomplete. Historical WAL, unknown rowids and missing overflow material retain limitations. Editing/export requires deliberate user action. |
| Registry / 注册表 · `registry` | Windows registry hive data; key/value inspection and structured findings | Supported hive structures and available bytes limit coverage; not every Windows artifact has a registry interpretation. |
| Plist · `plist` | XML/binary property lists | Decoded values are application-declared data; malformed or unsupported structures may be rejected. |
| Browser artifacts / 浏览器痕迹 · `browserartifacts` | Supported browser databases/artifacts; history and related records | Database availability, supported schema and encryption affect results. The tool does not bypass an unavailable system key store. |
| EVTX / 事件日志 · `evtx` | Windows event logs; BinXML records, filtering and supported Sigma checks | Corrupt/missing chunks and unsupported rule semantics limit coverage; absence of a hit is not proof of no event. |
| Office/PDF / 文档 · `documentforensics` | Supported PDF and Office structures, metadata, links and attachments | Container/structural triage, not full document rendering or malware detonation. Encrypted or unsupported features remain limited. |
| Android · `android` | Manifest/APK, permissions, signatures; optional `.idsig`; explicit re-signing | Parsing, verification and re-signing are separate. Re-signing creates a new identity, not the original developer's signature. |
| Email / 邮件 · `email` | EML/MSG, MIME headers/body/attachments and exports | Header/authentication fields are claims in the message. HTML preview is constrained and may differ from a mail client. |
| Archive / 压缩包 · `archive` | Supported ZIP/TAR/CPIO and archive/container data | Entry, expanded-byte and compression-ratio limits apply. Unsupported encryption/compression is not silently treated as successful extraction. |
| Windows artifacts / 系统痕迹 · `windows` | Supported shortcut/Prefetch/registry-export and NTFS MFT/USN structures | Format coverage is explicit; timestamps and path strings require source/context review. |
| Memory triage / 内存初筛 · `memory` | Supported minidump metadata and PE-header discovery in raw dumps | Bounded triage, not a full process-memory reconstruction or Volatility-equivalent framework. |
| Bulk scanner / 批量扫描 · `bulk` | Large arbitrary input; streaming strings, IOC and offset/context extraction | Pattern matches do not establish ownership or intent; resource/output budgets constrain results. |
| IOC · `ioc` | Text/log indicators and related normalized values | Extraction is syntactic and contextual, not a reputation or threat-intelligence verdict. |
| Lookup / 归属地 · `lookup` | IPv4, phone prefixes, Chinese ID-shaped values, card/BIN and validation rules | Static historical data and rule validation, not live positioning or identity/ownership confirmation. Batches over 5,000 require splitting. |
| PCAP · `pcap` | PCAP/PCAPNG, packets, TCP streams, HTTP/DNS and visible TLS handshake metadata | Missing TCP ranges and encrypted later handshakes remain incomplete. Application traffic is not decrypted by the TLS metadata parser. |

## Text, network utilities and transforms / 文本与转换

| Workspace / ID | Purpose | Boundary |
| --- | --- | --- |
| Codec / 编码解码 · `codec` | URL/Base64/Hex/Unicode, supported charsets/text operations | Encoding is not encryption. |
| Chinese conversion / 简繁转换 · `chinese` | Dedicated sidebar workspace; offline OpenCC in both directions, regional variants, file import/export and shortcuts | Input/file conversion is bounded at 2 MiB; UTF-8 file import. Names and ambiguous forms require review. |
| Cryptography / 密码算法 · `crypto` | Supported digests, HMAC and symmetric operations | Correct algorithm, mode, key/IV and input representation are the user's responsibility. |
| Hash / 哈希 · `hash` | Text/file digests, identification and comparisons | A matching digest compares bytes under that algorithm; it does not establish provenance or authenticity. |
| JWT · `jwt` | Decode/edit supported token structures and signing/verification operations | Decoding a payload is not verifying trust in its issuer. |
| Password / 口令 · `password` | Generation, strength utilities and supported bcrypt operations | Local heuristics are not proof of resistance to a particular attack. Secure generation needs browser randomness. |
| SQL · `sql` | SQL formatting and supported text analysis | Formatting does not execute a database query or establish query safety. |
| JSON · `json` | Parse, format and inspect structured text | Large/malformed input can hit browser or operation limits. |
| Regex / 正则 · `regex` | Pattern matching with bounded worker execution | Pathological expressions can time out; test the intended regex semantics and flags. |
| Timestamp / 时间戳 · `timestamp` | Supported epoch/date representations and conversions | Units and timezone assumptions must be recorded; an inferred unit can be ambiguous. |
| Timeline / 时间线 · `timeline` | Parse/organize event text and timestamps | Sorting does not resolve missing zones or establish causality. |
| Number bases / 进制 · `baseconvert` | Integer representation conversion | Confirm the input base and accepted integer syntax; not arbitrary floating-point conversion. |
| UUID · `uuid` | UUID generation and inspection | An identifier is not a security token or evidence of uniqueness across untrusted systems. |
| URL · `urltool` | URL components, normalization and inspection | Structural parsing does not check destination safety or fetch the target. |
| HTTP · `http` | Inspect request/response text | Text analysis is distinct from a network request and does not validate a server's behavior. |

## Navigation and bundled suite

| Workspace / ID | Purpose | Boundary |
| --- | --- | --- |
| Home / 首页 · `home` | Search, recent tools, text suggestions and navigation | Suggestions can be overridden; they are routing assistance, not analysis results. |
| CyberChef · `cyberchef` | Bundled upstream recipe engine and operations | Some upstream operations need external services. Offline resource policy prevents external requests; available modules/data and browser limits still apply. |

## Image metadata workflow

Overview places extracted capture details before the image's secondary analysis. The full table prioritizes populated common fields, supports Chinese/raw-name/value search and exports all metadata. Empty values can be included; more than 100 matching rows can be loaded progressively. No-metadata screenshots or re-shared photos are normal cases, not automatically failed analysis.

Capture time is kept as recorded. A timestamp without a declared zone must not be relabeled as UTC. GPS coordinates are displayed without online reverse-geocoding. Software metadata alone does not prove editing.

## Chinese conversion shortcuts

| Action | Shortcut |
| --- | --- |
| Traditional → Simplified | `Ctrl/⌘ + Enter` |
| Simplified → Traditional | `Ctrl/⌘ + Shift + Enter` |

Standard/Taiwan glyph modes and Taiwan regional-phrase mode have different outputs. The phrase mode can convert vocabulary such as 软件/軟體 and 鼠标/滑鼠 in addition to script. Hong Kong mode selects its supported regional forms. Original whitespace, Latin text and emoji are preserved by the conversion workflow.

For unexpected behavior, see [troubleshooting](TROUBLESHOOTING.md) and include the specific operation, source version and a safe reproducible sample in a report.

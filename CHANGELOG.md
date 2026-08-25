# Changelog

Forensics++ follows semantic versioning where practical. This file records user-visible changes and release engineering milestones.

## [Unreleased]

### Added
- APK v1 (JAR) 签名校验补齐 per-section `.SF` digest 比对：此前仅校验 whole-manifest digest，MANIFEST.MF 中被篡改的条目可绕过校验；现在逐段比对，被篡改条目直接报 mismatch，并支持 per-section 全覆盖视为 fully attested。
- 新增单元测试：jar-v1-manifest（4）、password（4）、jwt（5），覆盖 v1 签名 attestation 路径、MySQL native 密码、JWT HS256/RS256 round-trip。

### Changed
- 版本号升级为 `1.0.0-beta.5`。

## [1.0.0-beta.4] - 2026-08-16

### Changed

- **图片工作台收口**：PNG Analyzer 与 QR Decoder 合并进 Image Workbench；PNG chunk/CRC/IEND/尾部风险和二维码识别直接复用当前已打开图片，不再要求重复上传。
- **二进制工作台收口**：File Signature、Strings、Entropy、YARA 合并进 Binary Workbench，保留 Hex/结构/Embedded 页面；旧 hash/收藏/最近工具入口会自动迁移到新的 canonical workbench。
- Tool Registry 增加 `hidden` / `mergedInto` 和 canonical routing，首页、侧栏、命令面板只展示真实工作台，同时保持旧 URL hash 兼容。
- Firmware Analyzer 扫描器改用分组 native byte search，熵统计合并为单次遍历；候选对象不再默认读取 8 MiB 并二次执行完整 Carver。
- Firmware 边界解析改为按格式读取 256 KiB–2 MiB 的受控 probe，并直接调用对应 format extent resolver；父子关系改用 active interval 集合。
- Firmware 递归分析不再在小于 128 MiB 时重新读取并扫描完整源文件，只 materialize 已识别的 ZIP/gzip/zlib/TAR/CPIO 容器，并受总读取预算约束。
- Firmware 默认扫描块提升到 8 MiB，对象预计算 SHA-256 的默认预算从 256 MiB 收紧到 64 MiB/24 个对象；源文件 SHA-256 仍完整计算。
- Firmware 结果增加 scan / resolve / recursive / total timings，便于直接定位真实慢点。
- Firmware 达到对象上限后停止后续 signature 搜索（仍继续源文件 SHA-256/熵统计），避免高噪声固件在截断后继续做无意义匹配；Binary Workbench 的按需熵 Worker 使用 transferable buffer，减少一次结构化克隆。

### Verification

- 新增 workbench consolidation 回归，验证 `png/qr → image`、`fileid/strings/entropy/yara → binary` 及旧 hash 路由兼容。
- 新增 Firmware I/O 回归：16 MiB / 12 个 U-Boot signature 的样本在关闭对象预哈希时，总读取量必须低于源文件的 1.5 倍，防止重新出现“每候选 8 MiB probe + 整文件二次递归扫描”。
- 发布前仍应在完整 npm 依赖环境执行 `npm ci && npm run verify`。

## [1.0.0-beta.3] - 2026-08-16

### Added

- 新增独立 **Firmware Analyzer**：基于 `EvidenceReader`/Worker 的分块扫描、跨块 signature 命中、结构边界解析、流式 SHA-256、熵图、架构识别、Firmware triage 与 JSON scan manifest。
- Firmware 递归分析统一接入共享 container extractor，支持 ZIP/APK/JAR、gzip、zlib、TAR、CPIO，并受深度、对象数量、单对象和总膨胀量限制。
- 新增中央 Analyzer Routing，Firmware/Binary carved artifact 统一路由到 SQLite、Android、Archive、Image、Document、Disk 或 Binary 工作区。
- `.fppcase` 升级到 schema 1.1，新增 `analysis.json` 保存安全裁剪后的结构化 Analyzer 快照；继续兼容 1.0 导入。

### Changed

- Carver format 定义升级为共享 Registry，并补充 zlib、LZMA、vendor_boot、UBIFS、PEM certificate/private-key 等识别。
- Result Store 增加有界历史、订阅、案件安全快照与恢复，不再只是“每个工具一个当前结果”的临时 Map。
- Tool Handoff 从单个 pending object 升级为每目标工具的有界 FIFO 队列，并保持 5 分钟内存过期策略。
- Disk Image 工作区加入 handoff 消费，使 Firmware 中识别出的 FAT/exFAT/NTFS/EXT/ISO 对象可以真正直接送入 Disk Analyzer。
- 首页和全局工具搜索会同时检索工具的 accepts/capabilities 元数据，Firmware Analyzer 加入默认快速入口。
- Firmware 对 carved object 的 SHA-256 增加总读取预算，并预计算下一对象边界，避免大固件在解析阶段产生不受控的重复 I/O。

### Architecture

- 格式检测、container expansion、Analyzer 选择、结构化结果存储和案件序列化已从具体 React 工具中继续下沉；Binary 与 Firmware 不再维护各自的 Analyzer 路由分支。
- 大型固件默认保持分块分析；只有受限大小来源才自动进入递归容器展开，避免重新退化成全文件 `arrayBuffer()` 工作流。

### Verification

- 新增 Firmware streaming/cross-chunk、shared container extractor、Analyzer routing、Result Store/Handoff queue 与 `.fppcase` 1.1 回归。
- 独立运行样本已验证跨 chunk signature、U-Boot structural extent/architecture metadata、TAR→SQLite recursive extraction 与 Firmware Manifest 输出。
- 发布前仍应在完整 npm 依赖环境执行 `npm ci && npm run verify`。

## [1.0.0-beta.2] - 2026-08-16

### Added

- 新增 `EvidenceReader` 随机访问底层、结构化 `AnalysisEnvelope`/Result Store、Tool Runtime Registry，并让案件报告优先消费结构化分析结果。
- Firmware/File Carver 支持同类型多命中、结构边界、ZIP/gzip 安全递归展开与 carved artifact 内存直送目标 Analyzer。
- APK 增加 v1/JAR、v2、v3、v3.1 签名验证与可选 v4 `.idsig` 校验；增加本地 v2 重新签名/修复流程，可使用导入身份或临时本地身份。
- SQLite 增加 Deleted Record 结构恢复、Overflow Page 重组、历史 WAL 行版本与候选 Schema 匹配。
- PCAP 增加 TLS ClientHello/ServerHello/Certificate、SNI、ALPN、TLS 版本、JA3/JA3S 与证书 SHA-256。
- Binary Analyzer 深化 PE/ELF；新增 Disk Image Explorer、Bulk Artifact Scanner 与 Memory/Minidump Triage。
- Windows Artifact 增加 NTFS `$MFT` 与 `$UsnJrnl:$J` 解析。
- Case Reporter 增加版本化 `.fppcase` 参考型案件包与内部文件完整性验证。

### Changed

- Android/APK 与 Archive 共用 ZIP Central Directory 膨胀预检，限制异常条目数、单条/总解压体积与异常压缩比。
- `ToolHost` 收缩为薄宿主，工具懒加载与运行时依赖集中到 Registry。
- APK “签名修复”明确为重新签名；没有原开发者私钥时不会声称恢复原签名身份。

### Verification

- 新增 Disk、Bulk、Memory、MFT/USN、递归 Carver、APK v4、`.fppcase` 和 SQLite overflow 回归测试。
- 开发环境已执行源码版权头、全仓 TS/TSX 语法转译、核心解析器严格类型检查，以及 APK v1/v2/v4、SQLite overflow、Disk/MFT/USN/Memory/Bulk/Carver 的独立运行样本验证。
- 发布前仍应在完整 npm 依赖环境执行 `npm ci && npm run verify`。

## [1.0.0-beta.1] - 2026-07-23

### Changed

- 版本号从 `1.0.0-alpha.4` 升级为 `1.0.0-beta.1`。
- **案件记录 / 证据报告 全面重构**：导出按钮合并为「导出」下拉菜单，改为标签页布局（证据列表 / 报告预览 / 完整性 & 时间线），案件信息可折叠，摘要改为紧凑状态条，报告预览支持全宽查看。
- Service Worker 从 cache-first 改为 **network-first**，`CACHE_VERSION` 增加构建指纹（dist/assets 文件名 SHA1），每次重建自动清旧缓存，根除重建后工具页全挂的问题。
- 证据报告预览工具栏改为分段按钮（渲染预览 / Markdown 源码）+ 打印按钮。
- 全局复制操作增加「已复制」提示浮层，72 个 `copyText` 调用站点统一受益。
- 滚动条样式改为主题色自适应（深色模式下滚动条更清晰可见）。

### Fixed

- 修复 6 个 CSS token 从未定义的问题（`--app-mono` 被 40 处引用但从未定义，导致所有等宽 UI 回退到 sans-serif；`--app-border`、`--border-subtle`、`--text-secondary`、`--app-ok`、`--app-text-soft` 等同样缺失）。
- 修复密码工具分段按钮布局：SQL 按钮不再折行。
- 修复 `--app-mono` 未定义导致的等宽字体回退 bug（哈希值、十六进制数据、代码查看器等 40 处受影响）。

### Verification

- 137 个测试通过。
- TypeScript、版权头、生产构建、静态发布包验证通过。
- 36 个工具的布局审计通过。

## [1.0.0-alpha.4] - 2026-07-14

### Added

- 哈希页会保存已经明确计算出的文本哈希和文件哈希结果；恢复后仍可复制、筛选和导出，但必须重新选择文件才能再次计算。
- 字符串提取和熵值分析会保存已完成的分析结果，切换工具或刷新页面后可以继续查看。
- 文件分析工作区只保存受控大小的字节预览；大文件恢复后保留结果表和导出能力，需要原始上下文时再重新选择文件。
- 证据报告可以导出为不依赖外部资源的 HTML 文件，离线打开即可查看。
- 时间线支持合并多个日志或文本文件，并在 JSON 导出中保留文件名、来源和行号。
- 邮件附件和 PCAP 提取文件只在用户明确点击后计算 SHA-256。

### Changed

- 统一复制操作，在 `file://` 静态发布包和不支持 Clipboard API 的浏览器中使用降级方案。
- 浏览器工作区写入采用短暂合并，长文本编辑不会每次按键都写入存储。
- 密码、JWT 密钥/私钥和原始 `File` 对象继续保持会话内存，不写入持久化状态。

### Fixed

- 清理本地数据改为清空现有 IndexedDB 工作区记录，避免其他标签页打开数据库时出现“清理成功但数据仍在”的假成功。
- 设置页在不支持 `navigator.storage.estimate()` 的浏览器中不再因调用不存在的方法报错。

### Verification

- 85 个测试通过。
- TypeScript、版权头、生产构建、静态发布包和 36 个工具的桌面/窄屏布局审查通过。

## [1.0.0-alpha.3] - 2026-07-14

### Added

- Timeline Builder events now travel with a report item when the user explicitly selects “Add to Report”.
- Reports include parsed event count, source, format, line number, context, and the normalized timestamp in the Markdown, JSON, Bundle JSON, and preview timeline.
- Large persisted report and workspace state now falls back to the existing IndexedDB store instead of silently failing at the localStorage quota.
- Hash verification now respects filenames in standard checksum manifests while keeping standalone digest matching global.
- Report Bundle JSON can now be imported with validation and an explicit replacement confirmation.
- Reports can now verify registered source files against selected local files after an explicit SHA-256 action.

### Fixed

- Timeline report registration is kept in memory and does not add another browser-storage payload.

### Verification

- 83 tests passed.
- TypeScript, copyright-header, production-build, and static-package verification passed.

暂无未发布变更。

## [1.0.0-alpha.2] - 2026-07-14

### Added

- “加入报告”现在会登记当前工具仍可读取的源文件，记录文件名、大小、类型、修改时间和 SHA-256。
- 证据报告增加源文件清单，并把源文件数量、总大小和哈希写入 Markdown、CSV、JSON 和完整性摘要。
- 只有用户明确点击“加入报告”时才计算源文件 SHA-256，不改变普通工具的计算行为。

### Changed

- 报告清单在桌面、平板和手机宽度下保持独立滚动，长文件名和长哈希不会撑破弹窗。

### Verification

- 74 项自动测试通过。
- 36 个工具的桌面与窄屏布局审计通过。
- TypeScript、版权头和生产构建检查通过。

## [1.0.0-alpha.1] - 2026-07-14

### Added

- Started the v1.0 SQLite forensic workspace with page mapping, WAL frame provenance and printable fragments from verified free-space regions.
- Added IndexedDB-backed SQLite session restore, including locally edited working copies within a 160 MiB storage limit.
- Added a focused SQLite layout-audit scope for loaded database, editing, SQL, persistence and forensic-page checks.
- Added bidirectional TCP stream reassembly with out-of-order handling, retransmission overlap removal, sequence-gap markers and wraparound support.
- Added stream-level HTTP parsing and file extraction for messages split across TCP packets.
- Added IndexedDB restore for parsed packet captures and EML/MSG workspaces.
- Added versioned IndexedDB restore for image, browser-artifact, EVTX, and Office/PDF workspaces.
- Added focused packet-capture and email audits that verify loaded and restored states.
- Added conservative SQLite value and schema markers for sensitive columns, common identifiers, hash-like values, and external-extension actions.
- Added a local Case Notes / Evidence Report workspace with report metadata, tool-result snapshots, integrity summaries, timeline review and export formats.
- Added release checks for the open-source dependency inventory and the hash workflow contract.
- Added a layout-audit check for hidden file inputs so they remain out of the keyboard and screen-reader order.

### Changed

- Kept incomplete WAL tails visible for review while applying only frames through the last complete commit.
- Moved SQLite page and free-space inspection into a cancellable Worker task.
- Compact file-selection panels after a file has been opened so results stay closer to the top of the page.
- Combined HTTP-labelled packets into their underlying TCP conversations instead of splitting one flow by display protocol.
- Replacing a browser-artifact file now cancels the previous parse before accepting the new selection.
- Removed payload SHA-256 calculation from PCAP display serialization; hashes are kept for explicit evidence/report outputs only.
- Hash input changes now remain idle until the user explicitly starts calculation; the default selection stays at SHA-256.
- Declared both light and dark color schemes so browser-native controls follow the selected theme.
- Kept the mandatory legal confirmation dialog within stable margins on narrow mobile screens.

### Verification

- 72 automated tests across eleven test files.
- Responsive layout audit covers 36 routes, 17 populated states and 12 file-loaded states at 375 x 812, 1366 x 900, and 1920 x 1080.

## [0.9.0] - 2026-07-14

### Added

- Added a shared Worker task runner with cancellation, timeout, progress and cleanup handling.
- Added column-scoped SQLite filtering, BLOB text/hex previews and one-step undo for databases up to 32 MiB.

### Changed

- Replaced the partial in-house YARA evaluator with VirusTotal YARA-X running in WebAssembly.
- Moved EML, MSG, browser-record and Office-container parsing into cancellable Worker tasks.
- Moved EVTX, Sigma, PCAP and image byte/pixel analysis into the same cancellable Worker lifecycle.
- Unified IOC, string, Android, entropy and Registry analysis with the same cancellation, timeout and cleanup path.

### Fixed

- Prevented completed IOC and string tasks, and delayed file reads, from replacing newer input.
- Kept Clear available before IOC or string analysis has been run.
- Kept Clear and cancel actions usable while large files are being read, and prevented cancelled password operations from restoring stale results.
- Applied the default indigo theme before React starts so the first frame no longer flashes the old teal color.

### Verification

- 59 automated tests across ten test files, including YARA-X, MIME, PDF, EVTX, PCAP and Worker lifecycle coverage.
- Layout audit covers 36 routes, 17 populated states and 12 file-loaded states at 1366 x 900 in both light and dark themes.
- Production dependency audit reports no known vulnerabilities.

## [0.8.1] - 2026-07-13

### Changed

- Kept evidence inputs and analysis results in the current browser tab instead of persistent local storage, while preserving tool state during navigation.
- Reworked file and text tool empty states around one clear primary action and added practical file-size checks before expensive parsing.
- Expanded the legal notice with authorization, evidence preservation, data handling, security, result, third-party and liability boundaries.
- Refined About and Local Data settings, including a compact current-session list and clearer project links.
- Changed production asset, legal-page and CyberChef paths to support static hosting from a subdirectory.

### Fixed

- Added incremental large-file hashing, byte-level progress, cancellation and a clear SM3 size limit instead of reading every selected file into memory at once.
- Warned before closing or replacing a modified SQLite database and stopped persisting SQL query history.
- Removed legacy evidence values left in localStorage by older versions without repeatedly clearing current settings.
- Corrected stale SEO version metadata, service-worker cache naming and the cached social-image path.
- Updated the layout audit to exercise current-session inputs instead of relying on removed persistent evidence state.

### Verification

- 48 automated tests across eight test files.
- Layout audit covers 36 routes, 17 populated states and 12 file-loaded states at 1366 × 900.
- Production build, copyright headers, static-package checks and a real subdirectory deployment were verified.

## [0.8.0] - 2026-07-13

### Changed

- Refined the main evidence tools around explicit actions, compact controls, predictable result areas, and less duplicated output.
- Reworked SQLite browsing with resizable columns, in-place editing, clearer edit-mode behavior, and simpler navigation.
- Simplified image analysis to focus on preview, metadata, channel inspection, structure checks, and practical recovery output.
- Improved archive, document, packet capture, email, timestamp, Windows artifact, Registry, Plist, browser artifact, and EVTX workflows.
- Reduced large-file limits and deferred expensive filtering in tools that could otherwise stall the browser.
- Shortened legal and consent text and updated the product contact address to `toolab@digiforensics.cn`.

### Fixed

- Removed empty or never-calculated SHA-256 fields from several analysis results.
- Fixed HTML email handling, MSG body decoding, invalid-file state retention, table overflow, and inconsistent result selection.
- Added packet-capture parser coverage and expanded parser regression tests.

### Verification

- 45 automated tests across eight test files.
- TypeScript checks, copyright-header checks, production build, and static release-package verification.

## [0.7.1] - 2026-07-13

### Changed

- Shortened the About page and made Local Data fit common desktop viewports without page scrolling.
- Added a compact two-column list for tools retained in the current browser tab.

### Fixed

- Rebuilt EXIF output as a bounded table with predictable field width and wrapped values.
- Added EXIF overflow coverage to the desktop layout audit.

## [0.7.0] - 2026-07-12

### Added

- Registry Hive and Apple Plist browsers.
- Outlook MSG parsing in the email tool.
- SQLite WAL / SHM loading.
- Storage usage and quota display in Settings.
- Current-session tool management for releasing open files and results.

### Changed

- Tool pages remain mounted after they are opened, preserving state while navigating.
- SQLite columns can be resized and cells can be edited in place.
- Default accent color changed to `#4457A6`; four additional presets were added.
- Terms confirmation is a blocking modal again.
- README, Settings copy, and release notes were shortened.
- Persistent browser storage is now shown separately from current-tab memory.
- Tool loading and rendering were moved out of `App.tsx` into a dedicated host.

### Fixed

- PDF.js compatibility with Node.js 22 environments without `Promise.try`.
- Ant Design Switch styling inside tool panels.
- SQLite WAL recovery now verifies header and frame checksums and ignores corrupt tail frames.
- Generic OLE files are no longer accepted as Outlook MSG, and Registry Hive headers receive stricter validation.

## [0.6.0] - 2026-07-12

### Added

- Browser Artifact Studio for Chromium and Firefox history, downloads, cookies, logins, autofill and extension records.
- Windows EVTX Explorer with BinXML parsing, structured event filtering, raw XML and strict local Sigma matching.
- Office / PDF Forensics for PDF metadata and attachments, OOXML relationships and embedded parts, and OLE stream inspection.
- Static release ZIP generation with a SHA-256 checksum.
- Worker-based parsing for Android manifests, packet captures, IOC extraction and string extraction.

### Changed

- Reworked the desktop interface around a consistent Ant Design 5 tool layout.
- Rebuilt SQLite Browser with persistent table navigation and Browse, Structure, SQL and Changes views.
- Simplified password hash generation so bcrypt and Django PBKDF2 show only the requested result while common hashes remain available as a batch.
- Added isolated HTML email preview and reliable raw EML display.
- Changed archive browsing to read the directory first and extract entries only when requested.
- Changed image, JSON, IOC and string tools to use explicit actions instead of automatic heavy processing.
- Redesigned Settings, including Appearance, About, Local Data and a simplified open-source project list.
- Standardized upload areas, expandable sections, typography and desktop spacing across tools.

### Fixed

- Prevented raw evidence input from being stored in localStorage by affected tools.
- Moved large parsing tasks away from the main UI thread to reduce browser freezes.
- Fixed transparent select popups, collapsed-sidebar focus behavior, hidden file input accessibility and several table overflow issues.
- Corrected overly strong or ambiguous email authentication wording.

### Verification

- 31 automated tests across six test files.
- Layout audit covers 34 tool pages, 17 populated states and 12 file-loaded states.
- Production output is checked for required files, source leakage, copyright banners and size limits.

## [0.5.0] - 2026-07-12

### Changed

- The repository now publishes the complete React and TypeScript source instead of only compiled HTML, CSS and JavaScript.
- Rebuilt the interface around React 19 and Ant Design 5 with a shared workbench layout.
- The historical build workflow installs locked dependencies, verifies the source and builds `dist/`; site publishing is handled through GitHub.
- Added project copyright headers to first-party source and generated assets.

### Added

- Expanded browser-local tools for file integrity, SQLite, EML, images, archives, timestamps, traffic captures and system artifacts.
- Full build, development and deployment instructions.

### Notes

- `dist/` is generated output and is no longer committed to `main`.
- Static deployments should use the generated `dist/` package through GitHub or another configured static host.

## [0.2.0]

- Historical compiled-site release.

[Unreleased]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-beta.4...HEAD
[1.0.0-beta.5]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-beta.4...v1.0.0-beta.5
[1.0.0-beta.4]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-beta.3...v1.0.0-beta.4
[1.0.0-beta.3]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-beta.2...v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-beta.1...v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-alpha.4...v1.0.0-beta.1
[1.0.0-alpha.4]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-alpha.3...v1.0.0-alpha.4
[1.0.0-alpha.3]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-alpha.2...v1.0.0-alpha.3
[1.0.0-alpha.2]: https://github.com/DyNooob/ForensicsPP/compare/v1.0.0-alpha.1...v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/DyNooob/ForensicsPP/compare/v0.9.0...v1.0.0-alpha.1
[0.9.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/DyNooob/ForensicsPP/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/DyNooob/ForensicsPP/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/DyNooob/ForensicsPP/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/DyNooob/ForensicsPP/releases/tag/v0.5.0

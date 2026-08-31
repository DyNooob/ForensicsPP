# AnalysisEnvelope 覆盖表 — beta.6 阶段 C / B6-B1

> 跟踪 P0-2（统一 AnalysisEnvelope）的迁移进度。每批结束以 `tsc + 全量 vitest + vite build` 绿为门槛。
> 计划书原文要求「核心工具必须具备 reset/error recovery/result access/dispose」—— 此处「核心工具」限定为**检材分析类**，
> transform 类（codec/hash/json/regex…）无检材输入语义，**不强制** Envelope（符合原则 2「不为了统一而统一」）。

**最后更新**：2026-08-31（B6-B1：registry / plist / bulk 补齐，覆盖率达 **18 / 18**）
**覆盖率**：**18 / 18** 个 canonical 取证分析器产出 AnalysisEnvelope（基线 3/18：binary / firmware / pcap；B6-B1 补齐 registry / plist / bulk）

> **指标口径说明（B6-A 纠偏）**：分母不再是「全部 38 个工具」，而是 `canonicalForensicAnalyzers()` 返回的 **18** 个检材/网络分析器
> （`category ∈ {analysis, network}` 且具备 `accepts` / `capabilities` / `supportsEvidence` / `supportsResult` / `heavy` 之一，排除 `hidden` 别名）。
> transform 类（codec/hash/json/regex…）、`home`（`system`）、`cyberchef`（`integration`）、隐藏别名（qr/fileid/png/strings/entropy/yara）**不计入分母**——
> 它们无检材语义，不强制 Envelope（符合原则 2「不为了统一而统一」）。原「15/38」把 38 个总工具当分母，夸大了覆盖率，已弃用。
> 计算方法见 `tests/tool-registry.test.ts`：`canonicalForensicAnalyzers().length === 18` 且 `emitters.length === 18`。

---

## 已迁移（18）

| 工具 | 批 | Builder | 映射要点 |
|---|---|---|---|
| binary（含 fileid/strings/entropy/yara 别名） | 基线 | `BinaryTool.tsx` 内联 | 嵌入对象 / IOC / 字符串时间线 / 熵 |
| firmware | 基线 | `FirmwareAnalyzerTool.tsx` 内联 | 递归 carving / 提取产物 |
| pcap | 基线 | `PcapSimpleTool.tsx` 内联 | 网络会话 / TLS / DNS / IOC / 时间线 |
| **sqlite** | B1 | `src/features/sqlite/envelope.ts` | 删除记录恢复 / WAL 重放 / freelist + 碎片恢复 → findings + artifacts + metrics |
| **evtx** | B1 | `src/features/evtx/envelope.ts` | 事件→时间线 / IP·URL·域名 IOC 提取 / 严重度·脏状态·截断 findings |
| **disk** | B2 | `src/features/disk/envelope.ts` | 分区表 / 文件系统 / 删除条目 → findings + artifacts + metrics |
| **memory** | B2 | `src/features/memory/envelope.ts` | Minidump PE header 发现 / 模块枚举 → findings + pe-header artifacts |
| **android** | B2 | `src/features/android/envelope.ts` | 签名状态 / 危险权限 / 危险清单标志 / 风险 APK 条目 → findings + artifacts + IOC |
| **archive** | B3 | `src/features/archive/envelope.ts` | 加密条目 / 目录截断 / 压缩倍率(zip-bomb 信号) → findings + artifacts + metrics |
| **documentforensics** | B3 | `src/features/document/envelope.ts` | 结构检查(external/macro/action→warn) + 加密 error + 嵌入 extracts artifacts + 外部关系 URL/域名 IOC |
| **windows** | B3 | `src/features/windows/envelope.ts` | TimelineEvent→时间线(cap 5000) + records artifacts + 网络字符串 URL/IPv4/Email IOC + artifactType 取证相关性 |
| **browserartifacts** | B4 | `src/features/browserArtifacts/envelope.ts` | 时间戳记录→时间线(cap 5000) + 访问 URL→indicators + 解析源文件→artifacts + 截断→review finding |
| **image** | B4 | `src/features/image/envelope.ts` | PNG chunk CRC/风险→review finding + 嵌入 payload→artifacts + LSB/trailer/EXIF findings |
| **ioc** | B4 | `src/features/ioc/envelope.ts` | 提取 `IocRecord[]`→indicators + 风险标记→review finding（**修正**：ioc 是解析工具，非纯录入，详见豁免说明） |
| **email** | B4 | `src/features/email/envelope.ts` | Received 中继链→时间线 + 中继 IP→indicators + 附件→artifacts + SPF/DKIM/DMARC 失败→review finding |
| **registry** | B6-B1 | `src/features/registry/envelope.ts` | regf 二进制解析 → keys/values 结构 + FILETIME `lastWrite`→时间线(cap 2000) + 关键路径 artifacts + 序列号/校验和不符→review finding |
| **plist** | B6-B1 | `src/features/plist/envelope.ts` | bplist00/XML 解析 → NSDate(Cocoa)→时间线(cap 2000) + 顶层 entries→artifacts + 通用解析器限制说明 |
| **bulk** | B6-B1 | `src/features/bulk/envelope.ts` | 流式扫描 artifacts（真实字节 offset）→ artifacts + 网络指示符 indicators + exact/pattern/heuristic 置信度分级 |

---

## 计划迁移（已全部完成）

> B1–B4 完成 15/18；B6-B1 补齐 registry / plist / bulk，达到 **18 / 18**。剩余工具为 transform / 别名 / 隐藏类，按豁免规则不强制 Envelope。

---

## 明确豁免（transform 类，无检材语义）

`hash` `timestamp` `baseconvert` `uuid` `json` `regex` `crypto` `jwt` `password` `sql`
`urltool` `http` + 隐藏别名 `qr` `fileid` `png` `strings` `entropy` `yara`

> **`ioc` 豁免更正**：早期评估把 `ioc` 列为「纯 IOC 录入，非解析」而豁免。实际 `IocTool` 在 worker 中运行 `analyzeIocs`（见 `src/features/ioc/analyzer.ts`）从文本/日志/文件中**结构化提取** `IocRecord[]`，属于检材分析类，已在 B4 迁移并产出 envelope（`indicators` 为核心输出）。`qr` 仍为隐藏别名（合并进 `image`），不单独产 envelope。

---

## 诚实迁移矩阵（18 / 18 canonical 取证分析器）

> 分母 = `canonicalForensicAnalyzers()` = 18。状态由 `emitsEnvelope` 字段与 `publishAnalysisResult` 调用实证（见 `tests/tool-registry.test.ts`）。

| # | 分析器 | 域 | 状态 | 批 |
|---|---|---|---|---|
| 1 | binary | analysis | ✅ 已迁移 | 基线 |
| 2 | firmware | analysis | ✅ 已迁移 | 基线 |
| 3 | pcap | network | ✅ 已迁移 | 基线 |
| 4 | sqlite | analysis | ✅ 已迁移 | B1 |
| 5 | evtx | analysis | ✅ 已迁移 | B1 |
| 6 | disk | analysis | ✅ 已迁移 | B2 |
| 7 | memory | analysis | ✅ 已迁移 | B2 |
| 8 | android | analysis | ✅ 已迁移 | B2 |
| 9 | archive | analysis | ✅ 已迁移 | B3 |
| 10 | documentforensics | analysis | ✅ 已迁移 | B3 |
| 11 | windows | analysis | ✅ 已迁移 | B3 |
| 12 | browserartifacts | analysis | ✅ 已迁移 | B4 |
| 13 | image | analysis | ✅ 已迁移 | B4 |
| 14 | ioc | analysis | ✅ 已迁移 | B4 |
| 15 | email | analysis | ✅ 已迁移 | B4 |
| 16 | registry | analysis | ✅ 已迁移（B6-B1） | `src/features/registry/envelope.ts` |
| 17 | plist | analysis | ✅ 已迁移（B6-B1） | `src/features/plist/envelope.ts` |
| 18 | bulk | analysis | ✅ 已迁移（B6-B1，`supportsResult:false` 保持，emitters 计为 true） | `src/features/bulk/envelope.ts` |

**结论**：18/18 已迁移；registry / plist / bulk 在 B6-B1 补齐。分母 **Y=18 已冻结**，**X=18**。剩余工具为 transform / 别名 / 隐藏类，按豁免规则不强制 Envelope。

---

## Canonical 分析器架构矩阵（冻结）

> 字段说明：溯源(provenance) 标注证据定位方式——`exact`=精确字节偏移；`structural`=结构偏移（如入口/扇区）；`logical`=逻辑路径/ID（无字节偏移，不伪造 offset）。
> 本表为 B6-B1 冻结事实，除非真实代码结构变化，不再为数字反复调整。

| 分析器 | 域 | 检材输入 | 取证输出 | Envelope builder | 溯源 | Handoff | Case/Timeline | Validation | Maturity | Legacy 依赖 |
|---|---|---|---|---|---|---|---|---|---|---|
| binary | analysis | 任意二进制 | 文件识别 / 签名 / PE·ELF·Mach-O / 熵 / 字符串 / IOC / yara | `BinaryTool.tsx` 内联 | exact (signature offset) | carve / extract | ✅ | fixture-validated | stable | 无 |
| firmware | analysis | 固件镜像 | 文件系统识别 / 入口 / 架构 / 熵区 / carving | `FirmwareAnalyzerTool.tsx` 内联 | structural (entry offset) | archive / binary | ✅ | fixture-validated | triage | 无 |
| pcap | network | pcap/pcapng | TCP 重组 / HTTP·DNS·TLS 会话 / IOC / 时间线 | `PcapSimpleTool.tsx` 内联 | heuristic (session) | 无 | ✅ | fixture-validated | stable | 无 |
| sqlite | analysis | .sqlite/.db/-wal | 删除记录恢复 / WAL 重放 / freelist+碎片 | `sqlite/envelope.ts` | exact/structural (page/cell/freeblock) | 无 | ✅ timeline | fixture-validated | stable | 无 |
| evtx | analysis | .evtx | 事件聚合 / 严重度 / IOC / 时间线 | `evtx/envelope.ts` | logical (record id) | 无 | ✅ timeline | fixture-validated | stable | 无 |
| disk | analysis | .dd/.raw/.img/.iso | 分区表 / 文件系统 / 删除条目 | `disk/envelope.ts` | exact (sector/cluster) | 无 | ✅ | fixture-validated | triage | 无 |
| memory | analysis | .dmp/.raw | minidump 索引 / PE 进程·模块 carving | `memory/envelope.ts` | exact (PE header) | 无 | ✅ | fixture-validated | triage | 无 |
| android | analysis | .apk/.apks/.xapk/.xml | Manifest / 权限 / 签名 / 证书链 | `android/envelope.ts` | logical (APK path) | 无 | ✅ IOC | fixture-validated | stable | 无 |
| archive | analysis | .zip/.jar/.apk/.gz/.tar/.cpio | 条目递归列出 / zip-bomb 检测 / 提取 | `archive/envelope.ts` | structural (entry offset) | 下游分析 | ✅ | fixture-validated | stable | 无 |
| documentforensics | analysis | .pdf/.docx/.xlsx/.pptx | 结构检查 / 加密 / 嵌入对象 / 外部链接 | `document/envelope.ts` | structural (entry/stream) | 无 | ✅ | fixture-validated | stable | 无 |
| windows | analysis | .lnk/.pf/.reg/.mft/.j | LNK / Prefetch / MFT / USN / Registry 工件 | `windows/envelope.ts` | logical (record/string) | 无 | ✅ timeline | fixture-validated | triage | 无 |
| browserartifacts | analysis | 浏览器数据库 | 历史 / 下载 / Cookie / 自动填充 / 时间线 | `browserArtifacts/envelope.ts` | logical (row id) | 无 | ✅ timeline | fixture-validated | stable | 无 |
| image | analysis | png/jpg/gif/webp/bmp | EXIF / 元数据 / 隐写 / CRC / QR | `image/envelope.ts` | exact (chunk offset) | 无 | ✅ | fixture-validated | stable | 无 |
| ioc | analysis | 文本 / 日志 / 文件 | 结构化 IOC 提取（去重 / 分类） | `ioc/envelope.ts` | logical (line/context) | 无 | ✅ IOC | fixture-validated | stable | 无 |
| email | analysis | .eml/.msg | 信封 / 头字段 / Received 链 / 附件哈希 / 正文 | `email/envelope.ts` | logical (header/mime part) | 无 | ✅ timeline+IOC | fixture-validated | stable | 无 |
| registry | analysis | .reg/.dat | regf 解析 / keys-values / FILETIME / 一致性警告 | `registry/envelope.ts` | logical (key path) | 无 | ✅ timeline | fixture-validated | triage | 无 |
| plist | analysis | .plist | bplist00/XML 解析 / NSDate / 结构树 | `plist/envelope.ts` | logical (key path) | 无 | ✅ timeline | fixture-validated | triage | 无 |
| bulk | analysis | 任意大文件 | 流式 artifacts（URL/Email/IP/PEM/路径…）带字节 offset | `bulk/envelope.ts` | exact (byte offset) | 无 | ✅ | fixture-validated | triage | 无 |

---

## 统一基础设施（阶段 A/B 已就绪，C 直接复用）

- `publishAnalysisResult(toolId, envelope)` — `src/features/analysis/resultStore.ts`，发布时按 `evidenceKeyFromSources(source)` 派发 evidence 维度并写入 `run.runId` / `run.sequence`。
- `evidenceKeyFromSources` — `src/core/evidence/identity.ts`，优先级：resolved sha256 id → raw sha256 → `name:size:lastModified` → `__unkeyed__`。
- `AnalysisEnvelope` 类型 — `src/features/analysis/result.ts`。
- Case 集成：envelope 经 `useCaseReport` 自动进入报告（`analysisResultText` + `envelopeReportMarkdown`），`result.timeline` 自动并入 case timeline（`src/app/useCaseReport.ts`）。

---

## 验证门槛（每批结束必跑）

```
npx tsc --noEmit            # 0 错误
npx vitest run              # 全绿（当前 342 测试，随批递增）
npm run build               # 成功（B6-B0 已修复 index.html 版本号，verify:dist 绿灯）
```

> 注：`clean-dist` 沙箱守卫仍拦 >50 文件删除，本地验证可经 `vite build --outDir node_modules/.fpp-build` 绕开；CI 用真实 `npm run build`。

---

## 测试资产

- `tests/sqlite-envelope.test.ts`（5）：builder 映射 + resultStore 按证据分组/历史
- `tests/evtx-envelope.test.ts`（5）：时间线映射 + IOC 提取 + 截断/脏状态 findings + 5000 时间线封顶
- `tests/archive-envelope.test.ts`（4）：加密/截断/压缩倍率 findings + artifacts + resultStore 集成
- `tests/document-envelope.test.ts`（5）：结构检查映射 + 加密 error + 外部关系 IOC + extracts artifacts + store 集成
- `tests/windows-envelope.test.ts`（5）：时间线映射(cap 5000) + records artifacts + 网络 IOC + artifactType findings + store 集成
- `tests/registry-envelope.test.ts`（4）：regf 解析→findings + 关键路径 artifacts + 脏 hive review finding + lastWrite 时间线 + resultStore 集成
- `tests/plist-envelope.test.ts`（3）：NSDate→时间线 + 顶层 entries→artifacts + 通用解析器限制 + resultStore 集成
- `tests/bulk-envelope.test.ts`（4）：偏移 artifacts + 网络 indicators + PEM 高置信度 + 良性文本负向 + resultStore 集成
- `tests/tool-registry.test.ts`（7）：`emitsEnvelope` 集合实证 —— `emitters.length === 18`、`canonicalForensicAnalyzers().length === 18`、bulk 计为 true

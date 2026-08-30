# Forensics++ 1.0.0-beta.6 — 实地差距评估

生成日期：2026-08-29
基线提交：`3bdafd8` (main = loken/main = origin/main)
基线验证：`npm run verify` → **44 测试文件 / 199 测试全部通过**

> 本文不是计划书的复述，而是把计划书每一条落到**当前代码的具体位置**，给出「已有 / 部分 / 没有」的判定和改动落点。

---

## 0. 一句话结论

计划书的骨架假设**基本成立** —— `AnalysisEnvelope`、`ResultStore`、`EvidenceReader`、`ToolHandoff`、`analyzerRouting`、`CasePackage` 全都已经存在且可运行。

真正的差距集中在三处：

| 差距 | 量级 | 性质 |
|---|---|---|
| **Envelope 覆盖率 3/38** | 定义完整，但只有 binary / firmware / pcap 三个工具真正产出 | 工作量最大 |
| **Evidence 身份模型缺失** | `CaseEvidenceFile` 无 `id` / `source` / `verification`，身份目前由 `name:size:lastModified` 承担 | 与计划 P0-3 完全吻合，且是 P0-4 的前置 |
| **无生命周期 / 资源策略** | ToolHost 只做 memo + error boundary + suspense，无 dispose；`maxMountedTools=8` 永久挂载 | 全新基础设施 |

其余条目大多是「已有雏形，需要正式化」。

---

## 1. P0 逐条评估

### P0-1 统一 Tool Lifecycle —— ❌ 没有（需新建）

**现状**
- `src/components/ToolHost.tsx`（62 行）职责仅三项：`React.memo` 包裹、`ToolErrorBoundary` 包裹、`React.Suspense` 兜底。**没有任何生命周期钩子**。
- 生命周期完全由各工具自己手写。典型模式（`BinaryTool.tsx:125-169`，已被复用为事实标准）：

  ```ts
  const requestRef = React.useRef(0);      // 竞态序号
  const abortRef = React.useRef<AbortController | null>(null);
  const requestId = ++requestRef.current;
  abortRef.current?.abort();
  setError(""); setLoading(true);
  const controller = new AbortController();
  abortRef.current = controller;
  ... await runWorkerTask({ signal: controller.signal, timeoutMs: 180_000 });
  if (!active || requestId !== requestRef.current || controller.signal.aborted) return;
  ```

  这个模式本身是对的，但**没有抽象**，每个工具各抄一遍，细节不一致。
- `src/App.tsx:118` `mountedTools`（上限 `maxMountedTools = 8`）保持挂载，**无 dispose 时机、无资源回收**。
- 工具组件签名：`{ t, lang, active, onDirtyChange, setActiveTool, recentTools }`，**没有 dispose / onReset 契约**。

**改动落点**
- 新建 `src/core/runtime/`：
  - `lifecycle.ts` — `ToolPhase = "idle" | "loading" | "running" | "success" | "warning" | "error"`（对齐第十一节）
  - `useToolRuntime.ts` — 统一封装 `requestRef` 竞态 + `AbortController` + phase + error(stage/recovery) + dispose 注册表
  - `resourcePolicy.ts` — `retain | retain-with-cache-eviction | suspendable | dispose-on-switch`
- `ToolHost.tsx` 增加 dispose 调度；`App.tsx` 的 `mountedTools` 淘汰逻辑改由 policy 驱动。

**风险**：38 个工具改造面大。**建议只对 8 个重型工具先落地 dispose，其余沿用现有模式但不新增私有模式**（符合计划书「不得继续新增新的私有生命周期模式」的验收要求）。

---

### P0-2 AnalysisEnvelope 统一 —— ⚠️ 部分（定义完整，覆盖率 8%）

**现状 —— 定义完整**
`src/features/analysis/result.ts` 的 `AnalysisEnvelope` 已包含计划要求的全部字段：

```
schemaVersion("1") ✅  id ✅  analyzer{id,version} ✅  source ✅  run{startedAt,completedAt,parameters} ✅
summary{title,text,metrics} ✅  findings ✅  indicators ✅  artifacts ✅  timeline ✅  limitations ✅  data ✅
```

**现状 —— 覆盖率 3/38**

| 工具 | 产出 Envelope | 位置 |
|---|---|---|
| binary（含 fileid / strings / entropy / yara 别名路由） | ✅ | `BinaryTool.tsx:178` |
| firmware | ✅ | `FirmwareAnalyzerTool.tsx:111` |
| pcap | ✅ | `PcapSimpleTool.tsx:348` |
| **其余 35 个** | ❌ | — |

**建议迁移顺序**（按取证价值 × 结构化结果成熟度排序）

| 批次 | 工具 | 理由 |
|---|---|---|
| B1 | `sqlite` | 1266 行最大工具，已声明 `timeline` capability，deleted-record-recovery / WAL 结果高度结构化 |
| B1 | `evtx` | 已有 `CaseTimelineEvent` 映射路径，直接喂 Timeline + Case |
| B2 | `disk` | 已声明 `random-access` + mbr/gpt/fat/ntfs/ext/iso9660，是 Handoff 枢纽 |
| B2 | `memory` | minidump triage + PE carving，findings 天然结构化 |
| B2 | `android` | signing / certificate / manifest，beta.5 刚补 v1 `.SF` 分段校验 |
| B3 | `archive` | zip-bomb-guard + extraction，artifacts 天然对应 |
| B3 | `document` | metadata + embedded-files |
| B3 | `windows` | MFT / USN / Prefetch / LNK，**Timeline 主来源** |
| B4 | `browserartifacts` / `image` / `ioc` / `email` | ✅ 完成（见 ENVELOPE-COVERAGE，15/38） |
| — | transform 类（codec / hash / jwt / password / baseconvert / uuid / json / regex / timestamp / url / http / qr / sql / cyberchef） | **不强制**，无检材语义 |

**关键约束**：`transform` 类工具（无检材输入）不应被强制 Envelope 化 —— 这也符合原则 2「不为了统一而统一」。计划书的「核心工具」应理解为**检材分析类工具**。

**已有测试**：`tests/analysis-result.test.ts`（1 test），需扩到每批次。

---

### P0-3 Evidence Identity —— ⚠️ 部分（**恰好命中计划书批评的反模式**）

**现状**
```ts
// src/models.ts:294
export type CaseEvidenceFile = {
  name: string;
  size: number;
  type: string;
  lastModified?: string;
  sha256?: string;          // 可选 —— 指纹不是必填
};
```
- ❌ 无 `id`
- ❌ 无 `source`
- ❌ 无 `verification`
- ❌ `sha256` 可选 → 身份可退化为 metadata

```ts
// src/features/reporter/evidence.ts:28
export function evidenceFileKey(file) {
  return `${file.name}:${file.size}:${file.lastModified}`;
}
```
**这正是计划书第三节明确禁止的**：「不得把 metadata match 当成最终 hash identity」。该 key 目前同时用于去重和 case 导入对账。

**已有资产（可直接复用）**
```ts
// src/features/reporter/verification.ts:24
export type EvidenceVerificationStatus = "match" | "mismatch" | "missing" | "unverified";
export function verifyEvidenceRegister(registered, uploaded): EvidenceVerificationResult
```
状态枚举与计划书 `unverified / match / mismatch / missing` **完全一致**，但目前只服务于 case 导入对账表，未附着到 evidence 身份本体。

**改动落点**
- 新建 `src/core/evidence/identity.ts`：`EvidenceIdentity { id, name, size, lastModified, sha256?, source, verification }`
  - `id` 派生规则：`sha256` 可用 → `sha256:<hex>`；否则 `pending:<uuid>`（**明确标记为未定身份**，不得伪装成 hash identity）
  - `verification` 为独立状态机，初始 `unverified`
- `CaseEvidenceFile` 向后兼容演进（加可选字段，不破坏 `.fppcase` 旧包读取 —— `importer.ts:normalizeCaseBundle` 已具备容错）
- `evidenceFileKey` 保留为**去重键**，但导入对账改走 sha256 优先。

**风险**：`.fppcase` 兼容。必须保持 `normalizeCaseBundle` 对旧包的容错路径，并由 `tests/case-package.test.ts` 加回归。

---

### P0-4 Result Store 调整 —— ⚠️ 部分（API 兼容，需加 runId 维度）

**现状**（`src/features/analysis/resultStore.ts`，119 行）
```ts
const currentResults = new Map<ToolId, AnalysisEnvelope>();
const histories    = new Map<ToolId, AnalysisEnvelope[]>();
const MAX_HISTORY_PER_TOOL = 8;
```
- ❌ 纯 `ToolId` 键 —— 同 evidence 多次运行只能靠 `histories` 猜（**完全命中计划书的批评**）
- ✅ 已有 `caseSafeValue()` 快照裁剪（Uint8Array → `{byteLength, retained:false}`，深度 10 / 字符串 200KB / 数组 10k / 对象 2k 键），设计正确
- ✅ 已有 `analysisResultSnapshots()` / `restoreAnalysisResultSnapshots()` 往返

**改动落点**（保持现有导出签名不变）
```ts
// 内部索引演进，外部 API 不变
Map<EvidenceId, Map<ToolId, { current: AnalysisEnvelope; runs: AnalysisEnvelope[] }>>
```
- `run` 增加 `runId` + `sequence`（Run #1 / #2 / #3）
- `publishAnalysisResult(toolId, result)` 签名保留，自动从 `result.source[].id ?? sha256` 推导 evidenceKey；推导不出时退化为当前 `ToolId` 行为
- `analysisResultHistory(toolId, evidenceId?)` 增加可选第二参

---

### P0-5 Report Result-first —— ❌ 现状是纯 DOM 抓取

**现状**（`src/features/reporter/evidence.ts`）
```ts
const toolFileSources = new WeakMap<HTMLElement, Map<EventTarget, File[]>>();

function toolRoot(target) {
  return target instanceof Element ? target.closest<HTMLElement>(".tool-retained-view") : null;
}
export function rememberEvidenceFiles(target, files) { /* 挂到 DOM 元素 */ }
export function rememberedEvidenceFiles(root: HTMLElement) { /* 从 DOM 元素取回 */ }
```
```ts
// src/features/reporter/timeline.ts —— 同一套 WeakMap 模式
export function rememberTimelineEvents(target: object | null | undefined, events)
```

即：**报告来源 = 页面上 `.tool-retained-view` 容器里被记下的 `File[]`**，正是计划书要求降级为 fallback 的那种机制。
`CaseReporter.tsx`（828 行）是消费端。

**改动落点**
- 新建 `src/features/reporter/model.ts` — `ReportModel`（Case 元信息 / Evidence 段 / Analysis 段 / Timeline 段 / Findings / Limitations）
- 新建 `src/features/reporter/renderEnvelope.ts` — `AnalysisEnvelope → ReportModel → Markdown`
  - 可直接复用已有的 `analysisResultText(envelope)`（`result.ts:91`，已输出 title/text/metrics/findings/artifacts/limitations）
- `CaseReporter.tsx` 改为：**优先读 `analysisResultSnapshots()`；DOM 抓取仅在该工具未产出 Envelope 时兜底**
- 保留 `rememberEvidenceFiles` 不删（兼容未迁移工具）

---

## 2. P1 逐条评估

### P1-1 拆分 App.tsx —— ✅ 目标明确，859 行全部命中

**现状**（`src/App.tsx`，859 行）单文件内含五类职责，与计划书列举完全一致：

| 职责 | 行号 | 状态 |
|---|---|---|
| preferences（lang / themeMode / themeColor / legal / sidebarCollapsed / staleBanner） | 53, 59-62, 78, 109 | 内联 |
| tabs（mountedTools / dirtyTools / pendingToolClose） | 118-120, 258 | 内联 |
| commands（command palette 命令表，100 行 useMemo） | 461-558 | 内联 |
| routing（hash 同步 + `toolIdFromHash` / `writeToolHash`） | 55, 122-145 | 内联 |
| reporter（caseNotes / caseReportMeta / reportAddBusy / abortRef） | 68-72 | 内联 |

**落点**：`src/app/{routing,tabs,commands,preferences,lifecycle}/` + `App.tsx` 只做 composition。
**注意**：beta.1 时代做过一次同样拆分，在 beta.3 被回退（见项目记忆）。**这次拆分后必须锁死，避免第三次反复。**

---

### P1-2 拆分 models.ts —— ✅ 目标明确，1214 行

**现状**：`src/models.ts` 1214 行单文件，混装 pcap / sqlite / android / windows / document / archive / evidence / case / timeline 全部类型。
`src/types/` 目前**只有 3 个 `.d.ts`**（`assets.d.ts` / `sm-crypto.d.ts` / `sql-js.d.ts`），没有任何领域类型。

**落点**：按计划书拆为 `src/types/{common,evidence,analysis,sqlite,pcap,windows,android,image,document,archive,reporter}.ts`。
**风险**：1214 行的 import 面极广。**建议保留 `src/models.ts` 作为 re-export 桶**，逐域迁移而非一次性切换，避免 40 个工具文件同时改 import。

---

### P1-3 Tool Registry 标准化 —— ⚠️ 部分

**现状**（`src/config/app.ts`，154 行）
```ts
export type ToolDefinition = {
  id; category; name; desc;
  accepts?: readonly string[];
  capabilities?: readonly string[];
  hidden?: boolean;
  mergedInto?: ToolId;
};
```
- ✅ `accepts` / `capabilities` / `hidden` / `mergedInto` / `canonicalToolId()` 已有
- ❌ 缺 `heavy` / `supportsEvidence` / `supportsResult` / `supportsHandoff` / `supportsPersistence`
- ❌ **只有 14/38 工具声明了 `accepts`/`capabilities`**，其余为空 → 搜索与路由覆盖不全

已声明的工具：image, sqlite, documentforensics, android, archive, binary, firmware, disk, windows, memory, bulk, pcap（12 个可见）+ 2 个别名。
未声明：codec, crypto, jwt, password, sql, registry, plist, browserartifacts, evtx, ioc, email, urltool, http, hash, timestamp, timeline, baseconvert, uuid, json, regex 等。

---

### P1 重型工具资源治理 —— ❌ 没有

**现状**：`maxMountedTools = 8`，挂载后永久保留，**无任何 dispose 路径**。
最大内存风险源：

| 工具 | 行数 | 风险点 |
|---|---|---|
| `SqliteTool` | 1266 | sql.js WASM，整库载入内存 |
| `PcapSimpleTool` | 763 | 全量 packet 数组 + TCP 重组流 |
| `ImageTool` | 759 | 像素 buffer + 隐写分析（同时是 image/qr/png 三个路由的落点） |
| `AndroidManifestTool` | 672 | APK 解压 + DEX/签名块 |
| `BinaryTool` | 566 | **硬编码 128 MiB 上限**，全量 `Uint8Array` 常驻（同时是 binary/fileid/strings/entropy/yara 五个路由的落点） |
| `FirmwareAnalyzerTool` | 334 | 递归 carving + 流式提取 |

**建议 policy 映射**（按计划书第六节，结合代码事实微调）：

```
retain                 : hash, codec, json, baseconvert, uuid, regex, timestamp, url, http, crypto, jwt, password
retain-with-eviction   : binary, strings, entropy, yara, fileid, image, png, qr, documentforensics, email
suspendable            : sqlite, pcap, evtx, windows, browserartifacts, registry, plist, archive, android
dispose-on-switch      : firmware, disk, memory, bulk
```

**释放契约**：Case / Evidence / Analysis Snapshot 不丢（它们在 `resultStore` 与 `casePackage`，与组件解耦）；只释放 parsed cache / worker / large buffer / preview。

---

### P1 Worker 生命周期统一 —— ⚠️ 部分

**现状**
- ✅ `src/utils/workerTask.ts`（111 行）已封装 `create / run / progress / complete / error / abort / timeout`，被 **25 个工具**使用
- ✅ `tests/worker-task.test.ts` 存在
- ❌ **26 个 worker 文件**（`src/workers/` 5 个 + `src/features/**` 21 个），部分工具仍内联 `new Worker(new URL("../features/file/file.worker.ts", import.meta.url), { type: "module" })`（`BinaryTool.tsx:158`），绕过统一创建路径
- ❌ 无 dispose 时的 `terminate()` 保证 —— 切走工具后 worker 是否终止取决于各工具的 `abortRef` 是否记得清理

**落点**：`runWorkerTask` 增加 worker 句柄注册 → `useToolRuntime` 的 dispose 统一 terminate。

---

### P1 大型检材压力测试 —— ❌ 没有

**现状**：无任何大文件回归。已知的唯一硬上限是 `BinaryTool.tsx:143` 的 `128 MiB`，其余工具无声明。
**落点**：
- 新增 `scripts/perf-matrix.mjs`（1MB / 10MB / 50MB / 100MB / 500MB / 1GB）
- 输出 `Supported / Warning / Unsupported` + peak memory + 耗时 + failure mode
- 建议先做**只读型工具**（hash / binary / strings / entropy / bulk），流式工具单独评估

> 提醒：浏览器内存上限受设备与浏览器影响，1GB 级别在多数环境会失败。**这份报告的价值恰恰在于如实记录失败边界**，不应为了「跑通」而降低标准。

---

### P1 Analyzer Routing 加强 —— ⚠️ 部分（无 confidence / reason）

**现状**（`src/core/analyzerRouting.ts`，72 行）
```ts
export function analyzerForArtifact(input: ArtifactRoutingInput): ToolId
```
- ✅ extension / mime / magic-bytes（`bytesContainAscii` 探测 `AndroidManifest.xml` + `classes.dex`）机制齐全
- ✅ deterministic / rule-based，无 AI（符合计划书要求）
- ❌ 返回单个 `ToolId`，**无候选列表、无 confidence、无 reason**
- ⚠️ `tests/analyzer-routing.test.ts` 仅 1 test

**落点**：新增 `analyzerCandidates(input): Array<{ toolId, confidence, reason }>`，`analyzerForArtifact` 保留为 `candidates[0].toolId` 的薄封装。

---

### P1 Tool Handoff 标准化 —— ⚠️ 部分（payload 缺字段）

**现状**（`src/core/toolHandoff.ts`，89 行）
```ts
export type ToolHandoff = {
  id; sourceTool; targetTool; file: File; label; createdAt;
};
```
- ✅ 5 分钟 TTL + 每工具最多 8 条 pending + 订阅通知，机制完整
- ❌ 缺 `evidenceId` / `artifactType` / `dataRef` / `metadata`
- ⚠️ `tests/tool-handoff.test.ts` 仅 2 tests

**已稳定流程**（需回归覆盖）：Firmware → Binary、Carved Artifact → Analyzer、Extracted File → Analyzer、IOC → Network/Browser/Case、Analysis → Case。

---

### P1 Case Package 增强 —— ⚠️ 部分

**现状**（`src/features/reporter/casePackage.ts` 181 行 + `importer.ts` 160 行 + `verification.ts` 82 行）
- ✅ `buildCasePackage` / `readCasePackageBytes` / `isCasePackageName`
- ✅ `normalizeCaseBundle` 容错导入
- ✅ `verifyEvidenceRegister` 对账（match / mismatch / missing / unverified）
- ❌ **闭环未验证**：导出 → 关页 → 重开 → 重导 evidence → 重新 verify 的完整链路无测试
- ❌ **UI 未表达「`.fppcase` 不含原始检材」** 这一限制

---

### P1 错误处理统一 —— ⚠️ 部分

**现状**：38 个工具各自 `setError(string)`，无统一 stage / recovery。`ToolErrorBoundary` 只兜 render 期崩溃，不覆盖分析期错误。
目标状态（计划书第十一节）：
```
Idle / Loading / Running / Success / Warning / Error
Error = { Tool, Stage, Error, Recovery }
```

---

## 3. P2 逐条评估

| 项 | 现状 | 判定 |
|---|---|---|
| P2-1 搜索与工具发现 | `App.tsx:313-314` 命令表**已纳入 `accepts` + `capabilities`**，可按扩展名/能力搜到 | ⚠️ 机制已有，**缺的是 24 个工具未声明 accepts/capabilities**（与 P1-3 同一项工作） |
| P2-2 Recent / Favorite / Workspace 状态 | `recentTools` / `favoriteTools` / `dirtyTools` / `mountedTools` 四套状态分散在 `App.tsx`，无统一定义 | ⚠️ 需收敛（随 P1-1 一起做） |
| P2-3 Mobile | Desktop-first，需回归验证不溢出/不崩溃 | ⚠️ 未验证 |

---

## 4. 建议执行顺序

### 阶段 A — 地基（P0-3 → P0-4）
1. `src/core/evidence/identity.ts` — EvidenceIdentity + verification 状态机
2. `resultStore.ts` 加 evidenceKey + runId 维度（**API 向后兼容**）
3. 测试：`evidence-identity.test.ts` 新增；`analysis-result.test.ts` / `case-package.test.ts` 扩

> 先做这两项的原因：P0-2 的 Envelope 迁移依赖 `source[].id`，P0-5 的 Report 依赖 Store。**顺序反了会返工。**

### 阶段 B — 生命周期（P0-1 + P1 资源治理 + Worker）
4. `src/core/runtime/{lifecycle,useToolRuntime,resourcePolicy}.ts`
5. `runWorkerTask` 增加句柄注册 + dispose 统一 terminate
6. `ToolHost.tsx` + `App.tsx` 挂载淘汰改由 policy 驱动
7. 先接 4 个 `dispose-on-switch` 工具（firmware / disk / memory / bulk）验证契约

### 阶段 C — Envelope 迁移（P0-2，最大工作量）
8. B1: sqlite, evtx
9. B2: disk, memory, android
10. B3: archive, document, windows
11. B4: browserartifacts, image, ioc, email
12. 产出 `docs/beta6/ENVELOPE-COVERAGE.md` 覆盖表

### 阶段 D — Report（P0-5）
13. `reporter/model.ts` + `reporter/renderEnvelope.ts`
14. `CaseReporter.tsx` 改为 result-first，DOM 抓取降级为 fallback
15. UI 表达 `.fppcase` 不含原始检材

### 阶段 E — 架构整理（P1-1 / P1-2 / P1-3）
16. App.tsx 拆分（5 个 concern 目录）
17. models.ts 分域（**保留 re-export 桶**，渐进迁移）
18. ToolDefinition 补齐 5 个 metadata 字段 + 24 个工具补 accepts/capabilities

### 阶段 F — 验证与文档（P1 压力测试 / 路由 / Handoff / 兼容）
19. `analyzerCandidates()` + confidence/reason
20. ToolHandoff payload 扩展
21. `scripts/perf-matrix.mjs` 大文件矩阵
22. Case 闭环回归（导出→关页→重开→重导→再校验）
23. CHANGELOG + 审计表 + 覆盖表

---

## 5. 与计划书的三处建议调整

| 计划书原文 | 建议调整 | 理由 |
|---|---|---|
| 「核心工具必须具备统一的 reset / error recovery / result access / dispose」 | 「核心」限定为**检材分析类工具**，transform 类（codec/hash/jwt/uuid/json/regex…）不强制 Envelope | 符合原则 2「不为了统一而统一」；无检材输入的工具产出 Envelope 无取证语义 |
| 「对所有主要工具建立覆盖清单并逐项迁移」 | 分 4 批迁移，**每批结束 `npm run verify` 必须绿** | 一次性迁移 35 个工具无法保证质量；分批次可回滚 |
| 「`src/types/` 按 domain 拆分」 | **保留 `src/models.ts` 作为 re-export 桶** | 1214 行的 import 面覆盖 40 个工具文件，一次性切换风险过高 |

---

## 6. 立即需要处理的技术债

| 项 | 位置 | 说明 |
|---|---|---|
| `dist/` 清理被安全策略拦截 | `scripts/clean-dist.mjs:25` | `npm run build` 在本机沙箱下因批量删除阈值（111 > 50）失败。**非项目缺陷**，正式构建不受影响 |
| 工作区未跟踪文件 | 根目录下 `dist-v4/ dist-v5/ dist-v7/ overflow-audit-* empty-shots-* fix-verify-* scripts/_*.mjs stale-banner-verification.png` | beta.5 遗留的审计产物，建议清理或加入 `.gitignore` |
| `SqliteTool.tsx` 1266 行 | — | 全项目最大文件，建议随 P0-1 一并拆分 |

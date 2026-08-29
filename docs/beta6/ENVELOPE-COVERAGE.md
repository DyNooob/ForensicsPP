# AnalysisEnvelope 覆盖表 — beta.6 阶段 C

> 跟踪 P0-2（统一 AnalysisEnvelope）的迁移进度。每批结束以 `tsc + 全量 vitest + vite build` 绿为门槛。
> 计划书原文要求「核心工具必须具备 reset/error recovery/result access/dispose」—— 此处「核心工具」限定为**检材分析类**，
> transform 类（codec/hash/json/regex…）无检材输入语义，**不强制** Envelope（符合原则 2「不为了统一而统一」）。

**最后更新**：2026-08-29（批 B1 + B2 + B3 完成）
**覆盖率**：**11 / 38** 工具产出 AnalysisEnvelope（基线 3/38）

---

## 已迁移（11）

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

---

## 计划迁移（按批，未开始）

| 批 | 工具 | 理由 |
|---|---|---|
| B4 | `browserartifacts` / `image` / `ioc` / `email` | 补齐 |

---

## 明确豁免（transform 类，无检材语义）

`hash` `timestamp` `baseconvert` `uuid` `json` `regex` `crypto` `jwt` `password` `sql`
`urltool` `http` `ioc`（纯 IOC 录入，非解析） + 隐藏别名 `qr` `fileid` `png` `strings` `entropy` `yara`

---

## 统一基础设施（阶段 A/B 已就绪，C 直接复用）

- `publishAnalysisResult(toolId, envelope)` — `src/features/analysis/resultStore.ts`，发布时按 `evidenceKeyFromSources(source)` 派发 evidence 维度并写入 `run.runId` / `run.sequence`。
- `evidenceKeyFromSources` — `src/core/evidence/identity.ts`，优先级：resolved sha256 id → raw sha256 → `name:size:lastModified` → `__unkeyed__`。
- `AnalysisEnvelope` 类型 — `src/features/analysis/result.ts`。

---

## 验证门槛（每批结束必跑）

```
npx tsc --noEmit            # 0 错误
npx vitest run              # 全绿（当前 269 测试，随批递增）
npx vite build              # 成功（注意：清 dist/ 受沙箱批量删除守卫拦，用 --outDir 临时目录绕开）
```

---

## 测试资产

- `tests/sqlite-envelope.test.ts`（5）：builder 映射 + resultStore 按证据分组/历史
- `tests/evtx-envelope.test.ts`（5）：时间线映射 + IOC 提取 + 截断/脏状态 findings + 5000 时间线封顶
- `tests/archive-envelope.test.ts`（4）：加密/截断/压缩倍率 findings + artifacts + resultStore 集成
- `tests/document-envelope.test.ts`（5）：结构检查映射 + 加密 error + 外部关系 IOC + extracts artifacts + store 集成
- `tests/windows-envelope.test.ts`（5）：时间线映射(cap 5000) + records artifacts + 网络 IOC + artifactType findings + store 集成

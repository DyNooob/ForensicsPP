# Forensics++ 全工具代码审查报告

- 日期：2026-08-31
- 范围：`src/tools/*Tool.tsx` 全部 40 个定义（含 6 个 `hidden:true` 合并工具），含其引用的 analyzer / worker / 共享组件
- 方法：代码级四维审查（样式/CSS、功能、代码逻辑、易用性/交互直觉），不运行构建、不修改文件
- 维度标签：`[HIGH]` 高危/必须修 · `[MED]` 中等/应修 · `[LOW]` 低风险/可延后 · `[INFO]` 备注

---

## 一、关键结论（先看这个）

1. **没有会导致崩溃/数据泄漏的高危运行时缺陷**。所有重型工具的 Worker 清理、`AbortController` 中止守卫、`useStaleRunGuard` / `requestRef` 竞态防护都基本一致且正确；`dispose-on-switch` 工具在切换时真实卸载并中止在途任务。
2. **最该先修的功能缺陷集中在三处**：
   - `JwtTool` 已算出 HMAC 校验结果与安全发现，但 UI 从不渲染 → "HS256 校验"形同虚设。
   - `browserartifacts` / `documentforensics` / `email` 三处 i18n key 末尾多了一个空格 → 错误提示渲染出字面量 `undefined`。
   - `SqliteTool` 打开数据库无竞态守卫 → 连续选库可能用**错误**的库覆盖状态。
3. **系统性双语违规**：大量用户可见文案直接硬编码 EN/ZH（绕过 `t.<key>`），跨 image/binary/registry/plist/evtx/android/ioc/email/pcap/http/password/uuid/json/urltool/home 等。违反项目双语规则，但不影响功能。
4. **6 个 hidden 工具是孤儿死代码**（`qr/fileid/png/strings/entropy/yara`）：从未被导入或渲染，功能被 `ImageTool`/`BinaryTool` 的合并实现重复；`toolRuntimeRegistry.tsx` 中 `qr`/`png` 条目若被调用会直接崩溃（缺少必需的 `services` prop）。生产无可见坏 UI，但需清理。
5. **两处功能/文案不符**：`ImageTool` 声称内置 yara/strings（实际没有）；`ArchiveTool` 声称支持 tar/gz/cpio（实际只解析 ZIP 中央目录）。

---

## 二、HIGH / 必修项

### 1. 6 个 hidden 工具为孤儿死代码（qr / png / fileid / strings / entropy / yara）
- 任意路径都触达不到：`#qr`→`canonicalToolId("qr")="image"` 渲染 `ImageTool` 的 QR 子页，从不渲染 `QrTool`；其余同理（D 批核查）。
- `grep` 全仓无任何模块 `import` 这些组件（仅自引用与一条测试注释）。
- `toolRuntimeRegistry.tsx:124`(`qr`)、`:126`(`png`) 仍注册了 `<ImageTool t active />`，**缺少 `services` prop** —— `ImageTool` 在 `:141-146` 解构 `services`，若未来任何代码调用 `toolRuntimeRegistry["qr"]` 会抛 `Cannot destructure property 'services' of undefined`。
- 合并逻辑实际写在 `ImageTool.tsx:154-168` 与 `BinaryTool.tsx:69-91` 内，靠 `window.location.hash` 嗅探预选子页 —— 与路由层 `useToolNavigation.ts:160-169` 的提前返回形成**未文档化的隐式耦合**；一旦该提前返回被移除，`#qr`/`#png` 深链会静默回退到 "overview"。
- `fileid` 合并到 binary 的 overview，**损失了** 原 `FileIdTool` 更丰富的"扩展名匹配判定 / 头部 hex 面板"UI。
- **建议**：要么把这 6 个组件真正接回为合并入口点（带齐 `services`），要么删除组件 + 删除注册表冗余条目 + 把 hash 嗅探改为确定性映射，以满足项目"无不可达代码"约束。

---

## 三、MED / 应修项

### 功能缺口 / 文案不符
| 工具 | 问题 | 位置 |
|------|------|------|
| **jwt** | 安全发现（`findings`：alg=none、过期、HMAC 有效/无效等）与安全校验结果（`signatureStatus`）已在 `inspectJwtToken` 算出，但 `JwtTool` 的 decoded 视图（`:191-214`、摘要区 `:116/:195`）从不渲染 → 用户看不到任何告警；HMAC 校验"无可见反馈" | `JwtTool.tsx:191-214` |
| **image** | `app.ts:25` 声称内置 yara/strings，但 `ImageTool` 无任何 yara/strings 调用（在 BinaryTool）。隐藏数据扫描仅做 trailer/LSB/PNG-text | `app.ts:25` vs `ImageTool.tsx` |
| **archive** | 声称支持 `.tar/.gz/.cpio`（`app.ts:45` accepts + help），但文件输入 `accept` 仅 zip/apk/jar/ooxml（`:347`），解析只走 `parseZipCentralDirectory`（`inferKind` 只认 zip/apk/jar/ooxml）。开 tar/gz/cpio → "no zip entries were found" | `ArchiveTool.tsx:68-83,347` |
| **sqlite** | 打开数据库无陈旧请求守卫：`handleFiles`/再次选库可在首个仍在加载时启动，既不 abort 前一次也不比对 requestId，且覆盖 `forensicTaskRef.current` → 较慢的首跑可能用**错误**库覆盖 `dbRef`/表/状态 | `SqliteTool.tsx:536-710` |
| **firmware** |  carved 产物若被 `analyzerForArtifact` 解析为 `pcap`/`windows`，点击 "Analyze →" 会派发 handoff，但 pcap/windows 工具未订阅 `takeToolHandoff` → 5 分钟后 handoff 过期、目标工具空开（静默 no-op） | `core/analyzerRouting.ts:48,55` |
| **cyberchef** | 重型 iframe 切换后从不释放：`hasActivated` 锁 `true`，`<iframe>` 一直挂在隐藏 DOM（~12MB 文档 + JS 堆常驻）直到应用卸载。建议按 `!active` 卸载 iframe | `CyberChefTool.tsx:33-37` |
| **bulk** | `clear()` 不调用 `clearAnalysisResult("bulk")`，清视图后已发布的 envelope 仍残留在 result store，与其他工具不一致 | `BulkArtifactTool.tsx:36` |

### 渲染字面量 `undefined` 的 i18n bug（最易修，建议最先处理）
- `browserartifacts`：`t.files_opened_but_no_supported_browser_records_were_found `（**:169**）key 末尾多空格 → `undefined`。
- `documentforensics`：`t.the_document_is_empty_or_exceeds_128_mib `（**:94**）同上。
- `email`：`t.pasted_email_text_is_limited_to_16_mib `（**:186**、**:440**）同上。
- 三处错误态都会把 `undefined` 当文案显示。删掉 key 末尾空格即可。

### i18n 双语违规（功能正常，仅违反双语规则）
| 工具 | 硬编码位置 |
|------|-----------|
| **password** | `:228` `<ASegmentedButton value="sql">SQL</ASegmentedButton>` 硬编码英文（其余用 `t.*`）；`:244/:245` 加载态写死 `bcrypt.../PBKDF2...` |
| **http** | `:263` `<PanelTitle title="Cookies" />` 硬编码；`:204-206` 协议字段 `HTTP/Host/Content-Type` 与其他 `t.*` 风格不一 |
| **pcap** | `:589` `A -> B`/`B -> A`、`:594` `Hex`、`:661` `TCP flags` 硬编码英文；`proto-${packet.protocol}` 假定每协议 CSS 类可能不存在 |
| **home** | `:76` `categoryLabel` 返回 `"全部"/"All"`（已有 `t.all` 却未用）；`:94` hero 链接 `"浏览工具目录"/"Browse Tools"` 硬编码（应用 `t.*`） |
| **image** | `:640-645` 页签 `Overview/概览…Repair/修复`、`:659-662` 表头 `Name/Display/EXIF/Extracted items/Trailer`、`:725-733` QR `Result/Corners/Geometry` 等大量硬编码 |
| **binary** | `:494` `Hex`、`:498` `YARA`、`:577` `IOC` 段标题、`:521` `Offset/Hex/ASCII` 表头硬编码 |
| **registry** | `:161` `hive.warnings` 只翻译两个硬编码中文子串，其余 worker 告警在英文模式下仍显示原文 |
| **plist** | `:157` `t.httpHeaderValue` 被复用作 "value" 列表头（key 语义错配） |
| **evtx** | `:283-285` labels、若干表头、`level` 筛选名硬编码 EN/ZH |
| **android** | `:459-462,482,491,500,509,629,644,658,661-663,676` 大量段落/表头硬编码 EN（Network Security/Source/Format/AXML/Central Directory/V1 Signer/Signer/Subject/Issuer/Actions/Categories/Data/Signature 等） |
| **ioc** | `:330` `Defanged` 表头硬编码 |
| **email** | `:376-379` 摘要标签 `From/To/Cc/Subject`、`:524` `SHA-256` 硬编码 |
| **uuid** | `:154-164` 行标签 `版本/变体/时间/节点…` 硬编码中文映射 |
| **json** | `:198` `JSONL` 按钮硬编码（其余用 `t.*`） |
| **urltool** | `:79` `<PanelTitle title="URL" />`、`:85` placeholder 硬编码英文 |
| **disk** | `:65-66` `LBA {p.startLba}`、`Cluster` 表头硬编码 |
| **firmware** | `:49-57` `entropyLabel` 硬编码双语字符串（数据标签） |
| **timestamp** | `:195` 转换表头复用 `t.httpHeaderValue` 作通用 "值" 列（key 复用） |

> 注：全局 `input[type="file"]{display:none}`（workbench.css:606）已隐藏文件输入，故 `CodecTool.tsx:164` / `HashTool.tsx:359` 的 `hidden-file-input` 类虽无 CSS 定义也不构成视觉 bug。

---

## 四、LOW / 低风险（逻辑正确，仅整洁度/性能/小瑕疵）

**死代码 / 重复**
- `android`：`hexPreview` 导入（`:31`）但从未使用。
- `sqlite`：`:319-325` 与 `:476-482` 出现**完全相同**的 `active` effect（双倍 `sqliteFileRequestRef` 自增 + 复制粘贴味道）。
- `sql`：`variant="tonal"`（`:289`）非 AntD 5 合法 variant（合法：filled/outlined/dashed/text/link），运行时会静默回退；高亮实际由 `className="active"` 提供，功能不受影响，但属无效死值。
- `baseconvert`：`english` 声明（`:121`）除 useMemo 依赖外从未使用（死变量）。
- `crypto`：affine 的 `a` 与 26 互素未在本层校验（依赖 service，非本文件 bug）。
- `codec`：`active` 守卫 `if (active) return;` 后 `requestRef.current += 1` 语义偏隐晦（非 bug）。

**性能 / 渲染**
- `ioc`：worker 解析完 `analyze()` 后，`:133-140` 的 effect 又在**主线程同步**重跑 `analyzeIocs`（双份工作）。
- `timeline`：缺 debounce（`:149` 解析 effect 每次文本变化都 `new Worker` 重解整段；有 `useDeferredValue` + 5000 事件/32MiB 上限保护，非正确性 bug）。
- `firmware`：熵图每个 block 渲染一个 `<button>` 且无上限（`:294`），大图细粒度下数千 DOM 节点；`showPreview`（`:178-197`）读 `readerRef.current.read(object.offset…)`，对递归展开对象的**虚拟 offset** 会读错字节或抛 `RangeError`（仅错误串可见；下载/分析路径用 `materializeFirmwareObject` 正确）。
- `archive`：`imageUrl = URL.createObjectURL(...)` 写在 `useMemo` 内（`:164-169`）—— render 期副作用反模式（虽由独立 effect 撤销，但应改为 `useEffect`）。
- `regex` / `json` / `image(108)`：解析 effect 依赖含 `english`，切语言会触发一次多余 Worker 重算（已有防抖/中止守卫，无害）。

**交互 / UX 细节**
- `binary`：Strings 子页始终显示初始 worker 跑出的 `analysis.stringAnalysis`，但 UI 文字暗示"按需扫描"（`:569`），scope 行也显示 `sideEvidenceScope` 直到手动重扫（`:571`）—— 数据已在却暗示没有，略矛盾。
- `windows`：`detailRows` 按英文名 `"Name"/"Size"/"Artifact type"` 剥离行（`:143`），依赖 worker 英文输出，locale 脆弱。
- `pcap`：整段先 `readEvidenceFully` 缓冲为单个 `Uint8Array`（`:333`，上限 128MiB）再交 worker；help 已说明"streaming 是 future"，但主线程先发生 128MiB 连续分配。
- `firmware`：`clear()`（`:83-95`）未重置 `busyObjectId`，materialize 中途清除会残留 "busy" 状态。

**资源 / 清理边角**
- `sqlite`：`beginSqliteColumnResize`（`:408-421`）向 `window` 加 `pointermove`/`pointerup`，仅 `pointerup` 时移除；组件在 resize 中途卸载会泄漏监听（无 cleanup effect）。
- `email`：`sanitizeEmailHtml`（`:108-109`）注入 `<style>` 硬编码 hex（`#182230/#fff/#d9e0e8`）；在 sandboxed `srcDoc` iframe 内，始终走浅色主题（邮件预览可接受，但属硬编码主题）。

---

## 五、按工具速查（状态概览）

| 工具 | 主要问题 |
|------|----------|
| home | MED：硬编码双语串（categoryLabel/hero 链接）绕过 `t.*` |
| cyberchef | MED：iframe 切换后不释放（~12MB 常驻） |
| image | MED：help 夸大 yara/strings；大量 i18n 硬编码；64MiB/50MP 守卫 OK |
| codec | 干净（仅 `active` 守卫语义隐晦） |
| crypto | 干净 |
| jwt | **MED：安全发现/HMAC 校验结果从不渲染** |
| password | MED：SQL 按钮硬编码；加载态英文 |
| sql | LOW：无效 `variant="tonal"`；Worker 清理 OK |
| sqlite | **MED：打开库无竞态守卫（错误库覆盖）**；LOW：重复 effect、死 CSS 选择器、resize 监听泄漏、i18n 硬编码 |
| urltool | LOW：标题/placeholder 硬编码 |
| http | MED：Cookies 等硬编码；协议字段风格不一 |
| hash | 干净 |
| timestamp | LOW：preset 标签挂载后不刷新；复用 `t.httpHeaderValue` |
| timeline | LOW：缺 debounce |
| baseconvert | LOW：死变量 `english`；负数边界不一致 |
| uuid | LOW：行标签硬编码中文 |
| json | LOW：JSONL 硬编码；effect 冗余 `english` 依赖 |
| regex | LOW：effect 冗余 `english` 依赖 |
| registry | LOW：部分告警未翻译；其余干净 |
| plist | LOW：`t.httpHeaderValue` 复用作 value 头 |
| browserartifacts | **MED：i18n key 尾空格→渲染 `undefined`**；部分硬编码 |
| evtx | LOW：labels/表头/level 名硬编码 |
| documentforensics | **MED：i18n key 尾空格→`undefined`**；handoff 后 `analyze` 未复用 128MiB 守卫 |
| android | LOW：死代码 `hexPreview`；大量表头硬编码；v4/重签逻辑稳健 |
| ioc | LOW：主线程双份解析；`Defanged` 硬编码 |
| email | **MED：i18n key 尾空格→`undefined`**；摘要/SHA-256 硬编码；iframe 浅色主题 |
| archive | **MED：tar/gz/cpio 声称但未实现（仅 ZIP）**；LOW：methodLabel/SHA-256 硬编码；useMemo 内 createObjectURL |
| binary | LOW：Hex/YARA/IOC/表头硬编码；Strings 子页 UI 暗示与数据矛盾 |
| firmware | MED：carved→pcap/windows 的 handoff 静默丢弃；LOW：熵图无 DOM 上限、虚拟 offset 预览、clear 未重置 busy |
| disk | LOW：LBA/Cluster 硬编码；主线程解析大图 |
| windows | LOW：整文件 arrayBuffer 加载（≤256MiB）；按英文名剥离行 locale 脆弱 |
| memory | 干净（流式读取、dispose-on-switch 中止 OK） |
| bulk | LOW：`clear()` 未清 result store；重复 stale 守卫 |
| pcap | MED：A->B/Hex/TCP flags 硬编码；LOW：128MiB 主线程缓冲、滚动math 脆弱 |
| qr / fileid / png / strings / entropy / yara | **HIGH：孤儿死代码 + 注册表 `qr/png` 潜在崩溃 + hash 嗅探隐式耦合** |

---

## 六、建议修复优先级

**P0（先修，影响用户可见正确性，且改动小）**
1. 三处 i18n key 尾空格（`browserartifacts`/`documentforensics`/`email`）→ 删空格。
2. `JwtTool` 渲染 `findings` 与 HMAC `signatureStatus`。
3. `SqliteTool` 打开库加 stale-run 守卫（仿 `analysisIdRef`/`useStaleRunGuard`）。
4. `ArchiveTool`：要么支持 tar/gz/cpio，要么从 `accepts`/help 移除（避免误导）。

**P1（应修）**
5. `ImageTool` help 移除 yara/strings 夸大（或真接进来）。
6. `firmware` carved→pcap/windows handoff 静默丢弃：让 pcap/windows 订阅 `takeToolHandoff`，或手off 前提示不支持。
7. `cyberchef` 按 `!active` 卸载 iframe。
8. `bulk` `clear()` 调 `clearAnalysisResult("bulk")`。

**P2（清理 / 一致性）**
9. 6 个 hidden 工具：接回或删除（含注册表冗余条目 + hash 嗅探改确定性映射）。
10. 系统性 i18n 硬编码：优先改用户高频路径（home/password/http/pcap/image/binary/email 表头）。
11. 死代码/无效值：`sql variant="tonal"`、`android hexPreview`、`sqlite` 重复 effect、`baseconvert english`。
12. 小性能/清理：`ioc` 双份解析、`timeline` debounce、`archive` useMemo 内 createObjectURL、`sqlite` resize 监听泄漏。

> 注：样式层面**未发现**硬编码 hex 导致暗/亮主题破裂的实例；AntD `ConfigProvider` 主题 token 使用整体良好。问题主要是"硬编码文案/标签"与"少量反模式"，而非视觉破损。

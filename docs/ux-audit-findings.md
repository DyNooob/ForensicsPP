# ForensicsPP — 全工具易用性审计（UX Audit Findings）

- **日期**：2026-09-01
- **范围**：34 个可见工具（home, cyberchef, image, codec, crypto, jwt, password, sql, sqlite, registry, plist, browserartifacts, evtx, documentforensics, android, ioc, email, urltool, http, archive, binary, firmware, disk, windows, memory, bulk, hash, timestamp, timeline, baseconvert, uuid, json, regex, pcap）
- **方法**：无头 Chrome（puppeteer-core）+ 程序化 DOM 文本 / 布局几何提取，桌面（1440×900）与平板（820×1180）两档视口。
- **状态**：1 个 P1 缺陷已修复并验证；其余为一致性 / 响应式 / 可访问性改进项。

---

## 0. 方法学与诚实声明（重要）

> **视觉截图评审在本环境不可行**：当前模型无法解码图片文件——此前所有 PNG 截图 `Read` 均返回 `Content filtered` / `Image unchanged`，无法作为证据。
> 因此本次审计以**程序化 DOM 文本 + 布局几何提取**替代视觉评审，覆盖「结构性 / 行为性」易用性，而非像素级美观（间距、配色对比、对齐观感仍需人工过目）。

每工具采集信号：可见按钮文案及其 `disabled`/`primary` 状态、输入控件 placeholder/label、告警横幅、空状态提示文案、文本溢出（`scrollWidth > clientWidth`）、横向越界元素、`SampleButton` / Help 抽屉是否存在。

**已排除的误报**（见第 5 节）确保结论不含噪声。

---

## 1. 结论速览

| 严重度 | 数量 | 项 |
|---|---|---|
| P1（已修复） | 1 | `baseconvert` 缺失「载入示例」按钮 |
| P2（一致性缺口） | 2 | 样例加载器覆盖不均；Help 抽屉仅覆盖分析类工具 |
| P3（打磨项） | 3 | ioc/email 自实现样例按钮；codec 平板宽度文本截断；缺少语义化 `<h1>` |

- **运行时健康**：全部 34 工具 **0 console / page / network 错误**（上一轮 `_ux-audit` 已确认；本轮 baseconvert 修复后复验 0 错误）。
- **无「假死 / 禁用主操作且无说明」的反模式**：被禁用的主操作（如「解析日志」「编码」「计算哈希」）均有上传按钮 / 输入 placeholder / 空状态提示（「选择文件」「上传 APK / Manifest」、XML 样例占位符）予以解释，属预期行为，不计为缺陷。

---

## 2. 逐项发现

### F1 · P1 · `baseconvert` 缺少「载入示例」按钮 —— 已修复 ✅

- **现象**：`src/tools/BaseConvertTool.tsx` 第 25 行 `import { SampleButton }` 已存在，但 JSX 中**从未渲染**该组件；而 `src/tools/samples.ts` 中 `baseconvert: { zh: "255", en: "255" }` 样例数据完整存在。结果：用户进入进制转换工具无任何「载入示例」入口，与其他转换类工具（codec/crypto/hash/json/jwt）体验不一致。
- **修复**：在输入面板 `ToolPanelHeader` 的 `actions` 中加入
  ```tsx
  <SampleButton toolId="baseconvert" english={english} onLoad={(text) => setValue(text)} />
  ```
- **验证**（静态服务器 4180 + 无头 Chrome）：
  - 面板正常渲染；头部按钮含 `载入示例`；
  - 点击后 `textarea` 值变为 `"255"`；
  - `tsc --noEmit` 通过；**0 运行时错误**。
- **文件**：`src/tools/BaseConvertTool.tsx`（未提交，待评审）。

### F2 · P2 · 样例加载器覆盖不均（7 / 34）

仅 **7** 个工具暴露「载入示例」按钮：`codec, crypto, jwt, ioc, email, hash, json`。

**13** 个工具**既无样例按钮、也无 Help 抽屉**（修复后 baseconvert 已移出此列）：
`home, cyberchef, password, sql, registry, plist, urltool, http, bulk, timestamp, timeline, uuid, regex`

其中**纯文本输入类工具**（`password, sql, regex, timestamp, uuid, urltool, http`）既无快速示例、也无内联帮助，首次上手摩擦最高。
**建议**：将 `SampleButton` + `toolSamples` 拓展到高频文本工具，并为剩余工具补 `help:` 字段。

### F3 · P2 · Help 抽屉仅覆盖分析类工具（15 / 34）

Topbar「?」Help 抽屉（`ToolDefinition.help`）仅 15 个分析类工具有内容：
`image, sqlite, browserartifacts, evtx, documentforensics, android, ioc, email, archive, binary, firmware, disk, windows, memory, pcap`。

转换 / 文本类工具（尤其 `regex, timestamp, uuid, urltool, http, sql, password`）无 per-tool 帮助。
**建议**：至少为高频文本工具补齐简洁 `help:`。

### F4 · P3 · `ioc` / `email` 各自实现「载入示例」，未复用共享组件

DOM 确认 ioc、email 均有可用的「载入示例」按钮，但其源码（`src/tools/IocTool.tsx`、`EmailTool.tsx`）**未引用 `SampleButton` 组件**，属独立实现。功能正常，但与共享组件路线分叉，不利于维护与一致性。
**建议**：统一收敛到 `SampleButton`。

### F5 · P3 · `codec` 在平板宽度（820px）文本截断

`codec-simple-operation-row` 中「格式 URL 编码 解码」在 820px 视口下 `scrollWidth=480 > clientWidth=369`，文本被裁切。桌面宽度正常。
**建议**：窄屏允许换行或收紧字号 / 间距。

### F6 · P3 · 缺少语义化 per-tool `<h1>`

每个工具提取到的文档标题均为 `Forensics++ Workbench`（即 `<title>`），DOM 中未检测到独立的工具级 `<h1>` 标题。对可访问性（屏幕阅读器 / 锚点导航）是轻微短板。
**建议**：为工具主体增加工具名 `<h1>` 或 `aria-labelledby` 区域标识。

---

## 3. 样例 / Help 覆盖矩阵（桌面视口实测）

| 工具 | 样例 | Help | 工具 | 样例 | Help |
|---|---|---|---|---|---|
| home | – | – | archive | – | ✅ |
| cyberchef | – | – | binary | – | ✅ |
| image | – | ✅ | firmware | – | ✅ |
| codec | ✅ | – | disk | – | ✅ |
| crypto | ✅ | – | windows | – | ✅ |
| jwt | ✅ | – | memory | – | ✅ |
| password | – | – | bulk | – | – |
| sql | – | – | hash | ✅ | – |
| sqlite | – | ✅ | timestamp | – | – |
| registry | – | – | timeline | – | – |
| plist | – | – | baseconvert | ✅* | – |
| browserartifacts | – | ✅ | uuid | – | – |
| evtx | – | ✅ | json | ✅ | – |
| documentforensics | – | ✅ | regex | – | – |
| android | – | ✅ | pcap | – | ✅ |
| ioc | ✅ | ✅ | urltool | – | – |
| email | ✅ | ✅ | http | – | – |

`✅*` = 本轮修复后新增（原为 `–`）。

---

## 4. 误报排除清单

下列信号经核查为结构 / 环境噪声，已排除出缺陷统计：

1. **横向越界按钮 `left:-274 / right:-147`（全部 34 工具一致）**：坐标在所有工具完全相同，属壳层固定 / 绝对定位元素（疑似 Topbar 工具导航箭头在窄屏 translate 出画布），非单工具布局缺陷。建议人工快速目检确认无控件被误裁。
2. **被禁用的主操作按钮**：详见第 1 节——均有上传 / 占位符 / 空状态提示解释，属预期交互，不计缺陷。
3. **`buttonCount` 偏高**：提取到的按钮数含全局侧边栏导航（每工具约 19 个导航项 + Topbar 控件），已通过仅对 `primary` / 特定文案按钮做判定来排除污染；`primaryDisabled`、`hasSample`、`hasHelp` 结论干净。
4. **运行时错误**：34 工具 0 错误（上一轮 `_ux-audit` 全量确认；本轮 baseconvert 修复后复验 0 错误）。

---

## 5. 后续建议（按性价比排序）

1. **（低成本·高收益）** 为纯文本工具补 `SampleButton` + `toolSamples`：`regex, timestamp, uuid, urltool`（及 `password, sql`）。直接降低首次上手门槛。
2. **（低成本）** 为剩余工具补 `help:` 字段（至少覆盖 `regex, timestamp, uuid, urltool, http, sql, password`）。
3. **（一致性）** 将 `ioc` / `email` 的样例按钮收敛到共享 `SampleButton`。
4. **（响应式）** 修复 `codec` 平板宽度文本截断。
5. **（a11y）** 为工具主体增加语义化 `<h1>`。
6. **（人工目检）** 因视觉评审受限，建议人工过一遍高频工具的间距 / 对比度 / 对齐；并确认壳层 `left:-274` 元素非误裁控件。

---

## 6. 验证与环境

- 构建：`vite build --outDir node_modules/.fpp-ux-audit`（沙箱安全，未触碰 `dist/`）。
- 运行验证：静态服务器 + 无头 Chrome 实测 baseconvert 样例按钮渲染与加载（`"255"`），0 错误。
- 类型：`tsc --noEmit` 通过。
- 测试套件：见 CI（`npm run verify` = test + build）。

> 修复文件 `src/tools/BaseConvertTool.tsx` **未提交**，遵循「显式要求才提交」约定，待你评审。

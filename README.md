<div align="center">
  <a href="https://www.forensicspp.com/">
    <img src="./public/og-image.png" width="100%" alt="Forensics++ Workbench" />
  </a>

  <h1>Forensics++ Workbench</h1>
  <p>Browser-local DFIR tools · 浏览器端电子数据取证工作台</p>

  <p>
    <a href="https://www.forensicspp.com/"><img alt="Website" src="https://img.shields.io/badge/Website-forensicspp.com-4457A6?style=flat-square" /></a>
    <a href="./LICENSE"><img alt="License MIT" src="https://img.shields.io/badge/License-MIT-1E6B4B?style=flat-square" /></a>
    <img alt="Version 1.0.0 beta 6" src="https://img.shields.io/badge/Version-1.0.0--beta.6-4457A6?style=flat-square" />
    <img alt="React 19" src="https://img.shields.io/badge/React-19-087EA4?style=flat-square" />
    <img alt="Ant Design 5" src="https://img.shields.io/badge/Ant%20Design-5-1677FF?style=flat-square" />
    <a href="https://github.com/DyNooob/ForensicsPP"><img alt="Source repository" src="https://img.shields.io/badge/Source-GitHub-52606D?style=flat-square" /></a>
  </p>

  <p>
    <a href="https://www.forensicspp.com/">Use Online</a>
    · <a href="https://github.com/DyNooob/ForensicsPP">Source</a>
    · <a href="#quick-start">Quick Start</a>
    · <a href="#production-build">Production Build</a>
    · <a href="./CONTRIBUTING.md">Contributing</a>
  </p>
</div>

## What is Forensics++

Forensics++ is a browser-local workbench for forensic triage, CTF/MISC, security research, and everyday evidence organization. It brings common file, image, email, database, log, network, and encoding tools into one consistent interface — open the browser and start working.

The core idea is simple: **tools should be direct, results should be reviewable, and the interface should suit long sessions.**

Most analysis runs locally in the browser and does not depend on a Forensics++ backend. The project is fully open source: source, build scripts, tests, and release assets all live in this repository.

Forensics++ 是一个面向取证初筛、CTF/MISC、安全研究和日常证据整理的浏览器端工作台。它把常用的文件、图片、邮件、数据库、日志、网络和编码工具放在一个统一界面中，打开浏览器即可使用。核心定位很简单：工具要直接、结果要可复核、界面要适合长时间工作。常见分析在浏览器本地完成，不依赖 Forensics++ 后端服务；项目完全开源，源码、构建脚本、测试和发布资源均在本仓库中。

## Capabilities

| Area | Capabilities |
| --- | --- |
| Files & Evidence | Hashing, type identification, strings/entropy analysis, standalone Firmware Analyzer (streaming signature scan, entropy map, structure boundaries, recursive container expansion, Firmware Manifest), deep PE/ELF analysis, carved artifacts handed off to the matching analyzer. · 文件哈希、文件类型识别、字符串/熵分析、独立 Firmware Analyzer（流式签名扫描、熵图、结构边界、递归容器展开、Firmware Manifest）、PE/ELF 深度分析、Carved Artifact 直接转交对应分析器 |
| Images & Attachments | Preview, EXIF, PNG structure, channel view, steganography leads, corrupted-image repair attempts, QR decoding, archive listing. · 图片预览、EXIF、PNG 结构、通道查看、隐写线索、损坏图片修复尝试、二维码识别、压缩包目录 |
| Databases | SQLite table browsing and queries, WAL/SHM, page/freeblock/freelist, deleted-record reconstruction, overflow-page reassembly, historical WAL row versions, export. · SQLite 表浏览与查询、WAL/SHM、页/Freeblock/Freelist、Deleted Record 重建、Overflow Page 重组、历史 WAL 行版本、导出 |
| Mail & Network | EML/MSG parsing, HTML body view, headers and authentication results, attachment view, HTTP, URL, IOC, PCAP/PCAPNG, TLS handshake metadata and JA3/JA3S. · EML/MSG 解析、HTML 正文查看、邮件头与认证结果、附件查看、HTTP、URL、IOC、PCAP/PCAPNG、TLS 握手元数据与 JA3/JA3S |
| System Records | AndroidManifest, APK v1/v2/v3/v3.1 verification with optional v4 `.idsig`, local v2 re-sign, Windows Registry/EVTX, $MFT, $UsnJrnl:$J, Prefetch, LNK, REG. · AndroidManifest、APK v1/v2/v3/v3.1 验证与可选 v4 `.idsig`、本地 v2 重签、Windows Registry/EVTX、$MFT、$UsnJrnl:$J、Prefetch、LNK、REG |
| Disk & Memory | MBR/GPT, FAT root directory, NTFS/exFAT/EXT/ISO metadata, memory/minidump triage, streaming bulk artifact scanner. · MBR/GPT、FAT 根目录、NTFS/exFAT/EXT/ISO 元数据、Memory/Minidump Triage、流式 Bulk Artifact Scanner |
| Documents & Time | PDF, OOXML, OLE, timestamp conversion, timeline assembly, multi-source event merge, versioned `.fppcase` case packages. · PDF、OOXML、OLE、时间戳转换、时间线整理、多源事件合并、`.fppcase` 版本化案件包 |
| Encoding & Security | Encode/decode, base conversion, UUID, JSON, regex, JWT, common password hashes, YARA, CyberChef. · 编码解码、进制转换、UUID、JSON、正则、JWT、常见密码哈希、YARA、CyberChef |

Top-level entries consolidate into workbenches: PNG/QR live in the Images workbench; file identification/strings/entropy/YARA live in the Binary workbench. Legacy links still auto-redirect to the matching workbench.

一级入口按工作台收口：PNG/QR 归入图片工作台，文件识别/字符串/熵/YARA 归入二进制工作台；旧链接仍会自动跳转到对应工作台。

Tools share uniform input, result, copy, download, and clear interactions. Large evidence analysis prefers `EvidenceReader` random/streaming reads; analyzers reuse existing parsers through a unified router and short-lived in-memory handoff. Structured `AnalysisEnvelope` results enter a bounded Result Store and can be saved as analysis snapshots inside a `.fppcase` 1.1 case package. A saved workspace survives tool switches or page reloads and can be added to a case report for unified review.

工具之间使用统一的输入、结果、复制、下载和清空交互。大型检材分析优先走 `EvidenceReader` 随机/流式读取；Analyzer 通过统一路由和短生命周期内存 Handoff 复用现有解析器。结构化 `AnalysisEnvelope` 会进入有界 Result Store，并可随 `.fppcase` 1.1 案件包保存分析快照。需要保存的工作区可以在切换工具或刷新页面后继续查看，也可以加入案件报告统一整理。

APK "signature repair" is an explicit re-sign: import your own PKCS#8 private key / X.509 certificate, or generate a temporary repair identity used only locally. Without the original developer's private key you cannot restore the original signing identity; a re-signed APK carries a different certificate identity than the original.

APK 的"签名修复"是显式重新签名：可导入自己的 PKCS#8 私钥/X.509 证书，或生成仅在本地使用的临时修复身份。没有原开发者私钥时无法恢复原签名身份；重新签名后的 APK 与原证书身份不同。

### 1.0.0-beta.6 Highlights

- **Image format-layer forensics**: the Images workbench now shows per-format container structure and risk layers for GIF/BMP/JPEG/WebP/TIFF/HEIF (frames, markers, chunks, TIFF entries, HEIF boxes). · 图片格式层取证：逐格式展示 GIF/BMP/JPEG/WebP/TIFF/HEIF 的容器结构与风险层。
- **JWT legacy PEM compatibility**: the analyzer auto-converts PKCS#1 (RSA) / SEC1 (EC) private keys to PKCS#8, matching OpenSSL's default export format; both compact and pretty-printed JWT headers parse. · JWT 旧式 PEM 兼容：自动把 PKCS#1/SEC1 私钥转换为 PKCS#8，紧凑与美化 JWT 头均可解析。
- **Static indexable routes + SPA 404**: every tool gets an indexable static page (clones the SPA shell with route-level meta injected); unknown routes render 404; preview builds (`VITE_PREVIEW=1`) auto-`noindex` with a Preview banner carrying version/commit/branch. · 静态可索引路由层 + SPA 404：每个工具生成可索引静态页，未知路由渲染 404，预览环境自动 noindex 并带版本/提交哈希/分支横幅。
- **Capability authenticity audit**: verified each user-visible capability against real code + tests, removed forensic claims that could not be substantiated (SQLite timeline, `.reg` text export, cramfs detection, Windows device leads, dual-brand top bar), and fixed several copy/language-switch labels. · 能力真实性审计：逐一核对用户可见能力是否可追溯到真实代码 + 测试，移除无法佐证的取证宣称，并修正若干文案与语言切换标签。
- **Release & test tooling**: added capability-audit and real-Chrome production smoke scripts, an SEO-copy lint gate; tests now total 463 (82 files). · 发布与测试工具：新增能力审计与真 Chrome 生产冒烟脚本、SEO 话术 lint 门禁，测试增至 463 例（82 文件）。

### 1.0.0-beta.5 Highlights

- **Stale-version notice**: when the release is older than 90 days, the page shows a top banner with a direct link to GitHub Releases; dismissed for the session, reappears after reload. · 版本过旧提示：超过 90 天时顶部自动提示并可直接跳转 GitHub Releases 下载新版。
- **Mobile usability**: Binary/PCAP/Browser tabs scroll horizontally on narrow screens; the CyberChef three-pane layout pans horizontally on phones instead of squashing. · 移动端可用性：窄屏下标签可横向滚动，CyberChef 三栏改为横向平移。
- **Empty-state layout**: the tool area fills the viewport with no evidence selected; input cards align to the top for a more complete look. · 空态布局：未选择检材时工具区铺满视口，输入卡片顶部对齐。
- **Forensic parsing improvements**: fixed skipped signed-PNG when a corrupted PNG preceded a valid one; Carver adds TIFF/MP4/Ogg/PCAP/FLAC structure-boundary detection; APK v1 verification now compares per-segment `.SF` digests. · 取证解析增强：修复签名损坏 PNG 前置时被跳过的问题，Carver 新增结构边界识别，APK v1 补齐逐段 `.SF` digest 比对。

## Quick Start

### Use Online

Open [forensicspp.com](https://www.forensicspp.com/) and pick a tool from the home page or the left tool catalog.

在线使用：打开 forensicspp.com，从首页或左侧工具目录选择工具即可。

### Local Development

Requirements:

环境要求：

- Node.js `22.13` or higher · Node.js `22.13` 或更高版本
- npm `10` or higher · npm `10` 或更高版本

```bash
git clone https://github.com/DyNooob/ForensicsPP.git
cd ForensicsPP
npm ci
npm run dev
```

Vite starts the dev server and prints the URL, usually `http://localhost:5173/`.

Vite 会启动开发服务器并输出访问地址，默认通常为 `http://localhost:5173/`。

## Production Build

Build the full static site:

构建完整的静态网站：

```bash
npm run build
```

After the build, `dist/` is the deployable static site. Preview the production build:

构建完成后，`dist/` 即为可部署的静态站点。预览生产构建：

```bash
npm run preview
```

Before releasing, run the full verification gate:

发布前建议执行完整校验：

```bash
npm run verify
```

This runs tests, the TypeScript type check, the production build, and artifact validation.

该命令会运行测试、TypeScript 类型检查、生产构建和构建产物校验。

## Static Release Package

Generate a ZIP for static hosting or file distribution:

生成可直接交给静态服务器或文件分发的 ZIP：

```bash
npm run build:standalone
npm run release:package
```

Outputs:

输出文件：

```text
release/ForensicsPP-v1.0.0-beta.6-static.zip
release/SHA256SUMS.txt
```

The ZIP contains the prebuilt static site, with no Node.js launcher. With `build:standalone`, all JS/CSS is inlined into a single `index.html` that opens from `file://` after unzip, and can also be deployed to Nginx, Apache, object storage, or any static host. Use `npm run build` instead when you need subdirectory hosting or on-demand multi-chunk loading.

ZIP 内是已经构建好的静态网站，不包含 Node.js 启动器。使用 `build:standalone` 时全部 JS/CSS 内联进单个 `index.html`，解压后双击即可从 `file://` 打开，也可以部署到 Nginx、Apache、对象存储或其他静态托管平台。需要子目录托管或按需加载多 chunk 时改用 `npm run build`。

## Data & Privacy

Forensics++ requires no backend. Files and text are usually processed in the current browser; UI settings and a recoverable workspace are saved by the browser. Opening a tool does not auto-upload the original file to a Forensics++ server.

Forensics++ 不要求后端服务。文件和文本通常在当前浏览器中处理；界面设置和可恢复的工作区由浏览器保存。原始文件不会因为打开工具而自动上传到 Forensics++ 服务器。

Browser storage only improves continuity of use and does not replace formal evidence custody, read-only imaging, evidence intake, or report archiving. Before handling sensitive data, confirm your browser configuration, extensions, and runtime environment meet your requirements.

浏览器存储只用于提升连续使用体验，不替代正式的检材保管、只读镜像、证据登记或报告归档。处理敏感数据前，请确认当前浏览器配置、扩展和运行环境符合你的工作要求。

You can view storage usage and clear Forensics++ settings and workspace under **Settings → Local Data**.

你可以在 **设置 → 本地数据** 查看存储占用，并清除 Forensics++ 保存的设置和工作区。

## Project Structure

```text
src/components/   Shared UI, ToolHost, and the tool runtime registry
src/config/       Tool catalog, version, and open-source dependencies
src/core/         EvidenceReader, analyzer routing, tool handoff, analysis core
src/features/     Parsers, AnalysisEnvelope, analyzers, and web workers
src/tools/        Tool pages
src/utils/        Storage, file, copy, and general helpers
tests/            Unit and parser tests
scripts/          Build, release, artifact validation, and layout audits
public/           Site assets, legal notices, and bundled static tools
docs/             Release and development documentation
```

## Common Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the dev server |
| `npm run test` | Run the test suite |
| `npm run typecheck` | Run the TypeScript type check |
| `npm run build` | Build the production static site |
| `npm run verify` | Test and build |
| `npm run preview` | Preview the production build |
| `npm run audit:layout` | Check tool layout and key interactions |
| `npm run release:package` | Generate the static release ZIP and checksums |

| 命令 | 用途 |
| --- | --- |
| `npm run dev` | 启动开发服务器 |
| `npm run test` | 运行测试 |
| `npm run typecheck` | 执行 TypeScript 类型检查 |
| `npm run build` | 构建生产静态文件 |
| `npm run verify` | 测试并构建 |
| `npm run preview` | 预览生产构建 |
| `npm run audit:layout` | 检查工具布局和关键交互 |
| `npm run release:package` | 生成静态发布 ZIP 和校验文件 |

The layout audit uses the local Chrome and hits port `5173` by default. If the dev server uses another port:

布局审计默认使用本机 Chrome，并访问 `5173` 端口。如开发服务器使用其他端口：

```bash
AUDIT_URL=http://localhost:5174 npm run audit:layout
```

## Contributing

1. Fork the repo and create a feature branch.
2. Keep tool input, result, error, and clear operations consistent with existing workbenches.
3. Add tests for parsing logic or edge behavior.
4. Run `npm run verify` before committing.
5. Do not upload real evidence, credentials, personal information, or unauthorized data when filing issues.

1. Fork 仓库并创建功能分支。
2. 保持工具输入、结果、错误和清空操作与现有工作台一致。
3. 为解析逻辑或边界行为补充测试。
4. 提交前运行 `npm run verify`。
5. 提交问题时不要上传真实检材、凭据、个人信息或未经授权的数据。

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for fuller conventions, [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) for the analysis architecture, and [`docs/RELEASE.md`](./docs/RELEASE.md) for the release process.

更完整的开发约定见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)，分析架构见 [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)，发布流程见 [`docs/RELEASE.md`](./docs/RELEASE.md)。

## Security

Contact the maintainer via the email published in [`SECURITY.md`](./SECURITY.md). Do not attach real evidence, passwords, access tokens, or full exploit details in a public Issue, Pull Request, or the first message of an email.

请通过 [`SECURITY.md`](./SECURITY.md) 中公布的邮箱联系维护者。请不要在公开 Issue、Pull Request 或邮件首条消息中附上真实检材、密码、访问令牌或完整利用细节。

## License & Contact

This project is licensed under the [MIT License](./LICENSE).

本项目使用 [MIT License](./LICENSE)。

- Repository: [DyNooob/ForensicsPP](https://github.com/DyNooob/ForensicsPP)
- Website: [forensicspp.com](https://www.forensicspp.com/)
- Feedback: `toolab@digiforensics.cn`

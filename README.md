<div align="center">
  <a href="https://www.forensicspp.com/">
    <img src="./public/og-image.png" width="100%" alt="Forensics++ Workbench" />
  </a>

  <h1>Forensics++ Workbench</h1>
  <p>浏览器端电子数据取证工作台 · Browser-local DFIR tools</p>

  <p>
    <a href="https://www.forensicspp.com/"><img alt="Website" src="https://img.shields.io/badge/Website-forensicspp.com-4457A6?style=flat-square" /></a>
    <a href="./LICENSE"><img alt="License MIT" src="https://img.shields.io/badge/License-MIT-1E6B4B?style=flat-square" /></a>
    <img alt="Version 1.0.0 beta 1" src="https://img.shields.io/badge/Version-1.0.0--beta.1-4457A6?style=flat-square" />
    <img alt="React 19" src="https://img.shields.io/badge/React-19-087EA4?style=flat-square" />
    <img alt="Ant Design 5" src="https://img.shields.io/badge/Ant%20Design-5-1677FF?style=flat-square" />
    <a href="https://github.com/DyNooob/ForensicsPP"><img alt="Source repository" src="https://img.shields.io/badge/Source-GitHub-52606D?style=flat-square" /></a>
  </p>

  <p>
    <a href="https://www.forensicspp.com/">在线使用</a>
    · <a href="https://github.com/DyNooob/ForensicsPP">源码仓库</a>
    · <a href="#快速开始">快速开始</a>
    · <a href="#生产构建">生产构建</a>
    · <a href="./CONTRIBUTING.md">参与开发</a>
  </p>
</div>

## Forensics++ 是什么

Forensics++ 是一个面向取证初筛、CTF/MISC、安全研究和日常证据整理的浏览器端工作台。它把常用的文件、图片、邮件、数据库、日志、网络和编码工具放在一个统一界面中，打开浏览器即可使用。

核心定位很简单：**工具要直接、结果要可复核、界面要适合长时间工作。**

常见分析在浏览器本地完成，不依赖 Forensics++ 后端服务。项目完全开源，源码、构建脚本、测试和发布资源均在本仓库中。

## 能做什么

| 方向 | 主要能力 |
| --- | --- |
| 文件与证据 | 文件哈希、文件类型识别、文件头解析、字符串提取、熵分析、二进制结构查看 |
| 图片与附件 | 图片预览、EXIF、PNG 结构、通道查看、隐写线索、损坏图片修复尝试、二维码识别、压缩包目录 |
| 数据库 | SQLite 表浏览、分页、排序、列宽调整、单元格编辑、插入与删除、SQL 查询、WAL/SHM 检查、导出 |
| 邮件与网络 | EML/MSG 解析、HTML 正文查看、邮件头与认证结果、附件查看、HTTP、URL、IOC、PCAP/PCAPNG 摘要 |
| 系统记录 | AndroidManifest、Windows Registry、EVTX、浏览器历史与下载记录、Prefetch、LNK、REG 等常见结构 |
| 文档与时间 | PDF、OOXML、OLE、时间戳转换、时间线整理、多源事件合并 |
| 编码与安全 | 编码解码、进制转换、UUID、JSON、正则、JWT、常见密码哈希、YARA、CyberChef |

工具之间使用统一的输入、结果、复制、下载和清空交互。需要保存的工作区可以在切换工具或刷新页面后继续查看，也可以加入案件报告统一整理。

## 快速开始

### 在线使用

打开 [forensicspp.com](https://www.forensicspp.com/)，从首页或左侧工具目录选择工具即可。

### 本地开发

环境要求：

- Node.js `22.13` 或更高版本
- npm `10` 或更高版本

```bash
git clone https://github.com/DyNooob/ForensicsPP.git
cd ForensicsPP
npm ci
npm run dev
```

Vite 会启动开发服务器并输出访问地址，默认通常为 `http://localhost:5173/`。

## 生产构建

构建完整的静态网站：

```bash
npm run build
```

构建完成后，`dist/` 即为可部署的静态站点。预览生产构建：

```bash
npm run preview
```

发布前建议执行完整校验：

```bash
npm run verify
```

该命令会运行测试、TypeScript 类型检查、生产构建和构建产物校验。

## 静态发布包

生成可直接交给静态服务器或文件分发的 ZIP：

```bash
npm run build
npm run release:package
```

输出文件：

```text
release/ForensicsPP-v1.0.0-beta.1-static.zip
release/SHA256SUMS.txt
```

ZIP 内是已经构建好的静态网站，不包含 Node.js 启动器。解压后可以部署到 Nginx、Apache、对象存储或其他静态托管平台。

## 数据与隐私

Forensics++ 不要求后端服务。文件和文本通常在当前浏览器中处理；界面设置和可恢复的工作区由浏览器保存。原始文件不会因为打开工具而自动上传到 Forensics++ 服务器。

浏览器存储只用于提升连续使用体验，不替代正式的检材保管、只读镜像、证据登记或报告归档。处理敏感数据前，请确认当前浏览器配置、扩展和运行环境符合你的工作要求。

你可以在 **设置 → 本地数据** 查看存储占用，并清除 Forensics++ 保存的设置和工作区。

## 项目结构

```text
src/components/   通用界面与工作台组件
src/config/       工具目录、版本与开源依赖
src/features/     解析器、分析器与 Web Worker
src/tools/        工具页面
src/utils/        存储、文件、复制和通用辅助函数
tests/            单元测试与解析器测试
scripts/          构建、发布、产物校验和布局审计
public/           网站资源、法律说明和内置静态工具
docs/             发布和开发文档
```

## 常用命令

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

布局审计默认使用本机 Chrome，并访问 `5173` 端口。如开发服务器使用其他端口：

```bash
AUDIT_URL=http://localhost:5174 npm run audit:layout
```

## 参与开发

1. Fork 仓库并创建功能分支。
2. 保持工具输入、结果、错误和清空操作与现有工作台一致。
3. 为解析逻辑或边界行为补充测试。
4. 提交前运行 `npm run verify`。
5. 提交问题时不要上传真实检材、凭据、个人信息或未经授权的数据。

更完整的开发约定见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)，发布流程见 [`docs/RELEASE.md`](./docs/RELEASE.md)。

## 安全问题

请通过 [`SECURITY.md`](./SECURITY.md) 中公布的邮箱联系维护者。请不要在公开 Issue、Pull Request 或邮件首条消息中附上真实检材、密码、访问令牌或完整利用细节。

## 许可证与联系

本项目使用 [MIT License](./LICENSE)。

- 项目仓库：[DyNooob/ForensicsPP](https://github.com/DyNooob/ForensicsPP)
- 产品网站：[forensicspp.com](https://www.forensicspp.com/)
- 产品反馈：`toolab@digiforensics.cn`

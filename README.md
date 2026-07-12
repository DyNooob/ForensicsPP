<div align="center">
  <a href="https://www.forensicspp.com/">
    <img src="./public/og-image.png" width="100%" alt="Forensics++ Workbench" />
  </a>

  <h1>Forensics++ Workbench</h1>
  <p>浏览器端电子数据取证工具箱</p>

  <p>
    <a href="https://www.forensicspp.com/"><img alt="Website" src="https://img.shields.io/badge/Website-forensicspp.com-4457A6?style=flat-square" /></a>
    <a href="./LICENSE"><img alt="License MIT" src="https://img.shields.io/badge/License-MIT-1E6B4B?style=flat-square" /></a>
    <img alt="Version 0.7.0" src="https://img.shields.io/badge/Version-0.7.0-4457A6?style=flat-square" />
    <img alt="React 19" src="https://img.shields.io/badge/React-19-087EA4?style=flat-square" />
    <img alt="Ant Design 5" src="https://img.shields.io/badge/Ant%20Design-5-1677FF?style=flat-square" />
    <a href="https://github.com/DyNooob/ForensicsPP/actions/workflows/ci.yml"><img alt="Verify source" src="https://github.com/DyNooob/ForensicsPP/actions/workflows/ci.yml/badge.svg" /></a>
  </p>

  <p>
    <a href="https://www.forensicspp.com/">在线使用</a>
    · <a href="#本地运行">本地运行</a>
    · <a href="#生产构建">生产构建</a>
    · <a href="./CONTRIBUTING.md">参与开发</a>
  </p>
</div>

## 这是什么

Forensics++ 是一个静态 React 网站。哈希、SQLite、邮件、图片、日志等工具直接在浏览器中运行，不需要 Forensics++ 服务器。

仓库包含 React / TypeScript 源码、Worker、构建脚本、测试和页面资源。构建结果在 `dist/`，不提交到 `main`。

## 工具

| 类别 | 工具 |
| --- | --- |
| 文件 | 文件哈希、文件头、字符串、熵、PE / ELF / Mach-O、YARA |
| 图片与压缩包 | 图片工作台、PNG、二维码、ZIP / APK / JAR / OOXML |
| 数据库与结构化数据 | SQLite（含 WAL / SHM）、SQL 转储、JSON、Plist、浏览器数据 |
| 邮件与网络 | EML / MSG、HTTP、URL、IOC、PCAP / PCAPNG |
| 系统记录 | Registry Hive、EVTX、LNK、Prefetch、REG、AndroidManifest |
| 文档与时间 | PDF / OOXML / OLE、时间戳转换、时间线 |
| 转换 | CyberChef、编码解码、进制、UUID、JWT、常见密码哈希 |

应用首页列出全部 36 个入口。

## 数据保存

- 切换工具时，已经打开的页面会保留在当前标签页中，输入和结果不会因为切页消失。
- 刷新或关闭标签页后，文件和大体积分析结果不会保留。
- 主题、语言、最近使用等小型设置保存在 `localStorage`。
- 设置 → 本地数据可以查看占用量并清除本地数据。

不要把浏览器页面当作检材保管位置。需要长期保存的内容请使用工具提供的导出功能。

## 本地运行

需要：

- Node.js `22.13` 或更高版本
- npm `10` 或更高版本

```bash
git clone https://github.com/DyNooob/ForensicsPP.git
cd ForensicsPP
npm ci
npm run dev
```

Vite 会打印访问地址，默认通常是 `http://localhost:5173/`。

## 生产构建

```bash
npm run build
```

该命令会：

1. 清理旧的 `dist/`。
2. 检查源码版权头。
3. 执行 TypeScript 类型检查。
4. 使用 Vite 构建静态文件。
5. 检查 `dist/` 是否缺文件、混入源码或超过体积限制。

本地预览：

```bash
npm run preview
```

完整测试和构建：

```bash
npm run verify
```

## 静态发布包

```bash
npm run build
npm run release:package
```

输出：

```text
release/ForensicsPP-v0.7.0-static.zip
release/SHA256SUMS.txt
```

ZIP 内只有已经构建的静态网站。解压后可放到 GitHub Pages、Nginx、Apache、对象存储或其他静态托管服务。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `npm run dev` | 启动开发服务器 |
| `npm test` | 运行测试 |
| `npm run typecheck` | TypeScript 类型检查 |
| `npm run build` | 构建 `dist/` |
| `npm run verify` | 测试并构建 |
| `npm run preview` | 预览 `dist/` |
| `npm run audit:layout` | 检查全部工具的桌面布局和文件加载状态 |
| `npm run release:package` | 生成静态 ZIP 和校验文件 |

## 目录

```text
src/components/   通用界面组件
src/config/       工具列表、版本、开源依赖
src/features/     解析器和业务逻辑
src/tools/        工具页面
src/utils/        下载、存储等通用代码
tests/            自动测试
scripts/          构建、打包和布局审计
public/           图标、法律页面、CyberChef 等静态文件
docs/releases/    GitHub Release 文案
```

## 部署

仓库已包含 GitHub Pages Workflow。Pages 的 Source 选择 **GitHub Actions**，推送到 `main` 后会自动测试、构建并部署。

其他平台使用：

```text
Build command: npm ci && npm run build
Publish directory: dist
```

不要把仓库根目录、`.git` 或 `node_modules` 作为网站目录。

## 其他

- 开源依赖及仓库地址见 [`src/config/openSource.ts`](./src/config/openSource.ts)。
- 发布步骤见 [`docs/RELEASE.md`](./docs/RELEASE.md)。
- 安全问题请按 [`SECURITY.md`](./SECURITY.md) 中的方式联系，不要在公开 Issue 上传真实检材或凭据。
- 项目许可证见 [`LICENSE`](./LICENSE)。

# 公共库 CDN（EdgeOne Makers）

当前资源域名：`https://static.digiforensics.cn`。本模式只分发构建后的 `assets/vendor-*.js/css`；页面、工具代码、Worker 入口、CyberChef、WASM 和查询数据包暂时仍保留原有加载路径。只修改 Vite 的 `base` 会把 Worker 入口一起移到跨域地址，不能用于此方案。

## 构建与上传

```sh
npm run build:cdn
```

生成两个相互匹配的产物：

- `dist/`：供主站部署的完整站点。
- `release/ForensicsPP-vendor-cdn.zip`：供资源域名部署的公共库包。

在当前 EdgeOne Makers 的 `landing-page-demo` 项目中创建新部署，上传此 ZIP（或解压后的目录）。上传内容根目录应直接包含 `index.html`、`assets/`、`manifest.json`、`edgeone.json`。包内 `edgeone.json` 为库文件设置 CORS 和长期缓存；Makers 根据文件扩展名提供 JavaScript/CSS MIME 类型。配置格式见 [官方文档](https://pages.edgeone.ai/document/edgeone-json)。

在项目域名管理中确认 `static.digiforensics.cn` 的 CNAME 验证通过，HTTPS 证书已签发并覆盖该域名。正式资源请求必须通过 HTTPS 证书验证。

先部署公共库，再执行：

```sh
npm run verify:cdn
```

校验逐个检查线上库文件的 HTTP 状态、CORS、MIME 类型与 SHA-256。全部通过后，再发布本次构建的 `dist/`。只验证首页能打开不够，库文件必须与主站构建版本一致。

## GitHub Pages 自动发布

仓库 Settings → Secrets and variables → Actions → Variables 中增加：

```text
VENDOR_CDN_URL=https://static.digiforensics.cn
```

工作流会构建 CDN 版本，并在发布前检查线上公共库是否匹配；未上传对应文件时发布会停止。该变量为空时仍使用全部本地资源，不依赖 CDN。`npm run build:standalone` 始终保持本地依赖。

## 发布后与回退

- 资源域名每次部署应保留旧版本哈希文件，供尚未刷新的页面继续使用。打包脚本自动保留本机 `release/vendor-cdn-assets/` 中的历史库文件；换电脑或使用全新 CI 环境时，需先恢复该目录或合并线上旧文件。旧部署域名可访问并不代表自定义域名仍可访问旧文件。
- Service Worker 只接管本次构建声明的 CDN 目录下的公共库文件，已缓存的文件可离线复用；其他跨域请求不受影响。
- CDN 首次不可用且本地无缓存时，外部模块仍会加载失败。主站保留库副本，回退方式是清空仓库变量并重新构建发布；不会自动切换到另一份 React 实例。
- 不要把当前主站已有库文件单独替换成公共 CDN 的 UMD 文件。这里上传的是保留模块导入关系的本次 Vite 构建产物。

## 本地验证

```sh
npm run smoke:cdn
```

此命令对实际构建文件模拟 CDN 的跨域响应，验证六个工具加载及哈希 Worker 运行；它不代表线上域名与证书已验证。线上可用性以 `npm run verify:cdn` 为准。

资源上线后，可运行 `CDN_SMOKE_LIVE=1 npm run smoke:cdn`，使用真实 CDN 验证二维码识别、同源 Worker 和缓存后的离线重载。


## 完整资源加速（可选，替代只加速公共库）

`ASSET_CDN_URL` 启用完整资源模式，优先于 `VENDOR_CDN_URL`。`assets/` 下的主程序、懒加载工具、CSS、WASM，以及完整的 `cyberchef/` 和 `lookup/` 都部署到 `https://static.digiforensics.cn/releases/<commit>/`。主站保留页面、SEO、Service Worker 和通常不足 1 KB 的同源 Worker 桥接脚本；分析器代码由桥接脚本从 CDN 导入。IP、手机号、行政区划数据包也随资源包镜像到资源域名根目录的 `lookup/<内容哈希>`，按需下载并保存到独立的数据包缓存；应用版本升级不会改变同一份数据的下载地址。

先提交全部更改，再构建，避免同一提交版本目录被不同的工作区内容覆盖：

```sh
npm run build:resources
npm run smoke:resources
```

生成 `release/ForensicsPP-resource-cdn.zip` 和 `release/resource-cdn-manifest.json`。构建脚本将目标分支标记为 main，使本地资源包与随后同一提交的 main 工作流一致；不得在构建后新增提交再直接使用旧包发布。资源包保留本机既有完整资源版本及 `release/vendor-cdn-assets/` 中的旧公共库。换机时先恢复这两个资源归档目录。

在当前 Makers 项目上传完整 ZIP，部署根目录应包含 `index.html`、`assets/`（兼容旧主站）、`releases/`、`edgeone.json` 和 `manifest.json`。检查没有把压缩包外层目录一起上传。

上传后执行：

```sh
npm run verify:resources
```

只有所有资源的状态、CORS、JS/CSS/WASM MIME 和 SHA-256 都通过后，才设置 GitHub 仓库变量 `ASSET_CDN_URL=https://static.digiforensics.cn`，并合并同一个提交到 main 或手动运行发布。工作流会再次校验完整资源清单，失败不会部署。不要提前启用此变量，也不要只上传旧的 vendor ZIP。

`RESOURCE_FULL_AUDIT=1 npm run smoke:resources` 会额外运行全部工具的布局和文件加载检查。测试通过两个本地 HTTP 源真实执行跨域模块、Worker、WASM 和 CyberChef，不读写用户剪贴板。它不能替代上传后的线上资源校验。

回退：清空 `ASSET_CDN_URL` 并重新发布；已有 `VENDOR_CDN_URL` 可继续维持公共库加速。独立离线构建始终使用本地资源。页面首个 HTML 仍由主站提供，本模式解决资源下载慢，不能保证主站 HTML 或用户所在地网络的延迟。


查询数据的来源、固定版本、字节数和 SHA-256 记录在 `src/features/lookup/dataSources.json`。完整资源构建会先校验本机 `release/lookup-data/` 缓存；缺失时从固定版本上游下载，字节数或 SHA-256 不匹配会停止构建。镜像不改变原数据内容与来源归属。数据更新需显式修改清单，并通过真实 IP、手机号与行政区划查询回归。新增数据包会进入上传清单，发布前与代码资源一起验证，避免代码已上线但数据文件缺失。

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

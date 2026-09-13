# Forensics++ Preview 部署 Runbook

> 目标站点：`pre.forensicspp.com`（未发布预览，必须 noindex + robots `Disallow: /`）
> 生产站：`www.forensicspp.com`（保持可索引，**绝不动**）
> 本 runbook 仅覆盖 Preview 静态部署。

---

## 0. 前置条件

- 本地已 `npm install`（node >= 22.13，TS `~5.7.2`）。
- 部署机：`43.167.9.203`，Web 根：`/www/wwwroot/pre.forensicspp.com`。
- 工具链（macOS 本机已具备）：`rsync`、`sshpass`、`ssh`、`scp`。
- **凭据**：能以 root 登录（`root` 可直接密码登录，无需密钥）。
  - **密码为 `Dy12345.`（注意末尾的英文句点 `.` 是密码一部分！）** 漏掉句点会 `Permission denied`。
  - 目标目录归属 `www:www`，推送后需 `chown -R www:www`。
  - 服务器 `43.167.9.203` 同时承载 `talk.llmcn.org` 等，均走宝塔 + Nginx。

---

## 1. 构建 Preview（env-aware）

```bash
cd /Users/dynooob/Projects/ForensicsPP
VITE_PREVIEW=1 npm run build
```

`VITE_PREVIEW=1` 通过 `vite.config.ts` 的 `define` 注入 `import.meta.env.VITE_PREVIEW`，
并被以下环节消费（均 mode-aware）：

| 产物 | Preview 模式 |
|------|--------------|
| `dist/robots.txt` | `Disallow: /` |
| 根 `index.html` + 10 个 `dist/tools/<slug>/index.html` | 注入 `name="robots" content="noindex,nofollow,noarchive"` |
| 根 `index.html` canonical / og:url | `https://pre.forensicspp.com/` |
| 路由页 canonical / og:url / JSON-LD | `https://pre.forensicspp.com/tools/<slug>/` |
| `dist/sitemap.xml` | 主机 `pre.forensicspp.com`，10 工具路由 + home + legal |
| 顶栏 | 渲染 Preview 横幅（含 `v{version} · 提交 {hash} · 分支 {branch}`） |

构建内已串联 `verify:dist`（preview 模式会**断言 noindex 存在 + robots Disallow**）
与 `lint:seo`，任一不达标即失败。

### 构建后本地核验（不依赖线上）

```bash
# 必须带 VITE_PREVIEW=1，否则 verify-dist 按生产模式断言会误报
VITE_PREVIEW=1 node scripts/verify-dist.mjs
# 期望: Release artifact verified: 197 files, 55.5 MiB.

grep -oE '<link rel="canonical" href="[^"]*"|name="robots" content="[^"]*"' dist/index.html
# 期望: canonical=https://pre.forensicspp.com/ 且 noindex
cat dist/robots.txt      # 期望: Disallow: /
grep -o 'pre.forensicspp.com' dist/sitemap.xml | head -1
```

---

## 2. 部署到服务器（整目录同步，非逐文件）

> **铁律（scp 多文件陷阱）**：禁止 `scp a b c root@host:/dst/` —— 每个文件会按 basename
> 落入 `/dst` 根，覆盖同名文件。本流程用 `rsync -az --delete` 整树同步，一次到位、并清理陈旧文件。

### 2.1 备份远端当前站点（先备后推）

```bash
# 用密钥或密码登录后执行
ssh <USER>@43.167.9.203 \
  'cp -a /www/wwwroot/pre.forensicspp.com /www/wwwroot/pre.forensicspp.com.bak.$(date +%Y%m%d-%H%M%S)'
```

### 2.2 推送（rsync + sshpass，整树覆盖 + 删除陈旧文件）

```bash
export SSHPASS='Dy12345.'
sshpass -e rsync -az --delete --exclude='.user.ini' \
  -e "ssh -o StrictHostKeyChecking=no" \
  /Users/dynooob/Projects/ForensicsPP/dist/ \
  root@43.167.9.203:/www/wwwroot/pre.forensicspp.com/
```

- 末尾的 `dist/` 斜杠 = 把 dist 内容同步进目标目录（保留子目录结构 `assets/`、`tools/`、`cyberchef/`）。
- `--delete` 清除目标目录中源已不存在的文件（防止旧 chunk / 旧路由残留）。本地 `dist` 含 `cyberchef/`（vendored iframe，~10MB），务必确认 `dist/cyberchef` 存在再推，否则会误删线上 CyberChef。
- **`--exclude='.user.ini'` 必加**：宝塔在 web 根写入 `.user.ini`（PHP 配置），并 `chattr +i` 加不可变位，连 root 也无法 `unlink`/`chown`。不加 exclude 时 `--delete` 会尝试删它并报 `Operation not permitted`，且会动到服务器配置——排除后既可正常同步又保留该文件。
- 若用密钥登录，去掉 `sshpass -e`，直接 `rsync -az --delete --exclude='.user.ini' -e "ssh -o StrictHostKeyChecking=no" ...`。

### 2.3 修正归属（若以 root 推送、目录本属 www）

```bash
ssh <USER>@43.167.9.203 'chown -R www:www /www/wwwroot/pre.forensicspp.com'
```
（仅当推送账户与目标归属不一致时执行；宝塔站点通常要求 `www:www`。）

---

## 3. 上线后核验（真实 HTTP）

```bash
# 1) HTTP 状态
curl -sI https://pre.forensicspp.com/ | head -1          # 期望 200
curl -sI https://pre.forensicspp.com/tools/evtx-viewer/ | head -1  # 期望 200

# 2) noindex（整站，含根页与路由页）
curl -s https://pre.forensicspp.com/ | grep -o 'name="robots" content="noindex,nofollow,noarchive"'
curl -s https://pre.forensicspp.com/tools/evtx-viewer/ | grep -o 'noindex,nofollow,noarchive'

# 3) canonical 指向 pre
curl -s https://pre.forensicspp.com/ | grep -o 'rel="canonical" href="https://pre.forensicspp.com/"'

# 4) robots.txt
curl -s https://pre.forensicspp.com/robots.txt          # 期望 Disallow: /
```

也可在本地起静态服务用真实 Chrome 跑 `npm run smoke:prod`（126 项，需先 `npm run build` 为对应模式）。

---

## 4. 回滚

```bash
ssh <USER>@43.167.9.203 \
  'rm -rf /www/wwwroot/pre.forensicspp.com && \
   mv /www/wwwroot/pre.forensicspp.com.bak.<TS> /www/wwwroot/pre.forensicspp.com && \
   chown -R www:www /www/wwwroot/pre.forensicspp.com'
```

---

## 5. 当前状态 / 已知阻塞

- ✅ 本地 `VITE_PREVIEW=1 npm run build` 已通过：`verify:dist`（preview 模式）、`lint:seo`、197 文件 / 55.5 MiB。
- ✅ 根页与 10 个路由页均为 `pre.forensicspp.com` canonical + noindex；`robots.txt` = `Disallow: /`；sitemap 主机 = pre。
- ✅ **已部署上线（2026-09-08 ~21:10）**：
  - 远端备份：`/www/wwwroot/pre.forensicspp.com.bak.20260908-210802`
  - `rsync -az --delete --exclude='.user.ini'` 推送成功（198 文件含 `.user.ini`）。
  - 上线 curl 验证全绿：`/` 与 `/tools/evtx-viewer/` 均 200；`robots.txt`=`Disallow: /`；根页 canonical=`pre.forensicspp.com/` + noindex；路由页 noindex；sitemap 主机=`pre.forensicspp.com/`。
- 凭据教训：密码是 **`Dy12345.`**（末尾句点是密码一部分），漏掉会 `Permission denied`。
- `www.forensicspp.com` 生产站未做任何改动。

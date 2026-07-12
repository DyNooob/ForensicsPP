# Release Guide / 发布指南

This checklist is the canonical release path for Forensics++.

## 1. Prepare

1. Confirm `package.json`, `src/config/app.ts`, `index.html` and the README badge use the intended version.
2. Move relevant entries from `CHANGELOG.md` under **Unreleased** into the new release section.
3. Install exactly the locked dependency tree with `npm ci`.
4. Do not add real evidence, credentials, private email or customer data to tests or fixtures.

## 2. Verify

```bash
npm run verify
npm run release:package
npm audit --omit=dev
git diff --check
```

For interface changes, also run the development server and full layout audit:

```bash
npm run dev -- --port 5174
npm run audit:layout
```

Review the generated report and representative desktop screenshots before release.

## 3. Publish Source

1. Commit the complete source tree; do not commit `dist/`, `release/`, `node_modules/`, audit screenshots or local environment files.
2. Push the reviewed commit to `main`.
3. Confirm **Verify source** succeeds.
4. Confirm **Build and deploy GitHub Pages** succeeds.
5. Verify the custom domain, legal page, PWA manifest, CyberChef entry and several tool routes on the deployed site.

## 4. Tag

After the deployed build is verified:

```bash
git tag -a v0.6.0 -m "Forensics++ v0.6.0"
git push origin v0.6.0
```

The release workflow verifies the source, builds `dist/`, creates `ForensicsPP-v0.6.0-static.zip`, writes `SHA256SUMS.txt`, and publishes both files with `docs/releases/v0.6.0.md` as the bilingual GitHub Release body.

发布工作流会重新验证源码、构建 `dist/`、生成静态 ZIP 与 SHA-256 校验文件，并使用对应的中英文 Release Notes 创建 GitHub Release。`dist/` 和 `release/` 都不提交到 `main`。

## Rollback

Revert the release commit through a normal pull request or push a reviewed corrective commit. GitHub Pages will rebuild from the new `main`. Do not restore an old generated `dist/` tree over the source repository.

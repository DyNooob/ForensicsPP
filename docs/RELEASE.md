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
npm audit --omit=dev --registry=https://registry.npmjs.org
git diff --check
```

For interface changes, also run the development server and full layout audit:

```bash
npm run dev -- --port 5174
AUDIT_URL=http://localhost:5174 npm run audit:layout
```

Review the generated report and representative desktop screenshots before release.

## 3. Publish Source

1. Commit the complete source tree; do not commit `dist/`, `release/`, `node_modules/`, audit screenshots or local environment files.
2. Confirm the release commit uses the maintainer identity `DyNooob <i@digiforensics.cn>`.
3. Push the reviewed commit to `main` on GitHub:

```bash
git push origin main
```

The publishing remote is `origin` (`https://github.com/DyNooob/ForensicsPP.git`). Keep `remote.pushdefault=origin` and `branch.main.remote=origin`; do not push to any other remote. A legacy source remote, if retained for read-only reference, must not have a push URL.

4. Confirm **Verify source** succeeds.
5. Confirm the GitHub CI/build check succeeds, if enabled.
6. Verify the custom domain, legal page, PWA manifest, CyberChef entry and several tool routes on the deployed site.

## 4. Tag

After the deployed build is verified:

```bash
git tag -a vX.Y.Z -m "Forensics++ vX.Y.Z"
git push origin vX.Y.Z
```

The local release commands verify the source, build `dist/`, create `ForensicsPP-vX.Y.Z-static.zip`, and write `SHA256SUMS.txt`. Upload the ZIP, checksum file and `docs/releases/vX.Y.Z.md` through the GitHub repository's release interface. Use a GitHub Release for the versioned package; GitHub Pages is optional and separate from source release.

本地发布命令会重新验证源码、构建 `dist/`、生成静态 ZIP 与 SHA-256 校验文件。将 ZIP、校验文件和对应的中英文 Release Notes 上传到 GitHub 仓库的 Release 页面；GitHub Release 用于版本包发布，GitHub Pages 部署与版本发布分开处理。`dist/` 和 `release/` 都不提交到 `main`。

Do not use `git push --tags` for a release. Push the reviewed version tag explicitly so unrelated local tags are never published.

发布时不要使用 `git push --tags`，只推送本次确认过的版本标签，避免把其他本地标签一并发布。

## Rollback

Revert the release commit through a normal review process or push a reviewed corrective commit to `origin`. Do not restore an old generated `dist/` tree over the source repository.

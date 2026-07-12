# Release Guide

This checklist is the canonical release path for Forensics++.

## 1. Prepare

1. Confirm `package.json`, the application version and README badge use the intended version.
2. Move relevant entries from `CHANGELOG.md` under **Unreleased** into the new release section.
3. Install exactly the locked dependency tree with `npm ci`.
4. Do not add real evidence, credentials, private email or customer data to tests or fixtures.

## 2. Verify

```bash
npm run verify
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

1. Commit the complete source tree; do not commit `dist/`, `node_modules/`, audit screenshots or local environment files.
2. Push the reviewed commit to `main`.
3. Confirm **Verify source** succeeds.
4. Confirm **Build and deploy GitHub Pages** succeeds.
5. Verify the custom domain, legal page, PWA manifest, CyberChef entry and several tool routes on the deployed site.

## 4. Tag

After the deployed build is verified:

```bash
git tag -a v0.5.0 -m "Forensics++ v0.5.0"
git push origin v0.5.0
```

Create a GitHub Release from the tag and use the matching `CHANGELOG.md` section as release notes. The source tag is the release of record; generated Pages assets are built by Actions.

## Rollback

Revert the release commit through a normal pull request or push a reviewed corrective commit. GitHub Pages will rebuild from the new `main`. Do not restore an old generated `dist/` tree over the source repository.

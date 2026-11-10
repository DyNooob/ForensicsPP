# Release engineering / 发布流程

[Documentation](README.md) · [Offline contract](OFFLINE.md) · [Validation](VALIDATION.md)

## Release artifacts and identity

A release consists of a reviewed source commit, an annotated `vX.Y.Z` tag, release notes and verified downloadable assets. The tag must identify the same source used to build the assets. Website deployment, offline packaging and GitHub Release publication are distinct operations.

Generated `dist/`, `release/`, local input caches, screenshots and evidence are not committed. The required user artifact is the complete `offline-static.zip`; GitHub-generated source archives are not a substitute.

## 1. Prepare the source

1. Update `package.json`/lockfile, `src/config/app.ts`, root HTML metadata, README version and release notes consistently.
2. Record new behavior and limitations in the changelog and current guides. Keep old release facts historical.
3. Review dependency/data provenance, notices and corresponding sources.
4. Check the working tree for credentials, private evidence and generated artifacts.
5. Confirm the intended publishing repository explicitly. Do not rely on a different remote's `pushDefault`.

The maintainer identity for this repository is `DyNooob <i@digiforensics.cn>`. Use the existing configured identity; do not rewrite other contributors' authorship.

## 2. Verify website behavior

```sh
npm ci
npm run verify
npm run smoke:prod
npm run smoke:settings
npm run smoke:image
npm run smoke:usability
npm audit --registry=https://registry.npmjs.org
git diff --check
```

Run relevant layout/performance checks. Report exact results and untested dimensions. A failure must be understood, not removed by weakening the corresponding assertion.

## 3. Build the offline package

Prepare matching inputs from a previously verified local offline release; the import and build perform no downloads:

```sh
npm run prepare:offline -- --package /absolute/path/verified-offline-static.zip
npm run build:offline
npm test
npm run smoke:offline
npm run smoke:standalone
npm run release:package -- --variant offline
```

For an initial codec/data update, curate and hash the new local inputs before this phase. Follow the upstream license/build requirements and update provenance. Do not make `build:offline` fetch a missing input.

The package must contain local runtime resources, the three fixed datasets, license inventory, codec sources, loopback launcher and readable usage/release/audit instructions. Variant validation rejects a website/CDN artifact being labeled offline.

## 4. Verify the delivered ZIP

Independently extract the final ZIP. Verify SHA-256 against the version-specific checksum file, expected member count/paths and launcher executable mode. Run offline browser checks with `OFFLINE_ROOT=<extracted package>` and start the actual packaged launcher. Confirm cold-cache queries and worker/WASM execution with external traffic blocked.

Do not assume `dist/` validation covers archive assembly. If only non-runtime packaging metadata changes, demonstrate that the verified extracted runtime bytes still match the final archive.

## 5. Publish source and wait for checks

When publication is authorized, commit the complete source/documentation changes. Push the reviewed source to the explicit repository/branch, using a normal fast-forward or a reviewed merge; do not force-push unrelated history. For this project's GitHub distribution, `origin` is `https://github.com/DyNooob/ForensicsPP.git`.

```sh
git push origin HEAD:main
```

Wait for the source verification and applicable Pages workflow. Ordinary Pages publication uses same-origin built assets. CDN mode is opt-in and requires its matching resources to be uploaded/verified first; see [CDN.md](CDN.md).

## 6. Tag and publish the Release

After checks pass, create only the intended tag:

```sh
git tag -a vX.Y.Z -m "Forensics++ vX.Y.Z"
git push origin vX.Y.Z
```

Create a draft Release using `docs/releases/vX.Y.Z.md` as its body. Attach:

- `ForensicsPP-vX.Y.Z-offline-static.zip`;
- `SHA256SUMS-vX.Y.Z.txt`;
- release notes and the validation/audit record when supplied as separate assets.

Verify the tag target, title, stable/prerelease status, uploaded asset names, sizes and hashes before publishing. Use the release interface or `gh release` with a body file so Markdown/newlines remain exact. Never use `git push --tags` to publish one release.

The manual release-verification workflow checks an existing tag and packages the standard source build; it does not automatically create or publish a GitHub Release. Local publication can also be a deliberate final target; do not push/deploy when only local artifacts are authorized.

## Release-note standard

Lead with what users gain. Describe changes by workflow, download choices, startup requirements, verification, compatibility and known limitations. Separate original evidence from preview derivatives and heuristic findings from validated facts. Describe actual offline/network behavior and avoid generic claims of complete format support or security certification.

## Corrections and rollback

Preserve existing published assets while investigating. Prefer a new patch version for corrected code or bytes; if an exceptional correction is necessary, explain what changed and replace its checksum transparently. Roll back website deployment through a reviewed commit/deployment action. Reverting source does not automatically undo a downloaded ZIP or revoke an exposed credential.

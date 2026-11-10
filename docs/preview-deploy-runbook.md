# Preview deployment / 预览部署

[Hosting](CDN.md) · [Release engineering](RELEASE.md) · [Security policy](../SECURITY.md)

## Purpose and prerequisites

A preview is a separate environment for reviewing a candidate. Use an operator-controlled host, a non-production document root and credentials managed outside the repository. Never copy a live password, private SSH key, token or production server address into this guide.

Prepare the locked toolchain with `npm ci`. Confirm the target environment, access method, backup location and rollback path before making a deployment. This guide provides a procedure; it does not authorize an unrelated host change.

## Build and verify

```sh
VITE_PREVIEW=1 npm run build
VITE_PREVIEW=1 node scripts/verify-dist.mjs
```

The preview flag controls runtime labeling and indexing metadata. Inspect the generated root/route HTML, robots and sitemap rather than assuming an environment variable reached every build stage.

Expected properties:

- noindex metadata on the root and generated route pages;
- `robots.txt` disallows crawling;
- canonical/OG/sitemap metadata use the intended preview-host configuration;
- application version and source identity match the candidate;
- real JS/CSS/WASM and CyberChef files are present.

The preview host policy is defined in `src/seo/seoPages.mjs`. If deploying elsewhere, review that source explicitly instead of inventing an unsupported environment variable.

## Deploy an immutable candidate

Use the hosting service's artifact/deployment mechanism or transfer the complete directory to a fresh release location. Keep an independently addressable previous deployment. Do not copy a few hashed files into a live tree and assume the HTML/modules still match.

SSH deployments should use verified host identity and environment-managed keys. Prefer an account scoped to the preview site. Follow the host's own procedure for permissions and atomic activation; do not disable host-key checks or run destructive root-level cleanup from a generic example.

## Validate the remote result

Check the actual preview origin:

1. Root, legal page, at least one canonical tool route and one SPA fallback route.
2. Version/source identity, preview label and noindex/robots/canonical policy.
3. JS/CSS/WASM status and MIME, plus worker execution.
4. CyberChef document identity and representative operation.
5. Cache/reload behavior and absence of missing old hashes.

A local smoke pass is not a claim that the remote environment was verified. Record target, commit, artifact identity, checks and outcome without recording credentials.

## Rollback and historical exposure

Reactivate the previous verified deployment through the hosting service or operator-controlled release pointer, then repeat the remote checks. Keep investigation evidence in the appropriate private operational system.

Older revisions of this document contained plaintext deployment credentials. They have been removed from the current guide. Existing historical copies must be treated as exposure: the owning operator should rotate/revoke those credentials and review access. Current-file removal does not remediate repository history or prior clones.

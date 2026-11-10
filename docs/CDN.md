# Hosting and CDN / 静态部署与 CDN

[Documentation](README.md) · [Release engineering](RELEASE.md) · [Preview deployment](preview-deploy-runbook.md)

## Distribution modes

| Mode | Build | Deployment contract |
| --- | --- | --- |
| Standard website | `npm run build` | App chunks/styles/workers/WASM are served from the website origin; website lookup data can remain on-demand |
| Vendor CDN | `npm run build:cdn` | Matching emitted vendor modules/styles hosted on the configured resource origin |
| Full resource CDN | `npm run build:resources` | Versioned app/resources with same-origin worker entry bridges and validated cross-origin payloads |
| Complete offline | `npm run build:offline` | Local resources/data/sources, local-resource policy and no runtime CDN fallback |

Do not deploy a CDN-configured HTML entry before its exact referenced content hashes exist on the resource origin. A working CDN hostname alone is insufficient.

## Standard static hosting

Serve `dist/` from the domain root over HTTPS. Return real MIME types for JavaScript, CSS and WASM. For client routes without a generated static page, fall back to `/index.html`; missing asset paths must return a useful 404 rather than the HTML shell.

Example Nginx shape (adapt paths and TLS in your own environment):

```nginx
location /assets/ { try_files $uri =404; }
location /cyberchef/ { try_files $uri =404; }
location /lookup/ { try_files $uri =404; }
location / { try_files $uri $uri/ /index.html; }
```

`public/CNAME` records the project custom domain. The Pages workflow builds and verifies the static artifact before deployment. Ordinary push-triggered publication uses same-origin resources. Its optional manual `use_cdn` input enables repository-configured resource variables only when the operator deliberately selects it.

## Vendor CDN preparation

```sh
npm run build:cdn
npm run smoke:cdn
```

This creates the website artifact plus `release/ForensicsPP-vendor-cdn.zip`. Deploy the resource archive with its expected root layout and CORS/cache configuration, then run `npm run verify:cdn` before deploying the matching website. The package contains emitted ESM, not unrelated public UMD replacements.

## Full resource CDN preparation

```sh
npm run build:resources
npm run smoke:resources
```

The resource archive and manifest use a source-build identity. Keep that commit and the intended deployment branch consistent; do not add a commit and then reuse resources generated under the previous identity.

Upload `release/ForensicsPP-resource-cdn.zip`, preserve old referenced hashes/releases and verify with `npm run verify:resources`. The verifier checks status, CORS, MIME and SHA-256. Resource mirrors include pinned lookup data with stable content-addressed paths. `ASSET_CDN_URL` takes precedence over vendor-only configuration.

The current repository's resource hostname is configured through Actions variables. This document intentionally contains no server credentials or private deployment addresses. Host-specific settings belong in the deployment environment, not source.

## Worker and cache boundaries

Worker entry points remain same-origin where required; full-resource mode imports the corresponding payload through a local bridge. Changing Vite's `base` alone is not a safe substitute for this architecture.

Service-worker build identity includes version, shell and emitted asset identity. The worker only caches resource-CDN locations declared by the build; it is not a general-purpose cross-origin proxy. Keep old immutable assets available for clients that still hold older HTML/cache state.

## Failure and rollback

A missing/mismatched resource fails validation. Use a standard same-origin build or a previously verified deployment rather than silently combining mismatched modules. Do not introduce a second React instance as a runtime fallback. CDN verification does not replace checking the final deployed HTML, tool routes and worker execution.

Offline builds ignore both CDN variables throughout Vite and finalization. Test the offline ZIP independently; success in either website mode is not evidence of offline completeness.

## Cached-page compatibility

A deployment must retain prior immutable `/assets/` URLs. Switching between a self-origin build and CDN mode changes chunk names; cached HTML and already-open lazy-loaded workspaces can still reference the previous names even when the new CDN files are correct. The Pages workflow restores assets from its two preceding successful artifacts without replacing the active HTML, service worker or current worker bridges. It refreshes the cache fingerprint after merging and validates the final upload, with an explicit retained-deployment size budget. A full cache purge is not a substitute for retaining assets used by open clients.

For recovery, the manual `source_ref` input can redeploy an existing application tag using the current deployment workflow. This allows restoring a validated CDN release without inventing a new resource prefix for a workflow-only repair. The deployment helper always comes from the workflow revision; application bytes come from the selected source revision.

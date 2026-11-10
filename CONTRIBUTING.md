# Contributing to Forensics++

[Documentation](docs/README.md) · [Development](docs/DEVELOPMENT.md) · [Security](SECURITY.md)

Contributions should improve a concrete examination workflow while preserving browser-local processing, bounded resource use and honest result semantics. Code, fixtures, documentation, translations and reproducible bug reports are all useful contributions.

## Choose a focused change

Search existing issues and discussions in the issue tracker. For a new analyzer or substantial behavior change, describe the intended input, output, user workflow, format references and limits before starting a large implementation. A new top-level tool is not always needed; consult [workbench organization](docs/WORKBENCH_CONSOLIDATION.md).

Use a bug report for a reproducible defect and a feature request for a proposed workflow. Security reports belong in the private channel described in `SECURITY.md`, not public issue comments.

## Prepare a checkout

```sh
git clone https://github.com/DyNooob/ForensicsPP.git
cd ForensicsPP
npm ci
npm run dev -- --host 127.0.0.1
```

Node.js 22.13+ and npm 10+ are required. Browser smoke tests need Chrome/Chromium. Offline builds additionally require verified local inputs; see [OFFLINE.md](docs/OFFLINE.md).

## Implementation expectations

- Keep parsers independent of React where practical and use shared execution/evidence abstractions.
- Validate offsets, counts, dimensions and expanded sizes before allocation or traversal.
- Make cancellation, stale-result invalidation and resource cleanup part of the feature.
- Preserve source/derived-artifact identity and state uncertainty in structured limitations.
- Add both UI languages, accessible names, help and documented behavior.
- Review new dependencies for browser support, offline assets, license/provenance and size.
- Maintain import, route and persisted-state compatibility deliberately.

## Safe fixtures and reports

Use synthetic or appropriately licensed public data. Record expected values and provenance. Never include private evidence, production credentials, real case material or unreviewed email/packet captures. A public source is not automatically a redistribution license; document its actual terms.

Tests should cover the defect or contract rather than reproduce the implementation's own assumptions. Parser changes normally need valid, malformed and boundary cases. Worker/storage/asset-path changes need real browser execution where relevant.

## Verification

```sh
npm run verify
git diff --check
```

Select additional suites from [VALIDATION.md](docs/VALIDATION.md): browser execution, layout, storage, offline delivery or performance. Do not imply a suite was run if it was not. Explain environment restrictions and remaining gaps.

Documentation-only changes should pass `npm run docs:check`; code/build changes still need the appropriate broader verification. Do not commit generated distribution trees or screenshots merely to demonstrate a check.

## Pull-request description

State the problem and resulting behavior first. Include a concrete trigger/example where helpful, the checks actually run, and material effects on storage, exports, networking, dependencies or compatibility. Add screenshots for visible UI changes. Follow the repository PR template without filling it with unrelated history.

Keep commits and reviews understandable. Address review findings explicitly and avoid mixing unrelated formatting or architecture changes into a focused fix. Maintainers may ask to split a change or narrow unsupported claims.

## Licensing and maintenance

Contributions to project code are distributed under the [MIT License](LICENSE). Preserve third-party notices and do not relicense imported code or data by copying it into the tree. Disclose provenance and licensing limitations for third-party material.

The project uses the lightweight [governance process](docs/GOVERNANCE.md). Releases, vulnerability fixes and reviews depend on maintainer availability; there is no implied commercial support SLA.

# Validation and testing / 测试与验证

[Documentation](README.md) · [1.0 validation record](releases/v1.0.0-audit.md)

## What a passing check means

A test demonstrates a specific behavior for its inputs and environment. It does not certify every file-format variant or the evidentiary meaning of a finding. Keep parser unit tests, known-evidence validation, browser integration, layout and release-package verification distinct.

The 1.0 release record reports **94 test files and 501 tests** at the recorded snapshot. These are measured release results, not hardcoded future targets. Additional tests should change the count.

## Test layers

| Layer | Location/command | Verifies |
| --- | --- | --- |
| Unit and parser contracts | `tests/`, `npm test` | Valid/malformed/boundary inputs, shared contracts and domain results |
| Known-evidence cases | `tests/validation/`, `npm run validate` | Actual analyzer output against generated or public expected evidence |
| Type and source checks | `npm run typecheck`, `check:headers`, `i18n:check`, `docs:check` | Build-time contracts, conventions and documentation links |
| Production artifact | `npm run verify:dist` | Required files, versions, cache identity, boundaries and size budget |
| Browser execution | `smoke:prod`, `smoke:image`, `smoke:settings`, `smoke:usability` | Real routes, workers/WASM, storage and interface workflows |
| Layout | `npm run audit:layout` | Visible tools, controls, overflow, seeded and file-loaded states |
| Offline distribution | `verify-offline.mjs`, `npm run smoke:offline` | Bundled inputs, local resources, cold-context operations and no external runtime requests |

## Standard verification

```sh
npm ci
npm run verify
npm run smoke:prod
npm run smoke:settings
npm run smoke:image
npm run smoke:usability
```

`verify` builds the website first. Run suites against the distribution they are written for: website/CDN test interception and sitemap assertions differ from an inline offline artifact. Tests recognize the offline manifest where website SEO output is intentionally absent.

Browser suites use local Chrome/Chromium. Set `CHROME_PATH` if needed. They create test browser state, local synthetic samples and output under `tmp/`; they should not read private case materials.

## Layout audit

Start a server for the intended source/build, then run:

```sh
AUDIT_URL=http://127.0.0.1:5173 npm run audit:layout
```

Useful options include `AUDIT_WIDTH`, `AUDIT_HEIGHT`, `AUDIT_THEME=dark`, `AUDIT_SCREENSHOTS=1` and `AUDIT_SCREENSHOT_DIR`. Review both machine output and representative screenshots. A layout pass does not demonstrate parser correctness; an analyzer unit test does not demonstrate a usable browser view.

For 1.0, the full audit exercised 35 empty states, 14 populated states, nine file-loaded flows and 12 specialized checks. The two-size usability pass covered 70 tool/viewport combinations. The release record explains which domains had actual file workflows versus parser-only/browser-initialization checks.

## Offline validation

Prepare local inputs as described in [OFFLINE.md](OFFLINE.md), then:

```sh
npm run build:offline
npm test
npm run smoke:offline
npm run smoke:standalone
npm run release:package -- --variant offline
```

The offline smoke opens `index.html` directly under `file://`, without starting a local HTTP server. It starts with fresh browser state and sends non-loopback browser/worker HTTP traffic through a closed proxy. It visits all visible tools and executes bundled lookup queries, Chinese conversion, hashing, SQLite/YARA WASM, a PDF document and a CyberChef recipe. `HEIC_FIXTURE=/absolute/path/to/fixture.heic` enables the recorded iPhone fixture-specific assertion; that fixture is an optional local test input, not a hidden build download.

`OFFLINE_ROOT=/absolute/path/to/extracted/package` tests independently extracted bytes. Verify the final ZIP checksum, members and launcher mode, and repeat key execution against the extraction rather than assuming a successful build proves correct packaging. The test's no-external-request result covers the app flows it executes, not unrelated browser/OS traffic.

## Known-evidence fixtures

`tests/fixtures/expected.json` records generated binary-carving and SQLite recovery expectations. `scripts/gen-validation-fixtures.mjs` regenerates those fixtures. The public EVTX fixture and historical/tampered case-package fixtures have different sizes and purposes; not every fixture is generated or under 16 KiB.

`npm run validate:fixtures` needs the generator's local prerequisites, including a usable `sqlite3` executable. Never regenerate all fixtures casually during an unrelated change. Document source, license, hash, construction steps and expected offsets/values for new material.

## Add a meaningful regression

1. State the externally observable failure or invariant.
2. Use a small safe fixture and the same analyzer shipped to users.
3. Derive expected values independently where practical, including exact offsets or known records.
4. Include malformed/truncated/boundary inputs when they exercise the failure.
5. Exercise lifecycle and browser integration when the change concerns workers, URLs, WASM, storage or cancellation.
6. Record untested dimensions honestly. Do not relabel scaffolded tests or UI rendering as format validation.

## Performance and dependency checks

`npm run perf:baseline` writes a deliberate baseline; `npm run perf:check` compares it. Review a baseline change, rather than updating it merely to hide a regression.

```sh
npm audit --registry=https://registry.npmjs.org
```

Audit results describe the queried advisory database and dependency snapshot. They complement parser bounds, browser testing and private disclosure; they are not a security certification.

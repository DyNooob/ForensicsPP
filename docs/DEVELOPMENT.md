# Development / 开发指南

[Architecture](ARCHITECTURE.md) · [Contributing](../CONTRIBUTING.md) · [Validation](VALIDATION.md)

## Toolchain and setup

Use Node.js 22.13+ and npm 10+. The lockfile defines the dependency tree; use `npm ci`, not an unreviewed dependency refresh. A current browser is required; browser automation uses local Chrome/Chromium or `CHROME_PATH`.

```sh
git clone https://github.com/DyNooob/ForensicsPP.git
cd ForensicsPP
npm ci
npm run dev -- --host 127.0.0.1
```

Run from the repository root. Vite normally selects port 5173 and prints the actual URL. Restrict the host to loopback for ordinary local work; expose it to another device only deliberately.

## Commands

| Command | Role |
| --- | --- |
| `npm run typecheck` | TypeScript validation |
| `npm test` / `npm run test:watch` | Full unit/contract/parser suite or watch mode |
| `npm run verify` | Translation checks, website build/artifact checks and full tests |
| `npm run build` / `npm run preview` | Standard website output and local preview |
| `npm run prepare:offline -- --package <zip>` | Import verified local offline build inputs |
| `npm run build:offline` | Complete offline output, with no input download fallback |
| `npm run smoke:offline` | Fresh-context browser checks with external traffic blocked |
| `npm run audit:layout` | Tool layout, controls and loaded-state audit |
| `npm run validate` | Known-evidence validation cases |
| `npm run check:headers` | Required copyright banners |
| `npm run i18n:check` | Existing translation-source convention check |

Not every command has the same input requirements. Read [VALIDATION.md](VALIDATION.md) before selecting browser suites and [OFFLINE.md](OFFLINE.md) before building offline artifacts.

## Repository layout

```text
src/app/          shell behavior and application hooks
src/components/   shared UI, tool hosts and specialized components
src/config/       tool metadata, help, version and dependency inventory
src/core/         evidence, task runtime, routes and handoff
src/features/     domain parsers, analyzers, workers and result builders
src/tools/        user-facing workspaces
src/seo/          route and crawlable-page metadata
src/styles/       shared visual foundations and workbench styles
src/utils/        browser/storage/file and other shared utilities
tests/            parser, contract, lifecycle and known-evidence tests
scripts/          build, validation, packaging and browser automation
packaging/        offline launcher and distribution instructions
public/           static assets, notices and bundled CyberChef
docs/             current guides, release history and archived records
```

## Add or change a tool

1. Define the user workflow, accepted inputs, outputs and limits. Check whether it belongs inside an existing workbench.
2. Implement parsing in `src/features/<domain>/` with structured values independent of React where practical.
3. Select bounded buffers, streams or `EvidenceReader` based on actual access needs. Add worker cancellation/timeouts for expensive tasks.
4. Declare metadata in `src/config/app.ts` and register the runtime once in `toolRuntimeRegistry.tsx`.
5. Publish an `AnalysisEnvelope` when the tool claims structured forensic reporting. A transform utility need not invent an evidence result.
6. Reuse routing/handoff, file/download helpers, shared UI controls and storage mechanisms.
7. Add both interface languages, tool help, searchable capabilities and relevant documentation.
8. Test valid/malformed/boundary behavior and actual browser execution when changing module/worker/WASM paths.

## Code and UI conventions

Use TypeScript's existing strict configuration and established React patterns. Keep parsers deterministic where possible. Prefer stable machine-readable codes over interpreting translated display text. Handle errors near the action that can explain them.

Use shared controls and `AutoTextarea` rather than one-off editor sizing. Provide accessible names, keyboard behavior and readable empty/error states. Match the existing theme tokens and reduced-motion behavior. Do not add network processing or external runtime dependencies to offline workflows.

New dependencies need an actual browser/offline fit, reviewed license/provenance, a lockfile update and an entry in the application's open-source inventory. Build tooling belongs to preparation/development; users of the prebuilt offline ZIP must not install npm dependencies.

## Storage and compatibility

Version persisted workspace shapes and validate restored input. Maintain case import compatibility and route aliases. Record migrations and behavioral changes in the changelog. Do not silently treat a metadata identity as a computed source hash.

## Files that must stay local

Never commit `dist/`, `release/`, `node_modules/`, environment files, private evidence, generated audit screenshots or local server credentials. Synthetic fixtures and safe expected values belong in source control; release binaries belong in GitHub Release assets.

## Before review

Run `npm run verify` and `git diff --check`. Choose browser/layout checks for the changed execution path. Explain what changed, why, the exact checks performed and remaining limits. See [CONTRIBUTING.md](../CONTRIBUTING.md) for pull-request scope and review requirements.

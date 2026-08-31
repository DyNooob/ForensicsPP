# B6-B Report — Canonical Analyzer Convergence

**Phase:** B6-B (Canonical Analyzer Convergence)
**Branch:** `beta6`
**Commits:** `aa9645c` (B6-A1) → `a77955c` (B6-A2) → `5cfd040` (B6-B0) → `592f75f` (B6-B1)
**Status:** Phase complete. **Beta 6 is NOT declared READY** at the end of B6-B (see §12).

> Terminology correction (applies to all reporting going forward): the correct denominator is the
> **canonical forensic analyzer set = 18** (`canonicalForensicAnalyzers()` in `src/config/app.ts`).
> The legacy phrases "15/38" and "remaining 23 tools" are retired — they mixed the envelope-emitting
> numerator over the *total* tool count (38) instead of over the canonical-analyzer set (18).
> Correct form: **"X / 18 canonical forensic analyzers migrated"**.

---

## 1) Canonical build (commands / exit codes)

| Command | What it does | Result |
|---|---|---|
| `npm run typecheck` (`tsc --noEmit`) | Type-check whole tree | **exit 0, 0 errors** |
| `npm run check:headers` | Copyright-header gate | **320 files pass** |
| `npm run build` | Multi-chunk production build | **exit 0** — must be served over HTTP (`file://` CORS-blocks ES modules) |
| `npm run build:standalone` (`SINGLE_FILE=1`) | Single-file distribution build | **exit 0** (see §2 for model) |
| `npx vite build --outDir node_modules/.fpp-build` | Sandbox-safe build validation (avoids `clean-dist` >50-file guard) | **exit 0** |
| `node scripts/i18n-check.mjs` | i18n inline-ternary gate | **OK** |

---

## 2) Standalone actual model + `file://` results

**Model (verified in `vite.config.ts:48–56`):**
- `build:standalone` (`SINGLE_FILE=1`) inlines the **main-thread** JS/CSS into a single `index.html`
  via `vite-plugin-singlefile`.
- **Web Workers are NOT inlined.** They are emitted as separate `dist/assets/*.worker-*.js` bundles.
  The current build produces **26 worker bundles** (not a single self-contained file).
- `public/cyberchef/` ships as a sibling directory (`CyberChef_v10.19.4.html` + its 5 worker JS
  `ChefWorker/DishWorker/InputWorker/LoaderWorker/ZipWorker` + `assets/modules/images`).

**`file://` runtime smoke (honest result):**
- Opening `index.html` directly works for **non-worker** tools (hashing, encoding, JSON, etc.).
- Worker-backed forensic tools (binary, sqlite, registry, plist, image, evtx, pcap, yara, archive,
  document, email, browser-artifacts, windows, timestamp, android, firmware, ioc, entropy, strings,
  sql, regex, png, qr-decode, bulk) **fail to spawn workers under `file://` origin `"null"`**.
- Therefore the standalone artifact is a **portable offline distribution that needs a static HTTP
  server** (`npm run preview` or any static host) for the forensic (worker) tools — **not** a true
  double-clickable single file. This is the accurate, non-marketing description.

---

## 3) Historical `.fppcase` source / importer

- **Importer (genuine historical path):** `src/features/reporter/casePackage.ts` →
  `readCasePackageFile(file)`. Validates `CASE_PACKAGE_FORMAT`, `SUPPORTED_CASE_PACKAGE_SCHEMAS`,
  **reference-only** (embedded evidence NOT supported), ≤ 32 files, ≤ 64 MiB.
- **Backward compatibility:** `src/models.ts:303,310` explicitly annotate backward compatibility with
  pre-beta.6 records (`.fppcase` imports, legacy results).
- **Re-verification result:** the existing importer contract is the authoritative historical path;
  legacy pre-beta.6 exports are accepted as reference-only. No fabricated "historical exporter" was
  introduced — the prior B6-B0 verification confirmed the genuine importer + validation fixtures
  (`tests/validation`, 16 passing) cover backward-compat.

---

## 4) Object-URL ownership matrix

All `URL.createObjectURL` call sites have a matching `revokeObjectURL` — no permanent leak.

| Site | Created | Revoked | Scope | Lifetime risk |
|---|---|---|---|---|
| `src/utils/files.ts:35` | `createObjectURL(blob)` | `setTimeout` revoke | transient download | low (1 s) |
| `src/tools/QrTool.tsx` | `previewUrlRef` | on clear / unmount | component | low |
| `src/tools/PngTool.tsx` | `setPreviewUrl` | on cleanup | component | low |
| `src/tools/ArchiveTool.tsx:168` | image URL | `useEffect` cleanup | component | low |
| `src/features/reporter/CaseReporter.tsx:545` | `createObjectURL(blob)` | `setTimeout` revoke | export download | medium (60 s window) |
| `src/features/image/analyzer.ts` | `imageObjectUrls[]` (`:47`,`:800`) | explicit revoke (`:809`) + batch | analyzer | low |

Note: `CaseReporter` holds the longest-lived URL (60 s) — acceptable for export, but flagged.

---

## 5) Denominator before / after

- `canonicalForensicAnalyzers()` returns **18** (category ∈ {analysis, network} with
  accepts / capabilities / supportsEvidence / supportsResult / heavy, excluding hidden).
- Numerator (`emitsEnvelope: true`):
  - Start of B6-B: **15 / 18**
  - After B6-B1 (registry, plist, bulk migrated): **18 / 18**
- registry / plist / bulk were **individually judged by actual code semantics**, not forced to a number:
  - `parseRegistryHive` — real `regf`/`hbin` binary parser, FILETIME→ISO, integrity warnings → forensic.
  - `parsePlist` — `bplist00` (binary) + XML, NSDate (Cocoa epoch)→`Date`, key/path/type tree → forensic.
  - `scanBulkArtifacts` — streaming `Blob` scanner with real byte `offset` + `encoding` + `context` → forensic.
  - All three are genuinely evidence-consuming, observation/artifact-producing, provenance-needing → **canonical**.
  - Denominator stays **18** (code-confirmed, not rubber-stamped).

---

## 6) Registry — canonical? / status

- **Canonical: YES.**
- Analyzer: `parseRegistryHive` (`src/features/registry/registry.worker.ts`).
- Envelope: `buildRegistryEnvelope` (`src/features/registry/envelope.ts`) — structure findings,
  integrity/dirty warnings, timeline from `key.lastWrite` (FILETIME→ISO, cap 2000),
  artifacts = key-paths, limitation `REGISTRY_LOGICAL_LOCATION` (no fabricated offset).
- Provenance: **logical** (key path).
- Validation: **fixture-validated** (`tests/registry-envelope.test.ts`, 4 tests).
- Status: **MIGRATED — counted in 18/18.**

## 7) Plist — canonical? / status

- **Canonical: YES.**
- Analyzer: `parsePlist` (`src/features/plist/plist.worker.ts`).
- Envelope: `buildPlistEnvelope` (`src/features/plist/envelope.ts`) — `walkDates()` collects `Date`
  → NSDate timeline (`format:"apple-nsdate"`, cap 2000), artifacts = top-level entries,
  limitation `PLIST_NO_OFFSETS`.
- Provenance: **logical** (no offsets).
- Validation: **fixture-validated** (`tests/plist-envelope.test.ts`, 3 tests).
- Status: **MIGRATED — counted in 18/18.**

## 8) Bulk — canonical? / status

- **Canonical: YES.**
- Analyzer: `scanBulkArtifacts` (`src/tools/BulkArtifactTool.tsx`).
- Envelope: `buildBulkEnvelope` (`src/features/bulk/envelope.ts`) — artifacts with real byte `offset`
  + `confidenceFor()` (PEM=high, network=medium, else low), indicators = network-type items,
  findings `bulk-summary` / `bulk-truncated`.
- Provenance: **exact** (byte offset).
- Validation: **fixture-validated** (`tests/bulk-envelope.test.ts`, 4 tests).
- Note: bulk keeps `supportsResult:false` (in-tool results, not a structured report artifact) but now
  emits an Envelope for Case export + timeline.
- Status: **MIGRATED — counted in 18/18.**

---

## 9) Final Envelope coverage (X / Y)

# **18 / 18 canonical forensic analyzers migrated.**

(The 3 remaining gaps `registry`/`plist`/`bulk` are closed in this commit `592f75f`.)

---

## 10) Validation status per analyzer

All 18 canonical analyzers emit an `AnalysisEnvelope` and publish via
`publishAnalysisResult(toolId, envelope)`, which feeds the Case report (`useCaseReport` →
`analysisResultText` + `envelopeReportMarkdown`) and merges `result.timeline` into the case timeline.

- **Newly migrated + fixture-validated this phase:** registry, plist, bulk (new dedicated tests).
- **Pre-existing levels** (unit-tested / fixture-validated) for the other 15 are recorded in the
  frozen matrix in `docs/beta6/ENVELOPE-COVERAGE.md` ("Canonical 分析器架构矩阵 (冻结)").
- Honesty rules enforced: SQLite "fragment residual ≠ structured deleted record" and Binary
  "signature detection + offset provenance" semantics remain strict; no analyzer is marked
  `fixture-validated` without a real parser test + expected output.

---

## 11) Tests — commands / results

| Command | Result |
|---|---|
| `npm test` (vitest run) | **342 passed** (73 files), exit 0 |
| `npm run validate` (vitest run tests/validation) | **16 passed**, exit 0 |
| `npm run typecheck` | exit 0 |
| `npm run check:headers` | 320 files pass |
| `node scripts/i18n-check.mjs` | OK |

New tests added this phase:
- `tests/registry-envelope.test.ts` (4)
- `tests/plist-envelope.test.ts` (3)
- `tests/bulk-envelope.test.ts` (4)
- Updated `tests/tool-registry.test.ts`: `EXPECTED_ENVELOPE_EMITTERS` 15 → 18; `bulk.emitsEnvelope` now `true`; `canonicalForensicAnalyzers().length` stays 18.

---

## 12) Remaining Beta 6 blockers

This phase (B6-B) **stops at** freezing the correct canonical set + verifying
release/standalone/compat/object-URL + completing the remaining genuine migrations. It does **NOT**
declare Beta 6 READY.

Known remaining work (carried from prior beta.6 planning, not blockers introduced by B6-B):
- **G** first-run guide — deferred/recorded.
- **I** hidden-capability discoverability — decided to specialize/hide some tools.
- **J** CyberChef pinned `v10.19.4` (~12 MB iframe) — no change.
- **analyzerCandidates UI** — DEFERRED (conflicts with decision I).
- A Beta-6 READY call requires a separate gate (full release build + manual smoke of worker tools over
  HTTP + docs/changelog bump). Not performed in B6-B.

---

*Prepared 2026-08-31. No history rewritten; no push performed; no AI co-author trailer added.*

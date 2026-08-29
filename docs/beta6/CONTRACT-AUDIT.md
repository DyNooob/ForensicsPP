# AnalysisEnvelope Contract Audit — beta.6

> Read-only audit of the provenance contracts **before** resuming tool migration (C-B4).
> Source of truth = current code on branch `beta6` (checkpoint `92799de`).
> Verdict per invariant: **HOLD** (already correct, keep + test) or **NEEDS-FIX** (break provenance, must fix before/with C-B4).
> No code was changed during this audit.

## 5.1 Evidence ID 与 SHA-256 必须分离 — ✅ FIXED

- `src/core/evidence/identity.ts:45-48` `deriveEvidenceId`:
  ```ts
  if (file.sha256 && SHA256_RE.test(file.sha256)) return `sha256:${file.sha256.toLowerCase()}`;
  return `pending:${crypto.randomUUID()}`;
  ```
  → When a hash is known, **the evidence id IS the SHA-256 digest**. This is exactly the anti-pattern the plan forbids: two logically distinct evidence items with identical bytes collapse to one identity, losing provenance/verification semantics.
- `src/models.ts:300-305` even documents `id` as `sha256:<hex>` — the anti-pattern is enshrined in the type comment.
- `CaseEvidenceFile` already keeps `sha256` as a **separate** field (models.ts:294-314), so the separation exists structurally; only the *assignment* is wrong.
- **Proposed minimal fix**: `deriveEvidenceId` returns a stable object identity `evid:<uuid>` unconditionally (never content-derived). `sha256` stays as the content fingerprint; `verification`/`source` carry provenance. `isResolvedEvidenceId` is repurposed to mean "has a content hash" (checks `sha256`), not id format. `evidenceKeyFromSources` groups by `id` (object identity) with `name:size:lastModified` fallback for pre-identity records. Update the models.ts comment. No fake Evidence; large evidence can still enter flow because id is assigned immediately (no hash needed).

> **Status: FIXED on branch `beta6`.** `deriveEvidenceId` now returns `evid:<uuid>` (object identity, never the hash); `isResolvedEvidenceId` checks the `evid:` prefix; `evidenceKeyFromSources` keys on `evid:` ids with sha256/legacy fallbacks; `buildEvidenceIdentity` normalizes `sha256` to lowercase; `models.ts:300` comment corrected. `tests/evidence-identity.test.ts` updated + new test asserting unique-per-acquisition identity independent of content. Tools still need to populate `source.id` from `buildEvidenceIdentity` at load — done where lineage requires it (§5.4/§5.5 handoff) and via a follow-up sweep.

## 5.2 一次用户动作 = 一个 Run — ✅ HOLD

- `src/features/analysis/result.ts:73-81` `run` carries `startedAt/completedAt/parameters/runId/sequence`.
- `src/features/analysis/resultStore.ts:93-105` `publishAnalysisResult` increments `sequence` per `(evidenceKey, toolId)` bucket → re-running the same tool+evidence yields a new Run. Correct.
- `clearAnalysisResult` (resultStore:111-118) nulls `current` but **keeps** `runs[]`. Correct.
- **Needs tests (not fix)**: same-evidence multi-run produces R1/R2/R3 with distinct `runId`.

## 5.3 多 Source 必须支持 — ✅ HOLD

- `src/features/analysis/result.ts:61-63` `source: AnalysisSource[]` (array). ✓
- `src/features/analysis/resultStore.ts:82-93` `evidenceKeyFromSources` joins resolved ids with `|`. ✓
- **Needs test (not fix)**: browserartifacts publishing multiple real sources preserves all of them through store → case serialize → import.

## 5.4 Derived Artifact 与 Source Evidence 必须分开 — ❌ NEEDS-FIX

- `src/models.ts`: `CaseEvidenceFile` exists, but there is **no** derived-artifact type carrying an origin link. `AnalysisArtifact` (result.ts:34-46) has `parentId`/`depth` but **no** origin `evidenceId`/`runId`.
- Handoff payload (`src/core/toolHandoff.ts:24-31`) carries only `file: File` — no `artifactId`/`sourceEvidenceId`/`sourceRunId`.
- Dispatch sites `BinaryTool.tsx:384` (`analyzeEmbedded` → `analyzerForArtifact`) and `FirmwareAnalyzerTool.tsx:223` (`analyzeObject`) pass **no lineage** — the carved/extracted object IS a derived artifact but its origin is lost.
- **Proposed minimal fix (coupled with 5.5)**: `ToolHandoff` gains optional `sourceEvidenceId?`, `sourceRunId?`, `sourceResultId?`, `artifactId?`. The target tool, on `takeToolHandoff`, builds a derived `CaseEvidenceFile` with `source: "handoff"` plus a `lineage` field `{ originEvidenceId, originRunId, originResultId, artifactId }`. The derived artifact's `id` is still a stable `evid:<uuid>` (per 5.1); binary/firmware envelope `source` references it. Chain `mail.eml → attachment.exe → binary Run R2` becomes traceable. No tool imports another tool's internals.

## 5.5 Tool Handoff 必须补足 lineage — ❌ NEEDS-FIX

- `src/core/toolHandoff.ts:24-31` `ToolHandoff = { id, sourceTool, targetTool, file, label, createdAt }`. No lineage.
- Same fix as 5.4: add `sourceEvidenceId?`, `sourceRunId?`, `sourceResultId?`, `artifactId?`. Keep `file` for bytes only; never couple tool internals. Lineage must survive case export/import (serialized on the derived `CaseEvidenceFile` + envelope `source`).

## 5.6 Finding 语义必须机器可读 — ❌ NEEDS-FIX (additive)

- `src/features/analysis/result.ts:25-32` `AnalysisFinding = { id?, level, title, detail, category?, confidence? }`.
  - No stable `code` → Reporter cannot match findings without string/regex heuristics.
  - `level` conflates **parser/runtime severity** with **forensic significance** (e.g. "WAL absent" is a limitation, not a risk).
- **Proposed minimal fix**: add required `code: string` (stable, snake_case, e.g. `sqlite.deleted_record_recovered`, `android.debuggable`, `evtx.severity_high`). Keep `level` as significance. Add optional `review?: boolean` (human must eyeball). Update all builders + Reporter to match `code`, not text. No risk-scoring system.

## 7 Canonical fields 足够生成报告 — ✅ HOLD

- `result.ts:82-93` `summary/findings/indicators/artifacts/timeline/limitations/source/run` are all canonical; `data` is analyzer-specific.
- `resultStore.ts:50-69` `caseSafeValue` drops `Uint8Array`/`ArrayBuffer` and truncates strings/arrays/keys — correct behavior.
- **Needs test (not fix)**: live envelope → `caseSafeValue` serialize → reimport → core conclusions (findings/indicators/artifacts/timeline/limitations) unchanged.

## 10 ResultStore multi-run / Case round-trip — ❌ NEEDS-FIX

- `resultStore.ts:128-134` `analysisResultSnapshots()` = `currentAnalysisResults()` = only `latestByTool` (**current result per tool**), NOT the full run history. → export drops older runs. Breaks "同 Evidence 多次 Run 不互相覆盖" and "Case export/import 后 provenance 不丢".
- `resultStore.ts:136-149` `restoreAnalysisResultSnapshots` re-publishes each envelope → bucket is fresh → `sequence = (previous?.runs.length ?? 0) + 1 = 1` → original `runId`/`sequence` are **NOT preserved** across round-trip.
- `resultStore.ts:26` `MAX_HISTORY_PER_TOOL = 8` caps runs per `(evidence,tool)`. Bounded history is acceptable **only if documented + tested** (which runs survive).
- **Proposed minimal fix**: export the full run history (`analysisResultHistory(toolId)` aggregated across evidence buckets), not just `current`. Import must preserve `run.runId`/`run.sequence` — `publishAnalysisResult` should accept an already-stamped envelope (skip re-stamp when `run.runId` present). Choose retention policy = "keep last 8 runs per evidence+tool" (document + test it). Add a Case round-trip test asserting R1..R3 survive export→import with original runIds.

## 11 Worker stale-run race — ❌ NEEDS-FIX

- `src/core/runtime/useToolRuntime.ts:71-97` `run` guards only `setStatus("success")` via `requestId === requestRef.current`. The tool's `publishAnalysisResult` / `setState` calls **inside** the task are NOT guarded unless the tool checks `ctx.requestId` itself.
- Grep of `requestId` across `src/tools` shows the `rt.run`-based migrated heavy tools — **disk, memory, android, archive, document** — have **no** requestId guard around `publishAnalysisResult` (only `WindowsArtifactTool` kept its own `requestRef` and guards at lines 101/110). So a late-completing R1 can publish/overwrite R2.
- **Proposed minimal fix**: add `rt.commit(requestId, fn)` to `ToolRuntime` that invokes `fn` only if `requestId === requestRef.current && activeRef.current`. Wrap every `publishAnalysisResult` + result `setState` in `rt.commit(ctx.requestId, () => …)`. Add race tests: (a) R1 late-complete cannot overwrite R2 `current`; (b) aborting R1 discards late result/error; (c) `publish` from a superseded request is dropped.

## Reporter (DOM fallback) — observation for task #30

- `src/features/reporter/CaseReporter.tsx` (828 lines) is DOM-anchored: it stashes evidence/timeline on `.tool-retained-view` via WeakMap and generates the report from DOM + notes. This is the legacy path the plan wants demoted to fallback.
- `src/features/reporter/casePackage.ts` already writes `analysis.json` (envelopes) + `evidence.json` + `timeline.json` + `notes.json` + `reports/report.md` (schema 1.1). The structured data IS already serialized — Reporter must consume it first, DOM only as fallback.

## Summary of NEEDS-FIX (ordered, minimal, no fabrication)

| # | Invariant | File(s) | Fix |
|---|---|---|---|
| 5.1 | id ≠ sha256 | identity.ts, models.ts | ✅ FIXED: `evid:<uuid>` object identity; sha256 separate (tools still populate `source.id` in 5.4/5.5 sweep) |
| 5.4 | derived artifact ≠ source | models.ts, toolHandoff.ts, BinaryTool, FirmwareAnalyzer | derived `CaseEvidenceFile` + `lineage` |
| 5.5 | handoff lineage | toolHandoff.ts | `sourceEvidenceId/sourceRunId/sourceResultId/artifactId` |
| 5.6 | finding machine-readable | result.ts + all builders + Reporter | add `code` (+`review`), keep `level` |
| 10 | multi-run / round-trip | resultStore.ts | export full history; preserve runId/sequence on import |
| 11 | stale-run race | useToolRuntime.ts + heavy tools | `rt.commit` guard; race tests |

HOLD (keep + add tests): 5.2, 5.3, 7.

## What is already correct (do not regress)

- Multi-source envelope model (5.3).
- Evidence-keyed ResultStore index (EvidenceKey → ToolId → {current, runs}) — foundation for multi-run.
- `caseSafeValue` truncation that keeps canonical fields (7).
- Per-run `runId`/`sequence` assignment on publish.
- `clearAnalysisResult` preserves run history.

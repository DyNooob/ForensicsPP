# Analysis contracts / 分析结果契约

[Architecture](../ARCHITECTURE.md) · [Runtime](RUNTIME.md)

## Envelope

The contract lives in [`src/features/analysis/result.ts`](../../src/features/analysis/result.ts). `AnalysisEnvelope<T>` uses schema version `"1"`; `T` carries domain-specific data.

| Field | Meaning |
| --- | --- |
| `id`, `analyzer` | Result identifier and producing analyzer/version |
| `source[]` | One or more source references, with evidence identity when available |
| `run` | Start/completion times, parameters and result-store run metadata |
| `summary` | Human summary and optional metrics |
| `findings[]` | Stable codes, severity, detail, confidence and review requirements |
| `indicators[]` | Typed observable values, normalization and context |
| `artifacts[]` | Derived objects with IDs, extent and optional lineage/hash |
| `timeline[]` | Events that retain their source context |
| `limitations[]` | Machine-readable codes and explanatory text |
| `data` | Analyzer-specific structured result |

Never infer a machine code by matching a translated finding title. Consumers should use `code` or the documented legacy category fallback. A high-confidence parser observation can still require human interpretation; `review` and limitations must survive export.

## Source, run and artifact identity

Evidence ID identifies a logical source. SHA-256 identifies content when it has actually been computed. They are separate fields and have different costs and semantics. Multiple sources belong in `source[]`; they must not be flattened into an invented filename.

One requested analysis is one run, even when it emits several findings or derived objects. The result store tracks a sequence for repeated examination of the same evidence/tool. Publishing replacement display state must not silently merge unrelated runs.

A derived artifact is distinct from its parent evidence. Preserve offset, size, boundary confidence and parent/depth information when available. A virtual archive path is useful context but does not replace an absolute byte offset when the extraction method can provide one.

## Store and serialization

[`resultStore.ts`](../../src/features/analysis/resultStore.ts) provides current results, per-tool history, subscriptions, case-safe snapshots and snapshot restoration. Binary values are reduced to bounded metadata for case export rather than silently embedding arbitrary source bytes. Functions and unsupported transient state are not serializable results.

Use `publishAnalysisResult` for analyzer results. Clear or invalidate the result when the current input no longer represents that run. Keep the preserved run history behavior distinct from the current-result panel.

## `.fppcase` schema

The writer in [`casePackage.ts`](../../src/features/reporter/casePackage.ts) emits schema **1.1**. Import supports **1.0** and **1.1**.

```text
manifest.json
case.json
notes.json
timeline.json
evidence.json
analysis.json
reports/report.md
```

The manifest records member names, lengths and SHA-256. Schema 1.1 requires registered analysis snapshots. Import validates paths, supported schema, member integrity and resource budgets. Current limits include 64 MiB package input, 32 MiB per expanded entry and 96 MiB total expansion; source constants remain authoritative if these change.

`evidenceEmbedded: false` is intentional: the package stores evidence references and report data, not a duplicate of every original file. Users must preserve originals independently. Hash manifests detect changed package members but do not establish authorship or the truth of a forensic conclusion.

## Compatibility

- Add optional fields compatibly when possible; do not reinterpret an existing field silently.
- Bump the appropriate schema when a consumer cannot safely interpret the new representation.
- Preserve legacy import fixtures and tamper-rejection tests.
- Do not remove the report fallback until all relevant consumers have a structured replacement.
- Document unsupported/missing source data and heuristic reconstruction in `limitations[]`.

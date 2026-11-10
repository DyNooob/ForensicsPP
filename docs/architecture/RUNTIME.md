# Runtime lifecycle / 运行时生命周期

[Architecture](../ARCHITECTURE.md) · [Development](../DEVELOPMENT.md)

## Workspace loading

[`toolRuntimeRegistry.tsx`](../../src/components/toolRuntimeRegistry.tsx) lazy-loads workspaces and supplies required services. `ToolHost` mounts the selected runtime without owning parser-specific state. Catalog metadata controls capability/resource behavior; route aliases resolve before selecting a runtime.

[`resourcePolicy.ts`](../../src/core/runtime/resourcePolicy.ts) resolves declared profiles. Transform tools normally retain state. Large analyzers can suspend or dispose on switch. [`retainedTools.ts`](../../src/core/runtime/retainedTools.ts) bounds retained workspaces and immediately evicts inactive `dispose-on-switch` tools.

## One action, one current run

A task owner should enforce this sequence:

1. Validate input and resource limits before expensive work.
2. Invalidate the prior request and abort owned work.
3. Allocate a run/request identity and create the worker only when required.
4. Apply progress and results only while that identity is still current.
5. On success or failure, clear task state and release owned resources.

`runWorkerTask` handles worker messages, abort listeners, timeout and termination. Shared run guards prevent stale completion from overwriting newer input. Some legacy workspaces implement the same contract locally; a shared hook is not yet universal.

Clear, input replacement, cancellation and tool disposal must invalidate dependent work. A language change alone should preserve the source and active preview; the run's recorded result language can remain part of that run.

## Worker boundaries

Send copied/transferred buffers intentionally. Transferring a live workspace buffer detaches it from its owner; copy first when the workspace must retain original bytes. Workers should send bounded structured results and transfer output buffers where practical.

Error handling should distinguish input validation, unsupported data, timeout and explicit cancellation. Never continue to publish a result after an abort just because an underlying library finishes later.

## Handoff

[`analyzerRouting.ts`](../../src/core/analyzerRouting.ts) chooses a target from artifact type/capabilities. [`toolHandoff.ts`](../../src/core/toolHandoff.ts) uses an in-memory per-target FIFO with at most eight pending items and five-minute expiry. Handoff does not upload or persist raw bytes. The target consumes the file and applies its own size and format checks.

The caller records the derived object's provenance; it should not duplicate the target parser. Queuing a handoff is not proof that the target successfully analyzed it.

## Resource ownership

| Resource | Owner responsibility |
| --- | --- |
| Worker | Terminate after success/error/abort/timeout; do not start on an idle page without need |
| Object URL | Revoke when the associated preview/export is no longer needed; preserve active references across unrelated renders |
| AbortController/listener | Abort obsolete work and remove listeners on completion |
| Timer/animation frame | Cancel on disposal and guard callbacks against stale state |
| Canvas/decoded pixels | Apply pixel limits and release large backing allocations after conversion |
| Persisted workspace | Apply schema/size checks; document what is restored and what remains session-only |

[`useToolWorkspace.ts`](../../src/utils/useToolWorkspace.ts) supports versioned workspace state where adopted. Restoration is a convenience, not a complete evidence-retention system. For example, Image applies distinct analysis and automatic-restoration limits.

## Regression expectations

Exercise cancel during work, Clear before completion, rapid file replacement, switch away/back, language change, reload, storage denial and object-URL cleanup for changes that touch these boundaries. Existing tests under `tests/` cover shared worker, guard, result-store, storage and evidence contracts; browser checks validate actual module/worker execution.

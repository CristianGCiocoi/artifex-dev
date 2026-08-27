# Durable runtime authority

ARTIFEX 2.0 M2 introduces a standalone, service-owned SQLite RunStore for durable
execution coordination. It does not move Project semantic authority into SQLite and it
does not authorize an automated Codex provider. Automated provider dispatch remains an
M3 concern.

## Authority boundaries

- Project Authority alone accepts semantic Project revisions in Git/files.
- ExecutionCoordinator alone changes the durable
  `Workstream → Run → ProjectJob → Attempt` hierarchy.
- Runtime Acceptance Authority interprets evidence and decides
  `ACCEPT`, `REJECT`, `REWORK`, or `REQUIRE_APPROVAL` after an Attempt finishes.
- Workspace promotion requires a recorded acceptance decision and a matching Project
  Authority baseline. A stale baseline becomes `PROMOTION_CONFLICT`.
- Runtime and implementation dashboards are rebuildable projections, never authority.

The standalone coordinator holds a leased generation in the RunStore. Each service
restart receives a new generation and fences the prior process. Related lifecycle
changes commit in one SQLite transaction. A foreign live coordinator cannot acquire the
same standalone instance. The managed-service profile uses a five-minute lease and the
coordinator primitive remains configurable for testing and future service profiles.

## Execution Envelope minimum

Every Run references an approved, versioned envelope containing the Project and baseline,
objective, allowed paths and capabilities, required gates, attempt limit, UNKNOWN stop
policy, recovery policy, and explicit actor. `provider:codex` is rejected by the M2
composition.

## Public control surface

The package exposes these semantic operations through `artifex call`:

- `runtime.bootstrap` and `runtime.status`
- `runtime.attempt.finish`, `runtime.attempt.cancel`, and `runtime.attempt.unknown`
- `runtime.attempt.reconcile` and `runtime.attempt.retry`
- `runtime.accept`
- `runtime.workspace.create` and `runtime.workspace.promote`

Each call takes a JSON object through `--arguments`. Runtime calls share a `store_path`
and stable `service_id`; rebuilding the frontend or service object from those values
reloads committed state. The runtime status response labels itself as a non-authoritative
projection derived from `SQLiteRunStore` and explicitly reports provider dispatch as
disabled.

## UNKNOWN and recovery

An uncertain external result changes the Attempt to `UNKNOWN`, the ProjectJob to
`UNKNOWN`, and the Run to `WAITING_RECONCILIATION` atomically. It cannot be accepted,
retried, or cancelled as though the outcome were known. Reconciliation may recover a
finished result, authorize a safe retry, or leave the Attempt blocked. A recovered result
is still only `FINISHED`; Acceptance Authority remains mandatory.

## Persistence and migration

The M2 migration creates a new empty RunStore. It never fabricates runtime history for a
V1 Project and does not alter accepted M1 provenance. OS service installation and start
policy are completed by M7; the M2 managed-service composition and restart/fencing
contracts are independent of frontend lifetime.

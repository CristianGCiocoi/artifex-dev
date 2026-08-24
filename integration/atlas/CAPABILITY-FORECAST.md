# ARTIFEX capability forecast for a future ATLAS contract

**Status:** DISCOVERY ONLY. The labels describe justified ARTIFEX capability needs, not a request to implement or activate an ATLAS integration. “NEEDED” can mean ARTIFEX already needs the capability at its own boundary; it does **not** mean an ATLAS service is mandatory.

## Decision rules

- `NEEDED`: required by released ARTIFEX architecture or an already accepted integration boundary.
- `PROBABLE`: directly forecast by V2 roadmap, but can remain local/standalone.
- `POSSIBLE`: a plausible optional provider capability with an identified roadmap seam.
- `UNLIKELY`: conflicts with ARTIFEX direction or has no justified use.
- `UNKNOWN`: the roadmap identifies a future area but not enough contract/operational detail.

| Capability | Forecast | Justification and boundary |
| --- | --- | --- |
| Capability discovery | **NEEDED** | The accepted Integration Registry already selects by roles/capabilities, compatibility, health, and provenance. Any future platform-facing discovery must remain optional and capability-neutral. |
| Provider metadata, compatibility, and health | **NEEDED** | Required to avoid vendor-name routing and to make degraded/unavailable state explicit. This is metadata/control-plane behavior, not an ATLAS state authority. |
| Observability | **NEEDED** | ARTIFEX already requires evidence, gates, compatibility reporting, and measured dashboard state. A provider may add telemetry, but ARTIFEX's Evidence Ledger remains canonical. |
| Generic workload execution | **PROBABLE** | V2 forecasts executable task DAGs, durable runs, workers, and capability routing. ARTIFEX can execute locally; any external worker is optional. |
| Long-running jobs | **PROBABLE** | V2 durable runs/resume points and V3 optional distributed work justify a versioned job lifecycle. No mandatory remote scheduler follows. |
| Cancellation | **PROBABLE** | Current integration contract has cancellation/failure mapping; durable work must preserve that behavior. Cancellation cannot imply an acceptance transition. |
| Progress | **POSSIBLE** | Helpful for V2/V3 liveness and visibility, but current ARTIFEX contract does not define a progress event schema. Pollable state may suffice. |
| Artifact management | **POSSIBLE** | ARTIFEX already uses repository artifacts and release artifacts. External artifact storage becomes plausible only for external/distributed workloads and must preserve digests, provenance, retention, and local semantic truth. |
| Queues | **POSSIBLE** | Plausible only after V2/V3 external capacity is deliberately adopted. A queue must expose admission/failure/cancellation rather than hide work. |
| Eventing | **POSSIBLE** | Could improve job and observability transitions in distributed mode, but V1/V2 has no mandatory event bus. A pollable, durable history remains acceptable. |
| Callbacks | **UNKNOWN** | No accepted ARTIFEX need chooses callbacks over polling. If added, callbacks require authentication, idempotency, replay protection, and durable correlation. |
| Streaming | **UNLIKELY** | ARTIFEX's primary contracts are durable packets, results, evidence, and artifacts—not token/UI streaming. It has no justified platform-streaming dependency. |
| Model discovery | **POSSIBLE** | A future optional provider might declare model-backed capabilities, but ARTIFEX does not own or require a model router. Discover capability/limits, not vendor models, unless a later handoff proves otherwise. |
| Model invocation | **POSSIBLE** | Research, evaluation, or an optional agent executor may invoke models, but ARTIFEX must not become coupled to a platform model API. Inputs/outputs remain normal ARTIFEX artifacts. |
| Agent Executor | **POSSIBLE** | ARTIFEX already supports harness/implementer roles. An external executor could be another capability provider if it accepts portable packets and returns bindable results; it is not a Core dependency. |
| Inference | **UNKNOWN** | ARTIFEX is not a model/inference platform. Whether future research/evaluation execution requires inference is not established. |
| GPU/CPU scheduling | **UNKNOWN** | V3 distributed execution is optional, and no ARTIFEX workload profile establishes GPU need. CPU/GPU selection must remain deployment-specific. |
| Compute Resource Broker | **POSSIBLE** | Relevant only if ARTIFEX opts into external/distributed jobs. It must accept optional Resource Envelope constraints without inventing quotas or hardware guarantees. |
| Inference Governor | **UNKNOWN** | No ARTIFEX requirement currently justifies a governor. If model invocation becomes real, rate/resource policy belongs in a future authorized handoff. |
| Distributed execution | **POSSIBLE** | Explicit V3 roadmap seam, but no V1/V2 dependency and no current distributed protocol. |
| Hermes / API General | **POSSIBLE** | Hermes is an accepted preferred ARTIFEX integration, and a generic API surface may be a future provider transport. Neither is mandatory for ARTIFEX and no current route/client is requested. |
| Result retrieval and stale-result classification | **PROBABLE** | ARTIFEX already binds execution baselines and returns `REBASE_REQUIRED`. Any future job provider needs terminal results that preserve those identifiers. |
| Durable run coordination | **PROBABLE** | V2 forecasts SQLite RunStore/index/metrics, durable runs, and resume points. A platform may assist only if it does not replace repository/Git semantic authority. |
| Cross-project knowledge analysis | **POSSIBLE** | V2/V3 forecast cross-project knowledge/pattern mining, with strict provenance and isolation. Centralization, inference, retention, and export remain unknown. |

## Minimum semantic properties where a capability is later supplied by ATLAS

A platform capability is compatible only if it can be consumed as an optional provider and supports:

1. explicit capability/version/health declaration;
2. bounded input and output schemas;
3. stable correlation IDs and idempotent retry semantics;
4. deadline, timeout, cancellation, and terminal failure states;
5. result/artifact digests and provenance;
6. base commit, contract fingerprint, and Project Model fingerprint for execution work;
7. additive, version-negotiated extension;
8. secret-safe, least-privilege, project-scoped authorization; and
9. a clear degraded/unavailable result that permits ARTIFEX standalone operation.

## Explicit non-forecasts

ARTIFEX does not presently justify a mandatory model catalog, model router, token streaming API, centralized queue, GPU scheduler, inference governor, distributed executor, callback broker, or platform-owned database. These remain optional, unknown, or unlikely exactly to avoid shaping ARTIFEX around a current ATLAS implementation.

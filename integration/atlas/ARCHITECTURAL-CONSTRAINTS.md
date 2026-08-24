# ARTIFEX architectural constraints for a future ATLAS Platform Contract

**Status:** DISCOVERY ONLY. These are compatibility constraints, not an ARTIFEX redesign request and not an ATLAS implementation specification.

The deciding question for the Platform Integration Orchestrator is:

> If the contract is defined this way, does it block ARTIFEX or force avoidable coupling?

## Non-negotiable compatibility constraints

| Area | ARTIFEX constraint | Platform-contract implication |
| --- | --- | --- |
| Standalone requirements | ARTIFEX V1 has no mandatory database, daemon, network control plane, model gateway, or remote provider. Manual, Codex, Claude, and Hermes configurations are first-class. | Platform reachability/configuration must be opt-in. Absence, outage, or deconfiguration must yield an explicit degraded/unavailable outcome, not startup failure or loss of semantic function. |
| Canonical authority | Git/files own semantic project truth. ARTIFEX Core owns lifecycle state, transition rules, Acceptance Contracts, Evidence Ledger, gates, waivers, and acceptance. | The platform may execute, coordinate, store derived artifacts, or report telemetry. It must not become a competing authority or mutate ARTIFEX semantic/acceptance state implicitly. |
| Coupling tolerance | ARTIFEX is agent-, interface-, executor-, and provider-neutral. Vendor branching belongs only inside a selected adapter. | Define capabilities and versioned schemas, not Pandora/ORPHEUS/Hermes-specific endpoint semantics. No mandatory product identity, provider-native session, or current ATLAS implementation assumption. |
| Provider abstraction | Roles are interface, harness, implementer, and research_provider; capabilities, health, compatibility, and configuration provenance are declared. | Provider discovery must expose role/capability/version/health metadata and allow ARTIFEX policy to select or decline a provider. |
| Execution identity | An Execution Packet binds task contract, base commit, Project Model fingerprint, acceptance criteria, ownership, expected result, interfaces, and invariants. | Any external work contract must preserve these bindings and return them in a result envelope. ARTIFEX must be able to classify a stale output as `REBASE_REQUIRED`. |
| Latency | Current V1 operations are local/file based. Future discovery should be bounded; execution/research/evolution jobs are not request-path latency critical. | Do not impose a low-latency streaming contract. Support bounded synchronous metadata calls and durable asynchronous work separately. |
| Throughput/concurrency | V1 has no platform throughput target. V2 may add parallel worktrees/workers; V3 distributed execution is optional. | No fixed quota, worker count, or burst assumption is an ARTIFEX requirement. Expose admission, capacity denial, and backpressure explicitly if the platform offers them. |
| Job duration | V2 durable/resumable work and V3 optional distributed work may be long-running. Exact durations are unknown. | Job state needs explicit admitted/running/terminal/cancelled/timed-out/lost semantics, bounded retry, and durable correlation—not provider-opaque sessions. |
| Artifact size | Repository files, evidence, documentation, bundles, and release artifacts are current inputs/outputs. Distributed artifact volume/size is unknown. | Do not assume a central blob store or fixed size. If offered, use digest-addressed references, retention metadata, exportability, and path containment. |
| Compute demand | ARTIFEX is not an inference platform. Current core work is CPU/file/Git-centric; GPU/model needs are unknown and optional. | Do not make GPU, model availability, inference governance, or a compute broker prerequisites. Resource envelopes are optional and distinguish hard constraints from soft preferences. |
| Persistence | Filesystem/Git remain semantic truth. V2 may use SQLite for run/index/metric coordination. | A platform can retain job/telemetry/artifact projections, but ARTIFEX must reconstruct meaning and continue from repository artifacts. Durable remote-only state is auxiliary unless a future handoff changes authority. |
| Eventing | No current mandatory event bus. Future jobs may benefit from observable transitions. | Pollable durable status is sufficient; events/callbacks are optional extensions with correlation, ordering/replay, idempotency, authentication, and retention semantics. |
| Version compatibility | Current integration metadata declares Core compatibility ranges and tested external product versions. | Use explicit protocol/schema versions, additive extension, compatibility negotiation, and fail-closed incompatibility. Never silently reinterpret unknown semantics. |
| Failure tolerance | Executor claims are not acceptance. Integration loss must degrade gracefully, and results can be stale, cancelled, failed, or rebase-required. | Define timeout, cancellation, lost-worker, partial-artifact, duplicate-delivery, retry, and unavailability behavior. No platform failure may advance a gate or erase local recovery evidence. |
| Security | External content is untrusted data; secrets are referenced rather than stored; self-improvement cannot expand privilege. Worktree/file boundaries matter. | Authenticate provider identity; authorize per project/task/capability; apply least privilege; redact secrets; bind work to scoped paths/worktrees; preserve source/artifact provenance; do not grant ambient host or repo authority. |
| Deployment independence | ARTIFEX is cross-platform and distributed as a standalone application; a server/control-plane profile is V3 optional. | A platform contract must not encode VM topology, Caddy/DNS route, container runtime, database, or deployment of the provider. Transport and deployment are separately selected adapters/profiles. |

## Contract tests before a future integration is approved

A proposed ATLAS Platform Contract v1 should be rejected or revised for ARTIFEX if any of these tests fail:

1. **Standalone test:** ARTIFEX can initialize, inspect, plan, execute through an existing local harness, validate, compile, and recover semantic state with the platform absent.
2. **Authority test:** a platform result cannot set ARTIFEX task, integration, milestone, or release acceptance; it is a claim subject to ARTIFEX validation.
3. **Stale-result test:** changing the base commit, contract, or Project Model causes the returned execution result to be non-acceptable (`REBASE_REQUIRED` or equivalent), not silently applied.
4. **Degraded-provider test:** discovery, admission, execution, or research failure produces an explicit record and preserves an approved fallback.
5. **Extension test:** an unknown additive field/capability is ignored safely or rejected by negotiated version—never reinterpreted as a state transition.
6. **Isolation test:** one project/provider cannot read another project's worktree, artifacts, secrets, evidence, or knowledge unless a separate policy authorizes it.
7. **Recovery test:** ARTIFEX can rebuild its semantic state/evidence references from repository artifacts after provider session, queue, callback, or platform persistence loss.
8. **Observability test:** every remote operation has a correlation ID, provider/version provenance, state/terminal reason, and artifact/result digest without leaking secrets.
9. **No hidden work test:** retries, callbacks, background processing, and cancellation are explicit; ARTIFEX can determine whether a task may still be running.

## POTENTIAL ARCHITECTURAL CONFLICT

These are conditional conflict candidates. This discovery makes **no claim** that current ATLAS direction has any of them; they must be checked by the Platform Integration Orchestrator.

### PAC-001 — Centralized semantic state or acceptance

- **ARTIFEX requirement:** Git/files remain semantic truth; ARTIFEX controls lifecycle, evidence, gates, waivers, and acceptance.
- **Why it could conflict:** a platform that writes or owns canonical lifecycle/acceptance state creates two authorities.
- **Impact:** ambiguous recovery, non-reconstructable state, gate bypass, and invalid evidence ownership.
- **Possible variants:** platform as coordination-only service; ARTIFEX-origin versioned projections; owner-controlled import of platform results.
- **Recommendation:** make platform records derived/auxiliary and require ARTIFEX to validate and persist every canonical decision.

### PAC-002 — Opaque provider sessions as the only execution record

- **ARTIFEX requirement:** portable transcript-independent execution packets/results and cross-interface continuity.
- **Why it could conflict:** provider-specific, non-exportable session state cannot be the sole source of task context, result, or cancellation status.
- **Impact:** ARTIFEX cannot classify staleness, recover after provider loss, or switch interfaces safely.
- **Possible variants:** portable packet/result contract with correlation IDs; provider session export; session treated as auxiliary metadata.
- **Recommendation:** require baseline-bound, durable result envelopes; keep provider-native session state optional.

### PAC-003 — Mandatory remote platform or fixed deployment

- **ARTIFEX requirement:** standalone V1 without mandatory daemon/DB/network control plane, portable across Windows/Linux/macOS.
- **Why it could conflict:** requiring ATLAS reachability, a fixed API/Gateway, a specific VM/container topology, or an always-on agent converts an optional provider into a Core dependency.
- **Impact:** blocked offline/local use, reduced distribution portability, and failure propagation outside ARTIFEX control.
- **Possible variants:** opt-in provider profile; local fallback; explicit V3 server profile.
- **Recommendation:** capability negotiation plus visible graceful degradation; do not require platform configuration at ARTIFEX startup.

### PAC-004 — Platform-imposed model/GPU semantics

- **ARTIFEX requirement:** ARTIFEX does not own a model router or inference platform; GPU/model use is not established.
- **Why it could conflict:** a contract that requires model IDs, streaming, GPU scheduling, or inference governance for ordinary ARTIFEX work overfits a possible future workload.
- **Impact:** unnecessary coupling and inability to use simple/local/CPU-only workflows.
- **Possible variants:** generic workload capability with optional resource envelope; separate model/inference extension only when justified.
- **Recommendation:** keep inference/model/GPU capabilities independently discoverable and optional.

## Revisit triggers

Reopen this discovery before any integration handoff if ARTIFEX adopts a concrete external worker, a real server profile, cross-project knowledge export, an inference-backed evaluation path, an artifact store outside the repository, or a callback/event protocol. Each trigger needs a target-specific contract, threat model, failure matrix, and acceptance evidence.

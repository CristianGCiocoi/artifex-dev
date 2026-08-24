# Future Integration Requirements — ARTIFEX → ATLAS

**Status:** DISCOVERY ONLY

**Decision:** no ARTIFEX → ATLAS integration is authorized or implied by this document.
**Ownership:** ARTIFEX Orchestrator remains owner of ARTIFEX. A future Platform Integration Orchestrator may use this package to assess contract compatibility and, only later, coordinate a separately authorized integration handoff.

## Scope and evidence boundary

This is a capability-neutral forecast derived from ARTIFEX's accepted V1 architecture, V1/V2/V3 roadmap, requirements baseline, and existing integration contract. It does not examine ATLAS implementation details, prescribe an ATLAS endpoint, or introduce an ARTIFEX adapter.

Observed ARTIFEX authority:

- ARTIFEX V1 is one Python application, not a microservice system.
- Git/files remain semantic truth; V2 storage may coordinate runs/indexing/metrics but does not replace that truth.
- ARTIFEX owns lifecycle, acceptance, Evidence Ledger, gates, semantic state, and the decision to use an integration.
- Integrations are capability-based and replaceable. Manual, Codex, Claude, and Hermes paths must remain viable when another provider is absent.
- Execution is already expressed through portable, transcript-independent packets bound to base commit, project-model fingerprint, contract fingerprint, ownership, acceptance criteria, interfaces, and invariants.
- V2 forecasts durable runs, task DAGs, parallel worktrees/workers, capability routing, cross-project knowledge, replay, and optional Maestro. V3 makes distributed execution and a server control plane explicitly optional.

The confidence labels below are about ARTIFEX's own prospective needs. They are not implementation approval, demand forecasts, or commitments that ATLAS must provide a service.

## Integration-point register

### AFR-001 — Capability discovery and provider health

| Field | Discovery finding |
| --- | --- |
| ARTIFEX component | Integration Registry; capability-based execution selection |
| Use case | Locate a compatible optional provider by role, version, capabilities, health, and secret-free configuration provenance. |
| Lifecycle / roadmap | V1 contract exists; automatic routing is deferred to V2. |
| Generic capability | Capability discovery, provider metadata, compatibility, health reporting. |
| Criticality | `LIKELY_REQUIRED` for ARTIFEX's own registry; consuming it from ATLAS is `LIKELY_OPTIONAL`. |
| Estimated input / output | Input: Core compatibility range, required role/capabilities, health/policy context. Output: versioned provider descriptors plus an explicit compatible/degraded/unavailable decision. |
| Sync / async | Synchronous query; a cache is acceptable only when its age/freshness is visible. |
| Workload / compute | Control-plane lookup; low CPU; no GPU assumption. |
| Latency | Interactive but not correctness-critical; use a bounded timeout. |
| State / lifecycle | Advisory discovery only. ARTIFEX retains routing, lifecycle, evidence, and acceptance authority. |
| Artifacts / results | Capability descriptor, health report, compatibility/selection decision record. |
| Failure | Provider is not selected; Manual/Codex/Claude/Hermes standalone paths remain available. |
| Observability | Provider ID/version, descriptor version, compatibility result, health freshness, selection reason. |
| Security | Authenticate remote provider identity if introduced; no secrets in descriptors; least-privilege discovery. |
| Unknown | Discovery transport, trust bootstrap, descriptor-cache lifetime. |

### AFR-002 — Optional bounded execution jobs

| Field | Discovery finding |
| --- | --- |
| ARTIFEX component | V2 executable task DAG, durable runs, workers, and parallel worktrees |
| Use case | Optionally submit a bounded implementation or deterministic validation task when an ARTIFEX deployment chooses external capacity. |
| Lifecycle / roadmap | V2. No V1 external-worker dependency is planned. |
| Generic capability | Generic workload execution, long-running jobs, cancellation, progress, result retrieval. |
| Criticality | `LIKELY_OPTIONAL`; platform consumption is `POSSIBLE`. ARTIFEX may keep execution local. |
| Estimated input / output | Input: portable Execution Packet, baseline commit/fingerprints, acceptance contract, ownership, optional Resource Envelope. Output: terminal status, artifact references/digests, structured validation facts, cancellation/failure reason. |
| Sync / async | Asynchronous submission. Polling or callback is **UNKNOWN**; it must never create hidden background work. |
| Workload / compute | Repository-scoped agent/harness task or deterministic validation; CPU-first. GPU need is `UNKNOWN`. |
| Latency | Not request-path sensitive. Admission, cancellation, liveness, and resume are more important than speed. |
| State / lifecycle | `queued → admitted → running → terminal`; ARTIFEX classifies stale results and owns acceptance. |
| Artifacts / results | Immutable result envelope, repository artifact references, logs/evidence references with retention metadata. |
| Failure | No canonical transition. Preserve a resumable local workflow when possible; stale output is `REBASE_REQUIRED`. |
| Observability | Job/attempt/correlation ID, queue/admission state, worker identity/version, baseline, terminal reason, measured resource use if available. |
| Security | Scoped worktree/repository access, task-bound authority, no ambient host privilege, path containment, secret redaction. |
| Unknown | External-worker adoption, sandbox model, capacity policy, result delivery mechanism. |

### AFR-003 — Optional research bundle processing

| Field | Discovery finding |
| --- | --- |
| ARTIFEX component | ResearchRequest / ResearchBundle; optional provider policy |
| Use case | Obtain research or decision-support material without granting a provider authority to transition the Project Model. |
| Lifecycle / roadmap | V1 optional Pandora provider; richer Pandora orchestration is likely in V2. |
| Generic capability | Research workload execution, artifact exchange, capability discovery. |
| Criticality | `LIKELY_OPTIONAL`; platform consumption is `POSSIBLE`. |
| Estimated input / output | Input: bounded ResearchRequest, scope/source policy/depth, correlation ID. Output: validated ResearchBundle with source/provenance metadata or explicit unavailable/failure result. |
| Sync / async | Async preferred; small synchronous requests are `UNKNOWN`. |
| Workload / compute | Network/CPU dominated; whether a provider uses models or GPU is provider-internal and `UNKNOWN`. |
| Latency | Low sensitivity; provenance and deadline matter more than immediate response. |
| State / lifecycle | `request → provider processing → bundle import/validation`; the bundle is non-authoritative input. |
| Artifacts / results | ResearchBundle, source references, provenance, validation report. |
| Failure | Continue without research or use another approved provider. No Core dependency or implicit state transition. |
| Observability | Request ID, provider/version, source policy, bundle digest, validation outcome, timings. |
| Security | Treat external content as data, never instruction authority; preserve source policy and avoid secret-bearing requests. |
| Unknown | Need for transport beyond filesystem exchange, large-result retention, provider trust negotiation. |

### AFR-004 — Knowledge/evolution analysis

| Field | Discovery finding |
| --- | --- |
| ARTIFEX component | Knowledge & Evolution; Improvement Proposals and Candidate Overlays |
| Use case | Optionally evaluate policy-approved lessons or methodology variants while preserving project/instance isolation. |
| Lifecycle / roadmap | V2 cross-project knowledge; V3 pattern mining and methodology evaluation. |
| Generic capability | Batch analysis, artifact management, long-running jobs, observability. |
| Criticality | `POSSIBLE`; platform consumption is `POSSIBLE`. |
| Estimated input / output | Input: explicitly selected knowledge artifacts plus sensitivity/confidence/revisit policy. Output: candidate insight/proposal/evaluation with provenance. |
| Sync / async | Asynchronous batch. |
| Workload / compute | CPU likely; inference/GPU is `UNKNOWN`. |
| Latency | Low. |
| State / lifecycle | `candidate → independently reviewed → accepted/rejected`; no implicit Core modification. |
| Artifacts / results | ImprovementProposal, CandidateOverlay, evaluation evidence. |
| Failure | No promotion and no Core drift; existing project-local knowledge persists. |
| Observability | Input scope, policy decision, provider/model if any, provenance, evaluation version, outcome. |
| Security | Sensitivity labels, cross-project isolation, least disclosure, no secret promotion. |
| Unknown | Whether data leaves ARTIFEX, retention/deletion, inference need, centralized versus local evaluation. |

### AFR-005 — Optional distributed execution

| Field | Discovery finding |
| --- | --- |
| ARTIFEX component | V3 optional distributed execution and server/control-plane profile |
| Use case | Distribute approved workloads only if an ARTIFEX deployment explicitly adopts a server profile. |
| Lifecycle / roadmap | V3 only; roadmap describes it as optional. |
| Generic capability | Distributed execution, compute brokering, queues, eventing, cancellation, progress, artifact management. |
| Criticality | `UNKNOWN`; platform consumption is `POSSIBLE`. |
| Estimated input / output | Future versioned job contract, resource constraints, routing policy, artifact/evidence references → scheduled result, terminal events, optional accounting telemetry. |
| Sync / async | Asynchronous. |
| Workload / compute | CPU/GPU scheduling requirements are `UNKNOWN`. |
| Latency | Control-plane responsiveness matters; workload latency is workload-specific. |
| State / lifecycle | Must be versioned, resumable, cancellable, and reconstructable from durable records. |
| Artifacts / results | Job/result envelopes, pollable history or event stream, artifact references. |
| Failure | Never a V1/V2 dependency; standalone/local operation remains valid. |
| Observability | Correlation IDs, state transitions, queue/admission, worker provenance, failure class. |
| Security | Project isolation, explicit resource authorization, no scheduling-driven privilege expansion. |
| Unknown | All detailed contract semantics; this is a roadmap seam rather than a present integration requirement. |

## Contract-compatibility checklist

A future Platform Integration Orchestrator can use this discovery to ask:

1. Can every optional provider be discovered by declared capabilities rather than product/vendor names?
2. Can ARTIFEX remain fully functional and semantically authoritative when the platform is unavailable, degraded, or deliberately not configured?
3. Can a submitted job preserve and return base commit, execution-contract fingerprint, and Project Model fingerprint so ARTIFEX can reject stale results?
4. Are cancellation, timeout, retry, admission, terminal failure, artifact retention, and observability explicit rather than provider-specific side effects?
5. Can result/artifact extensions be version-negotiated or ignored safely without silently changing ARTIFEX meaning?
6. Does the contract maintain source/provenance, least privilege, secret safety, path containment, and cross-project isolation?
7. Is each platform capability optional until a separately authorized ARTIFEX Integration Handoff defines an actual target and acceptance evidence?

## Non-requirements established by this discovery

- No mandatory ATLAS client, network control plane, database, daemon, model gateway, or API General/Hermes route.
- No ARTIFEX ownership transfer for semantic state, gates, Evidence Ledger, acceptance, or lifecycle transitions.
- No assumption of GPU, model inference, streaming, callbacks, distributed workers, or central artifact storage.
- No runtime deployment, credential creation, adapter, API client, or ATLAS change.

# PIO compatibility assessment — ARTIFEX and ATLAS Platform Contract v1

**Assessment ID:** `PIO-ARTIFEX-COMPATIBILITY-001`

**Status:** `PIO_DISCOVERY_COMPLETE`

**Outcome:** `CONDITIONALLY_COMPATIBLE_WITH_ADDITIVE_CONTRACT_RULES`

**Implementation authority:** none granted
**Read-only evidence cut:** 2026-08-24 local ATLAS architecture/standards/audit materials

## Evidence classified by status

| ATLAS evidence | Observed status | Assessment use |
| --- | --- | --- |
| Contract Standard | Accepted documented rule: contracts name owner/provider, version, policy, I/O, errors, compatibility and status; v1 permits additive/optional evolution only. | Strong alignment with ARTIFEX versioning and non-breaking-extension constraints. |
| Contract Registry schema | Registry schema exists for contract identity/version/status, compatibility, capability/provider and evidence. | A suitable registry shape exists, but it does not by itself define ARTIFEX execution/job semantics. |
| Common Platform boundary | Registry/contracts require extension/population; automation and observability have implementations but lack common contract/registry; task/decision primitives are fragmented/unknown. | Do not claim live coverage for provider discovery, jobs, queues, task coordination, eventing, or common observability. |
| Current ATLAS audit | Registry/review/facts/model/tool/automation/observability are partial, shadow, empty, or fragmented in relevant areas. | Platform capability status must be explicit; semantic contract must not be confused with deployed capability. |
| ARTIFEX future discovery | ARTIFEX is standalone, capability-neutral, Git/files-authoritative, and forecasts optional V2/V3 coordination. | Defines constraints against which Contract v1 is assessed. |

## Capability coverage matrix

| ARTIFEX need | ATLAS evidence | Coverage | PIO finding | Required Contract v1 treatment |
| --- | --- | --- | --- | --- |
| Capability discovery; provider metadata, health, compatibility | Contract Standard + Registry schema; registry needs extension/population | `CONDITIONALLY_COVERED` | Registry shape is compatible. A provider descriptor must explicitly include roles/capabilities, version, health/freshness, provenance, compatibility, and unavailable/degraded states. | Add an optional capability-provider descriptor semantic contract. Do not assert a live registry/provider. |
| ARTIFEX evidence/provenance observability | Common observability is not yet a common contract/projection | `GAP` | Current service-local health/audit is insufficient as an ARTIFEX cross-provider result contract. | Add an optional provenance/operation-observation contract with correlation ID, provider/version, timestamps, terminal reason, and secret-safe references. |
| Generic bounded workload execution | Coordination/automation/task primitives are incomplete or fragmented | `GAP` | No demonstrated common generic job contract covers packet baseline, owner boundaries, admission, cancellation, or stale results. | Add only an optional asynchronous job semantic contract; leave provider status `NOT_IMPLEMENTED` until a real provider exists. |
| Long-running jobs, cancellation, result retrieval | K0C mentions async jobs foundation, but no common demonstrated contract | `GAP` | A future platform job must expose lifecycle and failure semantics rather than an opaque worker session. | Optional job states, deadline, cancellation, retry/idempotency, lost-worker, terminal results, and durable correlation. |
| Artifact exchange / research bundles | Document platform and RAG exist, but ARTIFEX currently needs no central document/RAG dependency | `NOT_REQUESTED` | ARTIFEX ResearchBundle remains valid as a portable provider artifact. Reusing platform artifacts is future optional work, not v1 coverage required. | Do not couple ARTIFEX to Document Platform/RAG/Hindsight. If a generic artifact reference is defined, it must be digest/provenance/retention based. |
| Knowledge/evolution analysis | Hindsight/RAG are existing internal common capabilities; cross-project authority remains sensitive | `NOT_REQUESTED` | ARTIFEX has no present provider requirement. Central knowledge analysis could violate isolation unless separately designed. | No Contract v1 requirement beyond optional, policy-scoped artifact/provenance references. |
| Model discovery, invocation, inference, GPU scheduling, Inference Governor | Model policy/routing is present as fragmented/shadow/absent common contract | `NOT_REQUESTED` | ARTIFEX does not justify mandatory model or GPU semantics. | Keep independently discoverable, additive, and optional. Do not make any of these a job prerequisite. |
| Distributed execution, queues, eventing, callbacks, progress | Future/common capabilities are incomplete; V3 ARTIFEX is optional | `NOT_REQUESTED` | No current ARTIFEX requirement requires a queue/event/callback protocol. | Reserve only compatible extension points; polling plus durable status is sufficient. |
| Hermes / API General | ARTIFEX supports Hermes as a preferred integration but retains standalone Codex/Claude/Manual paths | `NOT_REQUESTED` | No ATLAS route/client binding is required for ARTIFEX compatibility. | Keep transport/provider identity out of the core platform contract. |

## Required additive Contract v1 rules for ARTIFEX compatibility

The PIO concludes that Platform Contract v1 may be declared compatible with ARTIFEX only if it records these rules as semantic, optional contract coverage:

1. **Provider descriptor:** capability/role metadata, semantic version, compatibility range, health plus freshness, secret-free provenance, and an explicit unavailable/degraded result.
2. **Authority and lifecycle boundary:** provider output is a claim/projection; ARTIFEX alone decides its Project Model, Evidence Ledger, gates, waivers, and acceptance.
3. **Optional job envelope:** when a job provider later exists, input/output bind correlation ID, base commit, execution-contract fingerprint, Project Model fingerprint, artifacts/results, cancellation, deadline, and terminal reason.
4. **Operation observation:** versioned, secret-safe correlation/provenance data may be emitted without replacing owner-specific evidence.
5. **Compatibility/degradation:** v1 additions are optional/additive; missing or incompatible capabilities must be visible and leave ARTIFEX standalone paths usable.

These are **contract-coverage rules**, not tickets to create a provider, queue, API, daemon, model service, or integration.

## Confirmed conflicts and conditional conflicts

**Confirmed structural conflicts:** none found in the read-only sources.

The ATLAS Contract Standard's additive/optional major-v1 rule aligns with ARTIFEX. The current platform boundary also correctly recognizes owner-specific approvals/effects and incomplete shared capabilities.

**Conditional conflict candidates retained:** `PAC-001` through `PAC-004` from the ARTIFEX discovery remain open guardrails. They become a real conflict only if Contract v1 or a later provider centralizes ARTIFEX authority, requires opaque sessions, mandates platform deployment, or imposes model/GPU semantics.

## PIO completion and gate disposition

PIO's compatibility discovery is complete. No implementation is recommended or authorized.

`ARCHITECT/HUMAN GATE REQUIRED BEFORE STABILIZATION` applies only to adopting the five required semantic rules into the authoritative ATLAS Platform Contract v1, because that would be a cross-platform architecture decision. It is **not** a request to change ARTIFEX and does not block ARTIFEX normal development.

Until that gate, the correct platform status is:

- Contract Standard: compatible direction;
- ARTIFEX coverage: conditional, not yet recorded as Platform Contract v1 semantic coverage;
- live provider coverage: not asserted;
- ARTIFEX integration: prohibited pending a separate, target-specific `INTEGRATION-HANDOFF`.

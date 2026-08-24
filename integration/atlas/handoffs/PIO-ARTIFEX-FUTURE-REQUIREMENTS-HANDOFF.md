# ARTIFEX → Platform Integration Orchestrator hand-off

**Handoff ID:** `PIO-ARTIFEX-FUTURE-REQUIREMENTS-001`

**Status:** ACCEPTED FOR READ-ONLY CONTRACT COMPATIBILITY ASSESSMENT

**Sender / ARTIFEX owner:** ARTIFEX Orchestrator

**Receiver / cross-project owner:** Platform Integration Orchestrator (PIO)
**Authority boundary:** PIO may assess platform-contract coverage and record a compatibility outcome. ARTIFEX Orchestrator retains all ARTIFEX lifecycle, semantic-state, evidence, acceptance, and future-integration ownership.

## Purpose

Assess whether the prospective ATLAS Platform Contract v1 can cover ARTIFEX's likely future capabilities without making ARTIFEX dependent on ATLAS, current ATLAS implementation details, a specific provider, or a server deployment profile.

This hand-off does **not** authorize:

- an ARTIFEX adapter, API client, client SDK, transport, credential, deployment, or runtime activation;
- an ATLAS source/runtime/configuration change;
- a transfer of ARTIFEX Project Model, Evidence Ledger, acceptance, or lifecycle authority;
- an ARTIFEX architectural redesign; or
- a claim that any platform capability is live merely because its architecture documents name it.

## Inputs

| Artifact | Purpose |
| --- | --- |
| `integration/atlas/FUTURE-INTEGRATION-REQUIREMENTS.md` | Five evidence-backed prospective integration points and their failure/security/lifecycle constraints. |
| `integration/atlas/CAPABILITY-FORECAST.md` | Need classification without prescribing an implementation. |
| `integration/atlas/ARCHITECTURAL-CONSTRAINTS.md` | Compatibility invariants, conditional conflicts, and contract tests. |
| `integration/atlas/machine-readable/artifex-atlas-future-requirements.yaml` | Machine-readable requirements, non-goals, acceptance checklist, and conflict candidates. |
| ATLAS Contract Standard / Common Platform boundary / current audit records | Read-only platform evidence. |

## Questions PIO must answer

1. Does Contract v1 permit capability-neutral, optional provider discovery with explicit version, health, compatibility, and provenance?
2. Can an optional job capability preserve ARTIFEX execution baselines and explicit terminal/cancellation/failure states without becoming ARTIFEX authority?
3. Can artifact/result/observability data be returned as versioned, provenance-bound projections while ARTIFEX retains canonical state?
4. Are coordination, automation, model/inference, and distributed execution treated according to current evidence—partial, future, or unavailable—not implied live?
5. Can every required contract provision be additive/optional within major v1?
6. Does the resulting contract leave ARTIFEX standalone operation, local fallback, and deployment independence intact?

## PIO acceptance criteria

The PIO outcome must:

- classify each ARTIFEX `NEEDED`/`PROBABLE` capability as `COVERED`, `CONDITIONALLY_COVERED`, `GAP`, or `NOT_REQUESTED`;
- distinguish a semantic contract from a deployed/live provider;
- identify any confirmed conflict separately from conditional conflict candidates;
- state the minimum additive contract properties before Platform Contract v1 can claim ARTIFEX compatibility;
- preserve owner/authority boundaries and all discovery-only non-goals; and
- produce no implementation or deployment mutation.

## Stop conditions

PIO must stop and request an Architect/Human Gate rather than infer authority if the proposed platform contract would:

- centralize ARTIFEX semantic state, evidence, gates, or acceptance;
- mandate platform availability, a remote daemon, a database, a model gateway, or a fixed deployment;
- make opaque provider sessions the only recoverable execution record;
- require GPU/model/streaming semantics for ordinary ARTIFEX work; or
- introduce a breaking required-field, semantic, authority, or effect change within contract major version 1.

## Completion record

The PIO assessment is recorded in:

- `integration/atlas/pio/PIO-ARTIFEX-COMPATIBILITY-ASSESSMENT.md`
- `integration/atlas/pio/machine-readable/pio-artifex-compatibility-assessment.yaml`

A future integration remains prohibited until a real ARTIFEX trigger produces an independent, target-specific `INTEGRATION-HANDOFF`.

# M2 — Workflow & Validation Core

## Goal
Make ARTIFEX the authority for workflow/acceptance rather than agent narration.

## Tasks

- **M2-T01 Stage state machine** with allowed forward/back transitions.
- **M2-T02 Stage Contract** requires/produces/capabilities/validators/transitions/liveness.
- **M2-T03 Acceptance Contract** immutable/fingerprinted after task start.
- **M2-T04 Typed Validator framework** deterministic/structured/independent-agent/manual abstractions.
- **M2-T05 Evidence Ledger** bound to commit/contract/model fingerprints; secret scrubbing/minimization.
- **M2-T06 Hierarchical Gate Graph** task→integration→milestone→release.
- **M2-T07 Waivers** request/authority/expiry semantics.
- **M2-T08 Evidence invalidation** current→STALE propagation.
- **M2-T09 Execution baseline binding** and `REBASE_REQUIRED`.
- **M2-T10 Liveness Guard** revisit/no-progress/stall detection.
- **M2-T11 Instruction trust hierarchy** external content cannot gain instruction authority.
- **M2-T12 Adversarial validation suite** premature done, self-certification, tampering, spoofing, stale evidence, waiver abuse, loop, stale worker.

## Required milestone evidence
Every adversarial scenario must fail safely. Deterministic checks must not be replaced with LLM narration when measurable.

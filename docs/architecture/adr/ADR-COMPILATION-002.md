# ADR-COMPILATION-002 — Project canonical understanding into generated views

Status: ACCEPTED
Date: 2026-08-22
ChangeSet: CHG-SELF-001
Supersedes: none

## Context

The V1 typed Project Model intentionally stores project identity, Git state, typed artifacts, typed entities, provenance, dependencies, and status. The Compilation Layer historically also accepted convenient rich mappings whose top-level documentation vocabulary is not part of the canonical Project Model schema.

Self-hosting requires the actual schema-valid ARTIFEX Project Model—not a test-only duplicate—to produce complete understanding views and a fresh-context comprehension rubric.

## Decision

The Compilation Layer will expose a pure projection that assembles its read model from the canonical Project Model:

1. The original Project Model remains the sole fingerprinted canonical input.
2. Only `ACCEPTED` artifacts may contribute the reserved `metadata.understanding` mapping.
3. The namespace is allowlisted to the existing Compilation Layer vocabulary.
4. Contributions are evaluated in stable artifact-ID order; unequal duplicate fields fail closed.
5. Typed entities are projected into deterministic requirement, invariant, capability, interface, milestone, and task collections when the accepted understanding mapping does not already supply that field.
6. Existing rich mapping inputs remain supported without mutation.
7. Rendered documents, packets, dashboards, shims, and rubrics remain explicitly non-canonical and carry the raw Project Model fingerprint.

## Authority boundary

This decision changes only the Compilation Layer read model. It does not change the Project Model schema, accepted Architecture, invariants, Core acceptance authority, ChangeSet authority, or integration privileges. It is therefore a minor implementation ADR and does not require Architect escalation under the frozen policy.

## Consequences

Schema-valid projects can compile complete documentation without a parallel semantic file. Ambiguous duplicate accepted meanings are rejected instead of merged by filesystem or insertion order. Projects that do not use `metadata.understanding` still receive deterministic entity-derived sections and honest missing-topic results.

## Rollback

Remove the projection calls and module. Existing rich mapping callers continue to work under the prior compiler behavior; generated self views can be deleted because they are non-canonical.

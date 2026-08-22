# ADR-RELEASE-001 — Canonical release evidence and V1 identity

Status: ACCEPTED
Date: 2026-08-22
ChangeSet: CHG-SELF-RELEASE

## Context

ARTIFEX's Validation component already defines the authoritative `EvidenceEntry` integrity payload, but the published YAML schema and historical repository files use incompatible shapes. The package also cannot truthfully identify as 1.0.0 while mandatory integrations declare an exclusive 1.0.0 ceiling.

## Decision

1. `EvidenceEntry` payload version 2.0 is the sole canonical persisted acceptance-evidence form for new evidence.
2. Canonical evidence includes explicit validator ID, version, kind, producer identity, independence, immutable binding, facts, output, timestamp, and integrity hash.
3. Known older shapes are classified `LEGACY_HISTORICAL`; unknown or malformed shapes fail. Classification never confers freshness or acceptance.
4. Final release gates consume only current canonical evidence bound to the final candidate. Historical milestone evidence is supporting history.
5. A deterministic release verifier reads repository state and fails closed; it cannot transition acceptance or create evidence.
6. Core/package version becomes 1.0.0 and all bundled integrations declare and test compatibility through the next major boundary, `<2.0.0`.
7. Source and native artifacts must report the same version and source identity.

## Consequences

Historical records remain inspectable but are no longer confused with current evidence. Release checks become reproducible from a clean repository. Compatibility remains explicit rather than inferred. The schema change intentionally rejects pre-2.0 evidence at canonical-load boundaries.

## Rollback

Revert source changes before publishing GA. Do not rewrite ledger history, release evidence, or a published tag. If a 1.0.0 candidate fails, issue a new candidate after correction.

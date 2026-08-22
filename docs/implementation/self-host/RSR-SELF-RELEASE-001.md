# RSR-SELF-RELEASE-001 — V1 release convergence assessment

Status: ACCEPTED
ChangeSet: CHG-SELF-RELEASE
Milestone: M11

## Question

What source changes are required for a truthful ARTIFEX 1.0.0 release after CHG-SELF-001, without rewriting historical evidence or weakening Core acceptance?

## Findings

Three release blockers are mechanical rather than architectural:

1. The in-memory `EvidenceEntry` and append-only `EvidenceLedger` use a flat record with explicit validator identity and `independent_of_executor`, while the published acceptance-evidence schema describes a different nested form. Historical milestone YAML also uses legacy wrappers. Only a typed, versioned codec can distinguish current canonical evidence from preserved historical representations without silently inventing provenance.
2. Package/Core version is `0.1.0`, while every integration's compatibility maximum is exclusive `1.0.0`. A 1.0.0 version bump without widening the tested range would make all integrations report incompatible.
3. The current traceability command checks requirement ownership and architecture only. Final release needs a deterministic verifier for requirement-to-task/evidence/gate coverage, mandatory gate presence, version consistency, generated-view freshness, and release status.

## Selected change

- Define canonical acceptance evidence schema/version 2.0 aligned byte-for-byte with `EvidenceEntry` payloads.
- Add typed YAML/JSON serialization, parsing, integrity verification, duplicate detection, and explicit legacy classification. Legacy documents remain unchanged and cannot be promoted to current evidence without independent revalidation.
- Add a deterministic release verifier that fails closed on missing mandatory gates, invalid evidence, version/compatibility disagreement, incomplete traceability, stale generated views, active mandatory waivers, or status inconsistency.
- Extend traceability validation to require explicit task, evidence, and gate mappings for every accepted requirement.
- Set Core/package version to `1.0.0`, update the lockfile, widen all integration compatibility ranges to tested `>=0.1.0,<2.0.0`, and add compatibility/version tests.
- Extend CI with locked source distribution build and isolated wheel/sdist identity smoke while retaining the existing six source and three native jobs.

## Historical evidence policy

M00–M10 evidence files are immutable historical inputs. The verifier classifies their known legacy encodings but does not treat them as current final-candidate evidence. M11 will create fresh final-candidate BUILD, VALIDATION, UNDERSTANDING, CONTINUITY, PORTABILITY, PACKAGING, SELFHOST, and SECURITY evidence under the canonical 2.0 codec.

Missing historical gate/history records may be added only as explicit reconciliation records backed by independently reproduced facts. No old evidence hash, timestamp, validator identity, or outcome may be rewritten.

## Authority and risk

The change does not add an acceptance authority. Core still evaluates immutable contracts and current independent evidence. The main risks are accidental legacy promotion, version drift, and a verifier that accepts narrated metrics. Controls are explicit formats, fail-closed parsing, measured repository state, exact version assertions, and adversarial tests.

No major Architecture component or invariant changes, so Architect escalation is not required.

## Rollback

Before GA, revert the implementation commit and retain V1 as unreleased. Canonical 2.0 evidence already appended remains historical and can be invalidated with a new append-only event; it must not be deleted. Never move a published release tag or silently downgrade an installed 1.0.0 artifact.

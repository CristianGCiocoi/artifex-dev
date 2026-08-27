# M8A Acceptance Report

## Identity

- Canonical M4/M5/M6A-checkpoint base: `28b8126f7fed53a2ceeae60d7ddefc86630e5c43`
- Implementation baseline: `8bc41f00fdea17ba62cf4557cc2419b73a7ed30d`
- Contract digest: `77a0a4330677c814cb1d6cb874cd8f759662f5351812acffb1fea7f73f5b646b`

## Accepted outcome

M8A provides a transactional Organizational Knowledge authority outside Project
repositories. Promoted records retain source Project revision/fingerprint, source lesson,
provenance, evidence digests, validation/promotion actors, confidence, applicability,
freshness, sensitivity and policy decision. Search and recommendation are advisory and
fail closed on inapplicable, stale, restricted or insufficiently proven content.

Adoption is an explicit semantic proposal followed by optimistic Project Authority
acceptance. It is not implemented through the V1 ProjectLessonStore. V1 instance
knowledge is only classified into non-searchable quarantine; migration acceptance is N/A.

## Public outcome

J12 passed through multiple public CLI processes from a clean installed wheel. Project B
remained byte-, revision- and fingerprint-identical after recommendation and adversarial
attempts. Explicit adoption advanced B from revision 1 to 2 and retained complete lineage
after restart. Low-confidence, stale, forged, direct-mutation and cross-project-leak paths
failed closed.

## Validation

Ruff and strict mypy over 89 modules passed. M8A-focused validation passed 6 tests in the
integration-owner rerun and 49 focused/compatibility tests in the workstream. The broad
suite excluding the preserved V1 release regression passed 420 tests with 7 Windows
symlink skips.

## Verdict

`ACCEPTED`

# ARTIFEX V1 — Final Release Gate

Core V1 GA requires all mandatory conditions:

## Product
- BUILD PASS
- VALIDATION PASS
- UNDERSTANDING PASS
- CONTINUITY PASS
- PORTABILITY PASS
- PACKAGING PASS
- SELF-HOST PASS

## Integration
- Manual fallback PASS
- Hermes preferred path PASS
- Codex standalone PASS
- Claude standalone PASS
- Interface continuity PASS

## Project truth
- requirements traceability current
- no critical orphan requirements
- evidence current for release claims
- documentation current
- no unresolved critical architecture escalation
- no secret-leak finding
- no privilege-escalation finding

## Self-host test

ARTIFEX adopts its own repository and completes a real `ChangeSet` through:
intent → research/impact → architecture delta → plan → implementation → evidence → docs/dashboard → comprehension → lesson.

## Optional providers

DeepSeek and Pandora packs are released only if their own gates pass. Their absence/failure does not block ARTIFEX Core V1 GA.

## Release result

PASS → tag V1 release candidate/final per release policy.
FAIL → identify blocking gates; do not narratively override them.

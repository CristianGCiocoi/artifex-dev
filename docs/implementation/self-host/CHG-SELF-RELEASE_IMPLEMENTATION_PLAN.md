# CHG-SELF-RELEASE — Implementation and validation plan

Status: FROZEN
Milestone: M11
Route: Manual fallback worker packet with independent Codex validation

## Worker-owned paths

- `src/artifex/validation/evidence.py`
- `src/artifex/validation/__init__.py`
- `schemas/acceptance-evidence.schema.json`
- `scripts/validate_release.py`
- `scripts/validate_traceability.py`
- `src/artifex/_version.py`
- `src/artifex/integrations/manual.py`
- `src/artifex/integrations/hermes.py`
- `src/artifex/integrations/codex.py`
- `src/artifex/integrations/claude.py`
- `src/artifex/integrations/deepseek.py`
- `src/artifex/integrations/pandora.py`
- `pyproject.toml`
- `uv.lock`
- `.github/workflows/ci.yml`
- `tests/test_release.py`
- `tests/test_validation.py`

Core-owned Project Model, ChangeSets, contracts, evidence, gates, status, traceability data, generated documentation, and release records are forbidden worker outputs.

## Required behavior

- Canonical evidence codec round-trips `EvidenceEntry` with integrity and schema validation.
- Legacy evidence is classified but never accepted as canonical/current.
- Unknown formats, duplicate IDs, invalid hashes, spoofed validators, stale bindings, and missing independence fail closed.
- Release verifier measures repository state and returns nonzero until every mandatory final-release condition is present.
- Traceability validator supports requirement-to-architecture/milestone/task/evidence/gate mappings and rejects every orphan or unknown ID.
- Core/package/CLI/artifact version agrees at 1.0.0.
- Manual, Hermes, Codex, Claude, DeepSeek, and Pandora report Core 1.0.0 compatible and Core 2.0.0 incompatible.
- Locked wheel and sdist build and isolated identity smoke are present in CI.

## Gates

Focused validation, adversarial evidence tests, version/compatibility tests, traceability negative tests, Ruff, strict mypy, full tests, coverage at least 85 percent, wheel/sdist build, and independent review must pass. Final release verifier is expected to remain BLOCKED until Core later supplies final M11 evidence/gates/docs; this expected precondition must be explicit, not bypassed.

## Rollback

Revert the implementation commit and retain release status as PLANNED. Preserve append-only evidence and audit records.

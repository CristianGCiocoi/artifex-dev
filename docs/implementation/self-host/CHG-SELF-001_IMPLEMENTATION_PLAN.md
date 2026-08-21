# CHG-SELF-001 — Implementation and validation plan

Status: FROZEN
Milestone: M11
Integration route: Codex standalone worker through the ARTIFEX Codex adapter

## Objective

Compile a schema-valid canonical Project Model into complete, deterministic, non-canonical understanding views while preserving raw-source fingerprinting and Core authority.

## Worker-owned implementation

- `src/artifex/compilation/projection.py`
- `src/artifex/compilation/renderers.py`
- `src/artifex/compilation/packets.py`
- `src/artifex/compilation/comprehension.py`
- `src/artifex/compilation/dashboard.py`
- `src/artifex/compilation/__init__.py`
- `tests/test_compilation.py`
- `tests/test_comprehension.py`

The worker must not modify `.artifex/project-model.json`, the governing ChangeSet, acceptance contracts, evidence, status, accepted architecture/requirements documents, release governance, or vendor configuration.

## Required behavior

1. Project a schema-valid typed Project Model without mutating it.
2. Read only `ACCEPTED` artifact `metadata.understanding` contributions.
3. Reject unknown understanding fields and unequal duplicate field definitions.
4. Derive stable typed-entity collections as fallbacks.
5. Preserve rich mapping compatibility.
6. Bind all generation and comprehension fingerprints to the raw canonical input.
7. Produce complete self-model human and machine packs and nine available comprehension topics.
8. Keep generated content explicitly non-canonical.

## Acceptance checks

- focused compilation and comprehension tests pass;
- canonical Project Model schema and typed round trip pass;
- deterministic repeat compilation is byte-identical;
- raw Project Model is byte-identical before and after compilation;
- non-accepted metadata cannot influence output;
- conflicting accepted metadata fails closed;
- raw semantic fingerprint appears in generated manifests and comprehension gate;
- all existing rich-mapping compiler tests pass;
- Ruff and strict mypy pass;
- full repository suite passes with total coverage at least 85 percent;
- independent reviewer reproduces the self-model compilation and comprehension availability checks.

## Execution sequence

1. Freeze immutable acceptance contract and execution packet at a clean Git base.
2. Create the isolated worker branch/worktree from that base.
3. Run the Codex adapter preflight and execute the bounded implementation.
4. Require an actual owned-path delta and exact result bindings.
5. Run independent validation before any Core acceptance transition.
6. Cherry-pick accepted implementation onto the M11 governance branch.
7. Generate self documentation under `.artifex/generated/understanding/` from the accepted implementation.

## Rollback

Revert the worker implementation commit and remove generated outputs. Do not rewrite the canonical Project Model or append-only audit history.

# ARTIFEX

ARTIFEX is an agent-neutral development control, continuity, and understanding
layer. Repository artifacts and Git are the canonical semantic truth; agent
conversations and native memories are auxiliary.

## What ARTIFEX does

ARTIFEX turns a software idea, change request, or existing repository into a
development process that remains understandable and auditable after the
original conversation, agent session, or implementation harness has gone
away. It is designed for teams and agents that need to preserve the reasoning
behind a system as carefully as the code itself.

ARTIFEX provides:

- a canonical Project Model for requirements, constraints, interfaces,
  invariants, dependencies, artifacts, and lifecycle state;
- an evidence-bound workflow from intake through research, architecture,
  planning, execution, verification, understanding, and learning;
- Acceptance Contracts, an Evidence Ledger, hierarchical gates, freshness, and
  stale-result detection so executor claims are not mistaken for acceptance;
- portable execution packets that bind work to the base commit, Project Model,
  task contract, ownership, and expected result;
- human and machine compilations of the same canonical project meaning,
  including documentation, context packets, execution packets, and dashboard
  views;
- agent-neutral integrations: Hermes is preferred when available, while Codex,
  Claude, and Manual operation remain first-class standalone paths; and
- controlled lessons, improvement proposals, and candidate overlays without
  allowing uncontrolled Core self-modification.

## What ARTIFEX is not

ARTIFEX is not an LLM router, coding model, generic multi-agent framework,
research engine, CI/CD replacement, IDE, Git hosting service, RAG/vector
platform, or mandatory server control plane. It can use external providers,
but providers do not own ARTIFEX semantic state or acceptance.

## Operating model

The core lifecycle is:

`INTAKE → IDEA → RESEARCH → DEFINITION → ARCHITECTURE → IMPLEMENTATION PLAN → EXECUTION → VERIFICATION → UNDERSTANDING → LEARNING`

Controlled backward transitions are allowed when evidence reveals that an
earlier decision must be revisited. Git/files retain semantic meaning;
databases, when introduced, are for coordination, indexing, and telemetry.

ARTIFEX 1.0.0 is released. M00 through M11 are accepted and the immutable
release tag is [`v1.0.0`](https://github.com/CristianGCiocoi/artifex-dev/releases/tag/v1.0.0).
Canonical release status is stored in `.artifex/status.yaml`; the dashboard is
a derived view. A version string or successful build is not release authority.

## Release scope and roadmap

### V1 — Standardize (released)

V1 establishes the portable, evidence-bound foundation: the Project Model,
workflow and validation core, filesystem/Git authority, compilation and
dashboard views, beginner-to-expert modes, ChangeSets, controlled knowledge,
and standalone Hermes/Codex/Claude/Manual integration paths. Optional DeepSeek
and Pandora providers do not block the Core release.

### V2 — Automate (planned)

V2 is planned to make development durable, resumable, orchestrated, and more
cross-project aware. Candidate work includes a SQLite RunStore/index/metrics,
an executable task DAG, durable runs and resume points, capability-based
harness routing, parallel worktrees/workers, stronger generator/evaluator
isolation, replay, cross-project portfolio/knowledge, overlay rebase/update
classification, methodology import, optional Maestro execution, and richer
Pandora orchestration.

### V3 — Evolve (planned)

V3 is planned to let the methodology improve within strict privilege and
evidence boundaries. Candidate work includes dynamic composition from approved
stage types, outcome-directed changes, dependency/integration maintenance,
assumption and ADR monitors, methodology evaluation, validator-effectiveness
learning, stronger Acceptance Contracts, pattern/anti-pattern mining,
continuous comprehension/drift detection, and optional distributed execution
or server/Postgres control-plane profiles.

V2 and V3 are roadmap directions, not release commitments. Neither makes
ATLAS, a remote provider, a GPU, a model gateway, or distributed execution a
mandatory ARTIFEX dependency.

## Development

ARTIFEX requires Python 3.12 or newer. The supported contributor workflow uses
[`uv`](https://docs.astral.sh/uv/):

```console
uv sync --locked --all-groups --python 3.12
uv run ruff check .
uv run mypy src
uv run pytest --cov=artifex --cov-report=term-missing
uv run python scripts/validate_release.py
uv run artifex system health
```

Release artifacts are built only from the immutable source candidate and are
verified after download. Native targets are Windows X64, Linux X64, and macOS
ARM64. They are provenance-attested, but V1 publisher signing and notarization
are not claimed.

## Documentation

- [Accepted V1 handoff](docs/handoff/)
- [Product definition](docs/product/PRODUCT_DEFINITION.md) and [roadmap](docs/product/ROADMAP.md)
- [Architecture](docs/architecture/ARCHITECTURE.md), [integration contract](docs/architecture/INTEGRATION_CONTRACT.md), and [security guidance](docs/guides/SECURITY_GUIDE.md)
- [ARTIFEX 2.0 durable runtime authority](docs/architecture/DURABLE_RUNTIME.md)
- [V1 migration authority](docs/architecture/V1_MIGRATION.md) and [V1 to 2.0 upgrade guide](docs/guides/UPGRADE_GUIDE.md)
- [Developer guide](docs/guides/DEVELOPER_GUIDE.md), [administrator guide](docs/guides/ADMIN_GUIDE.md), and [user guide](docs/guides/USER_GUIDE.md)
- [V1 release record](.artifex/releases/v1.0.0.yaml) and [release evidence](.artifex/validation/evidence/EVD-V1-RELEASE.yaml)
- [Dashboard deployment](docs/implementation/dashboard-deployment.md)

The `integration/atlas/` directory is a post-release, discovery-only
compatibility record. It does not implement an ARTIFEX → ATLAS integration.

## License

ARTIFEX is licensed under the [Apache License 2.0](LICENSE).

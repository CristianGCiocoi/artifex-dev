# ARTIFEX

ARTIFEX is an agent-neutral development control, continuity, and understanding
layer. Repository artifacts and Git are the canonical semantic truth; agent
conversations and native memories are auxiliary.

This repository contains the ARTIFEX 1.0.0 source candidate. M00 through M10
are accepted; M11 remains active until exact-source CI, packaging, independent
evidence, documentation, comprehension, and Core release gates all pass. A
version string or successful build is not release authorization. Canonical
status is stored in `.artifex/status.yaml`; the dashboard is a derived view.

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

The complete accepted handoff is preserved under `docs/handoff/`.

# ARTIFEX

ARTIFEX is an agent-neutral development control, continuity, and understanding
layer. Repository artifacts and Git are the canonical semantic truth; agent
conversations and native memories are auxiliary.

This repository is implementing the accepted ARTIFEX V1 architecture. The
machine-derived status is stored in `.artifex/status.yaml` and rendered into
`docs/implementation/dashboard/`.

## Development

ARTIFEX requires Python 3.12 or newer. The supported contributor workflow uses
[`uv`](https://docs.astral.sh/uv/):

```console
uv sync --python 3.12
uv run pytest
uv run ruff check .
uv run mypy src
uv run artifex system health
```

The complete accepted handoff is preserved under `docs/handoff/`.


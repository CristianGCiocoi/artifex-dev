# ARTIFEX

ARTIFEX is an agent-neutral development control, continuity, and understanding
layer. Repository artifacts and Git are the canonical semantic truth; agent
conversations and native memories are auxiliary.

ARTIFEX 1.0.0 is released. M00 through M11 are accepted and the immutable
release tag is [`v1.0.0`](https://github.com/CristianGCiocoi/artifex-dev/releases/tag/v1.0.0).
Canonical release status is stored in `.artifex/status.yaml`; the dashboard is
a derived view. A version string or successful build is not release authority.

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
- [Developer guide](docs/guides/DEVELOPER_GUIDE.md), [administrator guide](docs/guides/ADMIN_GUIDE.md), and [user guide](docs/guides/USER_GUIDE.md)
- [V1 release record](.artifex/releases/v1.0.0.yaml) and [release evidence](.artifex/validation/evidence/EVD-V1-RELEASE.yaml)
- [Dashboard deployment](docs/implementation/dashboard-deployment.md)

The `integration/atlas/` directory is a post-release, discovery-only
compatibility record. It does not implement an ARTIFEX → ATLAS integration.

## License

ARTIFEX is licensed under the [Apache License 2.0](LICENSE).

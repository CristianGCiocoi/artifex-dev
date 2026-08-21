"""Source fingerprint manifests and generated-view freshness classification."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from artifex.compilation._util import fingerprint_value, model_fingerprint


class GeneratedViewState(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


def fingerprint_sources(sources: Mapping[str, Any]) -> dict[str, str]:
    """Fingerprint source content by stable path/name order."""

    return {str(name): fingerprint_value(sources[name]) for name in sorted(sources, key=str)}


def generation_manifest(
    project_model: Mapping[str, Any],
    *,
    sources: Mapping[str, Any] | None = None,
    generator: str = "artifex.compilation",
) -> dict[str, Any]:
    """Create reproducible provenance for a non-canonical generated view."""

    source_content = sources if sources is not None else {"project_model": project_model}
    return {
        "generated": True,
        "canonical": False,
        "generator": generator,
        "project_model_fingerprint": model_fingerprint(project_model),
        "source_fingerprints": fingerprint_sources(source_content),
    }


def classify_generated_view(
    current_sources: Mapping[str, Any],
    stored_manifest: Mapping[str, Any] | None,
    *,
    applicable: bool = True,
) -> GeneratedViewState:
    """Classify a view without reading timestamps or remembered status."""

    if not applicable:
        return GeneratedViewState.NOT_APPLICABLE
    if stored_manifest is None:
        return GeneratedViewState.MISSING
    stored = stored_manifest.get("source_fingerprints")
    if not isinstance(stored, Mapping):
        return GeneratedViewState.STALE
    expected = fingerprint_sources(current_sources)
    normalized = {str(key): str(value) for key, value in stored.items()}
    return GeneratedViewState.CURRENT if normalized == expected else GeneratedViewState.STALE


# Concise alias for callers that deal specifically with documentation.
classify_documentation = classify_generated_view


__all__ = [
    "GeneratedViewState",
    "classify_documentation",
    "classify_generated_view",
    "fingerprint_sources",
    "generation_manifest",
]

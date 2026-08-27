"""Documentation and dashboard baselines derived from accepted Project semantics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from artifex.compilation import compile_dashboard
from artifex.documentation import DocumentationLifecycle, DocumentationStatus
from artifex.project.authority import SemanticRevision
from artifex.project.catalog import CatalogEntry, ProjectCatalog
from artifex.project.store import FileSystemProjectStore
from artifex.reality import RealityReconciliationService

DOCUMENTATION_DIRECTORY = ".artifex/docs"
PROJECT_DASHBOARD_PATH = ".artifex/dashboard/project.json"
PROJECT_DASHBOARD_HTML_PATH = ".artifex/dashboard/index.html"


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


class ProjectionFramework:
    """Shared Platform/Project projection vocabulary over authoritative sources."""

    @staticmethod
    def project_state(
        revision: SemanticRevision,
        entry: CatalogEntry,
        *,
        documentation: tuple[DocumentationStatus, ...] = (),
        reality: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        document_states = {item.state.value for item in documentation}
        aggregate_state = (
            "STALE"
            if "STALE" in document_states
            else "MISSING"
            if "MISSING" in document_states
            else "CURRENT"
        )
        reality_state: dict[str, object] = reality or {
            "observations": [],
            "divergences": [],
            "open_divergence_count": 0,
        }
        observations = reality_state.get("observations", [])
        divergences = reality_state.get("divergences", [])
        observation_count = len(observations) if isinstance(observations, list) else 0
        divergence_count = len(divergences) if isinstance(divergences, list) else 0
        return {
            "schema_version": "2.0",
            "scope": "PROJECT",
            "authoritative": False,
            "derived_from": ["PROJECT_AUTHORITY", "PROJECT_CATALOG"],
            "project": {
                "id": revision.project_id,
                "name": revision.model.project.name,
                "lifecycle": revision.model.project.lifecycle.value,
            },
            "semantic_revision": revision.number,
            "semantic_fingerprint": revision.fingerprint,
            "catalog": entry.to_dict(),
            "documentation": {
                "state": aggregate_state,
                "path": DOCUMENTATION_DIRECTORY,
                "documents": [item.to_dict() for item in documentation],
            },
            "observed_reality": {
                "observation_count": observation_count,
                "divergence_count": divergence_count,
                "open_divergence_count": reality_state.get("open_divergence_count", 0),
            },
        }

    @staticmethod
    def platform_state(catalog: ProjectCatalog) -> dict[str, Any]:
        return catalog.platform_projection()


def render_project_baseline(
    root: str | Path, revision: SemanticRevision, entry: CatalogEntry
) -> dict[str, Any]:
    """Create the initial/current Project documentation and dashboard projections."""

    DocumentationLifecycle(root).establish_baseline(revision)
    return render_project_projection(root, revision, entry)


def render_project_projection(
    root: str | Path, revision: SemanticRevision, entry: CatalogEntry
) -> dict[str, Any]:
    """Rebuild dashboard views from authoritative stores without changing semantics."""

    store = FileSystemProjectStore(root)
    model = revision.model.to_dict()
    documentation = DocumentationLifecycle(root).status(revision)
    reality = RealityReconciliationService(root).state()
    state = ProjectionFramework.project_state(
        revision, entry, documentation=documentation, reality=reality
    )
    store.write_atomic(PROJECT_DASHBOARD_PATH, _json_bytes(state))
    measured_state = {
        "milestones": [],
        "gates": [],
        "evidence": [],
        "tests": [],
        "documentation": [item.to_dict() for item in documentation],
    }
    store.write_atomic(
        PROJECT_DASHBOARD_HTML_PATH,
        compile_dashboard(model, measured_state).encode("utf-8"),
    )
    return state


__all__ = ["ProjectionFramework", "render_project_baseline", "render_project_projection"]

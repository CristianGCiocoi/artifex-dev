"""Documentation and dashboard baselines derived from accepted Project semantics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from artifex.compilation import compile_dashboard, compile_human_documentation
from artifex.project.authority import SemanticRevision
from artifex.project.catalog import CatalogEntry, ProjectCatalog
from artifex.project.store import FileSystemProjectStore

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
    def project_state(revision: SemanticRevision, entry: CatalogEntry) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
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
                "state": "CURRENT",
                "path": DOCUMENTATION_DIRECTORY,
            },
        }

    @staticmethod
    def platform_state(catalog: ProjectCatalog) -> dict[str, Any]:
        return catalog.platform_projection()


def render_project_baseline(
    root: str | Path, revision: SemanticRevision, entry: CatalogEntry
) -> dict[str, Any]:
    """Create the initial/current Project documentation and dashboard projections."""

    store = FileSystemProjectStore(root)
    model = revision.model.to_dict()
    documents = compile_human_documentation(model)
    for name, content in documents.items():
        store.write_atomic(f"{DOCUMENTATION_DIRECTORY}/{name}", content.encode("utf-8"))

    state = ProjectionFramework.project_state(revision, entry)
    store.write_atomic(PROJECT_DASHBOARD_PATH, _json_bytes(state))
    measured_state = {
        "milestones": [],
        "gates": [],
        "evidence": [],
        "tests": [],
        "documentation": [{"state": "CURRENT", "path": DOCUMENTATION_DIRECTORY}],
    }
    store.write_atomic(
        PROJECT_DASHBOARD_HTML_PATH,
        compile_dashboard(model, measured_state).encode("utf-8"),
    )
    return state


__all__ = ["ProjectionFramework", "render_project_baseline"]

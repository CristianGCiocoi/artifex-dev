"""Public Project bootstrap, continuation, proposal, and acceptance composition."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from artifex.project.authority import ProjectAuthority, SemanticProposal, SemanticRevision
from artifex.project.catalog import ProjectCatalog
from artifex.project.model import ProjectModel
from artifex.project.projections import ProjectionFramework, render_project_baseline
from artifex.project.repository import MODEL_PATH, ProjectRepository


class ProjectControlService:
    """Shipping M1 composition over Project Authority and Catalog Authority."""

    def __init__(self, catalog_path: str | Path) -> None:
        self.catalog = ProjectCatalog(catalog_path)

    def create(
        self,
        root: str | Path,
        *,
        name: str,
        description: str = "",
        project_id: str | None = None,
        actor: str = "user",
    ) -> dict[str, Any]:
        identifier = project_id or f"project-{uuid.uuid4()}"
        repository = ProjectRepository.initialize(
            root,
            project_id=identifier,
            name=name,
            description=description,
        )
        authority = ProjectAuthority.bootstrap(repository, actor=actor)
        revision = authority.current()
        entry = self.catalog.register(
            project_id=identifier,
            name=name,
            location=repository.store.root,
            lifecycle=revision.model.project.lifecycle.value,
            last_semantic_revision=revision.number,
            discovery_provenance="created",
            last_activity=revision.accepted_at,
        )
        dashboard = render_project_baseline(repository.store.root, revision, entry)
        return self._result(revision, entry.to_dict(), dashboard)

    def adopt(
        self,
        root: str | Path,
        *,
        name: str | None = None,
        description: str = "",
        project_id: str | None = None,
        actor: str = "user",
    ) -> dict[str, Any]:
        root_path = Path(root).expanduser().resolve()
        model_path = root_path / MODEL_PATH
        if model_path.is_file():
            repository = ProjectRepository(root_path)
            model = repository.load()
            if project_id is not None and project_id != model.project.id:
                raise ValueError("adoption cannot replace the V1 Project identity")
            authority = ProjectAuthority.bootstrap(
                repository,
                actor=actor,
                source="V1_MODEL_ADAPTER",
            )
        else:
            if name is None:
                raise ValueError("name is required when adopting a repository without a V1 model")
            repository = ProjectRepository.adopt(
                root_path,
                project_id=project_id or f"project-{uuid.uuid4()}",
                name=name,
                description=description,
            )
            authority = ProjectAuthority.bootstrap(
                repository,
                actor=actor,
                source="BROWNFIELD_ADOPTION",
            )
        revision = authority.current()
        display_name = name or revision.model.project.name
        aliases = (
            (revision.model.project.name,)
            if display_name.casefold() != revision.model.project.name.casefold()
            else ()
        )
        entry = self.catalog.register(
            project_id=revision.project_id,
            name=display_name,
            aliases=aliases,
            location=repository.store.root,
            lifecycle=revision.model.project.lifecycle.value,
            last_semantic_revision=revision.number,
            discovery_provenance="v1-adapter" if model_path.is_file() else "adopted",
            last_activity=revision.accepted_at,
        )
        dashboard = render_project_baseline(repository.store.root, revision, entry)
        return self._result(revision, entry.to_dict(), dashboard)

    def continue_by_name(self, name_or_alias: str) -> dict[str, Any]:
        entry, root = self.catalog.reachable_location(name_or_alias)
        authority = ProjectAuthority(root)
        revision = authority.current()
        if revision.project_id != entry.project_id:
            raise ValueError("catalog identity does not match repository Project identity")
        entry = self.catalog.record_revision(
            entry.project_id, revision.number, revision.accepted_at
        )
        dashboard = render_project_baseline(root, revision, entry)
        return self._result(revision, entry.to_dict(), dashboard)

    def propose(
        self,
        name_or_alias: str,
        model: Mapping[str, Any],
        *,
        expected_revision: int,
        actor: str,
        source: str = "CLIENT",
    ) -> SemanticProposal:
        entry, root = self.catalog.reachable_location(name_or_alias)
        proposal = ProjectAuthority(root).propose(
            ProjectModel.from_dict(model),
            expected_revision=expected_revision,
            actor=actor,
            source=source,
        )
        if proposal.project_id != entry.project_id:
            raise ValueError("catalog identity does not match proposal Project identity")
        return proposal

    def accept(
        self,
        name_or_alias: str,
        proposal_id: str,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        entry, root = self.catalog.reachable_location(name_or_alias)
        revision = ProjectAuthority(root).accept(
            proposal_id,
            expected_revision=expected_revision,
            actor=actor,
        )
        entry = self.catalog.record_revision(
            entry.project_id, revision.number, revision.accepted_at
        )
        dashboard = render_project_baseline(root, revision, entry)
        return self._result(revision, entry.to_dict(), dashboard)

    def observe_external(self, name_or_alias: str, *, actor: str = "external") -> dict[str, Any]:
        entry, root = self.catalog.reachable_location(name_or_alias)
        proposal = ProjectAuthority(root).observe_external_mutation(actor=actor)
        return {
            "project_id": entry.project_id,
            "semantic_revision_unchanged": True,
            "proposal": proposal.to_dict() if proposal is not None else None,
        }

    def platform_dashboard(self) -> dict[str, Any]:
        return ProjectionFramework.platform_state(self.catalog)

    @staticmethod
    def _result(
        revision: SemanticRevision,
        catalog: Mapping[str, Any],
        dashboard: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "project": revision.model.project.to_dict(),
            "semantic_revision": revision.number,
            "semantic_fingerprint": revision.fingerprint,
            "catalog": dict(catalog),
            "project_dashboard": dict(dashboard),
            "execution": {
                "automated_scheduler": False,
                "automated_codex_execution": False,
                "fallback": "manual",
                "fallback_mode": "DELIBERATE",
            },
        }


__all__ = ["ProjectControlService"]

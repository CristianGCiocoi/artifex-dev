"""Public Project bootstrap, continuation, proposal, and acceptance composition."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from artifex.documentation import DocumentationLifecycle
from artifex.project.authority import ProjectAuthority, SemanticProposal, SemanticRevision
from artifex.project.catalog import ProjectCatalog
from artifex.project.errors import ProjectError
from artifex.project.model import LifecycleContribution, ProjectModel
from artifex.project.projections import (
    ProjectionFramework,
    render_project_baseline,
    render_project_projection,
)
from artifex.project.repository import MODEL_PATH, ProjectRepository
from artifex.reality import RealityReconciliationService


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
        lifecycle = DocumentationLifecycle(root)
        if not lifecycle.status(revision) or not (root / ".artifex/docs/manifest.json").is_file():
            lifecycle.establish_baseline(revision)
        dashboard = render_project_projection(root, revision, entry)
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
        authority = ProjectAuthority(root)
        previous = authority.current()
        revision = authority.accept(
            proposal_id,
            expected_revision=expected_revision,
            actor=actor,
        )
        entry = self.catalog.record_revision(
            entry.project_id, revision.number, revision.accepted_at
        )
        RealityReconciliationService(root).resolve_proposal(proposal_id)
        DocumentationLifecycle(root).mark_accepted_change(previous, revision)
        dashboard = render_project_projection(root, revision, entry)
        return self._result(revision, entry.to_dict(), dashboard)

    def advance_lifecycle(
        self,
        name_or_alias: str,
        contribution: LifecycleContribution,
        *,
        expected_revision: int,
        authority_actor: str = "artifex-project-authority",
    ) -> dict[str, Any]:
        """Accept one ordered collaborative lifecycle contribution.

        The interaction actor remains proposal attribution. Acceptance still flows
        through Project Authority and optimistic semantic revisioning.
        """

        entry, root = self.catalog.reachable_location(name_or_alias)
        authority = ProjectAuthority(root)
        current = authority.current()
        if current.number != expected_revision:
            raise ValueError(
                "semantic revision conflict: "
                f"expected {expected_revision}, current {current.number}"
            )
        updated = ProjectModel(
            project=current.model.project,
            git=current.model.git,
            artifacts=current.model.artifacts,
            entities=current.model.entities,
            governance=current.model.governance.advance(contribution),
            schema_version=current.model.schema_version,
        )
        proposal = authority.propose(
            updated,
            expected_revision=expected_revision,
            actor=contribution.actor_id,
            source="INTERACTION_LIFECYCLE",
        )
        revision = authority.accept(
            proposal.id,
            expected_revision=expected_revision,
            actor=authority_actor,
        )
        entry = self.catalog.record_revision(
            entry.project_id, revision.number, revision.accepted_at
        )
        dashboard = render_project_baseline(root, revision, entry)
        return self._result(revision, entry.to_dict(), dashboard)

    def observe_external(self, name_or_alias: str, *, actor: str = "external") -> dict[str, Any]:
        entry, root = self.catalog.reachable_location(name_or_alias)
        result = RealityReconciliationService(root).observe_repository(actor=actor)
        revision = ProjectAuthority(root).current()
        render_project_projection(root, revision, entry)
        return result

    def reality_state(self, name_or_alias: str) -> dict[str, object]:
        _, root = self.catalog.reachable_location(name_or_alias)
        return RealityReconciliationService(root).state()

    def documentation_status(self, name_or_alias: str) -> dict[str, object]:
        _, root = self.catalog.reachable_location(name_or_alias)
        revision = ProjectAuthority(root).current()
        documents = DocumentationLifecycle(root).status(revision)
        return {
            "project_id": revision.project_id,
            "semantic_revision": revision.number,
            "authoritative": False,
            "derived_from": "PROJECT_AUTHORITY",
            "documents": [item.to_dict() for item in documents],
        }

    def regenerate_documentation(
        self, name_or_alias: str, names: tuple[str, ...] = ()
    ) -> dict[str, object]:
        entry, root = self.catalog.reachable_location(name_or_alias)
        revision = ProjectAuthority(root).current()
        documents = DocumentationLifecycle(root).regenerate(revision, names or None)
        dashboard = render_project_projection(root, revision, entry)
        return {
            "project_id": revision.project_id,
            "semantic_revision": revision.number,
            "documents": [item.to_dict() for item in documents],
            "project_dashboard": dashboard,
        }

    def project_dashboard(self, name_or_alias: str) -> dict[str, Any]:
        entry, root = self.catalog.reachable_location(name_or_alias)
        return render_project_projection(root, ProjectAuthority(root).current(), entry)

    def platform_dashboard(self) -> dict[str, Any]:
        state = ProjectionFramework.platform_state(self.catalog)
        projects: list[dict[str, Any]] = []
        for entry in self.catalog.list():
            summary = entry.to_dict()
            try:
                _, root = self.catalog.reachable_location(entry.primary_name)
                revision = ProjectAuthority(root).current()
                documentation = DocumentationLifecycle(root).status(revision)
                reality = RealityReconciliationService(root).state()
                summary["semantic_revision"] = revision.number
                summary["semantic_fingerprint"] = revision.fingerprint
                summary["documentation"] = {
                    state: sum(candidate.state.value == state for candidate in documentation)
                    for state in ("CURRENT", "STALE", "MISSING", "NOT_APPLICABLE")
                }
                summary["open_divergence_count"] = reality["open_divergence_count"]
            except (OSError, KeyError, ProjectError):
                summary["operational_state"] = "UNREACHABLE"
                summary["reachable"] = False
            projects.append(summary)
        return {**state, "schema_version": "2.0", "projects": projects}

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

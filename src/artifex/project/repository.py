"""High-level reconstruction and initialization of a repository Project Model."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from artifex.project.audit import AuditEvent, AuditLog
from artifex.project.errors import ArtifactCorruptError
from artifex.project.git import DirtyStatePolicy, GitRepository
from artifex.project.index import ArtifactIndex, ReconciliationEvent
from artifex.project.model import ProjectInfo, ProjectLifecycle, ProjectModel, WorkflowDepth
from artifex.project.store import FileSystemProjectStore

MODEL_PATH = ".artifex/project-model.json"


class ProjectRepository:
    """Application-facing Project Model service over files and Git."""

    def __init__(self, root: str | Path) -> None:
        self.store = FileSystemProjectStore(root)
        self.git = GitRepository(self.store.root)
        self.audit = AuditLog(self.store.root)

    @classmethod
    def initialize(
        cls,
        root: str | Path,
        *,
        project_id: str,
        name: str,
        description: str = "",
        workflow_depth: WorkflowDepth = WorkflowDepth.STANDARD,
    ) -> ProjectRepository:
        store = FileSystemProjectStore(root, create=True)
        repository = cls(store.root)
        if repository.store.exists(MODEL_PATH):
            raise FileExistsError(f"ARTIFEX project already exists: {store.root}")
        preexisting = any(repository.store.root.iterdir())
        repository.git.initialize(branch="main")
        state = repository.git.inspect()
        model = ProjectModel(
            project=ProjectInfo(
                id=project_id,
                name=name,
                description=description,
                lifecycle=(
                    ProjectLifecycle.BROWNFIELD if preexisting else ProjectLifecycle.GREENFIELD
                ),
                workflow_depth=workflow_depth,
            ),
            git=state,
        )
        repository.save(model)
        repository.audit.append(
            AuditEvent(
                event_type="PROJECT_ADOPTED" if preexisting else "PROJECT_INITIALIZED",
                actor="artifex",
                commit=state.current_commit,
                payload={"project_id": project_id, "lifecycle": model.project.lifecycle.value},
            )
        )
        return repository

    @classmethod
    def adopt(
        cls,
        root: str | Path,
        *,
        project_id: str,
        name: str,
        description: str = "",
        workflow_depth: WorkflowDepth = WorkflowDepth.STANDARD,
    ) -> ProjectRepository:
        root_path = Path(root)
        if not root_path.is_dir():
            raise FileNotFoundError(f"brownfield repository does not exist: {root_path}")
        if not any(root_path.iterdir()):
            raise ValueError("cannot adopt an empty repository as brownfield")
        repository = cls.initialize(
            root_path,
            project_id=project_id,
            name=name,
            description=description,
            workflow_depth=workflow_depth,
        )
        return repository

    def load(self) -> ProjectModel:
        try:
            value = json.loads(self.store.read(MODEL_PATH))
            if not isinstance(value, Mapping):
                raise ValueError("Project Model is not an object")
            return ProjectModel.from_dict(value)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ArtifactCorruptError(f"invalid Project Model: {MODEL_PATH}") from exc

    def save(self, model: ProjectModel) -> None:
        # Round-trip through the typed decoder before persistence so a written
        # model is always reconstructable without hidden in-memory state.
        value = model.to_dict()
        ProjectModel.from_dict(value)
        content = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
        self.store.write_atomic(MODEL_PATH, content + b"\n")

    def establish_baseline(self) -> ProjectModel:
        """Record the current commit as the managed baseline without committing."""

        model = self.load()
        observed = self.git.inspect()
        if observed.current_commit is None:
            raise ValueError("cannot establish a baseline before the repository has a commit")
        observed.enforce(DirtyStatePolicy.REQUIRE_CLEAN)
        state = self.git.inspect(baseline_commit=observed.current_commit)
        updated = ProjectModel(
            project=model.project,
            git=state,
            artifacts=model.artifacts,
            entities=model.entities,
            governance=model.governance,
            knowledge_adoptions=model.knowledge_adoptions,
            schema_version=model.schema_version,
        )
        self.save(updated)
        self.audit.append(
            AuditEvent(
                event_type="GIT_BASELINE_ESTABLISHED",
                actor="artifex",
                commit=observed.current_commit,
                payload={"baseline_commit": observed.current_commit},
            )
        )
        return updated

    def reconcile(self, index: ArtifactIndex) -> tuple[ReconciliationEvent, ...]:
        events = index.reconcile(self.store)
        commit = self.git.current_commit()
        for event in events:
            self.audit.append(
                AuditEvent(
                    event_type=event.kind,
                    actor="external",
                    commit=commit,
                    occurred_at=event.observed_at,
                    payload=event.to_dict(),
                )
            )
        return events


def initialize_project(
    root: str | Path,
    *,
    project_id: str,
    name: str,
    description: str = "",
) -> ProjectRepository:
    """Convenience entry point for greenfield initialization or safe adoption."""

    return ProjectRepository.initialize(
        root, project_id=project_id, name=name, description=description
    )


def adopt_project(
    root: str | Path,
    *,
    project_id: str,
    name: str,
    description: str = "",
) -> ProjectRepository:
    return ProjectRepository.adopt(root, project_id=project_id, name=name, description=description)

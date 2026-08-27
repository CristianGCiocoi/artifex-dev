"""Typed, serializable ARTIFEX Project Model entities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from artifex.ids import StableId
from artifex.project.git import GitRemote, GitState
from artifex.project.paths import normalize_relative_path

SCHEMA_VERSION = "1.0"


class ProjectLifecycle(StrEnum):
    GREENFIELD = "greenfield"
    BROWNFIELD = "brownfield"


class WorkflowDepth(StrEnum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"


class ArtifactStatus(StrEnum):
    DRAFT = "DRAFT"
    REVIEW = "REVIEW"
    ACCEPTED = "ACCEPTED"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"


class EntityKind(StrEnum):
    REQUIREMENT = "requirement"
    ASSUMPTION = "assumption"
    CONSTRAINT = "constraint"
    CAPABILITY = "capability"
    INTERFACE = "interface"
    INVARIANT = "invariant"
    MILESTONE = "milestone"
    TASK = "task"


class LifecycleStage(StrEnum):
    IDEA = "IDEA"
    EXPLORATION = "EXPLORATION"
    RESEARCH = "RESEARCH"
    DEFINITION = "DEFINITION"
    ARCHITECTURE = "ARCHITECTURE"
    REQUIREMENTS_ADRS = "REQUIREMENTS_ADRS"
    PLAN = "PLAN"
    ENVELOPE_PROPOSED = "ENVELOPE_PROPOSED"
    APPROVED_PLAN = "APPROVED_PLAN"


_LIFECYCLE_ORDER = tuple(LifecycleStage)


@dataclass(frozen=True, slots=True)
class LifecycleContribution:
    stage: LifecycleStage
    summary: str
    actor_id: str
    session_id: str
    evidence_refs: tuple[str, ...] = ()
    decision_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.summary, self.actor_id, self.session_id)):
            raise ValueError("lifecycle contribution summary, actor and session are required")
        if any(not value.strip() for value in self.evidence_refs + self.decision_refs):
            raise ValueError("lifecycle references must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "summary": self.summary,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "evidence_refs": list(self.evidence_refs),
            "decision_refs": list(self.decision_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> LifecycleContribution:
        return cls(
            stage=LifecycleStage(str(value["stage"])),
            summary=str(value["summary"]),
            actor_id=str(value["actor_id"]),
            session_id=str(value["session_id"]),
            evidence_refs=tuple(_string_sequence(value.get("evidence_refs", []), "evidence_refs")),
            decision_refs=tuple(_string_sequence(value.get("decision_refs", []), "decision_refs")),
        )


@dataclass(frozen=True, slots=True)
class ProjectGovernanceState:
    stage: LifecycleStage = LifecycleStage.IDEA
    contributions: tuple[LifecycleContribution, ...] = ()

    def __post_init__(self) -> None:
        previous = -1
        for contribution in self.contributions:
            position = _LIFECYCLE_ORDER.index(contribution.stage)
            if position < previous:
                raise ValueError("lifecycle contributions must be monotonic")
            previous = position
        if self.contributions and self.contributions[-1].stage is not self.stage:
            raise ValueError("lifecycle stage must match the latest contribution")

    def advance(self, contribution: LifecycleContribution) -> ProjectGovernanceState:
        current = _LIFECYCLE_ORDER.index(self.stage)
        target = _LIFECYCLE_ORDER.index(contribution.stage)
        if target != current + 1:
            raise ValueError(
                f"lifecycle must advance one stage at a time: {self.stage.value} -> "
                f"{contribution.stage.value}"
            )
        return ProjectGovernanceState(contribution.stage, (*self.contributions, contribution))

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "contributions": [item.to_dict() for item in self.contributions],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ProjectGovernanceState:
        contributions = _mapping_sequence(value.get("contributions", []), "contributions")
        return cls(
            stage=LifecycleStage(str(value.get("stage", LifecycleStage.IDEA.value))),
            contributions=tuple(LifecycleContribution.from_dict(item) for item in contributions),
        )


@dataclass(frozen=True, slots=True)
class Provenance:
    path: str
    commit: str | None = None
    source: str = "repository"

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))

    def to_dict(self) -> dict[str, str | None]:
        return {"path": self.path, "commit": self.commit, "source": self.source}


@dataclass(frozen=True, slots=True)
class Artifact:
    id: StableId
    type: str
    path: str
    status: ArtifactStatus
    fingerprint: str
    depends_on: tuple[StableId, ...] = ()
    provenance: Provenance | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        if not self.type.strip():
            raise ValueError("artifact type must be non-empty")
        invalid_fingerprint = len(self.fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.fingerprint
        )
        if invalid_fingerprint:
            raise ValueError("artifact fingerprint must be a lowercase SHA-256 hex digest")
        if self.id in self.depends_on:
            raise ValueError(f"artifact {self.id} cannot depend on itself")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("artifact dependencies must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "type": self.type,
            "path": self.path,
            "status": self.status.value,
            "fingerprint": self.fingerprint,
            "depends_on": [str(dependency) for dependency in self.depends_on],
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Artifact:
        provenance_value = value.get("provenance")
        provenance = None
        if isinstance(provenance_value, Mapping):
            provenance = Provenance(
                path=str(provenance_value["path"]),
                commit=_optional_string(provenance_value.get("commit")),
                source=str(provenance_value.get("source", "repository")),
            )
        dependencies = _string_sequence(value.get("depends_on", []), "depends_on")
        metadata = value.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("artifact metadata must be an object")
        return cls(
            id=StableId.parse(str(value["id"])),
            type=str(value["type"]),
            path=str(value["path"]),
            status=ArtifactStatus(str(value["status"])),
            fingerprint=str(value["fingerprint"]),
            depends_on=tuple(StableId.parse(item) for item in dependencies),
            provenance=provenance,
            metadata=dict(metadata),
        )


@dataclass(frozen=True, slots=True)
class StructuredEntity:
    id: StableId
    kind: EntityKind
    title: str
    statement: str
    artifact_id: StableId
    depends_on: tuple[StableId, ...] = ()

    def __post_init__(self) -> None:
        if not self.title.strip() or not self.statement.strip():
            raise ValueError("entity title and statement must be non-empty")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("entity dependencies must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "kind": self.kind.value,
            "title": self.title,
            "statement": self.statement,
            "artifact_id": str(self.artifact_id),
            "depends_on": [str(dependency) for dependency in self.depends_on],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StructuredEntity:
        dependencies = _string_sequence(value.get("depends_on", []), "depends_on")
        return cls(
            id=StableId.parse(str(value["id"])),
            kind=EntityKind(str(value["kind"])),
            title=str(value["title"]),
            statement=str(value["statement"]),
            artifact_id=StableId.parse(str(value["artifact_id"])),
            depends_on=tuple(StableId.parse(item) for item in dependencies),
        )


@dataclass(frozen=True, slots=True)
class ProjectInfo:
    id: str
    name: str
    description: str
    lifecycle: ProjectLifecycle
    workflow_depth: WorkflowDepth = WorkflowDepth.STANDARD

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.name.strip():
            raise ValueError("project id and name must be non-empty")

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "lifecycle": self.lifecycle.value,
            "workflow_depth": self.workflow_depth.value,
        }


@dataclass(frozen=True, slots=True)
class ProjectModel:
    project: ProjectInfo
    git: GitState
    artifacts: tuple[Artifact, ...] = ()
    entities: tuple[StructuredEntity, ...] = ()
    governance: ProjectGovernanceState = field(default_factory=ProjectGovernanceState)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported Project Model schema version: {self.schema_version}")
        artifact_ids = [artifact.id for artifact in self.artifacts]
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("artifact identifiers must be unique")
        paths = [artifact.path for artifact in self.artifacts]
        if len(set(paths)) != len(paths):
            raise ValueError("artifact paths must be unique")
        entity_ids = [entity.id for entity in self.entities]
        if len(set(entity_ids)) != len(entity_ids):
            raise ValueError("entity identifiers must be unique")
        artifact_id_set = set(artifact_ids)
        missing = [
            entity.artifact_id
            for entity in self.entities
            if entity.artifact_id not in artifact_id_set
        ]
        if missing:
            raise ValueError(f"entities reference missing artifacts: {missing}")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "project": self.project.to_dict(),
            "git": self.git.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "entities": [entity.to_dict() for entity in self.entities],
        }
        # Preserve the exact M1 portable representation/fingerprint until M4
        # governance state is first accepted for this Project.
        if self.governance != ProjectGovernanceState():
            value["governance"] = self.governance.to_dict()
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ProjectModel:
        project_value = _mapping(value.get("project"), "project")
        git_value = _mapping(value.get("git"), "git")
        artifact_values = _mapping_sequence(value.get("artifacts", []), "artifacts")
        entity_values = _mapping_sequence(value.get("entities", []), "entities")
        governance_value = _mapping(value.get("governance", {}), "governance")
        remote_values = _mapping_sequence(git_value.get("remotes", []), "git.remotes")
        project = ProjectInfo(
            id=str(project_value["id"]),
            name=str(project_value["name"]),
            description=str(project_value.get("description", "")),
            lifecycle=ProjectLifecycle(str(project_value["lifecycle"])),
            workflow_depth=WorkflowDepth(str(project_value.get("workflow_depth", "STANDARD"))),
        )
        git = GitState(
            initialized=bool(git_value["initialized"]),
            branch=_optional_string(git_value.get("branch")),
            baseline_commit=_optional_string(git_value.get("baseline_commit")),
            current_commit=_optional_string(git_value.get("current_commit")),
            dirty=_optional_bool(git_value.get("dirty")),
            remotes=tuple(GitRemote(str(item["name"]), str(item["url"])) for item in remote_values),
        )
        return cls(
            project=project,
            git=git,
            artifacts=tuple(Artifact.from_dict(item) for item in artifact_values),
            entities=tuple(StructuredEntity.from_dict(item) for item in entity_values),
            governance=ProjectGovernanceState.from_dict(governance_value),
            schema_version=str(value.get("schema_version", SCHEMA_VERSION)),
        )


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _mapping_sequence(value: object, name: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be an array")
    return [_mapping(item, f"{name} item") for item in value]


def _string_sequence(value: object, name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{name} must be an array")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} items must be strings")
    return list(value)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected a string or null")
    return value


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError("expected a boolean or null")
    return value

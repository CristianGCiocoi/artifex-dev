"""Portable Project semantic authority with optimistic revision acceptance."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from artifex.compilation._util import model_fingerprint
from artifex.project.audit import AuditEvent
from artifex.project.errors import (
    ArtifactCorruptError,
    ArtifactNotFoundError,
    ExternalMutationError,
    SemanticConflictError,
)
from artifex.project.model import ProjectModel
from artifex.project.repository import ProjectRepository

REVISION_DIRECTORY = ".artifex/semantic-revisions"
PROPOSAL_DIRECTORY = ".artifex/semantic-proposals"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _object(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _serialize(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SemanticProposal:
    id: str
    project_id: str
    expected_revision: int
    model: ProjectModel
    actor: str
    source: str
    created_at: str

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.actor.strip() or not self.source.strip():
            raise ValueError("proposal id, actor, and source must be non-empty")
        if self.expected_revision < 1:
            raise ValueError("expected revision must be positive")
        if self.model.project.id != self.project_id:
            raise ValueError("proposal Project identity does not match its model")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "SEMANTIC_PROPOSAL",
            "id": self.id,
            "project_id": self.project_id,
            "expected_revision": self.expected_revision,
            "model_fingerprint": model_fingerprint(self.model.to_dict()),
            "model": self.model.to_dict(),
            "actor": self.actor,
            "source": self.source,
            "created_at": self.created_at,
            "status": "PROPOSED",
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SemanticProposal:
        model = ProjectModel.from_dict(_object(value.get("model"), "proposal model"))
        proposal = cls(
            id=str(value["id"]),
            project_id=str(value["project_id"]),
            expected_revision=int(value["expected_revision"]),
            model=model,
            actor=str(value["actor"]),
            source=str(value["source"]),
            created_at=str(value["created_at"]),
        )
        if value.get("model_fingerprint") != model_fingerprint(model.to_dict()):
            raise ValueError("proposal model fingerprint does not match content")
        return proposal


@dataclass(frozen=True, slots=True)
class SemanticRevision:
    number: int
    project_id: str
    fingerprint: str
    parent_fingerprint: str | None
    proposal_id: str
    actor: str
    accepted_at: str
    model: ProjectModel

    def __post_init__(self) -> None:
        if self.number < 1:
            raise ValueError("semantic revision number must be positive")
        if self.model.project.id != self.project_id:
            raise ValueError("revision Project identity does not match its model")
        if self.fingerprint != model_fingerprint(self.model.to_dict()):
            raise ValueError("semantic revision fingerprint does not match content")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "ACCEPTED_SEMANTIC_REVISION",
            "revision": self.number,
            "project_id": self.project_id,
            "fingerprint": self.fingerprint,
            "parent_fingerprint": self.parent_fingerprint,
            "proposal_id": self.proposal_id,
            "actor": self.actor,
            "accepted_at": self.accepted_at,
            "model": self.model.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SemanticRevision:
        model = ProjectModel.from_dict(_object(value.get("model"), "revision model"))
        parent = value.get("parent_fingerprint")
        return cls(
            number=int(value["revision"]),
            project_id=str(value["project_id"]),
            fingerprint=str(value["fingerprint"]),
            parent_fingerprint=str(parent) if parent is not None else None,
            proposal_id=str(value["proposal_id"]),
            actor=str(value["actor"]),
            accepted_at=str(value["accepted_at"]),
            model=model,
        )


class ProjectAuthority:
    """Sole acceptance path for Project semantic revisions.

    Revision records contain the accepted model and live in the Project repository.
    ``project-model.json`` remains a portable materialization, but reading the accepted
    state always starts from the immutable revision chain.
    """

    def __init__(self, root: str | Path) -> None:
        self.repository = ProjectRepository(root)

    @classmethod
    def bootstrap(
        cls,
        repository: ProjectRepository,
        *,
        actor: str = "artifex",
        source: str = "PROJECT_BOOTSTRAP",
        accepted_at: str | None = None,
    ) -> ProjectAuthority:
        authority = cls(repository.store.root)
        if authority._revision_paths():
            return authority
        model = repository.load()
        revision = SemanticRevision(
            number=1,
            project_id=model.project.id,
            fingerprint=model_fingerprint(model.to_dict()),
            parent_fingerprint=None,
            proposal_id=source,
            actor=actor,
            accepted_at=accepted_at or _now(),
            model=model,
        )
        repository.audit.read_all()
        authority._write_revision(revision)
        repository.audit.append(
            AuditEvent(
                event_type="SEMANTIC_REVISION_ACCEPTED",
                actor=actor,
                payload={
                    "revision": 1,
                    "fingerprint": revision.fingerprint,
                    "proposal_id": source,
                    "source": source,
                },
            )
        )
        return authority

    def current(self) -> SemanticRevision:
        paths = self._revision_paths()
        if not paths:
            raise ArtifactNotFoundError("Project has no accepted semantic revision")
        revisions = tuple(self._read_revision(path) for path in paths)
        for expected, revision in enumerate(revisions, 1):
            if revision.number != expected:
                raise ArtifactCorruptError("semantic revision sequence is not contiguous")
            if expected == 1 and revision.parent_fingerprint is not None:
                raise ArtifactCorruptError("initial semantic revision has a parent")
            if expected > 1 and revision.parent_fingerprint != revisions[expected - 2].fingerprint:
                raise ArtifactCorruptError("semantic revision parent fingerprint is invalid")
        return revisions[-1]

    def propose(
        self,
        model: ProjectModel | Mapping[str, Any],
        *,
        expected_revision: int,
        actor: str,
        source: str = "CLIENT",
        proposal_id: str | None = None,
        created_at: str | None = None,
    ) -> SemanticProposal:
        proposed_model = model if isinstance(model, ProjectModel) else ProjectModel.from_dict(model)
        current = self.current()
        if proposed_model.project.id != current.project_id:
            raise ValueError("proposal cannot change stable Project identity")
        proposal = SemanticProposal(
            id=proposal_id or f"proposal-{uuid.uuid4()}",
            project_id=current.project_id,
            expected_revision=expected_revision,
            model=proposed_model,
            actor=actor,
            source=source,
            created_at=created_at or _now(),
        )
        path = self._proposal_path(proposal.id)
        if self.repository.store.exists(path):
            raise FileExistsError(f"semantic proposal already exists: {proposal.id}")
        self.repository.store.write_atomic(path, _serialize(proposal.to_dict()))
        self.repository.audit.append(
            AuditEvent(
                event_type="SEMANTIC_PROPOSAL_CREATED",
                actor=actor,
                payload={
                    "proposal_id": proposal.id,
                    "expected_revision": expected_revision,
                    "source": source,
                },
            )
        )
        return proposal

    def accept(
        self,
        proposal_id: str,
        *,
        expected_revision: int,
        actor: str,
        accepted_at: str | None = None,
    ) -> SemanticRevision:
        current = self.current()
        proposal = self._read_proposal(self._proposal_path(proposal_id))
        if expected_revision != current.number or proposal.expected_revision != current.number:
            raise SemanticConflictError(
                "semantic revision conflict: "
                f"expected {expected_revision}, current {current.number}"
            )
        if proposal.project_id != current.project_id:
            raise ValueError("proposal Project identity does not match current revision")

        materialized = self.repository.load()
        materialized_fingerprint = model_fingerprint(materialized.to_dict())
        proposal_fingerprint = model_fingerprint(proposal.model.to_dict())
        if materialized_fingerprint not in {current.fingerprint, proposal_fingerprint}:
            external = self.observe_external_mutation(actor="external")
            identifier = external.id if external is not None else "unknown"
            raise ExternalMutationError(
                f"external Project mutation requires reconciliation via proposal {identifier}"
            )

        revision = SemanticRevision(
            number=current.number + 1,
            project_id=current.project_id,
            fingerprint=proposal_fingerprint,
            parent_fingerprint=current.fingerprint,
            proposal_id=proposal.id,
            actor=actor,
            accepted_at=accepted_at or _now(),
            model=proposal.model,
        )
        self.repository.audit.read_all()
        # Materialize first and publish the immutable accepted revision last. A crash
        # before the final write is therefore external drift, never partial acceptance.
        self.repository.save(proposal.model)
        self._write_revision(revision)
        self.repository.audit.append(
            AuditEvent(
                event_type="SEMANTIC_REVISION_ACCEPTED",
                actor=actor,
                payload={
                    "revision": revision.number,
                    "fingerprint": revision.fingerprint,
                    "proposal_id": proposal.id,
                },
            )
        )
        return revision

    def observe_external_mutation(self, *, actor: str = "external") -> SemanticProposal | None:
        current = self.current()
        observed = self.repository.load()
        if model_fingerprint(observed.to_dict()) == current.fingerprint:
            return None
        return self.propose(
            observed,
            expected_revision=current.number,
            actor=actor,
            source="EXTERNAL_REPOSITORY_MUTATION",
        )

    def _revision_paths(self) -> tuple[str, ...]:
        prefix = f"{REVISION_DIRECTORY}/"
        return tuple(
            path
            for path in self.repository.store.iter_files()
            if path.startswith(prefix) and path.endswith(".json")
        )

    @staticmethod
    def _revision_path(number: int) -> str:
        return f"{REVISION_DIRECTORY}/{number:020d}.json"

    @staticmethod
    def _proposal_path(proposal_id: str) -> str:
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        if not proposal_id or any(character not in allowed for character in proposal_id):
            raise ValueError("proposal id contains unsafe characters")
        return f"{PROPOSAL_DIRECTORY}/{proposal_id}.json"

    def _write_revision(self, revision: SemanticRevision) -> None:
        path = self._revision_path(revision.number)
        if self.repository.store.exists(path):
            raise SemanticConflictError(f"semantic revision already exists: {revision.number}")
        self.repository.store.write_atomic(path, _serialize(revision.to_dict()))

    def _read_revision(self, path: str) -> SemanticRevision:
        try:
            value = json.loads(self.repository.store.read(path))
            return SemanticRevision.from_dict(_object(value, "semantic revision"))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ArtifactCorruptError(f"invalid semantic revision: {path}") from exc

    def _read_proposal(self, path: str) -> SemanticProposal:
        try:
            value = json.loads(self.repository.store.read(path))
            return SemanticProposal.from_dict(_object(value, "semantic proposal"))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ArtifactCorruptError(f"invalid semantic proposal: {path}") from exc


__all__ = [
    "ProjectAuthority",
    "SemanticProposal",
    "SemanticRevision",
]

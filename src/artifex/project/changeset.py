"""Lightweight brownfield ChangeSet lifecycle."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from artifex.ids import StableId
from artifex.project.audit import AuditEvent, AuditLog
from artifex.project.contracts import ProjectStore
from artifex.project.errors import ArtifactCorruptError, InvalidTransitionError


class ChangeSetStatus(StrEnum):
    PROPOSED = "PROPOSED"
    ACCEPTED = "ACCEPTED"
    IMPLEMENTING = "IMPLEMENTING"
    VERIFIED = "VERIFIED"
    APPLIED = "APPLIED"
    ARCHIVED = "ARCHIVED"


_NEXT_STATUS: dict[ChangeSetStatus, ChangeSetStatus] = {
    ChangeSetStatus.PROPOSED: ChangeSetStatus.ACCEPTED,
    ChangeSetStatus.ACCEPTED: ChangeSetStatus.IMPLEMENTING,
    ChangeSetStatus.IMPLEMENTING: ChangeSetStatus.VERIFIED,
    ChangeSetStatus.VERIFIED: ChangeSetStatus.APPLIED,
    ChangeSetStatus.APPLIED: ChangeSetStatus.ARCHIVED,
}


@dataclass(frozen=True, slots=True)
class ChangeSet:
    id: StableId
    title: str
    description: str
    affected_artifacts: tuple[StableId, ...]
    status: ChangeSetStatus = ChangeSetStatus.PROPOSED
    baseline_commit: str | None = None

    def __post_init__(self) -> None:
        if not str(self.id).startswith("CHG-"):
            raise ValueError("ChangeSet id must use the CHG- namespace")
        if not self.title.strip() or not self.description.strip():
            raise ValueError("ChangeSet title and description must be non-empty")

    def transition(
        self,
        target: ChangeSetStatus | str,
        *,
        actor: str,
        audit_log: AuditLog | None = None,
        commit: str | None = None,
    ) -> ChangeSet:
        try:
            next_status = ChangeSetStatus(target)
        except ValueError as exc:
            raise InvalidTransitionError(f"unknown ChangeSet status: {target!r}") from exc
        expected = _NEXT_STATUS.get(self.status)
        if next_status is not expected:
            raise InvalidTransitionError(
                f"ChangeSet {self.id} cannot transition {self.status.value} -> {next_status.value}"
            )
        updated = replace(self, status=next_status)
        if audit_log is not None:
            audit_log.append(
                AuditEvent(
                    event_type="CHANGESET_TRANSITION",
                    actor=actor,
                    commit=commit,
                    payload={
                        "changeset_id": str(self.id),
                        "from": self.status.value,
                        "to": next_status.value,
                    },
                )
            )
        return updated

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "affected_artifacts": [str(item) for item in self.affected_artifacts],
            "status": self.status.value,
            "baseline_commit": self.baseline_commit,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ChangeSet:
        affected = value.get("affected_artifacts", [])
        if not isinstance(affected, Sequence) or isinstance(affected, (str, bytes)):
            raise ValueError("affected_artifacts must be an array")
        return cls(
            id=StableId.parse(str(value["id"])),
            title=str(value["title"]),
            description=str(value["description"]),
            affected_artifacts=tuple(StableId.parse(str(item)) for item in affected),
            status=ChangeSetStatus(str(value.get("status", "PROPOSED"))),
            baseline_commit=(
                str(value["baseline_commit"]) if value.get("baseline_commit") is not None else None
            ),
        )


class ChangeSetRepository:
    """Persist ChangeSets as inspectable JSON artifacts through ProjectStore."""

    def __init__(self, store: ProjectStore, directory: str = ".artifex/changesets") -> None:
        self.store = store
        self.directory = directory.rstrip("/\\")

    def save(self, changeset: ChangeSet) -> str:
        path = self.path_for(changeset.id)
        content = json.dumps(
            changeset.to_dict(), sort_keys=True, indent=2, ensure_ascii=False
        ).encode("utf-8") + b"\n"
        self.store.write_atomic(path, content)
        return path

    def load(self, changeset_id: str | StableId) -> ChangeSet:
        stable_id = (
            changeset_id if isinstance(changeset_id, StableId) else StableId.parse(changeset_id)
        )
        path = self.path_for(stable_id)
        try:
            value = json.loads(self.store.read(path))
            if not isinstance(value, Mapping):
                raise ValueError("ChangeSet is not an object")
            return ChangeSet.from_dict(value)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ArtifactCorruptError(f"invalid ChangeSet artifact: {path}") from exc

    def path_for(self, changeset_id: StableId) -> str:
        if not str(changeset_id).startswith("CHG-"):
            raise ValueError("ChangeSet id must use the CHG- namespace")
        return f"{self.directory}/{changeset_id}.json"

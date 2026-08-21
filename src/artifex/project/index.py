"""Artifact indexing, dependency staleness and external-edit reconciliation."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from artifex.ids import StableId
from artifex.project.contracts import ProjectStore
from artifex.project.errors import ArtifactCorruptError, DuplicateArtifactError
from artifex.project.model import Artifact, ArtifactStatus
from artifex.project.parser import ArtifactParser


@dataclass(frozen=True, slots=True)
class ReconciliationEvent:
    artifact_id: StableId
    path: str
    previous_fingerprint: str
    current_fingerprint: str | None
    stale_artifacts: tuple[StableId, ...]
    observed_at: str
    kind: str = "EXTERNAL_EDIT"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "artifact_id": str(self.artifact_id),
            "path": self.path,
            "previous_fingerprint": self.previous_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "stale_artifacts": [str(item) for item in self.stale_artifacts],
            "observed_at": self.observed_at,
        }


class ArtifactIndex:
    """In-memory semantic index reconstructed exclusively from artifacts."""

    def __init__(self, artifacts: Iterable[Artifact] = ()) -> None:
        self._artifacts: dict[StableId, Artifact] = {}
        self._paths: dict[str, StableId] = {}
        for artifact in artifacts:
            self.add(artifact)

    @property
    def artifacts(self) -> tuple[Artifact, ...]:
        return tuple(sorted(self._artifacts.values(), key=lambda item: str(item.id)))

    def add(self, artifact: Artifact) -> None:
        if artifact.id in self._artifacts:
            raise DuplicateArtifactError(f"duplicate artifact id: {artifact.id}")
        if artifact.path in self._paths:
            raise DuplicateArtifactError(f"duplicate artifact path: {artifact.path}")
        self._artifacts[artifact.id] = artifact
        self._paths[artifact.path] = artifact.id

    def get(self, artifact_id: str | StableId) -> Artifact:
        stable_id = (
            artifact_id if isinstance(artifact_id, StableId) else StableId.parse(artifact_id)
        )
        return self._artifacts[stable_id]

    @classmethod
    def build(
        cls,
        store: ProjectStore,
        paths: Iterable[str] | None = None,
        *,
        parser: ArtifactParser | None = None,
        commit: str | None = None,
        strict: bool = False,
    ) -> ArtifactIndex:
        artifact_parser = parser or ArtifactParser()
        index = cls()
        for path in paths if paths is not None else store.iter_files():
            if not path.lower().endswith((".md", ".markdown", ".yaml", ".yml", ".json")):
                continue
            try:
                artifact = artifact_parser.parse(path, store.read(path), commit=commit)
            except ArtifactCorruptError:
                if strict:
                    raise
                continue
            index.add(artifact)
        return index

    def stale_closure(self, changed: Iterable[str | StableId]) -> tuple[StableId, ...]:
        reverse: dict[StableId, set[StableId]] = defaultdict(set)
        for artifact in self._artifacts.values():
            for dependency in artifact.depends_on:
                reverse[dependency].add(artifact.id)
        queue = deque(
            item if isinstance(item, StableId) else StableId.parse(item) for item in changed
        )
        stale: set[StableId] = set(queue)
        while queue:
            dependency = queue.popleft()
            for dependent in sorted(reverse[dependency], key=str):
                if dependent not in stale:
                    stale.add(dependent)
                    queue.append(dependent)
        return tuple(sorted(stale, key=str))

    def mark_stale(self, changed: Iterable[str | StableId]) -> tuple[StableId, ...]:
        stale = self.stale_closure(changed)
        for artifact_id in stale:
            artifact = self._artifacts.get(artifact_id)
            if artifact is not None and artifact.status is not ArtifactStatus.SUPERSEDED:
                self._artifacts[artifact_id] = replace(artifact, status=ArtifactStatus.STALE)
        return stale

    def reconcile(
        self,
        store: ProjectStore,
        *,
        observed_at: datetime | None = None,
    ) -> tuple[ReconciliationEvent, ...]:
        """Detect direct filesystem edits and propagate their stale state."""

        timestamp = (observed_at or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
        changed: list[tuple[Artifact, str | None]] = []
        for artifact in self.artifacts:
            current = store.fingerprint(artifact.path) if store.exists(artifact.path) else None
            if current != artifact.fingerprint:
                changed.append((artifact, current))
        if not changed:
            return ()
        stale = self.mark_stale(artifact.id for artifact, _ in changed)
        events: list[ReconciliationEvent] = []
        for artifact, current in changed:
            if current is not None:
                updated = replace(self._artifacts[artifact.id], fingerprint=current)
                self._artifacts[artifact.id] = updated
            events.append(
                ReconciliationEvent(
                    artifact_id=artifact.id,
                    path=artifact.path,
                    previous_fingerprint=artifact.fingerprint,
                    current_fingerprint=current,
                    stale_artifacts=stale,
                    observed_at=timestamp,
                    kind="EXTERNAL_DELETE" if current is None else "EXTERNAL_EDIT",
                )
            )
        return tuple(events)

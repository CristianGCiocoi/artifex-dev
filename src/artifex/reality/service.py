"""Reality observers and explicit reconciliation over accepted Project intent."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from artifex.compilation._util import fingerprint_value, model_fingerprint
from artifex.project.authority import ProjectAuthority
from artifex.project.errors import ArtifactCorruptError
from artifex.project.repository import MODEL_PATH, ProjectRepository
from artifex.project.store import FileSystemProjectStore
from artifex.reality.models import (
    Divergence,
    DivergenceStatus,
    Observation,
    ObservationStatus,
    ObserverKind,
)
from artifex.reality.store import RealityStore


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RealityObserver(Protocol):
    """Interface for Git/file/test/provider/runtime/service observer adapters."""

    kind: ObserverKind

    def observe(self) -> tuple[str, ObservationStatus, str | None]:
        """Return source reference, status, and a content fingerprint."""


class CallbackObserver:
    """Small adapter boundary for externally implemented observers."""

    def __init__(
        self,
        kind: ObserverKind,
        callback: Callable[[], tuple[str, ObservationStatus, str | None]],
    ) -> None:
        self.kind = kind
        self._callback = callback

    def observe(self) -> tuple[str, ObservationStatus, str | None]:
        return self._callback()


class FileFingerprintObserver:
    """Read one bounded Project file and compare its actual digest to a known digest."""

    kind = ObserverKind.FILE

    def __init__(self, root: str | Path, path: str, expected_fingerprint: str) -> None:
        self._store = FileSystemProjectStore(root)
        self._path = path
        self._expected = expected_fingerprint

    def observe(self) -> tuple[str, ObservationStatus, str | None]:
        if not self._store.exists(self._path):
            return self._path, ObservationStatus.UNREACHABLE, None
        observed = self._store.fingerprint(self._path)
        status = (
            ObservationStatus.MATCH
            if observed == self._expected
            else ObservationStatus.DIVERGED
        )
        return self._path, status, observed


class GitStateObserver:
    """Read current Git state through the bounded Project repository adapter."""

    kind = ObserverKind.GIT

    def __init__(self, root: str | Path, expected_fingerprint: str) -> None:
        self._repository = ProjectRepository(root)
        self._expected = expected_fingerprint

    def observe(self) -> tuple[str, ObservationStatus, str | None]:
        observed = fingerprint_value(self._repository.git.inspect().to_dict())
        status = (
            ObservationStatus.MATCH
            if observed == self._expected
            else ObservationStatus.DIVERGED
        )
        return "git://working-tree", status, observed


class RealityReconciliationService:
    """Observe actual state while leaving semantic acceptance to Project Authority."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.store = RealityStore(self.root)

    def observe_repository(self, *, actor: str = "observer") -> dict[str, object]:
        authority = ProjectAuthority(self.root)
        accepted = authority.current()
        model_path = self.root / MODEL_PATH
        raw = model_path.read_bytes()
        observed_fingerprint: str
        proposal_id: str | None = None
        try:
            observed_model = ProjectRepository(self.root).load()
            observed_fingerprint = model_fingerprint(observed_model.to_dict())
            status = (
                ObservationStatus.MATCH
                if observed_fingerprint == accepted.fingerprint
                else ObservationStatus.DIVERGED
            )
            if status is ObservationStatus.DIVERGED:
                proposal = authority.observe_external_mutation(actor=actor)
                proposal_id = proposal.id if proposal is not None else None
        except ArtifactCorruptError:
            observed_fingerprint = hashlib.sha256(raw).hexdigest()
            status = ObservationStatus.INVALID
        timestamp = _now()
        observation = Observation(
            observation_id=f"observation-{uuid.uuid4()}",
            project_id=accepted.project_id,
            observer_kind=ObserverKind.FILE,
            source_ref=MODEL_PATH,
            status=status,
            observed_fingerprint=observed_fingerprint,
            expected_fingerprint=accepted.fingerprint,
            observed_at=timestamp,
            actor=actor,
        )
        self.store.append_observation(observation)
        divergence = None
        if status is not ObservationStatus.MATCH:
            divergence = Divergence(
                divergence_id=f"divergence-{uuid.uuid4()}",
                project_id=accepted.project_id,
                observation_id=observation.observation_id,
                status=(
                    DivergenceStatus.PROPOSED if proposal_id is not None else DivergenceStatus.OPEN
                ),
                proposal_id=proposal_id,
                detected_at=timestamp,
            )
            self.store.append_divergence(divergence)
        return {
            "observation": observation.to_dict(),
            "divergence": divergence.to_dict() if divergence is not None else None,
            "proposal_id": proposal_id,
            "semantic_revision": accepted.number,
            "semantic_revision_unchanged": True,
        }

    def observe_adapter(
        self,
        observer: RealityObserver,
        *,
        actor: str,
        expected_fingerprint: str | None = None,
    ) -> Observation:
        """Persist a sourced adapter fact without granting it semantic authority."""

        source_ref, status, fingerprint = observer.observe()
        project_id = ProjectAuthority(self.root).current().project_id
        observation = Observation(
            observation_id=f"observation-{uuid.uuid4()}",
            project_id=project_id,
            observer_kind=observer.kind,
            source_ref=source_ref,
            status=status,
            observed_fingerprint=fingerprint,
            expected_fingerprint=expected_fingerprint,
            observed_at=_now(),
            actor=actor,
        )
        self.store.append_observation(observation)
        if status is not ObservationStatus.MATCH:
            self.store.append_divergence(
                Divergence(
                    divergence_id=f"divergence-{uuid.uuid4()}",
                    project_id=project_id,
                    observation_id=observation.observation_id,
                    status=DivergenceStatus.OPEN,
                    proposal_id=None,
                    detected_at=observation.observed_at,
                )
            )
        return observation

    def state(self) -> dict[str, object]:
        accepted = ProjectAuthority(self.root).current()
        observations = self.store.observations()
        divergences = self.store.divergences()
        return {
            "schema_version": "1.0",
            "authoritative": False,
            "derived_from": ["PROJECT_AUTHORITY", "OBSERVATION_STORE"],
            "project_id": accepted.project_id,
            "semantic_revision": accepted.number,
            "observations": [item.to_dict() for item in observations],
            "divergences": [item.to_dict() for item in divergences],
            "open_divergence_count": sum(
                item.status is not DivergenceStatus.RESOLVED for item in divergences
            ),
        }

    def resolve_proposal(self, proposal_id: str) -> tuple[Divergence, ...]:
        """Close divergences only after their semantic proposal was accepted elsewhere."""

        timestamp = _now()
        resolved: list[Divergence] = []
        for divergence in self.store.divergences():
            if (
                divergence.proposal_id != proposal_id
                or divergence.status is DivergenceStatus.RESOLVED
            ):
                continue
            event = Divergence(
                divergence_id=divergence.divergence_id,
                project_id=divergence.project_id,
                observation_id=divergence.observation_id,
                status=DivergenceStatus.RESOLVED,
                proposal_id=proposal_id,
                detected_at=divergence.detected_at,
                resolved_at=timestamp,
            )
            self.store.append_divergence(event)
            resolved.append(event)
        return tuple(resolved)


__all__ = [
    "CallbackObserver",
    "FileFingerprintObserver",
    "GitStateObserver",
    "RealityObserver",
    "RealityReconciliationService",
]

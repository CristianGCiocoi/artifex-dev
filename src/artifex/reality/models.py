"""Sourced Observed Reality and explicit reconciliation records."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from artifex.policy import scrub_secrets

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ObserverKind(StrEnum):
    GIT = "GIT"
    FILE = "FILE"
    TEST = "TEST"
    PROVIDER = "PROVIDER"
    RUNTIME = "RUNTIME"
    SERVICE = "SERVICE"


class ObservationStatus(StrEnum):
    MATCH = "MATCH"
    DIVERGED = "DIVERGED"
    INVALID = "INVALID"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


class DivergenceStatus(StrEnum):
    OPEN = "OPEN"
    PROPOSED = "PROPOSED"
    RESOLVED = "RESOLVED"


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    project_id: str
    observer_kind: ObserverKind
    source_ref: str
    status: ObservationStatus
    observed_fingerprint: str | None
    expected_fingerprint: str | None
    observed_at: str
    actor: str

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (self.observation_id, self.project_id, self.source_ref, self.actor)
        ):
            raise ValueError("observation identity, source, and actor must be non-empty")
        if scrub_secrets(self.source_ref) != self.source_ref:
            raise ValueError("observation source reference must not contain credential material")
        for value in (self.observed_fingerprint, self.expected_fingerprint):
            if value is not None and not _SHA256.fullmatch(value):
                raise ValueError("observation fingerprints must be SHA-256 digests")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "OBSERVATION",
            "observation_id": self.observation_id,
            "project_id": self.project_id,
            "observer_kind": self.observer_kind.value,
            "source_ref": self.source_ref,
            "status": self.status.value,
            "observed_fingerprint": self.observed_fingerprint,
            "expected_fingerprint": self.expected_fingerprint,
            "observed_at": self.observed_at,
            "actor": self.actor,
            "semantic_acceptance": False,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Observation:
        return cls(
            observation_id=str(value["observation_id"]),
            project_id=str(value["project_id"]),
            observer_kind=ObserverKind(str(value["observer_kind"])),
            source_ref=str(value["source_ref"]),
            status=ObservationStatus(str(value["status"])),
            observed_fingerprint=(
                str(value["observed_fingerprint"])
                if value.get("observed_fingerprint") is not None
                else None
            ),
            expected_fingerprint=(
                str(value["expected_fingerprint"])
                if value.get("expected_fingerprint") is not None
                else None
            ),
            observed_at=str(value["observed_at"]),
            actor=str(value["actor"]),
        )


@dataclass(frozen=True, slots=True)
class Divergence:
    divergence_id: str
    project_id: str
    observation_id: str
    status: DivergenceStatus
    proposal_id: str | None
    detected_at: str
    resolved_at: str | None = None

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (self.divergence_id, self.project_id, self.observation_id)
        ):
            raise ValueError("divergence identity must be non-empty")
        if self.status is DivergenceStatus.RESOLVED and self.resolved_at is None:
            raise ValueError("resolved divergence requires resolved_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "kind": "DIVERGENCE",
            "divergence_id": self.divergence_id,
            "project_id": self.project_id,
            "observation_id": self.observation_id,
            "status": self.status.value,
            "proposal_id": self.proposal_id,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
            "semantic_acceptance": False,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Divergence:
        return cls(
            divergence_id=str(value["divergence_id"]),
            project_id=str(value["project_id"]),
            observation_id=str(value["observation_id"]),
            status=DivergenceStatus(str(value["status"])),
            proposal_id=(str(value["proposal_id"]) if value.get("proposal_id") else None),
            detected_at=str(value["detected_at"]),
            resolved_at=(str(value["resolved_at"]) if value.get("resolved_at") else None),
        )


__all__ = [
    "Divergence",
    "DivergenceStatus",
    "Observation",
    "ObservationStatus",
    "ObserverKind",
]

"""Typed knowledge and controlled-evolution artifacts.

The records in this module are deliberately serialization-first.  They can be
reconstructed from files without harness history and they never carry an
implicit authority to promote themselves or mutate Core.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from artifex.ids import StableId
from artifex.policy import scrub_secrets


class KnowledgeScope(StrEnum):
    CORE = "CORE"
    PROFILE = "PROFILE"
    INSTANCE = "INSTANCE"
    PROJECT = "PROJECT"
    RUN = "RUN"
    HARNESS = "HARNESS"


class KnowledgeKind(StrEnum):
    FACT = "FACT"
    ASSUMPTION = "ASSUMPTION"
    DECISION = "DECISION"
    PREFERENCE = "PREFERENCE"
    LESSON = "LESSON"
    PATTERN = "PATTERN"


class Sensitivity(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    RESTRICTED = "RESTRICTED"


class KnowledgeState(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"


class RevisitKind(StrEnum):
    ARTIFACT_CHANGED = "ARTIFACT_CHANGED"
    CORE_VERSION_CHANGED = "CORE_VERSION_CHANGED"
    DATE_REACHED = "DATE_REACHED"
    MANUAL = "MANUAL"


class OverlayValidationStatus(StrEnum):
    PROPOSED = "PROPOSED"
    PASSED = "PASSED"
    FAILED = "FAILED"


class UpdateClassification(StrEnum):
    CARRY_FORWARD = "CARRY_FORWARD"
    SUPERSEDED = "SUPERSEDED"
    REVALIDATE = "REVALIDATE"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class KnowledgeProvenance:
    source: str
    observed_at: str
    artifact: str | None = None
    commit: str | None = None
    integration: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _non_secret_text(self.source, "provenance source")
        _parse_timestamp(self.observed_at)
        if not any((self.artifact, self.commit, self.integration, self.evidence_ids)):
            raise ValueError(
                "provenance must identify an artifact, commit, integration, or evidence"
            )
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("provenance evidence identifiers must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "observed_at": self.observed_at,
            "artifact": self.artifact,
            "commit": self.commit,
            "integration": self.integration,
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> KnowledgeProvenance:
        return cls(
            source=str(value["source"]),
            observed_at=str(value["observed_at"]),
            artifact=_optional_string(value.get("artifact")),
            commit=_optional_string(value.get("commit")),
            integration=_optional_string(value.get("integration")),
            evidence_ids=tuple(_strings(value.get("evidence_ids", ()), "evidence_ids")),
        )


@dataclass(frozen=True, slots=True)
class VerifiedAgainst:
    artifact: str
    fingerprint: str
    verified_at: str

    def __post_init__(self) -> None:
        _non_secret_text(self.artifact, "verified artifact")
        if len(self.fingerprint) != 64 or any(
            c not in "0123456789abcdef" for c in self.fingerprint
        ):
            raise ValueError("verified fingerprint must be a lowercase SHA-256 digest")
        _parse_timestamp(self.verified_at)

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact": self.artifact,
            "fingerprint": self.fingerprint,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> VerifiedAgainst:
        return cls(str(value["artifact"]), str(value["fingerprint"]), str(value["verified_at"]))


@dataclass(frozen=True, slots=True)
class RevisitTrigger:
    kind: RevisitKind
    value: str

    def __post_init__(self) -> None:
        _non_secret_text(self.value, "revisit trigger value")
        if self.kind is RevisitKind.DATE_REACHED:
            _parse_timestamp(self.value)

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "value": self.value}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RevisitTrigger:
        return cls(RevisitKind(str(value["kind"])), str(value["value"]))


@dataclass(frozen=True, slots=True)
class PromotionPolicy:
    """Evidence and sensitivity ceiling for a single knowledge item."""

    allowed_targets: frozenset[KnowledgeScope] = frozenset(
        {KnowledgeScope.PROJECT, KnowledgeScope.INSTANCE}
    )
    minimum_confidence: float = 0.7
    minimum_evidence: int = 1
    maximum_sensitivity: Sensitivity = Sensitivity.SENSITIVE
    require_validation: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_confidence <= 1:
            raise ValueError("minimum confidence must be between 0 and 1")
        if self.minimum_evidence < 1:
            raise ValueError("promotion requires at least one evidence item")
        if not self.allowed_targets.issubset({KnowledgeScope.PROJECT, KnowledgeScope.INSTANCE}):
            raise ValueError("V1 promotion targets are limited to PROJECT and INSTANCE")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_targets": sorted(scope.value for scope in self.allowed_targets),
            "minimum_confidence": self.minimum_confidence,
            "minimum_evidence": self.minimum_evidence,
            "maximum_sensitivity": self.maximum_sensitivity.value,
            "require_validation": self.require_validation,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PromotionPolicy:
        targets = _strings(value.get("allowed_targets", ()), "allowed_targets")
        return cls(
            allowed_targets=frozenset(KnowledgeScope(item) for item in targets),
            minimum_confidence=float(value.get("minimum_confidence", 0.7)),
            minimum_evidence=int(value.get("minimum_evidence", 1)),
            maximum_sensitivity=Sensitivity(str(value.get("maximum_sensitivity", "SENSITIVE"))),
            require_validation=bool(value.get("require_validation", True)),
        )


@dataclass(frozen=True, slots=True)
class KnowledgeItem:
    id: StableId
    scope: KnowledgeScope
    kind: KnowledgeKind
    statement: str
    provenance: tuple[KnowledgeProvenance, ...]
    confidence: float
    sensitivity: Sensitivity
    promotion_policy: PromotionPolicy
    verified_against: tuple[VerifiedAgainst, ...] = ()
    revisit_triggers: tuple[RevisitTrigger, ...] = ()
    state: KnowledgeState = KnowledgeState.CURRENT
    project_id: str | None = None
    run_id: str | None = None
    promoted_from: KnowledgeScope | None = None

    def __post_init__(self) -> None:
        if self.kind is KnowledgeKind.LESSON and not str(self.id).startswith("LES-"):
            raise ValueError("lesson identifiers must use the LES- prefix")
        _non_secret_text(self.statement, "knowledge statement")
        if not self.provenance:
            raise ValueError("knowledge requires provenance")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if self.scope is KnowledgeScope.PROJECT and not self.project_id:
            raise ValueError("PROJECT knowledge requires project_id")
        if self.scope is KnowledgeScope.RUN and not self.run_id:
            raise ValueError("RUN knowledge requires run_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "scope": self.scope.value,
            "kind": self.kind.value,
            "statement": self.statement,
            "provenance": [item.to_dict() for item in self.provenance],
            "confidence": self.confidence,
            "sensitivity": self.sensitivity.value,
            "promotion_policy": self.promotion_policy.to_dict(),
            "verified_against": [item.to_dict() for item in self.verified_against],
            "revisit_triggers": [item.to_dict() for item in self.revisit_triggers],
            "state": self.state.value,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "promoted_from": self.promoted_from.value if self.promoted_from else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> KnowledgeItem:
        return cls(
            id=StableId.parse(str(value["id"])),
            scope=KnowledgeScope(str(value["scope"])),
            kind=KnowledgeKind(str(value["kind"])),
            statement=str(value["statement"]),
            provenance=tuple(
                KnowledgeProvenance.from_dict(item)
                for item in _mappings(value.get("provenance", ()), "provenance")
            ),
            confidence=float(value["confidence"]),
            sensitivity=Sensitivity(str(value["sensitivity"])),
            promotion_policy=PromotionPolicy.from_dict(
                _mapping(value.get("promotion_policy"), "promotion_policy")
            ),
            verified_against=tuple(
                VerifiedAgainst.from_dict(item)
                for item in _mappings(value.get("verified_against", ()), "verified_against")
            ),
            revisit_triggers=tuple(
                RevisitTrigger.from_dict(item)
                for item in _mappings(value.get("revisit_triggers", ()), "revisit_triggers")
            ),
            state=KnowledgeState(str(value.get("state", "CURRENT"))),
            project_id=_optional_string(value.get("project_id")),
            run_id=_optional_string(value.get("run_id")),
            promoted_from=(
                KnowledgeScope(str(value["promoted_from"]))
                if value.get("promoted_from") is not None
                else None
            ),
        )

    def revisit(
        self,
        *,
        changed_artifacts: frozenset[str] = frozenset(),
        current_core_version: str | None = None,
        now: datetime | None = None,
        manual_triggers: frozenset[str] = frozenset(),
    ) -> KnowledgeItem:
        """Return a STALE copy when any mechanical revisit trigger fires."""

        instant = now or datetime.now(UTC)
        for trigger in self.revisit_triggers:
            fired = (
                (
                    trigger.kind is RevisitKind.ARTIFACT_CHANGED
                    and trigger.value in changed_artifacts
                )
                or (
                    trigger.kind is RevisitKind.CORE_VERSION_CHANGED
                    and current_core_version is not None
                    and trigger.value != current_core_version
                )
                or (
                    trigger.kind is RevisitKind.DATE_REACHED
                    and instant >= _parse_timestamp(trigger.value)
                )
                or (trigger.kind is RevisitKind.MANUAL and trigger.value in manual_triggers)
            )
            if fired:
                return replace(self, state=KnowledgeState.STALE)
        return self


@dataclass(frozen=True, slots=True)
class ImprovementProposal:
    id: StableId
    title: str
    lesson_ids: tuple[StableId, ...]
    target: str
    reason: str
    expected_benefit: str
    evidence: tuple[str, ...]
    requested_privileges: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not str(self.id).startswith("IMP-"):
            raise ValueError("Improvement Proposal identifiers must use the IMP- prefix")
        for value, name in (
            (self.title, "title"),
            (self.target, "target"),
            (self.reason, "reason"),
            (self.expected_benefit, "expected benefit"),
        ):
            _non_secret_text(value, name)
        if not self.lesson_ids or not self.evidence:
            raise ValueError("Improvement Proposal requires lessons and evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "title": self.title,
            "lesson_ids": [str(item) for item in self.lesson_ids],
            "target": self.target,
            "reason": self.reason,
            "expected_benefit": self.expected_benefit,
            "evidence": list(self.evidence),
            "requested_privileges": sorted(self.requested_privileges),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ImprovementProposal:
        return cls(
            id=StableId.parse(str(value["id"])),
            title=str(value["title"]),
            lesson_ids=tuple(
                StableId.parse(item) for item in _strings(value["lesson_ids"], "lesson_ids")
            ),
            target=str(value["target"]),
            reason=str(value["reason"]),
            expected_benefit=str(value["expected_benefit"]),
            evidence=tuple(_strings(value["evidence"], "evidence")),
            requested_privileges=frozenset(
                _strings(value.get("requested_privileges", ()), "requested_privileges")
            ),
        )


@dataclass(frozen=True, slots=True)
class CandidateOverlay:
    id: str
    proposal_id: StableId
    origin_core_version: str
    reason: str
    evidence: tuple[str, ...]
    target: str
    expected_benefit: str
    compatibility: str
    validation_status: OverlayValidationStatus
    changes: Mapping[str, Any]
    requested_privileges: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for value, name in (
            (self.id, "overlay id"),
            (self.origin_core_version, "origin Core version"),
            (self.reason, "reason"),
            (self.target, "target"),
            (self.expected_benefit, "expected benefit"),
            (self.compatibility, "compatibility"),
        ):
            _non_secret_text(value, name)
        if not self.evidence:
            raise ValueError("candidate overlay requires evidence")
        if not str(self.proposal_id).startswith("IMP-"):
            raise ValueError("candidate overlay must reference an Improvement Proposal")
        _reject_secrets(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "proposal_id": str(self.proposal_id),
            "origin_core_version": self.origin_core_version,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "target": self.target,
            "expected_benefit": self.expected_benefit,
            "compatibility": self.compatibility,
            "validation_status": self.validation_status.value,
            "changes": dict(self.changes),
            "requested_privileges": sorted(self.requested_privileges),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CandidateOverlay:
        return cls(
            id=str(value["id"]),
            proposal_id=StableId.parse(str(value["proposal_id"])),
            origin_core_version=str(value["origin_core_version"]),
            reason=str(value["reason"]),
            evidence=tuple(_strings(value["evidence"], "evidence")),
            target=str(value["target"]),
            expected_benefit=str(value["expected_benefit"]),
            compatibility=str(value["compatibility"]),
            validation_status=OverlayValidationStatus(str(value["validation_status"])),
            changes=dict(_mapping(value.get("changes"), "changes")),
            requested_privileges=frozenset(
                _strings(value.get("requested_privileges", ()), "requested_privileges")
            ),
        )


@dataclass(frozen=True, slots=True)
class OverlayUpdateAssessment:
    overlay_id: str
    from_core_version: str
    to_core_version: str
    classification: UpdateClassification
    reason: str

    def __post_init__(self) -> None:
        for value in (self.overlay_id, self.from_core_version, self.to_core_version, self.reason):
            _non_secret_text(value, "update assessment value")

    def to_dict(self) -> dict[str, str]:
        return {
            "overlay_id": self.overlay_id,
            "from_core_version": self.from_core_version,
            "to_core_version": self.to_core_version,
            "classification": self.classification.value,
            "reason": self.reason,
        }


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _mappings(value: object, name: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array")
    return [_mapping(item, f"{name} item") for item in value]


def _strings(value: object, name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
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


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def _non_secret_text(value: str, name: str) -> None:
    if not value.strip():
        raise ValueError(f"{name} must be non-empty")
    if scrub_secrets(value) != value:
        raise ValueError(f"{name} contains secret-like material")


def _reject_secrets(value: object) -> None:
    if isinstance(value, str):
        _non_secret_text(value, "overlay change")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _non_secret_text(str(key), "overlay change key")
            _reject_secrets(item)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            _reject_secrets(item)

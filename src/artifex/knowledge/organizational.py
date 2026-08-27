"""Separate advisory Organizational Knowledge authority for ARTIFEX 2.0 M8A."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from artifex.project import (
    KnowledgeAdoptionProvenance,
    ProjectAuthority,
    ProjectKnowledgeAdoption,
    ProjectModel,
)
from artifex.runtime import ActorPrincipal, ActorType

from .model import (
    KnowledgeItem,
    KnowledgeKind,
    KnowledgeScope,
    KnowledgeState,
    Sensitivity,
)
from .store import InstanceKnowledgeStore, ProjectLessonStore

_PROJECT_SOURCE = re.compile(r"^project:([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
_SENSITIVITY_RANK = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.SENSITIVE: 2,
    Sensitivity.RESTRICTED: 3,
}


class OrganizationalKnowledgeError(ValueError):
    """An Organizational Knowledge trust or isolation boundary failed."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OrganizationalKnowledgeError(f"invalid timestamp: {value}") from exc
    if result.tzinfo is None:
        raise OrganizationalKnowledgeError("timestamp must include a timezone")
    return result


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha256(value: str, name: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise OrganizationalKnowledgeError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _authorize(actor: ActorPrincipal, action: str, project_id: str) -> None:
    if actor.actor_type in {ActorType.PROVIDER, ActorType.INTERACTION_CLIENT, ActorType.AGENT}:
        raise PermissionError(f"{actor.actor_type.value} cannot exercise Knowledge Authority")
    actor.require(action, project_id, now=int(time.time()))


@dataclass(frozen=True, slots=True)
class KnowledgeApplicability:
    project_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    excluded_project_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not any((self.project_ids, self.tags, self.domains)):
            raise OrganizationalKnowledgeError(
                "applicability requires an explicit positive boundary"
            )
        values = (*self.project_ids, *self.tags, *self.domains, *self.excluded_project_ids)
        if any(not value.strip() for value in values):
            raise OrganizationalKnowledgeError("applicability values must be non-empty")
        if any(len(set(items)) != len(items) for items in (
            self.project_ids, self.tags, self.domains, self.excluded_project_ids
        )):
            raise OrganizationalKnowledgeError("applicability values must be unique")

    def matches(
        self, project_id: str, *, tags: frozenset[str] = frozenset(),
        domains: frozenset[str] = frozenset()
    ) -> bool:
        if project_id in self.excluded_project_ids:
            return False
        return (
            project_id in self.project_ids
            or bool(set(self.tags) & tags)
            or bool(set(self.domains) & domains)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_ids": list(self.project_ids),
            "tags": list(self.tags),
            "domains": list(self.domains),
            "excluded_project_ids": list(self.excluded_project_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> KnowledgeApplicability:
        return cls(
            _strings(value.get("project_ids", [])),
            _strings(value.get("tags", [])),
            _strings(value.get("domains", [])),
            _strings(value.get("excluded_project_ids", [])),
        )


@dataclass(frozen=True, slots=True)
class OrganizationalKnowledgeRecord:
    id: str
    source_project_id: str
    source_project_revision: int
    source_project_fingerprint: str
    source_lesson_id: str
    kind: KnowledgeKind
    statement: str
    provenance: tuple[Mapping[str, Any], ...]
    evidence_digests: tuple[str, ...]
    confidence: float
    sensitivity: Sensitivity
    applicability: KnowledgeApplicability
    fresh_until: str
    validator_id: str
    promotion_actor_id: str
    promotion_policy: str
    promotion_decision: str
    created_at: str
    record_digest: str

    def __post_init__(self) -> None:
        if not self.id.startswith("ORGK-"):
            raise OrganizationalKnowledgeError("Organizational Knowledge requires ORGK identity")
        if self.source_project_revision < 1 or not self.provenance:
            raise OrganizationalKnowledgeError("source revision and provenance are required")
        _sha256(self.source_project_fingerprint, "source Project fingerprint")
        _sha256(self.record_digest, "record digest")
        if not self.evidence_digests:
            raise OrganizationalKnowledgeError("evidence digests are required")
        for value in self.evidence_digests:
            _sha256(value, "evidence digest")
        if self.confidence < 0.7 or self.confidence > 1:
            raise OrganizationalKnowledgeError("promotion confidence must be between 0.7 and 1")
        if self.sensitivity is Sensitivity.RESTRICTED:
            raise OrganizationalKnowledgeError("RESTRICTED knowledge cannot enter the org store")
        if _instant(self.fresh_until) <= _instant(self.created_at):
            raise OrganizationalKnowledgeError("freshness horizon must follow promotion")
        if self.promotion_decision != "APPROVED":
            raise OrganizationalKnowledgeError("only approved promotion decisions are active")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_project_id": self.source_project_id,
            "source_project_revision": self.source_project_revision,
            "source_project_fingerprint": self.source_project_fingerprint,
            "source_lesson_id": self.source_lesson_id,
            "kind": self.kind.value,
            "statement": self.statement,
            "provenance": [dict(item) for item in self.provenance],
            "evidence_digests": list(self.evidence_digests),
            "confidence": self.confidence,
            "sensitivity": self.sensitivity.value,
            "applicability": self.applicability.to_dict(),
            "fresh_until": self.fresh_until,
            "validator_id": self.validator_id,
            "promotion_actor_id": self.promotion_actor_id,
            "promotion_policy": self.promotion_policy,
            "promotion_decision": self.promotion_decision,
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "record_digest": self.record_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> OrganizationalKnowledgeRecord:
        provenance = value.get("provenance", [])
        if not isinstance(provenance, Sequence) or isinstance(provenance, (str, bytes)):
            raise OrganizationalKnowledgeError("provenance must be an array")
        record = cls(
            id=str(value["id"]),
            source_project_id=str(value["source_project_id"]),
            source_project_revision=int(value["source_project_revision"]),
            source_project_fingerprint=str(value["source_project_fingerprint"]),
            source_lesson_id=str(value["source_lesson_id"]),
            kind=KnowledgeKind(str(value["kind"])),
            statement=str(value["statement"]),
            provenance=tuple(_mapping(item) for item in provenance),
            evidence_digests=_strings(value.get("evidence_digests", [])),
            confidence=float(value["confidence"]),
            sensitivity=Sensitivity(str(value["sensitivity"])),
            applicability=KnowledgeApplicability.from_dict(_mapping(value["applicability"])),
            fresh_until=str(value["fresh_until"]),
            validator_id=str(value["validator_id"]),
            promotion_actor_id=str(value["promotion_actor_id"]),
            promotion_policy=str(value["promotion_policy"]),
            promotion_decision=str(value["promotion_decision"]),
            created_at=str(value["created_at"]),
            record_digest=str(value["record_digest"]),
        )
        if _digest(record.unsigned_dict()) != record.record_digest:
            raise OrganizationalKnowledgeError("Organizational Knowledge record is tampered")
        return record


@dataclass(frozen=True, slots=True)
class KnowledgeRecommendation:
    id: str
    knowledge_id: str
    knowledge_digest: str
    target_project_id: str
    target_revision: int
    target_fingerprint: str
    recommended_by: str
    created_at: str
    advisory: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "knowledge_id": self.knowledge_id,
            "knowledge_digest": self.knowledge_digest,
            "target_project_id": self.target_project_id,
            "target_revision": self.target_revision,
            "target_fingerprint": self.target_fingerprint,
            "recommended_by": self.recommended_by, "created_at": self.created_at,
            "advisory": self.advisory,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> KnowledgeRecommendation:
        result = cls(
            str(value["id"]), str(value["knowledge_id"]), str(value["knowledge_digest"]),
            str(value["target_project_id"]), int(value["target_revision"]),
            str(value["target_fingerprint"]), str(value["recommended_by"]),
            str(value["created_at"]), bool(value.get("advisory", True)),
        )
        if not result.id.startswith("ORGR-") or not result.advisory:
            raise OrganizationalKnowledgeError("recommendation identity/advisory marker is invalid")
        _sha256(result.knowledge_digest, "knowledge digest")
        _sha256(result.target_fingerprint, "target fingerprint")
        return result


class OrganizationalKnowledgeStore:
    """Transactional authority isolated from all Project semantic repositories."""

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS organizational_knowledge (
                    id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recommendations (
                    id TEXT PRIMARY KEY, knowledge_id TEXT NOT NULL,
                    target_project_id TEXT NOT NULL, digest TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    FOREIGN KEY(knowledge_id) REFERENCES organizational_knowledge(id)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS migration_quarantine (
                    migration_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
                    lesson_id TEXT NOT NULL, classification TEXT NOT NULL, payload TEXT NOT NULL,
                    UNIQUE(instance_id, lesson_id)
                );
                """
            )

    def add_record(self, record: OrganizationalKnowledgeRecord) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO organizational_knowledge(id,digest,payload) VALUES(?,?,?)",
                (record.id, record.record_digest, _canonical(record.to_dict())),
            )
            self._audit(connection, "KNOWLEDGE_PROMOTED", record.promotion_actor_id,
                        {"id": record.id, "digest": record.record_digest})

    def get_record(self, identifier: str) -> OrganizationalKnowledgeRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload,digest FROM organizational_knowledge WHERE id=?", (identifier,)
            ).fetchone()
        if row is None:
            raise OrganizationalKnowledgeError(f"unknown Organizational Knowledge: {identifier}")
        record = OrganizationalKnowledgeRecord.from_dict(_mapping(json.loads(str(row[0]))))
        if record.record_digest != row[1]:
            raise OrganizationalKnowledgeError("Organizational Knowledge index is tampered")
        return record

    def records(self) -> tuple[OrganizationalKnowledgeRecord, ...]:
        with self._connect() as connection:
            ids = tuple(row[0] for row in connection.execute(
                "SELECT id FROM organizational_knowledge ORDER BY id"
            ))
        return tuple(self.get_record(str(identifier)) for identifier in ids)

    def add_recommendation(self, recommendation: KnowledgeRecommendation) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO recommendations(id,knowledge_id,target_project_id,digest,payload) "
                "VALUES(?,?,?,?,?)",
                (recommendation.id, recommendation.knowledge_id,
                 recommendation.target_project_id, _digest(recommendation.to_dict()),
                 _canonical(recommendation.to_dict())),
            )
            self._audit(connection, "KNOWLEDGE_RECOMMENDED", recommendation.recommended_by,
                        recommendation.to_dict())

    def get_recommendation(self, identifier: str) -> KnowledgeRecommendation:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload,knowledge_id,target_project_id,digest "
                "FROM recommendations WHERE id=?", (identifier,)
            ).fetchone()
        if row is None:
            raise OrganizationalKnowledgeError(f"unknown recommendation: {identifier}")
        recommendation = KnowledgeRecommendation.from_dict(_mapping(json.loads(str(row[0]))))
        if (
            recommendation.knowledge_id != row[1]
            or recommendation.target_project_id != row[2]
            or _digest(recommendation.to_dict()) != row[3]
        ):
            raise OrganizationalKnowledgeError("recommendation is tampered")
        return recommendation

    def quarantine(self, instance_id: str, item: KnowledgeItem,
                   classification: str, reasons: tuple[str, ...], actor_id: str) -> dict[str, Any]:
        payload = {
            "migration_id": f"MIGK-{uuid.uuid4()}", "instance_id": instance_id,
            "lesson_id": str(item.id), "classification": classification,
            "reasons": list(reasons), "knowledge": item.to_dict(),
            "acceptance": "N/A", "searchable": False, "created_at": _now(),
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload FROM migration_quarantine WHERE instance_id=? AND lesson_id=?",
                (instance_id, str(item.id)),
            ).fetchone()
            if existing is not None:
                return dict(_mapping(json.loads(str(existing[0]))))
            connection.execute(
                "INSERT INTO migration_quarantine VALUES(?,?,?,?,?)",
                (payload["migration_id"], instance_id, str(item.id), classification,
                 _canonical(payload)),
            )
            self._audit(connection, "V1_KNOWLEDGE_QUARANTINED", actor_id, payload)
        return payload

    @staticmethod
    def _audit(connection: sqlite3.Connection, event: str, actor: str,
               payload: Mapping[str, Any]) -> None:
        connection.execute("INSERT INTO audit(event_type,actor_id,payload) VALUES(?,?,?)",
                           (event, actor, _canonical(payload)))


class OrganizationalKnowledgeService:
    def __init__(self, database_path: str | Path) -> None:
        self.store = OrganizationalKnowledgeStore(database_path)

    def record_project_lesson(
        self, *, project_root: str | Path, project_id: str,
        lesson: KnowledgeItem, actor: ActorPrincipal,
    ) -> KnowledgeItem:
        """Record the Project-scoped source candidate; this is never an adoption path."""

        self._require_separate_from(project_root)
        _authorize(actor, "knowledge:record", project_id)
        current = ProjectAuthority(project_root).current()
        if current.project_id != project_id:
            raise OrganizationalKnowledgeError("Project identity does not match authority")
        if lesson.scope is not KnowledgeScope.PROJECT or lesson.project_id != project_id:
            raise OrganizationalKnowledgeError("source lesson must be scoped to its Project")
        self._validate_promotable(lesson)
        ProjectLessonStore(project_root, project_id).add(lesson)
        return lesson

    def promote(
        self, *, source_project_root: str | Path, source_project_id: str,
        lesson_id: str, applicability: KnowledgeApplicability, fresh_until: str,
        evidence_digests: tuple[str, ...], validator_id: str,
        actor: ActorPrincipal, created_at: str | None = None,
    ) -> OrganizationalKnowledgeRecord:
        self._require_separate_from(source_project_root)
        _authorize(actor, "knowledge:promote", source_project_id)
        authority = ProjectAuthority(source_project_root)
        source = authority.current()
        if source.project_id != source_project_id:
            raise OrganizationalKnowledgeError("source Project identity does not match authority")
        matches = [item for item in ProjectLessonStore(
            source_project_root, source_project_id
        ).list() if str(item.id) == lesson_id]
        if len(matches) != 1:
            raise OrganizationalKnowledgeError("promotion source lesson is missing or ambiguous")
        lesson = matches[0]
        self._validate_promotable(lesson)
        for value in evidence_digests:
            _sha256(value, "evidence digest")
        evidence_ids = {
            identifier for item in lesson.provenance for identifier in item.evidence_ids
        }
        if len(evidence_digests) < max(1, len(evidence_ids)):
            raise OrganizationalKnowledgeError("evidence digests do not cover source provenance")
        timestamp = created_at or _now()
        policy = _canonical(lesson.promotion_policy.to_dict())
        unsigned: dict[str, Any] = {
            "id": f"ORGK-{uuid.uuid4()}", "source_project_id": source_project_id,
            "source_project_revision": source.number,
            "source_project_fingerprint": source.fingerprint,
            "source_lesson_id": str(lesson.id), "kind": lesson.kind.value,
            "statement": lesson.statement,
            "provenance": [item.to_dict() for item in lesson.provenance],
            "evidence_digests": list(evidence_digests), "confidence": lesson.confidence,
            "sensitivity": lesson.sensitivity.value,
            "applicability": applicability.to_dict(), "fresh_until": fresh_until,
            "validator_id": validator_id, "promotion_actor_id": actor.actor_id,
            "promotion_policy": policy, "promotion_decision": "APPROVED",
            "created_at": timestamp,
        }
        record = OrganizationalKnowledgeRecord.from_dict(
            {**unsigned, "record_digest": _digest(unsigned)}
        )
        self.store.add_record(record)
        return record

    def search(
        self, *, query: str, target_project_id: str, actor: ActorPrincipal,
        clearance: Sensitivity = Sensitivity.INTERNAL,
        tags: frozenset[str] = frozenset(), domains: frozenset[str] = frozenset(),
        now: str | None = None,
    ) -> tuple[OrganizationalKnowledgeRecord, ...]:
        _authorize(actor, "knowledge:read", target_project_id)
        if not query.strip():
            raise OrganizationalKnowledgeError("search query is required")
        instant = _instant(now or _now())
        terms = {term.casefold() for term in re.findall(r"[A-Za-z0-9_-]+", query)}
        result = []
        for record in self.store.records():
            if _instant(record.fresh_until) <= instant:
                continue
            if _SENSITIVITY_RANK[record.sensitivity] > _SENSITIVITY_RANK[clearance]:
                continue
            if not record.applicability.matches(target_project_id, tags=tags, domains=domains):
                continue
            haystack = set(re.findall(r"[A-Za-z0-9_-]+", record.statement.casefold()))
            if terms & haystack:
                result.append(record)
        return tuple(sorted(result, key=lambda item: (-item.confidence, item.id)))

    def recommend(
        self, *, knowledge_id: str, target_project_root: str | Path,
        target_project_id: str, actor: ActorPrincipal,
        clearance: Sensitivity = Sensitivity.INTERNAL, now: str | None = None,
    ) -> KnowledgeRecommendation:
        self._require_separate_from(target_project_root)
        _authorize(actor, "knowledge:recommend", target_project_id)
        record = self.store.get_record(knowledge_id)
        instant = _instant(now or _now())
        if _instant(record.fresh_until) <= instant:
            raise OrganizationalKnowledgeError("stale knowledge cannot be recommended")
        if _SENSITIVITY_RANK[record.sensitivity] > _SENSITIVITY_RANK[clearance]:
            raise PermissionError("knowledge sensitivity exceeds actor clearance")
        if not record.applicability.matches(target_project_id):
            raise OrganizationalKnowledgeError("knowledge is not applicable to target Project")
        target = ProjectAuthority(target_project_root).current()
        if target.project_id != target_project_id:
            raise OrganizationalKnowledgeError("target Project identity does not match authority")
        recommendation = KnowledgeRecommendation(
            f"ORGR-{uuid.uuid4()}", record.id, record.record_digest, target_project_id,
            target.number, target.fingerprint, actor.actor_id, now or _now(), True,
        )
        self.store.add_recommendation(recommendation)
        return recommendation

    def adopt(
        self, *, recommendation_id: str, target_project_root: str | Path,
        expected_revision: int, actor: ActorPrincipal, accepted_at: str | None = None,
    ) -> dict[str, Any]:
        self._require_separate_from(target_project_root)
        recommendation = self.store.get_recommendation(recommendation_id)
        _authorize(actor, "knowledge:adopt", recommendation.target_project_id)
        authority = ProjectAuthority(target_project_root)
        current = authority.current()
        if current.number != expected_revision or current.number != recommendation.target_revision:
            raise OrganizationalKnowledgeError("recommendation baseline is stale")
        if current.fingerprint != recommendation.target_fingerprint:
            raise OrganizationalKnowledgeError("recommendation target fingerprint is tampered")
        record = self.store.get_record(recommendation.knowledge_id)
        if record.record_digest != recommendation.knowledge_digest:
            raise OrganizationalKnowledgeError("recommendation knowledge binding is tampered")
        if _instant(record.fresh_until) <= _instant(accepted_at or _now()):
            raise OrganizationalKnowledgeError("stale knowledge cannot be adopted")
        if not record.applicability.matches(current.project_id):
            raise OrganizationalKnowledgeError("knowledge is not applicable to target Project")
        adoption = ProjectKnowledgeAdoption(
            organizational_knowledge_id=record.id,
            recommendation_id=recommendation.id,
            statement=record.statement,
            source_project_id=record.source_project_id,
            source_project_revision=record.source_project_revision,
            source_project_fingerprint=record.source_project_fingerprint,
            source_lesson_id=record.source_lesson_id,
            provenance=tuple(KnowledgeAdoptionProvenance.from_dict(item)
                             for item in record.provenance),
            confidence=record.confidence,
            applicable_project_ids=record.applicability.project_ids,
            applicability_tags=record.applicability.tags,
            applicability_domains=record.applicability.domains,
            fresh_until=record.fresh_until,
            record_digest=record.record_digest,
            evidence_digests=record.evidence_digests,
            validator_id=record.validator_id,
            promotion_actor_id=record.promotion_actor_id,
            promotion_policy=record.promotion_policy,
            promotion_decision=record.promotion_decision,
            adopted_by=actor.actor_id,
            adopted_at=accepted_at or _now(),
        )
        model = ProjectModel(
            project=current.model.project, git=current.model.git,
            artifacts=current.model.artifacts, entities=current.model.entities,
            governance=current.model.governance,
            knowledge_adoptions=(*current.model.knowledge_adoptions, adoption),
            schema_version=current.model.schema_version,
        )
        proposal = authority.propose(
            model, expected_revision=expected_revision, actor=actor.actor_id,
            source="ORGANIZATIONAL_KNOWLEDGE_ADOPTION",
        )
        revision = authority.accept(
            proposal.id, expected_revision=expected_revision, actor=actor.actor_id,
            accepted_at=accepted_at,
        )
        return {"proposal": proposal.to_dict(), "revision": revision.to_dict(),
                "adoption": adoption.to_dict()}

    def classify_v1_instance(
        self, *, state_root: str | Path, instance_id: str,
        actor: ActorPrincipal, apply: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        _authorize(actor, "knowledge:migrate", "*")
        results = []
        for item in InstanceKnowledgeStore(state_root, instance_id).list():
            reasons: list[str] = []
            sources = [match.group(1) for provenance in item.provenance
                       if (match := _PROJECT_SOURCE.fullmatch(provenance.source))]
            if item.scope is not KnowledgeScope.INSTANCE:
                reasons.append("NOT_INSTANCE")
            if item.promoted_from is not KnowledgeScope.PROJECT:
                reasons.append("NOT_PROJECT_PROMOTED")
            if item.state is not KnowledgeState.CURRENT:
                reasons.append("NOT_CURRENT")
            if len(set(sources)) != 1:
                reasons.append("PROJECT_PROVENANCE_UNBOUND")
            if item.sensitivity is Sensitivity.RESTRICTED:
                reasons.append("RESTRICTED")
            if item.confidence < 0.7:
                reasons.append("LOW_CONFIDENCE")
            if not any(provenance.evidence_ids for provenance in item.provenance):
                reasons.append("EVIDENCE_UNBOUND")
            classification = "ELIGIBLE_QUARANTINE" if not reasons else "INELIGIBLE_QUARANTINE"
            value = {"instance_id": instance_id, "lesson_id": str(item.id),
                     "classification": classification, "reasons": reasons,
                     "acceptance": "N/A", "searchable": False}
            if apply:
                value = self.store.quarantine(
                    instance_id, item, classification, tuple(reasons), actor.actor_id
                )
            results.append(value)
        return tuple(results)

    @staticmethod
    def _validate_promotable(item: KnowledgeItem) -> None:
        if item.scope is not KnowledgeScope.PROJECT or item.state is not KnowledgeState.CURRENT:
            raise OrganizationalKnowledgeError("only CURRENT Project knowledge is promotable")
        if item.kind not in {KnowledgeKind.LESSON, KnowledgeKind.PATTERN}:
            raise OrganizationalKnowledgeError("only validated lessons or patterns are promotable")
        if item.confidence < max(0.7, item.promotion_policy.minimum_confidence):
            raise OrganizationalKnowledgeError("knowledge confidence is below promotion policy")
        if item.sensitivity is Sensitivity.RESTRICTED:
            raise OrganizationalKnowledgeError("RESTRICTED knowledge cannot be promoted")
        if (
            _SENSITIVITY_RANK[item.sensitivity]
            > _SENSITIVITY_RANK[item.promotion_policy.maximum_sensitivity]
        ):
            raise OrganizationalKnowledgeError(
                "knowledge sensitivity exceeds its promotion policy"
            )
        evidence = sum(len(provenance.evidence_ids) for provenance in item.provenance)
        if evidence < item.promotion_policy.minimum_evidence:
            raise OrganizationalKnowledgeError("knowledge evidence is below promotion policy")

    def _require_separate_from(self, project_root: str | Path) -> None:
        root = Path(project_root).expanduser().resolve()
        if self.store.path == root or self.store.path.is_relative_to(root):
            raise OrganizationalKnowledgeError(
                "Organizational Knowledge authority must be outside every Project repository"
            )


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OrganizationalKnowledgeError("expected object")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise OrganizationalKnowledgeError("expected string array")
    if not all(isinstance(item, str) for item in value):
        raise OrganizationalKnowledgeError("expected string array")
    return tuple(value)

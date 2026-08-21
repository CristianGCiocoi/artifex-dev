"""Provider-neutral research request and evidence bundle contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from artifex.integrations.contracts import IntegrationError


@dataclass(frozen=True, slots=True)
class ResearchRequest:
    request_id: str
    purpose: str
    stage: str
    questions: tuple[str, ...]
    project_constraints: tuple[str, ...]
    required_freshness: str
    required_source_quality: str
    resource_envelope: Mapping[str, Any]
    desired_alternatives: int = 2
    desired_risks: bool = True
    output_form: str = "research-bundle-v1"
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise IntegrationError("unsupported research request schema")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.request_id):
            raise IntegrationError("research request ID must be portable")
        required = (
            self.purpose,
            self.stage,
            self.required_freshness,
            self.required_source_quality,
            self.output_form,
        )
        if not all(item.strip() for item in required) or not self.questions:
            raise IntegrationError("research purpose, stage, questions, and policy are required")
        if any(not item.strip() for item in self.questions + self.project_constraints):
            raise IntegrationError("questions and constraints must be non-empty")
        if self.desired_alternatives < 0:
            raise IntegrationError("desired_alternatives cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "RESEARCH_REQUEST",
            "request_id": self.request_id,
            "purpose": self.purpose,
            "stage": self.stage,
            "questions": list(self.questions),
            "project_constraints": list(self.project_constraints),
            "required_freshness": self.required_freshness,
            "required_source_quality": self.required_source_quality,
            "resource_envelope": dict(self.resource_envelope),
            "desired_alternatives": self.desired_alternatives,
            "desired_risks": self.desired_risks,
            "output_form": self.output_form,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ResearchRequest:
        _expect_kind(value, "RESEARCH_REQUEST")
        return cls(
            request_id=str(value.get("request_id", "")),
            purpose=str(value.get("purpose", "")),
            stage=str(value.get("stage", "")),
            questions=_strings(value.get("questions"), "questions"),
            project_constraints=_strings(
                value.get("project_constraints", ()), "project_constraints"
            ),
            required_freshness=str(value.get("required_freshness", "")),
            required_source_quality=str(value.get("required_source_quality", "")),
            resource_envelope=_object(value.get("resource_envelope", {}), "resource_envelope"),
            desired_alternatives=_integer(
                value.get("desired_alternatives", 2), "desired_alternatives"
            ),
            desired_risks=_boolean(value.get("desired_risks", True), "desired_risks"),
            output_form=str(value.get("output_form", "research-bundle-v1")),
            schema_version=str(value.get("schema_version", "")),
        )


@dataclass(frozen=True, slots=True)
class ResearchClaim:
    claim: str
    evidence_source_ids: tuple[str, ...]
    confidence: float

    def __post_init__(self) -> None:
        if not self.claim.strip() or not self.evidence_source_ids:
            raise IntegrationError("a research claim requires evidence")
        if not 0.0 <= self.confidence <= 1.0:
            raise IntegrationError("claim confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "evidence_source_ids": list(self.evidence_source_ids),
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ResearchClaim:
        confidence = value.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise IntegrationError("confidence must be a number")
        return cls(
            claim=str(value.get("claim", "")),
            evidence_source_ids=_strings(value.get("evidence_source_ids"), "evidence_source_ids"),
            confidence=float(confidence),
        )


@dataclass(frozen=True, slots=True)
class ResearchSource:
    source_id: str
    uri: str
    title: str
    retrieved_at: str
    quality: str

    def __post_init__(self) -> None:
        if not all(
            item.strip()
            for item in (self.source_id, self.uri, self.title, self.retrieved_at, self.quality)
        ):
            raise IntegrationError("research source manifest entries must be complete")
        try:
            parsed = datetime.fromisoformat(self.retrieved_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise IntegrationError("source retrieved_at must be ISO-8601") from exc
        if parsed.tzinfo is None:
            raise IntegrationError("source retrieved_at must include a timezone")

    def to_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "uri": self.uri,
            "title": self.title,
            "retrieved_at": self.retrieved_at,
            "quality": self.quality,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ResearchSource:
        return cls(
            source_id=str(value.get("source_id", "")),
            uri=str(value.get("uri", "")),
            title=str(value.get("title", "")),
            retrieved_at=str(value.get("retrieved_at", "")),
            quality=str(value.get("quality", "")),
        )


@dataclass(frozen=True, slots=True)
class ResearchBundle:
    bundle_id: str
    request_id: str
    findings: tuple[str, ...]
    alternatives: tuple[Mapping[str, Any], ...]
    claims: tuple[ResearchClaim, ...]
    unresolved_questions: tuple[str, ...]
    source_manifest: tuple[ResearchSource, ...]
    generation_metadata: Mapping[str, Any]
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise IntegrationError("unsupported research bundle schema")
        if not self.bundle_id.strip() or not self.request_id.strip() or not self.findings:
            raise IntegrationError("research bundle identity and findings are required")
        source_ids = [source.source_id for source in self.source_manifest]
        if len(source_ids) != len(set(source_ids)):
            raise IntegrationError("research source IDs must be unique")
        missing = {
            source_id
            for claim in self.claims
            for source_id in claim.evidence_source_ids
            if source_id not in source_ids
        }
        if missing:
            raise IntegrationError(f"research claims reference missing sources: {sorted(missing)}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "RESEARCH_BUNDLE",
            "bundle_id": self.bundle_id,
            "request_id": self.request_id,
            "findings": list(self.findings),
            "alternatives": [dict(item) for item in self.alternatives],
            "claims": [item.to_dict() for item in self.claims],
            "unresolved_questions": list(self.unresolved_questions),
            "source_manifest": [item.to_dict() for item in self.source_manifest],
            "generation_metadata": dict(self.generation_metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ResearchBundle:
        _expect_kind(value, "RESEARCH_BUNDLE")
        alternatives = _array(value.get("alternatives", ()), "alternatives")
        claims = _array(value.get("claims", ()), "claims")
        sources = _array(value.get("source_manifest", ()), "source_manifest")
        return cls(
            bundle_id=str(value.get("bundle_id", "")),
            request_id=str(value.get("request_id", "")),
            findings=_strings(value.get("findings"), "findings"),
            alternatives=tuple(_object(item, "alternative") for item in alternatives),
            claims=tuple(ResearchClaim.from_dict(_object(item, "claim")) for item in claims),
            unresolved_questions=_strings(
                value.get("unresolved_questions", ()), "unresolved_questions"
            ),
            source_manifest=tuple(
                ResearchSource.from_dict(_object(item, "source")) for item in sources
            ),
            generation_metadata=_object(value.get("generation_metadata"), "generation_metadata"),
            schema_version=str(value.get("schema_version", "")),
        )


def _expect_kind(value: Mapping[str, Any], kind: str) -> None:
    supplied = value.get("kind")
    if supplied is not None and supplied != kind:
        raise IntegrationError(f"expected {kind}, got {supplied!r}")


def _array(value: Any, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise IntegrationError(f"{name} must be an array")
    return value


def _strings(value: Any, name: str) -> tuple[str, ...]:
    items = _array(value, name)
    if not all(isinstance(item, str) for item in items):
        raise IntegrationError(f"{name} must contain only strings")
    return tuple(items)


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrationError(f"{name} must be an object")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IntegrationError(f"{name} must be an integer")
    return int(value)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise IntegrationError(f"{name} must be a boolean")
    return value

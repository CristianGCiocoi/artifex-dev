"""Agent-neutral contracts for ARTIFEX integrations and manual execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from artifex.workflow import ExecutionBaseline, ExecutionStatus, classify_execution_result


class IntegrationError(ValueError):
    """An integration value violates the frozen integration contract."""


class IntegrationRole(StrEnum):
    INTERFACE = "interface"
    HARNESS = "harness"
    IMPLEMENTER = "implementer"
    RESEARCH_PROVIDER = "research_provider"


class Capability(StrEnum):
    INTERACTIVE = "interactive"
    HEADLESS = "headless"
    RESUME = "resume"
    SKILLS = "skills"
    MCP = "MCP"
    WORKTREES = "worktrees"
    SUBAGENTS = "subagents"
    STRUCTURED_OUTPUT = "structured_output"
    REPOSITORY_READ = "repository_read"
    REPOSITORY_WRITE = "repository_write"
    TEST_EXECUTION = "test_execution"
    BACKGROUND_JOBS = "background_jobs"


class HealthStatus(StrEnum):
    PASS = "PASS"
    DEGRADED = "DEGRADED"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class CompatibilityRange:
    """Inclusive minimum and exclusive maximum Core versions."""

    minimum: str
    maximum_exclusive: str | None = None

    def __post_init__(self) -> None:
        _version_tuple(self.minimum)
        if self.maximum_exclusive is not None and _version_tuple(
            self.maximum_exclusive
        ) <= _version_tuple(self.minimum):
            raise IntegrationError("maximum_exclusive must be greater than minimum")

    def supports(self, core_version: str) -> bool:
        observed = _version_tuple(core_version)
        return observed >= _version_tuple(self.minimum) and (
            self.maximum_exclusive is None or observed < _version_tuple(self.maximum_exclusive)
        )

    def to_dict(self) -> dict[str, str | None]:
        return {"minimum": self.minimum, "maximum_exclusive": self.maximum_exclusive}


@dataclass(frozen=True, slots=True)
class ConfigurationProvenance:
    """Secret-free description of where adapter configuration came from."""

    source: str
    reference: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise IntegrationError("configuration provenance source is required")

    def to_dict(self) -> dict[str, str | None]:
        return {"source": self.source, "reference": self.reference}


@dataclass(frozen=True, slots=True)
class IntegrationMetadata:
    integration_id: str
    name: str
    version: str
    compatibility: CompatibilityRange
    tested_external_versions: tuple[str, ...]
    roles: frozenset[IntegrationRole]
    capabilities: frozenset[str]
    configuration: ConfigurationProvenance

    def __post_init__(self) -> None:
        if not all(item.strip() for item in (self.integration_id, self.name, self.version)):
            raise IntegrationError("integration ID, name, and version are required")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", self.integration_id):
            raise IntegrationError("integration ID must be a portable lowercase identifier")
        if not self.roles:
            raise IntegrationError("an integration must advertise at least one role")
        if any(not capability.strip() for capability in self.capabilities):
            raise IntegrationError("capabilities must be non-empty strings")

    def to_dict(self, *, core_version: str | None = None) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.integration_id,
            "name": self.name,
            "version": self.version,
            "compatibility": self.compatibility.to_dict(),
            "tested_external_versions": list(self.tested_external_versions),
            "roles": sorted(role.value for role in self.roles),
            "capabilities": sorted(self.capabilities),
            "configuration_provenance": self.configuration.to_dict(),
        }
        if core_version is not None:
            value["core_compatible"] = self.compatibility.supports(core_version)
        return value


@dataclass(frozen=True, slots=True)
class HealthReport:
    status: HealthStatus
    summary: str
    checks: Mapping[str, HealthStatus] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise IntegrationError("health summary is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "summary": self.summary,
            "checks": {key: value.value for key, value in sorted(self.checks.items())},
        }


@dataclass(frozen=True, slots=True)
class ExecutionPacket:
    """Portable, transcript-independent manual implementer contract."""

    task_contract: Mapping[str, Any]
    context: Mapping[str, Any]
    base_commit: str
    project_model_fingerprint: str
    acceptance_criteria: tuple[Any, ...]
    ownership: Mapping[str, Any]
    expected_result: Mapping[str, Any]
    interfaces: tuple[str, ...] = ()
    invariants: tuple[str, ...] = ()
    schema_version: str = "1.0"
    kind: str = "EXECUTION_PACKET"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0" or self.kind != "EXECUTION_PACKET":
            raise IntegrationError("unsupported execution packet contract")
        if not self.task_contract or not self.base_commit.strip():
            raise IntegrationError("task contract and base commit are required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.project_model_fingerprint):
            raise IntegrationError("project_model_fingerprint must be a SHA-256 digest")
        if not self.acceptance_criteria:
            raise IntegrationError("acceptance criteria are required")
        if not self.expected_result:
            raise IntegrationError("expected result contract is required")

    @property
    def contract_fingerprint(self) -> str:
        return _fingerprint(self._contract_dict())

    @property
    def baseline(self) -> ExecutionBaseline:
        return ExecutionBaseline(
            self.base_commit, self.contract_fingerprint, self.project_model_fingerprint
        )

    def _contract_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "task_contract": _copy_json(self.task_contract),
            "context": _copy_json(self.context),
            "base_commit": self.base_commit,
            "project_model_fingerprint": self.project_model_fingerprint,
            "acceptance_criteria": _copy_json(self.acceptance_criteria),
            "ownership": _copy_json(self.ownership),
            "expected_result": _copy_json(self.expected_result),
            "interfaces": list(self.interfaces),
            "invariants": list(self.invariants),
        }

    def to_dict(self) -> dict[str, Any]:
        value = self._contract_dict()
        value["execution_contract_fingerprint"] = self.contract_fingerprint
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExecutionPacket:
        criteria = value.get("acceptance_criteria", ())
        interfaces = value.get("interfaces", ())
        invariants = value.get("invariants", ())
        packet = cls(
            task_contract=_mapping(value.get("task_contract"), "task_contract"),
            context=_mapping(value.get("context", {}), "context"),
            base_commit=str(value.get("base_commit", "")),
            project_model_fingerprint=str(value.get("project_model_fingerprint", "")),
            acceptance_criteria=tuple(_sequence(criteria, "acceptance_criteria")),
            ownership=_mapping(value.get("ownership", {}), "ownership"),
            expected_result=_mapping(value.get("expected_result"), "expected_result"),
            interfaces=tuple(str(item) for item in _sequence(interfaces, "interfaces")),
            invariants=tuple(str(item) for item in _sequence(invariants, "invariants")),
            schema_version=str(value.get("schema_version", "")),
            kind=str(value.get("kind", "")),
        )
        supplied = value.get("execution_contract_fingerprint")
        if supplied is not None and supplied != packet.contract_fingerprint:
            raise IntegrationError("execution packet contract fingerprint does not match content")
        return packet


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    status: ExecutionStatus
    base_commit: str
    execution_contract_fingerprint: str
    project_model_fingerprint: str
    artifacts: tuple[Mapping[str, Any], ...] = ()
    validation: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""

    def __post_init__(self) -> None:
        if not all(
            item.strip()
            for item in (
                self.base_commit,
                self.execution_contract_fingerprint,
                self.project_model_fingerprint,
            )
        ):
            raise IntegrationError("result baseline fields are required")

    @property
    def baseline(self) -> ExecutionBaseline:
        return ExecutionBaseline(
            self.base_commit,
            self.execution_contract_fingerprint,
            self.project_model_fingerprint,
        )

    def classified(self, current: ExecutionBaseline) -> ExecutionResult:
        status = classify_execution_result(self.baseline, current, self.status)
        if status is self.status:
            return self
        return ExecutionResult(
            status,
            self.base_commit,
            self.execution_contract_fingerprint,
            self.project_model_fingerprint,
            self.artifacts,
            self.validation,
            self.message,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "base_commit": self.base_commit,
            "execution_contract_fingerprint": self.execution_contract_fingerprint,
            "project_model_fingerprint": self.project_model_fingerprint,
            "artifacts": [_copy_json(item) for item in self.artifacts],
            "validation": _copy_json(self.validation),
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExecutionResult:
        artifacts = _sequence(value.get("artifacts", ()), "artifacts")
        return cls(
            status=ExecutionStatus(str(value.get("status", ""))),
            base_commit=str(value.get("base_commit", "")),
            execution_contract_fingerprint=str(value.get("execution_contract_fingerprint", "")),
            project_model_fingerprint=str(value.get("project_model_fingerprint", "")),
            artifacts=tuple(_mapping(item, "artifact") for item in artifacts),
            validation=_mapping(value.get("validation", {}), "validation"),
            message=str(value.get("message", "")),
        )


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?", value)
    if match is None:
        raise IntegrationError(f"invalid semantic version: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _copy_json(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise IntegrationError("integration contracts must be JSON-serializable") from exc


def _fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrationError(f"{name} must be an object")
    return value


def _sequence(value: Any, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise IntegrationError(f"{name} must be an array")
    return value

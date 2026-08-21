"""Typed contracts for installation, discovery, and beginner presentation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ExperienceMode(StrEnum):
    BEGINNER = "BEGINNER"
    GUIDED = "GUIDED"
    EXPERT = "EXPERT"


class RiskLevel(StrEnum):
    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    HIGH_IMPACT = "HIGH_IMPACT"


@dataclass(frozen=True, slots=True)
class ResourceEnvelope:
    logical_cpu_count: int
    memory_bytes: int | None
    disk_free_bytes: int
    platform: str
    architecture: str

    def __post_init__(self) -> None:
        if self.logical_cpu_count < 1 or self.disk_free_bytes < 0:
            raise ValueError("resource measurements cannot be negative or empty")
        if self.memory_bytes is not None and self.memory_bytes < 0:
            raise ValueError("memory_bytes cannot be negative")

    def to_dict(self) -> dict[str, int | str | None]:
        return {
            "logical_cpu_count": self.logical_cpu_count,
            "memory_bytes": self.memory_bytes,
            "disk_free_bytes": self.disk_free_bytes,
            "platform": self.platform,
            "architecture": self.architecture,
        }


@dataclass(frozen=True, slots=True)
class ToolDiscovery:
    tool: str
    status: str
    executable: str | None
    version: str | None
    detail: str
    probe: str = "PATH + --version (read-only)"

    def to_dict(self) -> dict[str, str | None]:
        return {
            "tool": self.tool,
            "status": self.status,
            "executable": self.executable,
            "version": self.version,
            "detail": self.detail,
            "probe": self.probe,
        }


@dataclass(frozen=True, slots=True)
class EnvironmentDiscovery:
    tools: tuple[ToolDiscovery, ...]
    resources: ResourceEnvelope
    bounded_read_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": [tool.to_dict() for tool in self.tools],
            "resources": self.resources.to_dict(),
            "bounded_read_only": self.bounded_read_only,
        }


@dataclass(frozen=True, slots=True)
class DecisionExplanation:
    action: str
    risk: RiskLevel
    effects: tuple[str, ...]
    rollback: str
    approval_required: bool
    confirmation_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "risk": self.risk.value,
            "effects": list(self.effects),
            "rollback": self.rollback,
            "approval_required": self.approval_required,
            "confirmation_token": self.confirmation_token,
        }


@dataclass(frozen=True, slots=True)
class SetupAction:
    integration_id: str
    state_path: str
    effect: str
    vendor_configuration_mutated: bool = False

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "integration_id": self.integration_id,
            "state_path": self.state_path,
            "effect": self.effect,
            "vendor_configuration_mutated": self.vendor_configuration_mutated,
        }


@dataclass(frozen=True, slots=True)
class SetupPlan:
    project_root: str
    actions: tuple[SetupAction, ...]
    decision: DecisionExplanation
    applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": self.project_root,
            "actions": [action.to_dict() for action in self.actions],
            "decision": self.decision.to_dict(),
            "applied": self.applied,
        }


@dataclass(frozen=True, slots=True)
class DoctorFinding:
    finding_id: str
    status: str
    summary: str
    remediation_id: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "id": self.finding_id,
            "status": self.status,
            "summary": self.summary,
            "remediation_id": self.remediation_id,
        }


@dataclass(frozen=True, slots=True)
class DistributionDoctorReport:
    status: str
    findings: tuple[DoctorFinding, ...]
    fixes: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    dry_run: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "fixes": [dict(fix) for fix in self.fixes],
            "dry_run": self.dry_run,
        }

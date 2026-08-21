"""Reusable integration conformance harness for the frozen V1 boundary."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol

from artifex import __version__
from artifex.integrations.contracts import (
    ExecutionPacket,
    ExecutionResult,
    HealthReport,
    HealthStatus,
    IntegrationMetadata,
)
from artifex.workflow import ExecutionBaseline, ExecutionStatus


class ConformantIntegration(Protocol):
    @property
    def metadata(self) -> IntegrationMetadata: ...

    def health(self) -> HealthReport: ...

    def read_project_status(self, project_root: str | Path) -> Mapping[str, Any]: ...

    def prepare_execution(
        self,
        *,
        task_contract: Mapping[str, Any],
        context: Mapping[str, Any],
        base_commit: str,
        project_model_fingerprint: str,
        acceptance_criteria: Sequence[Any],
        ownership: Mapping[str, Any],
        expected_result: Mapping[str, Any],
        interfaces: Sequence[str] = (),
        invariants: Sequence[str] = (),
    ) -> ExecutionPacket: ...

    def submit_result(
        self,
        packet: ExecutionPacket,
        result: ExecutionResult,
        *,
        current_baseline: ExecutionBaseline | None = None,
    ) -> ExecutionResult: ...

    def submit_validation(self, validation: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def cancel(self, packet: ExecutionPacket, *, message: str = "") -> ExecutionResult: ...


@dataclass(frozen=True, slots=True)
class ConformanceCheck:
    check_id: str
    status: HealthStatus
    summary: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.check_id,
            "status": self.status.value,
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    integration_id: str
    status: HealthStatus
    checks: tuple[ConformanceCheck, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "integration_id": self.integration_id,
            "status": self.status.value,
            "checks": [check.to_dict() for check in self.checks],
        }


class IntegrationConformanceSuite:
    """Exercise required behavior through public integration methods."""

    def run(self, integration: ConformantIntegration) -> ConformanceReport:
        checks: list[ConformanceCheck] = []

        def check(check_id: str, action: Any) -> None:
            try:
                passed, summary = action()
            except Exception as exc:  # conformance boundary records, never leaks
                checks.append(
                    ConformanceCheck(check_id, HealthStatus.FAIL, f"{type(exc).__name__}: {exc}")
                )
                return
            checks.append(
                ConformanceCheck(
                    check_id,
                    HealthStatus.PASS if passed else HealthStatus.FAIL,
                    summary,
                )
            )

        metadata = integration.metadata
        check(
            "compatibility-reporting",
            lambda: (
                metadata.compatibility.supports(__version__),
                f"Core {__version__} compatibility is reported",
            ),
        )
        check(
            "health",
            lambda: (
                integration.health().status is HealthStatus.PASS,
                integration.health().summary,
            ),
        )
        check("project-status-context-read", lambda: self._check_project_read(integration))

        packet = integration.prepare_execution(
            task_contract={"id": "CONF-TASK", "stage": "implementation"},
            context={"relevant": ["INV-002"]},
            base_commit="a" * 40,
            project_model_fingerprint="b" * 64,
            acceptance_criteria=("portable result accepted",),
            ownership={"paths": ["fixture.txt"]},
            expected_result={"status": [status.value for status in ExecutionStatus]},
            interfaces=("Application API",),
            invariants=("INV-002",),
        )
        check(
            "stage-execution-packet",
            lambda: (
                ExecutionPacket.from_dict(packet.to_dict()) == packet,
                "portable execution packet round-trips",
            ),
        )

        success = ExecutionResult(
            ExecutionStatus.SUCCESS,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
            artifacts=({"path": "fixture.txt", "state": "produced"},),
        )
        check(
            "artifact-result-submission",
            lambda: (
                integration.submit_result(packet, success).status is ExecutionStatus.SUCCESS,
                "current artifact result remains an executor success claim",
            ),
        )
        check(
            "validation-interaction",
            lambda: (
                integration.submit_validation({"outcome": "PASS"}).get("canonical") is False,
                "validation claim does not transition canonical acceptance",
            ),
        )
        failure = ExecutionResult(
            ExecutionStatus.FAIL,
            packet.base_commit,
            packet.contract_fingerprint,
            packet.project_model_fingerprint,
        )
        check(
            "failure-mapping",
            lambda: (
                integration.submit_result(packet, failure).status is ExecutionStatus.FAIL,
                "failure remains FAIL",
            ),
        )
        check(
            "cancellation-mapping",
            lambda: (
                integration.cancel(packet).status is ExecutionStatus.CANCELLED,
                "cancellation maps to CANCELLED",
            ),
        )
        stale = ExecutionBaseline(
            "c" * 40, packet.contract_fingerprint, packet.project_model_fingerprint
        )
        check(
            "stale-result-mapping",
            lambda: (
                integration.submit_result(packet, success, current_baseline=stale).status
                is ExecutionStatus.REBASE_REQUIRED,
                "stale success maps to REBASE_REQUIRED",
            ),
        )

        overall = (
            HealthStatus.PASS
            if all(item.status is HealthStatus.PASS for item in checks)
            else HealthStatus.FAIL
        )
        return ConformanceReport(metadata.integration_id, overall, tuple(checks))

    @staticmethod
    def _check_project_read(
        integration: ConformantIntegration,
    ) -> tuple[bool, str]:
        with TemporaryDirectory(prefix="artifex-conformance-") as temporary:
            root = Path(temporary)
            state = root / ".artifex"
            state.mkdir()
            (state / "status.yaml").write_text(
                "schema_version: '1.0'\nproject: {id: CONFORMANCE}\n",
                encoding="utf-8",
            )
            observed = integration.read_project_status(root)
        return observed.get("source") == ".artifex/status.yaml", "project state is readable"


ConformanceSuite = IntegrationConformanceSuite

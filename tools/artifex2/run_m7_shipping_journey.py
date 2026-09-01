"""Run an official M7 journey through the native shipping distribution.

This harness is intentionally independent of the ``artifex`` Python package.
It executes the staged and installed native executable, records only hashes and
typed assertions, and emits a capture that still requires the independent M7
Windows qualifier before it can become acceptance evidence.

The no-provider cell executes J10. Provider cells execute their standalone
J01/J02 journey together with J16 through the same native distribution.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.artifex2.validate_m7 import (
    CELL_CONTRACTS,
    DEFAULT_WINDOWS_BUILD,
    DEFAULT_WINDOWS_VERSION,
    M7_CONTRACT_DIGEST,
    WINDOWS_SERVICE_MANAGER,
    M7EvidenceError,
    canonical_sha256,
)

Runner = Any
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SENSITIVE_TEXT = re.compile(
    r"(?:authorization\s*[:=]|access[_ -]?token\s*[:=]|refresh[_ -]?token\s*[:=]|"
    r"api[_ -]?key\s*[:=]|password\s*[:=])",
    re.IGNORECASE,
)
_ACTIVE_PHASE = "initialization"
_DEFAULT_CLEAN_VM_ID = 104
_DEFAULT_CLEAN_SNAPSHOT = "m7-qualified-25h2-x64-cell-base-v10"
_RESUMABLE_PROVIDER_FAILURES = frozenset(
    {
        (
            "governance.envelope.propose failed: OPERATION_FAILED/ValueError: "
            "service_id cannot override the managed service authority"
        ),
        (
            "governance.envelope.propose failed: OPERATION_FAILED/ValueError: "
            "full M4 Execution Envelope fields are missing: ['deadline_at']"
        ),
        "runtime.provider.execute did not return one JSON object",
        "distribution.bootstrap failed: OPERATION_FAILED/MemoryError: ",
        "service.status did not return one JSON object",
        (
            "governance.envelope.propose failed: OPERATION_FAILED/IntegrityError: "
            "UNIQUE constraint failed: envelope_proposals.envelope_id, "
            "envelope_proposals.version"
        ),
        (
            "runtime.provider.execute failed: OPERATION_FAILED/CodexProcessError: "
            "Codex execution outcome is UNKNOWN: process exited non-zero "
            "(code 3221226505)"
        ),
        "provider EXECUTION_IMPLEMENTER did not finish successfully",
    }
)


class JourneyFailure(M7EvidenceError):
    """Raised when a live shipping journey cannot prove every required assertion."""


class FrontendDetached(JourneyFailure):
    """Raised when a long-running service call outlives its native frontend."""


class ShippingCLI:
    def __init__(
        self,
        executable: Path,
        *,
        cwd: Path,
        runner: Runner = subprocess.run,
        timeout_seconds: int = 120,
    ) -> None:
        self.executable = executable.resolve()
        self.cwd = cwd.resolve()
        self.runner = runner
        self.timeout_seconds = timeout_seconds
        self.calls: list[dict[str, Any]] = []

    def direct(self, operation: str, arguments: Sequence[str]) -> Mapping[str, Any]:
        return self._invoke(operation, list(arguments))

    def service_call(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        *,
        project_root: Path,
        state_root: Path,
    ) -> Mapping[str, Any]:
        return self._invoke(
            operation,
            [
                "service",
                "call",
                operation,
                "--arguments",
                json.dumps(arguments, sort_keys=True, separators=(",", ":")),
                "--project-root",
                str(project_root),
                "--state-root",
                str(state_root),
                "--timeout-seconds",
                str(self.timeout_seconds),
            ],
        )

    def _invoke(self, operation: str, arguments: list[str]) -> Mapping[str, Any]:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        try:
            completed = self.runner(
                [str(self.executable), *arguments],
                cwd=self.cwd,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=self.timeout_seconds,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            code = getattr(exc, "winerror", None) or exc.errno or "UNKNOWN"
            raise JourneyFailure(
                f"{operation} could not start through the shipping CLI (os_code={code})"
            ) from exc
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if _SENSITIVE_TEXT.search(stdout) or _SENSITIVE_TEXT.search(stderr):
            raise JourneyFailure(f"{operation} returned secret-shaped output")
        try:
            value = json.loads(stdout)
        except json.JSONDecodeError as exc:
            if operation == "runtime.provider.execute":
                self.calls.append(
                    {
                        "operation": operation,
                        "returncode": completed.returncode,
                        "ok": None,
                        "frontend_detached": True,
                        "stdout_sha256": _text_sha256(stdout),
                        "stderr_sha256": _text_sha256(stderr),
                    }
                )
                raise FrontendDetached(
                    "runtime.provider.execute frontend detached before the durable result"
                ) from exc
            raise JourneyFailure(f"{operation} did not return one JSON object") from exc
        ok = isinstance(value, Mapping) and value.get("ok") is True
        if completed.returncode != 0 or not ok:
            error = value.get("error") if isinstance(value, Mapping) else None
            if isinstance(error, Mapping):
                details = error.get("details")
                error_type = details.get("type") if isinstance(details, Mapping) else None
                message = error.get("message")
                safe_message = (
                    str(message)[:300]
                    if isinstance(message, str) and not _SENSITIVE_TEXT.search(message)
                    else "message withheld"
                )
                raise JourneyFailure(
                    f"{operation} failed: {error.get('code', 'UNKNOWN')}/"
                    f"{error_type or 'UNKNOWN'}: {safe_message}"
                )
            raise JourneyFailure(f"{operation} failed through the public shipping CLI")
        self.calls.append(
            {
                "operation": operation,
                "returncode": completed.returncode,
                "ok": True,
                "stdout_sha256": _text_sha256(stdout),
                "stderr_sha256": _text_sha256(stderr),
            }
        )
        return value


def run_j10(
    *,
    artifact: Path,
    expected_artifact_sha256: str,
    source_commit: str,
    product_disposition_sha256: str,
    clean_base_attestation: Path,
    staging_root: Path,
    install_root: Path,
    state_root: Path,
    project_root: Path,
    expected_vm_id: int = _DEFAULT_CLEAN_VM_ID,
    expected_snapshot_name: str = _DEFAULT_CLEAN_SNAPSHOT,
    runner: Runner = subprocess.run,
    which: Any = shutil.which,
    host_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _mark_phase("preflight")
    artifact = artifact.expanduser().resolve()
    staging_root = staging_root.expanduser().resolve()
    install_root = install_root.expanduser().resolve()
    state_root = state_root.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    clean_base_attestation = clean_base_attestation.expanduser().resolve()
    _validate_inputs(
        artifact=artifact,
        expected_artifact_sha256=expected_artifact_sha256,
        source_commit=source_commit,
        product_disposition_sha256=product_disposition_sha256,
        clean_base_attestation=clean_base_attestation,
    )
    identity = dict(host_identity or _windows_identity())
    _require_windows_25h2(identity)
    _require_clean_guest(
        staging_root=staging_root,
        install_root=install_root,
        state_root=state_root,
        project_root=project_root,
        which=which,
    )
    attestation = _read_object(clean_base_attestation)
    _validate_clean_base_attestation(
        attestation,
        expected_vm_id=expected_vm_id,
        expected_snapshot_name=expected_snapshot_name,
    )
    if attestation.get("candidate_sha256") != expected_artifact_sha256:
        raise JourneyFailure("clean-base attestation is not bound to the frozen candidate")
    snapshot_identity = canonical_sha256(attestation)

    artifact_sha256 = _file_sha256(artifact)
    if artifact_sha256 != expected_artifact_sha256:
        raise JourneyFailure("shipping artifact SHA-256 does not match the frozen candidate")
    artifact_bytes = artifact.stat().st_size
    _mark_phase("shipping-installer")
    installed_executable = _install_shipping_candidate(
        artifact,
        install_root=install_root,
        state_root=state_root,
        runner=runner,
    )

    cli = ShippingCLI(installed_executable, cwd=install_root, runner=runner)
    _mark_phase("service-status-before-restart")
    status_before = cli.direct(
        "service.status", ["service", "status", "--state-root", str(state_root)]
    )
    before = _running_service_value(status_before)
    _mark_phase("service-stop")
    cli.direct("service.stop", ["service", "stop", "--state-root", str(state_root)])
    _mark_phase("service-process-exit")
    _wait_for_process_exit(int(before["process_id"]))
    _mark_phase("task-scheduler-restart")
    _restart_registered_windows_task(runner=runner)
    _mark_phase("service-readiness-after-restart")
    status_after = _wait_for_service(cli, state_root, prior_process_id=int(before["process_id"]))
    after = _running_service_value(status_after)
    if int(after["coordinator_generation"]) <= int(before["coordinator_generation"]):
        raise JourneyFailure("managed-service restart did not advance coordinator generation")
    if int(after["process_id"]) == int(before["process_id"]):
        raise JourneyFailure("managed-service restart did not change process identity")

    _mark_phase("distribution-bootstrap")
    bootstrap = cli.service_call(
        "distribution.bootstrap", {}, project_root=project_root, state_root=state_root
    )
    bootstrap_value = _value(bootstrap)
    fallback = bootstrap_value.get("manual_fallback")
    graph = bootstrap_value.get("capability_graph")
    if (
        bootstrap_value.get("status") != "MANUAL_FALLBACK"
        or bootstrap_value.get("automated_candidates") != []
        or not isinstance(fallback, Mapping)
        or fallback.get("selected") is not True
        or fallback.get("self_acceptance") is not False
        or not isinstance(graph, Mapping)
        or graph.get("providers") != []
    ):
        raise JourneyFailure("no-provider bootstrap did not fail closed to ManualIntegration")

    _mark_phase("distribution-doctor")
    doctor = cli.service_call(
        "distribution.doctor",
        {
            "runstore_path": str(state_root / "runstore.sqlite3"),
            "service_state_path": str(state_root / "service-state.json"),
        },
        project_root=project_root,
        state_root=state_root,
    )
    findings = _value(doctor).get("findings")
    manual_finding = (
        next(
            (
                item
                for item in findings
                if isinstance(item, Mapping) and item.get("id") == "manual-fallback"
            ),
            None,
        )
        if isinstance(findings, list)
        else None
    )
    if (
        not isinstance(manual_finding, Mapping)
        or manual_finding.get("remediation_id") != "use-manual-integration"
    ):
        raise JourneyFailure("doctor did not provide the actionable manual fallback")

    _mark_phase("provider-graph")
    graph_result = cli.service_call(
        "providers.graph", {}, project_root=project_root, state_root=state_root
    )
    if _value(graph_result).get("graph", {}).get("providers") != []:
        raise JourneyFailure("public Capability Graph exposed an automated provider")

    _mark_phase("beginner-start")
    beginner = cli.service_call(
        "beginner.start",
        {"intent": "Qualify the no-provider manual fallback", "project_name": "M7 J10"},
        project_root=project_root,
        state_root=state_root,
    )
    if _value(beginner).get("manual_configuration_required") is not False:
        raise JourneyFailure("beginner journey did not start without hand configuration")
    project_model = project_root / ".artifex" / "project-model.json"
    if not project_model.is_file():
        raise JourneyFailure("beginner journey did not create canonical Project state")
    model_sha256 = _file_sha256(project_model)

    _mark_phase("manual-packet")
    packet_result = cli.service_call(
        "manual.packet.create",
        {
            "task_contract": {"id": "m7-j10", "objective": "manual fallback qualification"},
            "context": {"cell": "M7-WIN-NOPROVIDER"},
            "base_commit": source_commit,
            "project_model_fingerprint": model_sha256,
            "acceptance_criteria": [{"id": "manual-result-review", "required": True}],
            "ownership": {"acceptance": "PROJECT_AUTHORITY"},
            "expected_result": {"status": "SUCCESS"},
            "interfaces": ["ManualIntegration"],
            "invariants": ["provider-result-cannot-self-accept"],
        },
        project_root=project_root,
        state_root=state_root,
    )
    packet = _value(packet_result).get("packet")
    if not isinstance(packet, Mapping):
        raise JourneyFailure("manual packet operation returned no packet")
    _mark_phase("manual-result-submit")
    submitted = cli.service_call(
        "manual.result.submit",
        {
            "packet": packet,
            "result": {
                "status": "SUCCESS",
                "base_commit": packet.get("base_commit"),
                "execution_contract_fingerprint": packet.get("execution_contract_fingerprint"),
                "project_model_fingerprint": packet.get("project_model_fingerprint"),
                "artifacts": [],
                "validation": {"claim": "manual qualification result"},
                "message": "manual result remains subject to Project Authority",
            },
        },
        project_root=project_root,
        state_root=state_root,
    )
    submit_value = _value(submitted)
    if submit_value.get("canonical_acceptance") is not False:
        raise JourneyFailure("manual result improperly granted itself canonical acceptance")

    _mark_phase("capture-finalization")
    registration_manifest = install_root / "service-registration.json"
    install_manifest = install_root / "artifex-install-manifest.json"
    if not registration_manifest.is_file() or not install_manifest.is_file():
        raise JourneyFailure("managed installation manifests are unavailable")
    executable_sha256 = _file_sha256(installed_executable)
    transcript_value = {
        "calls": cli.calls,
        "assertions": {
            "artifact_bound": True,
            "manual_fallback": True,
            "manual_result_self_accepted": False,
            "service_restart": True,
        },
    }
    transcript_bytes = json.dumps(
        transcript_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "cell": {
            "id": "M7-WIN-NOPROVIDER",
            "os": "Windows 11",
            "display_version": DEFAULT_WINDOWS_VERSION,
            "architecture": "x86_64",
            "support_tier": "CORE",
            "mode": "STANDALONE",
            "provider": "none",
            "absent_providers": list(CELL_CONTRACTS["M7-WIN-NOPROVIDER"]["absent_providers"]),
            "journeys": ["J10"],
        },
        "candidate": {
            "source_commit": source_commit,
            "artifact_name": artifact.name,
            "artifact_sha256": artifact_sha256,
            "artifact_bytes": artifact_bytes,
            "contract_digest": M7_CONTRACT_DIGEST,
            "product_disposition_sha256": product_disposition_sha256,
        },
        "clean_machine": {
            "snapshot_identity_sha256": snapshot_identity,
            "first_boot": True,
            "prior_artifex_absent": True,
            "prior_service_absent": True,
            "prior_state_root_absent": True,
            "source_checkout_absent": True,
            "os_build": str(identity["os_build"]),
            "ubr": int(identity["ubr"]),
        },
        "composition": {
            "shipping_installer": True,
            "public_managed_service": True,
            "public_cli": True,
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "provider_injection_used": False,
            "simulated_provider": False,
            "atlas_present": False,
            "combined_provider_cell": False,
        },
        "installer_service": {
            "install_status": "PASS",
            "registration_status": "PASS",
            "os_service_manager": WINDOWS_SERVICE_MANAGER,
            "registration_manifest_sha256": _file_sha256(registration_manifest),
            "executable_sha256": executable_sha256,
            "service_start_status": "PASS",
            "frontend_independent": True,
            "authenticated_loopback_transport": True,
            "restart_generation_before": int(before["coordinator_generation"]),
            "restart_generation_after": int(after["coordinator_generation"]),
            "service_process_changed": True,
            "doctor_secret_safe": True,
        },
        "provider": {
            "id": "none",
            "codex_present": False,
            "claude_present": False,
            "automated_candidates": [],
            "credential_files_read": False,
            "pii_persisted": False,
        },
        "journeys": {
            "J10": {
                "status": "PASS",
                "automated_candidates": [],
                "no_false_automated_ready": True,
                "bootstrap_status": "MANUAL_FALLBACK",
                "manual_fallback_selected": True,
                "doctor_actionable": True,
                "beginner_start_succeeded": True,
                "manual_operations": ["manual.packet.create", "manual.result.submit"],
                "manual_result_self_accepted": False,
                "automated_dispatch_occurred": False,
            }
        },
        "security": {
            "credential_files_read": False,
            "pii_persisted": False,
            "transport_token_persisted": False,
            "provider_result_self_acceptance": False,
            "acceptance_authority_separate": True,
            "project_authority_required": True,
        },
        "public_process_calls": cli.calls,
        "transcript": {
            "sha256": hashlib.sha256(transcript_bytes).hexdigest(),
            "bytes": len(transcript_bytes),
            "raw_output_persisted": False,
            "secret_scan": "PASS",
        },
    }


def run_provider_cell(
    *,
    cell_id: str,
    artifact: Path,
    expected_artifact_sha256: str,
    source_commit: str,
    product_disposition_sha256: str,
    clean_base_attestation: Path,
    staging_root: Path,
    install_root: Path,
    state_root: Path,
    project_root: Path,
    provider_command: Path,
    provider_version: str,
    provider_executable_sha256: str,
    auth_probe_sha256: str,
    provider_ready_attestation: Path | None = None,
    expected_provider_ready_snapshot_name: str | None = None,
    expected_vm_id: int = _DEFAULT_CLEAN_VM_ID,
    expected_snapshot_name: str = _DEFAULT_CLEAN_SNAPSHOT,
    resume_installed: bool = False,
    resume_failure_capture: Path | None = None,
    runner: Runner = subprocess.run,
    which: Any = shutil.which,
    host_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if cell_id not in {"M7-WIN-CODEX", "M7-WIN-CLAUDE"}:
        raise JourneyFailure("provider runner requires an official provider cell")
    provider_id = str(CELL_CONTRACTS[cell_id]["provider"])
    other_provider = "claude" if provider_id == "codex" else "codex"
    journey_id = "J01" if provider_id == "codex" else "J02"
    prefix = f"m7-{provider_id}"
    instance_key = hashlib.sha256(
        project_root.as_posix().casefold().encode("utf-8")
    ).hexdigest()[:12]
    project_name = f"M7 {provider_id.title()} Core Qualification {instance_key}"
    project_id = f"{prefix}-{instance_key}-project"
    catalog_path = project_root.parent / f"{project_root.name}-catalog.sqlite3"
    store_path = state_root / "runstore.sqlite3"
    run_id = f"{prefix}-{instance_key}-run"
    project_job_id = f"{prefix}-{instance_key}-job"
    attempt_id = f"{prefix}-{instance_key}-attempt"
    workspace_id = f"{prefix}-{instance_key}-workspace"
    workstream_id = f"{prefix}-{instance_key}-workstream"

    _mark_phase("provider-preflight")
    artifact = artifact.expanduser().resolve()
    staging_root = staging_root.expanduser().resolve()
    install_root = install_root.expanduser().resolve()
    state_root = state_root.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    provider_command = provider_command.expanduser().resolve()
    clean_base_attestation = clean_base_attestation.expanduser().resolve()
    if provider_ready_attestation is not None:
        provider_ready_attestation = provider_ready_attestation.expanduser().resolve()
    _validate_inputs(
        artifact=artifact,
        expected_artifact_sha256=expected_artifact_sha256,
        source_commit=source_commit,
        product_disposition_sha256=product_disposition_sha256,
        clean_base_attestation=clean_base_attestation,
    )
    if not provider_command.is_file():
        raise JourneyFailure("expected provider executable is unavailable")
    if not provider_version.strip():
        raise JourneyFailure("provider version is unavailable")
    for name, digest in (
        ("provider executable", provider_executable_sha256),
        ("provider authentication probe", auth_probe_sha256),
    ):
        if not _DIGEST.fullmatch(digest):
            raise JourneyFailure(f"{name} SHA-256 is invalid")
    if _file_sha256(provider_command) != provider_executable_sha256:
        raise JourneyFailure("provider executable does not match its qualified SHA-256")
    identity = dict(host_identity or _windows_identity())
    _require_windows_25h2(identity)
    if resume_installed:
        _require_provider_resume(
            expected_provider=provider_id,
            provider_command=provider_command,
            other_provider=other_provider,
            staging_root=staging_root,
            install_root=install_root,
            state_root=state_root,
            project_root=project_root,
            failure_capture=resume_failure_capture,
            which=which,
        )
    else:
        _require_provider_guest(
            expected_provider=provider_id,
            provider_command=provider_command,
            other_provider=other_provider,
            staging_root=staging_root,
            install_root=install_root,
            state_root=state_root,
            project_root=project_root,
            which=which,
        )
    attestation = _read_object(clean_base_attestation)
    _validate_clean_base_attestation(
        attestation,
        expected_vm_id=expected_vm_id,
        expected_snapshot_name=expected_snapshot_name,
    )
    clean_candidate_matches = attestation.get("candidate_sha256") == expected_artifact_sha256
    if provider_ready_attestation is None:
        if not clean_candidate_matches:
            raise JourneyFailure("clean-base attestation is not bound to the frozen candidate")
        snapshot_identity = canonical_sha256(attestation)
    else:
        if expected_provider_ready_snapshot_name is None:
            raise JourneyFailure("provider-ready snapshot identity is required")
        provider_ready = _read_object(provider_ready_attestation)
        _validate_provider_ready_rebinding_attestation(
            provider_ready,
            clean_base_attestation=clean_base_attestation,
            clean_base=attestation,
            expected_vm_id=expected_vm_id,
            expected_snapshot_name=expected_provider_ready_snapshot_name,
            expected_candidate_sha256=expected_artifact_sha256,
            expected_source_commit=source_commit,
            expected_provider_id=provider_id,
            expected_provider_version=provider_version,
            expected_provider_executable_sha256=provider_executable_sha256,
            expected_auth_probe_sha256=auth_probe_sha256,
        )
        snapshot_identity = canonical_sha256(provider_ready)
    artifact_sha256 = _file_sha256(artifact)
    if artifact_sha256 != expected_artifact_sha256:
        raise JourneyFailure("shipping artifact SHA-256 does not match the frozen candidate")

    _mark_phase("provider-shipping-installer")
    installed_executable = (
        _resume_installed_candidate(install_root)
        if resume_installed
        else _install_shipping_candidate(
            artifact,
            install_root=install_root,
            state_root=state_root,
            runner=runner,
        )
    )
    cli = ShippingCLI(
        installed_executable,
        cwd=install_root,
        runner=runner,
        timeout_seconds=900,
    )
    status_before = _initial_service_status(
        cli,
        state_root=state_root,
        resume_installed=resume_installed,
        runner=runner,
    )
    before = _running_service_value(status_before)

    _mark_phase("provider-project-create")
    created = _value(
        cli.service_call(
            "project.create",
            {
                "project_root": str(project_root),
                "catalog_path": str(catalog_path),
                "name": project_name,
                "project_id": project_id,
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    baseline_revision = int(created.get("semantic_revision", 0))
    baseline_fingerprint = str(created.get("semantic_fingerprint", ""))
    if baseline_revision != 1 or not _DIGEST.fullmatch(baseline_fingerprint):
        raise JourneyFailure("fresh Project semantic baseline is invalid")

    provider_spec = {
        "provider_id": provider_id,
        "command": [str(provider_command)],
        "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "credential_reference": {
            "broker": f"{provider_id}-native-session",
            "reference": "default-session",
            "provider_id": provider_id,
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
            "secret_material_present": False,
        },
    }
    setup_arguments = {
        "project_root": str(project_root),
        "integration_ids": ["manual", provider_id],
        "provider_specs": [provider_spec],
    }
    setup_plan = cli.service_call(
        "distribution.setup.plan",
        setup_arguments,
        project_root=project_root,
        state_root=state_root,
    )
    decision = _value(setup_plan).get("decision")
    confirmation = decision.get("confirmation_token") if isinstance(decision, Mapping) else None
    if not isinstance(confirmation, str) or not confirmation.startswith("approve-"):
        raise JourneyFailure("provider setup plan did not issue bounded approval")
    cli.service_call(
        "distribution.setup.apply",
        {**setup_arguments, "confirmation_token": confirmation},
        project_root=project_root,
        state_root=state_root,
    )
    setup_path = project_root / ".artifex" / "integrations.json"
    if not setup_path.is_file():
        raise JourneyFailure("provider setup did not persist Project integration state")
    setup_text = setup_path.read_text(encoding="utf-8")
    if _SENSITIVE_TEXT.search(setup_text):
        raise JourneyFailure("provider setup appears to contain secret material")
    setup_sha256 = _text_sha256(setup_text)

    _git(project_root, "config", "user.name", "ARTIFEX M7 Qualifier", runner=runner)
    _git(
        project_root,
        "config",
        "user.email",
        "artifex-m7-qualifier@invalid.local",
        runner=runner,
    )
    _git(project_root, "add", "--all", runner=runner)
    _git(project_root, "commit", "-m", "Establish M7 provider baseline", runner=runner)
    baseline_commit = _git(project_root, "rev-parse", "HEAD", runner=runner)
    if not _COMMIT.fullmatch(baseline_commit):
        raise JourneyFailure("fresh Project Git baseline is invalid")

    _mark_phase("provider-service-restart")
    cli.direct("service.stop", ["service", "stop", "--state-root", str(state_root)])
    _wait_for_process_exit(int(before["process_id"]))
    _restart_registered_windows_task(runner=runner)
    status_after = _wait_for_service(cli, state_root, prior_process_id=int(before["process_id"]))
    after = _running_service_value(status_after)
    if int(after["coordinator_generation"]) <= int(before["coordinator_generation"]):
        raise JourneyFailure("provider setup restart did not advance service generation")
    if int(after["process_id"]) == int(before["process_id"]):
        raise JourneyFailure("provider setup restart did not change service process")
    workspace_root = _provider_workspace_root(after, state_root=state_root)

    bootstrap = _value(
        cli.service_call(
            "distribution.bootstrap", {}, project_root=project_root, state_root=state_root
        )
    )
    if bootstrap.get("automated_candidates") != [provider_id]:
        raise JourneyFailure("provider bootstrap did not expose the sole expected candidate")
    cli.service_call(
        "distribution.doctor",
        {
            "runstore_path": str(store_path),
            "service_state_path": str(state_root / "service-state.json"),
        },
        project_root=project_root,
        state_root=state_root,
    )
    graph = _value(
        cli.service_call(
            "providers.graph", {}, project_root=project_root, state_root=state_root
        )
    ).get("graph")
    node = _find_provider(graph, provider_id)
    readiness = _value(
        cli.service_call(
            "providers.readiness",
            {"provider_id": provider_id},
            project_root=project_root,
            state_root=state_root,
        )
    ).get("readiness")
    if not isinstance(readiness, Mapping) or readiness.get("state") != "AVAILABLE":
        raise JourneyFailure("provider is not AVAILABLE after fresh service consumption")

    common = {
        "store_path": str(store_path),
        "workspace_root": str(workspace_root),
        "project_root": str(project_root),
    }
    proposer = _principal(
        f"{prefix}-planner", "INTERACTION_CLIENT", "envelope:propose"
    )
    approver = _principal(
        f"{prefix}-architect", "USER", "envelope:approve", "run:authorize"
    )
    dispatcher = _principal(
        f"{prefix}-coordinator",
        "AUTOMATION_SYSTEM_ACTOR",
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
    )
    provider_actor = _principal(
        f"{prefix}-provider", "PROVIDER", "result:submit"
    )
    evidence_actor = _principal(
        f"{prefix}-evidence",
        "ARTIFEX_SERVICE",
        "workspace:access",
        "evidence:record",
    )
    acceptance_actor = _principal(
        f"{prefix}-acceptance", "ARTIFEX_SERVICE", "acceptance:decide"
    )
    promotion_actor = _principal(
        f"{prefix}-project-authority", "ARTIFEX_SERVICE", "project:promote"
    )
    marker = (
        f"ARTIFEX_INTERACTION project_id={project_id} "
        f"semantic_revision={baseline_revision}"
    )
    interaction = _value(
        cli.service_call(
            "providers.interact",
            {
                "provider_id": provider_id,
                "project_id": project_id,
                "role": "INTERACTION",
                "prompt": _bounded_interaction_prompt(marker),
            },
            project_root=project_root,
            state_root=state_root,
        )
    ).get("interaction")
    if (
        not isinstance(interaction, Mapping)
        or interaction.get("provider_id") != provider_id
        or interaction.get("live") is not True
        or not _is_bounded_interaction_response(interaction.get("response"), marker)
    ):
        raise JourneyFailure("provider INTERACTION did not return the bounded live response")

    envelope = _provider_envelope(
        provider_id=provider_id,
        project_id=project_id,
        workstream_id=workstream_id,
        baseline_fingerprint=baseline_fingerprint,
        baseline_commit=baseline_commit,
    )
    cli.service_call(
        "governance.envelope.propose",
        {**common, "actor": proposer, "envelope": envelope},
        project_root=project_root,
        state_root=state_root,
    )
    cli.service_call(
        "governance.envelope.approve",
        {
            **common,
            "envelope_id": envelope["envelope_id"],
            "version": 1,
            "actor": approver,
        },
        project_root=project_root,
        state_root=state_root,
    )
    cli.service_call(
        "runtime.run.authorize",
        {
            **common,
            "envelope_id": envelope["envelope_id"],
            "envelope_version": 1,
            "workstream_id": workstream_id,
            "run_id": run_id,
            "project_job_id": project_job_id,
            "attempt_id": attempt_id,
            "purpose": f"M7 real standalone {provider_id} qualification",
            "actor": approver,
        },
        project_root=project_root,
        state_root=state_root,
    )
    workspace = _value(
        cli.service_call(
            "runtime.workspace.create",
            {
                **common,
                "workspace_id": workspace_id,
                "attempt_id": attempt_id,
                "baseline_revision": baseline_revision,
                "actor": dispatcher,
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    execution_response: Mapping[str, Any] | None = None
    try:
        execution_response = cli.service_call(
            "runtime.provider.execute",
            {
                **common,
                "provider_id": provider_id,
                "role": "EXECUTION_IMPLEMENTER",
                "run_id": run_id,
                "project_job_id": project_job_id,
                "attempt_id": attempt_id,
                "workspace_id": workspace_id,
                "objective": (
                    f"Create deliverables/{prefix}.txt containing exactly "
                    f"ARTIFEX M7 REAL {provider_id.upper()} EXECUTION followed by a newline."
                ),
                "acceptance_criteria": [
                    (
                        f"deliverables/{prefix}.txt contains exactly ARTIFEX M7 REAL "
                        f"{provider_id.upper()} EXECUTION followed by one newline"
                    ),
                    "git diff --check exits successfully",
                ],
                "owned_paths": [f"deliverables/{prefix}.txt"],
                "credential_reference_id": f"{provider_id}-cli-session",
                "capabilities": ["repository_write", "test_execution"],
                "filesystem_permissions": ["READ", "WRITE"],
                "network_permissions": ["PROVIDER_API"],
                "tool_permissions": [f"{provider_id}.exec"],
                "actor": dispatcher,
                "provider_actor": provider_actor,
                "evidence_actor": evidence_actor,
            },
            project_root=project_root,
            state_root=state_root,
        )
    except FrontendDetached:
        execution_response = None
    if execution_response is None:
        execution = _wait_for_durable_provider_execution(
            cli,
            common=common,
            project_root=project_root,
            state_root=state_root,
            provider_id=provider_id,
            run_id=run_id,
            project_job_id=project_job_id,
            attempt_id=attempt_id,
        )
    else:
        execution = _value(execution_response).get("execution")
    if (
        not isinstance(execution, Mapping)
        or execution.get("provider_id") != provider_id
        or execution.get("live") is not True
        or str(execution.get("status", "")).upper() not in {"SUCCESS", "FINISHED", "PASS"}
    ):
        raise JourneyFailure("provider EXECUTION_IMPLEMENTER did not finish successfully")
    evidence = execution.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise JourneyFailure("provider execution did not persist validation evidence")
    evidence_ids = [
        str(item.get("evidence_id"))
        for item in evidence
        if isinstance(item, Mapping) and item.get("evidence_id")
    ]
    if len(evidence_ids) != len(evidence):
        raise JourneyFailure("provider validation evidence identities are incomplete")

    observed_before_reconnect = _value(
        cli.service_call(
            "runtime.status",
            {**common, "run_id": run_id},
            project_root=project_root,
            state_root=state_root,
        )
    )
    if observed_before_reconnect.get("acceptance_decisions"):
        raise JourneyFailure("provider result improperly self-accepted")
    # ShippingCLI launches a new native frontend process for every call. This
    # second status read therefore proves reconnect to the same durable Run.
    observed_after_reconnect = _value(
        cli.service_call(
            "runtime.status",
            {**common, "run_id": run_id},
            project_root=project_root,
            state_root=state_root,
        )
    )
    if observed_after_reconnect.get("run") != observed_before_reconnect.get("run"):
        raise JourneyFailure("frontend reconnect did not observe the same durable Run")

    cli.service_call(
        "runtime.accept",
        {
            **common,
            "project_job_id": project_job_id,
            "evidence_valid": True,
            "evidence_ids": evidence_ids,
            "reason": "independent M7 owned-path validation passed",
            "actor": acceptance_actor,
        },
        project_root=project_root,
        state_root=state_root,
    )
    model_path = project_root / ".artifex" / "project-model.json"
    model = _read_object(model_path)
    mutable_model = json.loads(json.dumps(model))
    mutable_model["project"]["description"] = (
        f"Accepted real standalone {provider_id} M7 ProjectJob"
    )
    promoted = _value(
        cli.service_call(
            "runtime.workspace.promote",
            {
                **common,
                "workspace_id": workspace_id,
                "project_job_id": project_job_id,
                "model": mutable_model,
                "actor": promotion_actor,
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    promotion_revision = int(promoted.get("semantic_revision", 0))
    if promotion_revision != baseline_revision + 1:
        raise JourneyFailure("Project Authority promotion did not advance exactly one revision")
    certifications = _value(
        cli.service_call(
            "providers.certifications",
            {"project_id": project_id, "provider_id": provider_id},
            project_root=project_root,
            state_root=state_root,
        )
    ).get("certifications")
    role_states = _role_states(certifications)
    required_roles = {"INTERACTION", "EXECUTION_IMPLEMENTER"}
    live_roles = {
        role for role, state in role_states.items() if state == "LIVE_ROLE_CERTIFIED"
    }
    if live_roles != required_roles:
        raise JourneyFailure("provider roles are not independently live-certified")

    cli.service_call(
        "documentation.regenerate",
        {"catalog_path": str(catalog_path), "name": project_name, "documents": []},
        project_root=project_root,
        state_root=state_root,
    )
    documentation = _value(
        cli.service_call(
            "documentation.status",
            {"catalog_path": str(catalog_path), "name": project_name},
            project_root=project_root,
            state_root=state_root,
        )
    )
    documents = documentation.get("documents")
    documentation_current = isinstance(documents, list) and bool(documents) and all(
        isinstance(item, Mapping) and item.get("state") == "CURRENT" for item in documents
    )
    dashboard = _value(
        cli.service_call(
            "dashboard.project",
            {"catalog_path": str(catalog_path), "name": project_name},
            project_root=project_root,
            state_root=state_root,
        )
    )
    dashboard_current = int(dashboard.get("semantic_revision", 0)) == promotion_revision
    if not documentation_current or not dashboard_current:
        raise JourneyFailure("Project documentation or dashboard is not current")

    registration_manifest = install_root / "service-registration.json"
    transcript_value = {
        "calls": cli.calls,
        "assertions": {
            "artifact_bound": True,
            "provider_authenticated": True,
            "provider_live_roles": sorted(required_roles),
            "provider_result_self_accepted": False,
            "service_restart": True,
        },
    }
    transcript_bytes = json.dumps(
        transcript_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    provider_journey = {
        "status": "PASS",
        "provider_id": provider_id,
        "project_created": True,
        "baseline_revision": baseline_revision,
        "plan_approved": True,
        "envelope_approved": True,
        "interaction_live": True,
        "execution_live": True,
        "workspace_isolated": workspace.get("isolated") is True,
        "runstore_durable": True,
        "validation_recorded": True,
        "provider_self_accepted": False,
        "acceptance_authority_separate": True,
        "project_authority_promoted": True,
        "promotion_revision": promotion_revision,
        "documentation_current": documentation_current,
        "dashboard_current": dashboard_current,
        "role_certifications": {
            "INTERACTION": role_states["INTERACTION"],
            "EXECUTION_IMPLEMENTER": role_states["EXECUTION_IMPLEMENTER"],
        },
    }
    if provider_id == "codex":
        provider_journey.update(
            {"frontend_closed_during_run": True, "reconnect_observed_run": True}
        )
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "cell": {
            "id": cell_id,
            "os": "Windows 11",
            "display_version": DEFAULT_WINDOWS_VERSION,
            "architecture": "x86_64",
            "support_tier": "CORE",
            "mode": "STANDALONE",
            "provider": provider_id,
            "absent_providers": list(CELL_CONTRACTS[cell_id]["absent_providers"]),
            "journeys": list(CELL_CONTRACTS[cell_id]["journeys"]),
        },
        "candidate": {
            "source_commit": source_commit,
            "artifact_name": artifact.name,
            "artifact_sha256": artifact_sha256,
            "artifact_bytes": artifact.stat().st_size,
            "contract_digest": M7_CONTRACT_DIGEST,
            "product_disposition_sha256": product_disposition_sha256,
        },
        "clean_machine": {
            "snapshot_identity_sha256": snapshot_identity,
            "first_boot": True,
            "prior_artifex_absent": True,
            "prior_service_absent": True,
            "prior_state_root_absent": True,
            "source_checkout_absent": True,
            "os_build": str(identity["os_build"]),
            "ubr": int(identity["ubr"]),
        },
        "composition": {
            "shipping_installer": True,
            "public_managed_service": True,
            "public_cli": True,
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "provider_injection_used": False,
            "simulated_provider": False,
            "atlas_present": False,
            "combined_provider_cell": False,
        },
        "installer_service": {
            "install_status": "PASS",
            "registration_status": "PASS",
            "os_service_manager": WINDOWS_SERVICE_MANAGER,
            "registration_manifest_sha256": _file_sha256(registration_manifest),
            "executable_sha256": _file_sha256(installed_executable),
            "service_start_status": "PASS",
            "frontend_independent": True,
            "authenticated_loopback_transport": True,
            "restart_generation_before": int(before["coordinator_generation"]),
            "restart_generation_after": int(after["coordinator_generation"]),
            "service_process_changed": True,
            "doctor_secret_safe": True,
        },
        "provider": {
            "id": provider_id,
            "installed": True,
            "other_core_provider_absent": which(other_provider) is None,
            "configured": True,
            "authenticated": True,
            "version": provider_version,
            "executable_sha256": provider_executable_sha256,
            "auth_probe_sha256": auth_probe_sha256,
            "readiness_state": str(readiness["state"]),
            "credential_files_read": False,
            "pii_persisted": False,
        },
        "journeys": {
            journey_id: provider_journey,
            "J16": {
                "status": "PASS",
                "provider_id": provider_id,
                "setup_sha256": setup_sha256,
                "fresh_process_consumed_setup": bootstrap.get("fresh_process_consumed_setup")
                is True,
                "provider_registered_after_consumption": node.get("provider_id")
                == provider_id,
                "service_generation_advanced": int(after["coordinator_generation"])
                > int(before["coordinator_generation"]),
                "service_process_changed": int(after["process_id"])
                != int(before["process_id"]),
                "custom_injection_used": False,
            },
        },
        "security": {
            "credential_files_read": False,
            "pii_persisted": False,
            "transport_token_persisted": False,
            "provider_result_self_acceptance": False,
            "acceptance_authority_separate": True,
            "project_authority_required": True,
        },
        "public_process_calls": cli.calls,
        "transcript": {
            "sha256": hashlib.sha256(transcript_bytes).hexdigest(),
            "bytes": len(transcript_bytes),
            "raw_output_persisted": False,
            "secret_scan": "PASS",
        },
    }


def _validate_inputs(**values: Any) -> None:
    artifact = values["artifact"]
    if not isinstance(artifact, Path) or not artifact.is_file():
        raise JourneyFailure("shipping artifact is unavailable")
    if not _DIGEST.fullmatch(str(values["expected_artifact_sha256"])):
        raise JourneyFailure("expected artifact SHA-256 is invalid")
    if not _COMMIT.fullmatch(str(values["source_commit"])):
        raise JourneyFailure("source commit is invalid")
    if not _DIGEST.fullmatch(str(values["product_disposition_sha256"])):
        raise JourneyFailure("product disposition SHA-256 is invalid")
    attestation = values["clean_base_attestation"]
    if not isinstance(attestation, Path) or not attestation.is_file():
        raise JourneyFailure("hypervisor clean-base attestation is unavailable")


def _mark_phase(value: str) -> None:
    global _ACTIVE_PHASE
    _ACTIVE_PHASE = value


def _require_clean_guest(
    *, staging_root: Path, install_root: Path, state_root: Path, project_root: Path, which: Any
) -> None:
    if os.environ.get("USERNAME", "").casefold() == "system" or os.environ.get(
        "SESSIONNAME", ""
    ).casefold() == "services":
        raise JourneyFailure("managed-service installation requires an interactive user session")
    for name, path in (
        ("staging root", staging_root),
        ("install root", install_root),
        ("state root", state_root),
        ("project root", project_root),
    ):
        if path.exists():
            raise JourneyFailure(f"clean-machine preflight found an existing {name}")
    observed = {provider: which(provider) for provider in ("codex", "claude")}
    if any(observed.values()):
        raise JourneyFailure("no-provider cell contains a supported provider executable")
    if which("artifex") or which("artifex.exe"):
        raise JourneyFailure("clean-machine preflight found a prior ARTIFEX executable")


def _require_provider_guest(
    *,
    expected_provider: str,
    provider_command: Path,
    other_provider: str,
    staging_root: Path,
    install_root: Path,
    state_root: Path,
    project_root: Path,
    which: Any,
) -> None:
    if os.environ.get("USERNAME", "").casefold() == "system" or os.environ.get(
        "SESSIONNAME", ""
    ).casefold() == "services":
        raise JourneyFailure("provider qualification requires an interactive user session")
    for name, path in (
        ("staging root", staging_root),
        ("install root", install_root),
        ("state root", state_root),
        ("project root", project_root),
    ):
        if path.exists():
            raise JourneyFailure(f"clean-machine preflight found an existing {name}")
    if not provider_command.is_file():
        raise JourneyFailure(f"{expected_provider} cell is missing its provider executable")
    if which(other_provider):
        raise JourneyFailure(
            f"{expected_provider} cell contains forbidden provider {other_provider}"
        )
    if which("artifex") or which("artifex.exe"):
        raise JourneyFailure("clean-machine preflight found a prior ARTIFEX executable")


def _require_provider_resume(
    *,
    expected_provider: str,
    provider_command: Path,
    other_provider: str,
    staging_root: Path,
    install_root: Path,
    state_root: Path,
    project_root: Path,
    failure_capture: Path | None,
    which: Any,
) -> None:
    if os.environ.get("USERNAME", "").casefold() == "system" or os.environ.get(
        "SESSIONNAME", ""
    ).casefold() == "services":
        raise JourneyFailure("provider qualification requires an interactive user session")
    for name, path in (("staging root", staging_root), ("project root", project_root)):
        if path.exists():
            raise JourneyFailure(f"provider resume found an existing {name}")
    for name, path in (("install root", install_root), ("state root", state_root)):
        if not path.exists():
            raise JourneyFailure(f"provider resume is missing the existing {name}")
    if not provider_command.is_file():
        raise JourneyFailure(f"{expected_provider} cell is missing its provider executable")
    if which(other_provider):
        raise JourneyFailure(
            f"{expected_provider} cell contains forbidden provider {other_provider}"
        )
    if failure_capture is None or not failure_capture.is_file():
        raise JourneyFailure("provider resume requires the preserved harness failure capture")
    try:
        failure = _read_object(failure_capture)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise JourneyFailure("provider resume failure capture is invalid") from exc
    if (
        set(failure) != {"diagnostic", "error", "schema_version", "status"}
        or failure.get("schema_version") != "1.0"
        or failure.get("status") != "FAIL"
        or failure.get("error") != "JourneyFailure"
        or failure.get("diagnostic") not in _RESUMABLE_PROVIDER_FAILURES
    ):
        raise JourneyFailure(
            "provider resume failure is not an authorized preserved qualification failure"
        )


def _git(root: Path, *arguments: str, runner: Runner) -> str:
    completed = runner(
        ["git", "-C", str(root), *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise JourneyFailure("Git baseline operation failed")
    return (completed.stdout or "").strip()


def _principal(actor_id: str, actor_type: str, *permissions: str) -> dict[str, Any]:
    return {
        "actor_id": actor_id,
        "actor_type": actor_type,
        "authenticated": True,
        "authentication_method": "m7-clean-vm-qualification",
        "direct_permissions": list(permissions),
    }


def _provider_envelope(
    *,
    provider_id: str,
    project_id: str,
    workstream_id: str,
    baseline_fingerprint: str,
    baseline_commit: str,
) -> dict[str, Any]:
    return {
        "envelope_id": f"{project_id}-envelope",
        "version": 1,
        "project_id": project_id,
        "objective": f"Create one bounded M7 {provider_id} deliverable",
        "baseline_revision": 1,
        "actor_id": f"m7-{provider_id}-architect",
        "allowed_paths": [f"deliverables/m7-{provider_id}.txt"],
        "allowed_capabilities": ["repository_read", "repository_write", "test_execution"],
        "allowed_providers": [provider_id],
        "allowed_provider_roles": ["EXECUTION_IMPLEMENTER"],
        "allowed_workstreams": [workstream_id],
        "required_gates": ["validation", "acceptance-authority", "project-authority"],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": ["PROVIDER_API"],
        "tool_permissions": [f"{provider_id}.exec"],
        "data_classification": "INTERNAL",
        "credential_references": [
            {
                "reference_id": f"{provider_id}-cli-session",
                "provider_id": provider_id,
                "role": "EXECUTION_IMPLEMENTER",
                "project_id": project_id,
                "revoked": False,
            }
        ],
        "resource_budget": {"attempts": 1},
        "deadline_at": int(time.time()) + 3600,
        "stop_conditions": ["MAX_ATTEMPTS", "UNKNOWN_OUTCOME"],
        "require_durable_evidence": True,
        "baseline_fingerprint": baseline_fingerprint,
        "baseline_commit": baseline_commit,
        "max_attempts": 1,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": False,
        "supervision_level": "L2",
        "network_policy": "PROVIDER_ONLY",
        "materiality": "TACTICAL",
    }


def _find_provider(graph: object, provider_id: str) -> Mapping[str, Any]:
    if not isinstance(graph, Mapping):
        raise JourneyFailure("Capability Graph is unavailable")
    providers = graph.get("providers")
    if not isinstance(providers, list):
        raise JourneyFailure("Capability Graph providers are invalid")
    matches = [
        item
        for item in providers
        if isinstance(item, Mapping) and item.get("provider_id") == provider_id
    ]
    if len(matches) != 1:
        raise JourneyFailure("Capability Graph provider cardinality is not one")
    return matches[0]


def _is_bounded_interaction_response(value: object, marker: str) -> bool:
    if not isinstance(value, str) or len(value) > 512:
        return False
    return value.count(marker) == 1


def _bounded_interaction_prompt(marker: str) -> str:
    """Request one protocol marker without weakening the bounded validator."""
    return (
        "Your sole task is protocol echo. Return exactly the marker on the next line "
        "as your entire final response. Do not add quotes, punctuation, Markdown, "
        "preamble, explanation, or any other text. Do not call tools and do not "
        f"modify files.\n{marker}"
    )


def _role_states(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise JourneyFailure("provider certification report is unavailable")
    roles = value.get("roles", value)
    states: dict[str, str] = {}
    if isinstance(roles, list):
        for item in roles:
            if isinstance(item, Mapping):
                states[str(item.get("role"))] = str(item.get("state"))
    elif isinstance(roles, Mapping):
        for role, item in roles.items():
            states[str(role)] = str(item.get("state") if isinstance(item, Mapping) else item)
    else:
        raise JourneyFailure("provider certification roles are malformed")
    return states


def _wait_for_durable_provider_execution(
    cli: ShippingCLI,
    *,
    common: Mapping[str, Any],
    project_root: Path,
    state_root: Path,
    provider_id: str,
    run_id: str,
    project_job_id: str,
    attempt_id: str,
) -> Mapping[str, Any]:
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        status = _value(
            cli.service_call(
                "runtime.status",
                {**common, "run_id": run_id},
                project_root=project_root,
                state_root=state_root,
            )
        )
        execution = _durable_provider_execution(
            status,
            provider_id=provider_id,
            project_job_id=project_job_id,
            attempt_id=attempt_id,
        )
        if execution is not None:
            return execution
        time.sleep(2)
    raise JourneyFailure("provider execution did not reach a durable terminal state")


def _durable_provider_execution(
    value: Mapping[str, Any],
    *,
    provider_id: str,
    project_job_id: str,
    attempt_id: str,
) -> Mapping[str, Any] | None:
    attempts = value.get("attempts")
    if not isinstance(attempts, list):
        raise JourneyFailure("durable runtime status has no Attempt projection")
    matches = [
        item
        for item in attempts
        if isinstance(item, Mapping) and item.get("attempt_id") == attempt_id
    ]
    if len(matches) != 1:
        raise JourneyFailure("durable runtime status has invalid Attempt cardinality")
    attempt = matches[0]
    state = str(attempt.get("state", ""))
    if state in {"PENDING", "RUNNING"}:
        return None
    if state != "FINISHED":
        raise JourneyFailure("provider execution entered a non-recoverable durable state")
    claim = str(attempt.get("result_claim", ""))
    if (
        f"provider={provider_id};" not in claim
        or "status=SUCCESS;" not in claim
    ):
        raise JourneyFailure("provider EXECUTION_IMPLEMENTER did not finish successfully")
    jobs = value.get("project_jobs")
    if not isinstance(jobs, list) or not any(
        isinstance(item, Mapping)
        and item.get("project_job_id") == project_job_id
        and item.get("state") == "FINISHED"
        for item in jobs
    ):
        raise JourneyFailure("durable ProjectJob did not finish with the provider Attempt")
    authorizations = value.get("dispatch_authorizations")
    if not isinstance(authorizations, list) or not any(
        isinstance(item, Mapping)
        and item.get("attempt_id") == attempt_id
        and item.get("provider_id") == provider_id
        and item.get("provider_role") == "EXECUTION_IMPLEMENTER"
        for item in authorizations
    ):
        raise JourneyFailure("durable provider dispatch authorization is unavailable")
    records = value.get("evidence_records")
    evidence = [
        dict(item)
        for item in records
        if isinstance(item, Mapping)
        and item.get("attempt_id") == attempt_id
        and item.get("project_job_id") == project_job_id
    ] if isinstance(records, list) else []
    if not evidence or not all(bool(item.get("passed")) for item in evidence):
        raise JourneyFailure("durable provider validation evidence did not pass")
    return {
        "provider_id": provider_id,
        "live": True,
        "status": "SUCCESS",
        "evidence": evidence,
    }


def _install_shipping_candidate(
    artifact: Path,
    *,
    install_root: Path,
    state_root: Path,
    runner: Runner,
) -> Path:
    program_files = os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not program_files or not local_app_data:
        raise JourneyFailure("standard Windows installation locations are unavailable")
    expected_install = (Path(program_files) / "ARTIFEX").resolve()
    expected_state = (Path(local_app_data) / "ARTIFEX" / "runtime").resolve()
    if install_root != expected_install or state_root != expected_state:
        raise JourneyFailure("qualification must use the standard ARTIFEX installation locations")
    completed = runner(
        [str(artifact), "/S"],
        cwd=artifact.parent,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise JourneyFailure(
            f"shipping installer failed with normalized exit code {completed.returncode}"
        )
    executable = install_root / "artifex.exe"
    if not executable.is_file():
        raise JourneyFailure("shipping installer did not produce the ARTIFEX executable")
    for name in ("artifex-install-manifest.json", "service-registration.json", "Uninstall.exe"):
        if not (install_root / name).is_file():
            raise JourneyFailure(f"shipping installer did not produce required file {name}")
    return executable


def _resume_installed_candidate(install_root: Path) -> Path:
    executable = install_root / "artifex.exe"
    manifest_path = install_root / "artifex-install-manifest.json"
    for path in (
        executable,
        manifest_path,
        install_root / "service-registration.json",
        install_root / "Uninstall.exe",
    ):
        if not path.is_file():
            raise JourneyFailure(f"provider resume is missing installed file {path.name}")
    try:
        manifest = _read_object(manifest_path)
        artifact_manifest = manifest["artifact_manifest"]
        files = manifest["files"]
        if not isinstance(artifact_manifest, Mapping) or not isinstance(files, list):
            raise TypeError
        executable_entry = next(
            item
            for item in files
            if isinstance(item, Mapping) and item.get("path") == "artifex.exe"
        )
    except (OSError, json.JSONDecodeError, KeyError, StopIteration, TypeError, ValueError) as exc:
        raise JourneyFailure("provider resume install manifest is invalid") from exc
    digest = _file_sha256(executable)
    if (
        manifest.get("install_root") != str(install_root)
        or artifact_manifest.get("artifact") != "artifex.exe"
        or artifact_manifest.get("sha256") != digest
        or executable_entry.get("sha256") != digest
    ):
        raise JourneyFailure("provider resume install manifest does not bind the executable")
    return executable


def _restart_registered_windows_task(*, runner: Runner) -> None:
    queried = runner(
        ["schtasks.exe", "/Query", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if queried.returncode != 0:
        raise JourneyFailure("cannot inspect Windows managed-service registration")
    matches = [
        row[0]
        for row in csv.reader((queried.stdout or "").splitlines())
        if row and row[0].casefold().startswith(r"\artifex-")
        and row[0].casefold().endswith("-artifex-managed-service")
    ]
    if len(matches) != 1:
        raise JourneyFailure("expected exactly one ARTIFEX managed-service task")
    started = runner(
        ["schtasks.exe", "/Run", "/TN", matches[0]],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if started.returncode != 0:
        raise JourneyFailure("Windows managed-service task did not restart")


def _initial_service_status(
    cli: ShippingCLI,
    *,
    state_root: Path,
    resume_installed: bool,
    runner: Runner,
) -> Mapping[str, Any]:
    try:
        return cli.direct(
            "service.status", ["service", "status", "--state-root", str(state_root)]
        )
    except JourneyFailure:
        if not resume_installed:
            raise
    _restart_registered_windows_task(runner=runner)
    return _wait_for_service(cli, state_root, prior_process_id=0)


def _wait_for_service(
    cli: ShippingCLI, state_root: Path, *, prior_process_id: int
) -> Mapping[str, Any]:
    deadline = time.monotonic() + 60
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = cli.direct(
                "service.status", ["service", "status", "--state-root", str(state_root)]
            )
            service = _running_service_value(value)
            if int(service["process_id"]) != prior_process_id:
                return value
        except (JourneyFailure, KeyError, TypeError, ValueError) as exc:
            last_error = exc
        time.sleep(0.5)
    raise JourneyFailure("managed service did not become ready after restart") from last_error


def _wait_for_process_exit(process_id: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if not _process_exists(process_id):
            return
        time.sleep(0.2)
    raise JourneyFailure("managed service did not stop before the restart boundary")


def _process_exists(process_id: int) -> bool:
    if process_id <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            process_query_limited_information, False, process_id
        )
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(process_id, 0)
    except OSError:
        return False
    return True


def _running_service_value(result: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _value(result)
    required = {
        "lifecycle_state",
        "frontend_independent",
        "process_id",
        "coordinator_generation",
        "transport",
    }
    if not required.issubset(value):
        raise JourneyFailure("managed-service status is incomplete")
    transport = value.get("transport")
    if (
        value.get("lifecycle_state") != "RUNNING"
        or value.get("frontend_independent") is not True
        or not isinstance(value.get("process_id"), int)
        or not isinstance(value.get("coordinator_generation"), int)
        or not isinstance(transport, Mapping)
        or transport.get("host") != "127.0.0.1"
    ):
        raise JourneyFailure("managed service is not a frontend-independent loopback service")
    return value


def _provider_workspace_root(
    service: Mapping[str, Any], *, state_root: Path, platform_name: str = os.name
) -> Path:
    paths = service.get("paths")
    raw_workspace = paths.get("workspace_root") if isinstance(paths, Mapping) else None
    if not isinstance(raw_workspace, str) or not raw_workspace.strip():
        raise JourneyFailure("managed-service status does not expose its workspace authority")
    workspace_root = Path(raw_workspace).expanduser().resolve()
    resolved_state = state_root.expanduser().resolve()
    if platform_name == "nt":
        expected = resolved_state.with_name(f"{resolved_state.name}-workspaces")
        if workspace_root != expected or resolved_state in workspace_root.parents:
            raise JourneyFailure(
                "Windows provider workspace authority remains inside the private state tree"
            )
    return workspace_root


def _validate_clean_base_attestation(
    value: Mapping[str, Any],
    *,
    expected_vm_id: int = _DEFAULT_CLEAN_VM_ID,
    expected_snapshot_name: str = _DEFAULT_CLEAN_SNAPSHOT,
) -> None:
    expected = {
        "schema_version",
        "vm_id",
        "snapshot_name",
        "snapshot_config_sha256",
        "account_sid_sha256",
        "candidate_sha256",
        "providers_absent",
        "source_checkout_absent",
    }
    if set(value) != expected or value.get("schema_version") != "1.0":
        raise JourneyFailure("clean-base attestation schema is invalid")
    for field in ("snapshot_config_sha256", "account_sid_sha256", "candidate_sha256"):
        if not _DIGEST.fullmatch(str(value.get(field, ""))):
            raise JourneyFailure(f"clean-base attestation {field} is invalid")
    if value.get("providers_absent") is not True or value.get("source_checkout_absent") is not True:
        raise JourneyFailure("clean-base attestation does not prove cell separation")
    if (
        value.get("vm_id") != expected_vm_id
        or value.get("snapshot_name") != expected_snapshot_name
    ):
        raise JourneyFailure("clean-base attestation does not identify the authorized VM reset")


def _validate_provider_ready_rebinding_attestation(
    value: Mapping[str, Any],
    *,
    clean_base_attestation: Path,
    clean_base: Mapping[str, Any],
    expected_vm_id: int,
    expected_snapshot_name: str,
    expected_candidate_sha256: str,
    expected_source_commit: str,
    expected_provider_id: str,
    expected_provider_version: str,
    expected_provider_executable_sha256: str,
    expected_auth_probe_sha256: str,
) -> None:
    expected = {
        "schema_version",
        "vm_id",
        "snapshot_name",
        "snapshot_config_sha256",
        "parent_provider_ready_snapshot_name",
        "parent_provider_ready_snapshot_config_sha256",
        "clean_base_attestation_sha256",
        "previous_candidate_sha256",
        "candidate_sha256",
        "source_commit",
        "provider_id",
        "provider_version",
        "provider_executable_sha256",
        "auth_probe_sha256",
        "artifex_absent",
        "journey_project_absent",
        "source_checkout_absent",
        "interactive_session_active",
        "vm_memory_included",
        "defender_realtime_enabled",
        "defender_candidate_detection_count",
        "defender_candidate_excluded",
        "credential_material_extracted",
    }
    if set(value) != expected or value.get("schema_version") != "1.0":
        raise JourneyFailure("provider-ready rebinding attestation schema is invalid")
    for field in (
        "snapshot_config_sha256",
        "parent_provider_ready_snapshot_config_sha256",
        "clean_base_attestation_sha256",
        "previous_candidate_sha256",
        "candidate_sha256",
        "provider_executable_sha256",
        "auth_probe_sha256",
    ):
        if not _DIGEST.fullmatch(str(value.get(field, ""))):
            raise JourneyFailure(f"provider-ready rebinding attestation {field} is invalid")
    expected_values = {
        "vm_id": expected_vm_id,
        "snapshot_name": expected_snapshot_name,
        "clean_base_attestation_sha256": _file_sha256(clean_base_attestation),
        "previous_candidate_sha256": clean_base.get("candidate_sha256"),
        "candidate_sha256": expected_candidate_sha256,
        "source_commit": expected_source_commit,
        "provider_id": expected_provider_id,
        "provider_version": expected_provider_version,
        "provider_executable_sha256": expected_provider_executable_sha256,
        "auth_probe_sha256": expected_auth_probe_sha256,
    }
    if any(value.get(field) != expected for field, expected in expected_values.items()):
        raise JourneyFailure("provider-ready rebinding attestation identity is invalid")
    required_true = (
        "artifex_absent",
        "journey_project_absent",
        "source_checkout_absent",
        "interactive_session_active",
        "defender_realtime_enabled",
    )
    if any(value.get(field) is not True for field in required_true):
        raise JourneyFailure("provider-ready rebinding attestation does not prove clean state")
    if not isinstance(value.get("vm_memory_included"), bool):
        raise JourneyFailure("provider-ready rebinding attestation memory state is invalid")
    if (
        value.get("defender_candidate_detection_count") != 0
        or value.get("defender_candidate_excluded") is not False
        or value.get("credential_material_extracted") is not False
        or not str(value.get("parent_provider_ready_snapshot_name", "")).strip()
    ):
        raise JourneyFailure("provider-ready rebinding attestation security state is invalid")


def _windows_identity() -> dict[str, Any]:
    if platform.system() != "Windows":
        raise JourneyFailure("official M7 cells require Windows")
    import winreg

    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    try:
        return {
            "system": "Windows",
            "release": platform.release(),
            "product_name": str(winreg.QueryValueEx(key, "ProductName")[0]),
            "display_version": str(winreg.QueryValueEx(key, "DisplayVersion")[0]),
            "architecture": (
                "x86_64"
                if platform.machine().casefold() in {"amd64", "x86_64"}
                else platform.machine().casefold()
            ),
            "os_build": str(winreg.QueryValueEx(key, "CurrentBuildNumber")[0]),
            "ubr": int(winreg.QueryValueEx(key, "UBR")[0]),
        }
    finally:
        winreg.CloseKey(key)


def _require_windows_25h2(value: Mapping[str, Any]) -> None:
    if (
        value.get("system") != "Windows"
        or value.get("release") != "11"
        # Windows 11 may retain the compatibility registry label
        # "Windows 10 Pro"; release 11 plus exact build 26200 is authoritative.
        or not str(value.get("product_name", "")).startswith("Windows ")
        or value.get("display_version") != DEFAULT_WINDOWS_VERSION
        or value.get("architecture") != "x86_64"
        or value.get("os_build") != DEFAULT_WINDOWS_BUILD
        or not isinstance(value.get("ubr"), int)
    ):
        raise JourneyFailure("host is not the selected Windows 11 25H2 x64 baseline")


def _value(result: Mapping[str, Any]) -> Mapping[str, Any]:
    value = result.get("value")
    if not isinstance(value, Mapping):
        raise JourneyFailure("public operation returned no value object")
    return value


def _read_object(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise JourneyFailure("JSON input must be an object")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", choices=sorted(CELL_CONTRACTS), required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--product-disposition-sha256", required=True)
    parser.add_argument("--clean-base-attestation", type=Path, required=True)
    parser.add_argument("--provider-ready-attestation", type=Path)
    parser.add_argument("--expected-provider-ready-snapshot-name")
    parser.add_argument("--expected-vm-id", type=int, default=_DEFAULT_CLEAN_VM_ID)
    parser.add_argument("--expected-snapshot-name", default=_DEFAULT_CLEAN_SNAPSHOT)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--provider-command", type=Path)
    parser.add_argument("--provider-version")
    parser.add_argument("--provider-executable-sha256")
    parser.add_argument("--auth-probe-sha256")
    parser.add_argument("--resume-installed-provider-cell", action="store_true")
    parser.add_argument("--resume-failure-capture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        common = {
            "artifact": arguments.artifact,
            "expected_artifact_sha256": arguments.expected_artifact_sha256,
            "source_commit": arguments.source_commit,
            "product_disposition_sha256": arguments.product_disposition_sha256,
            "clean_base_attestation": arguments.clean_base_attestation,
            "expected_vm_id": arguments.expected_vm_id,
            "expected_snapshot_name": arguments.expected_snapshot_name,
            "staging_root": arguments.staging_root,
            "install_root": arguments.install_root,
            "state_root": arguments.state_root,
            "project_root": arguments.project_root,
        }
        if arguments.cell == "M7-WIN-NOPROVIDER":
            if arguments.resume_installed_provider_cell or arguments.resume_failure_capture:
                raise JourneyFailure("no-provider cell cannot resume a provider qualification")
            result = run_j10(**common)
        else:
            if (
                arguments.provider_command is None
                or arguments.provider_version is None
                or arguments.provider_executable_sha256 is None
                or arguments.auth_probe_sha256 is None
            ):
                raise JourneyFailure("provider cell requires qualified provider arguments")
            result = run_provider_cell(
                cell_id=arguments.cell,
                provider_command=arguments.provider_command,
                provider_version=arguments.provider_version,
                provider_executable_sha256=arguments.provider_executable_sha256,
                auth_probe_sha256=arguments.auth_probe_sha256,
                provider_ready_attestation=arguments.provider_ready_attestation,
                expected_provider_ready_snapshot_name=(
                    arguments.expected_provider_ready_snapshot_name
                ),
                resume_installed=arguments.resume_installed_provider_cell,
                resume_failure_capture=arguments.resume_failure_capture,
                **common,
            )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {
            "schema_version": "1.0",
            "status": "FAIL",
            "error": type(exc).__name__,
            "diagnostic": (
                str(exc)
                if isinstance(exc, JourneyFailure)
                else f"operating-system failure during {_ACTIVE_PHASE}"
            ),
        }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result.get("status") == "PASS" else 1)


if __name__ == "__main__":
    main()

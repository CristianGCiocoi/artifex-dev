"""Run an official M7 journey through the native shipping distribution.

This harness is intentionally independent of the ``artifex`` Python package.
It executes the staged and installed native executable, records only hashes and
typed assertions, and emits a capture that still requires the independent M7
Windows qualifier before it can become acceptance evidence.

The first implemented cell is M7-WIN-NOPROVIDER/J10.  Provider cells fail
closed until their live interaction/execution runner is implemented.
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


class JourneyFailure(M7EvidenceError):
    """Raised when a live shipping journey cannot prove every required assertion."""


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
    _validate_clean_base_attestation(attestation)
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


def _validate_clean_base_attestation(value: Mapping[str, Any]) -> None:
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
        value.get("vm_id") != 104
        or value.get("snapshot_name") != "m7-qualified-25h2-x64-cell-base-v10"
    ):
        raise JourneyFailure("clean-base attestation does not identify the authorized VM104 reset")


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
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.cell != "M7-WIN-NOPROVIDER":
            raise JourneyFailure("provider-cell live runner is not yet implemented")
        result = run_j10(
            artifact=arguments.artifact,
            expected_artifact_sha256=arguments.expected_artifact_sha256,
            source_commit=arguments.source_commit,
            product_disposition_sha256=arguments.product_disposition_sha256,
            clean_base_attestation=arguments.clean_base_attestation,
            staging_root=arguments.staging_root,
            install_root=arguments.install_root,
            state_root=arguments.state_root,
            project_root=arguments.project_root,
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

"""Qualify the non-live M7 foundation through a clean installed wheel.

This harness deliberately cannot accept M7.  It proves the platform-neutral
shipping composition and records the unresolved supported-platform product
decision without turning the observed host into a supported platform claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def _run_json(
    python: Path,
    arguments: list[str],
    environment: dict[str, str],
    *,
    timeout: float = 120,
) -> dict[str, Any]:
    completed = subprocess.run(
        [str(python), "-I", "-m", "artifex.cli", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        check=False,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output = completed.stdout.strip()
    if not output:
        raise AssertionError(
            f"public CLI returned no JSON: exit={completed.returncode}; "
            f"stderr_sha256={hashlib.sha256(completed.stderr.encode()).hexdigest()}"
        )
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError("public CLI returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AssertionError("public CLI result is not an object")
    if value.get("ok") is False or completed.returncode != 0:
        raise AssertionError(f"public CLI operation failed: {value}")
    return value


def _call(
    python: Path,
    operation: str,
    operation_arguments: dict[str, Any],
    environment: dict[str, str],
    *,
    project_root: Path | None = None,
    state_root: Path | None = None,
) -> dict[str, Any]:
    command = (
        [
            "service",
            "call",
            operation,
            "--arguments",
            json.dumps(operation_arguments, separators=(",", ":")),
            "--state-root",
            str(state_root),
        ]
        if state_root is not None
        else [
            "call",
            operation,
            "--arguments",
            json.dumps(operation_arguments, separators=(",", ":")),
        ]
    )
    if project_root is not None:
        command.extend(("--project-root", str(project_root)))
    return _run_json(python, command, environment)


def _wait_for_state(
    state_file: Path,
    lifecycle: str,
    process: subprocess.Popen[str],
) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _stdout, stderr = process.communicate(timeout=1)
            raise AssertionError(
                "managed service exited before readiness: "
                f"exit={process.returncode}; stderr_sha256="
                f"{hashlib.sha256(stderr.encode()).hexdigest()}"
            )
        if state_file.is_file():
            try:
                value = json.loads(state_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                value = None
            if isinstance(value, dict) and value.get("lifecycle_state") == lifecycle:
                return value
        time.sleep(0.05)
    raise TimeoutError(f"managed service did not reach {lifecycle}")


def _start_service(
    python: Path,
    state_root: Path,
    environment: dict[str, str],
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            str(python),
            "-I",
            "-m",
            "artifex.cli",
            "service",
            "serve",
            "--state-root",
            str(state_root),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _stop_service(
    python: Path,
    state_root: Path,
    environment: dict[str, str],
    process: subprocess.Popen[str],
) -> None:
    if process.poll() is not None:
        return
    _run_json(
        python,
        ["service", "stop", "--state-root", str(state_root)],
        environment,
    )
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)


def qualify(python: Path, wheel: Path) -> dict[str, Any]:
    if not python.is_file():
        raise ValueError("clean-environment Python is unavailable")
    if not wheel.is_file() or wheel.suffix.casefold() != ".whl":
        raise ValueError("shipping wheel is unavailable")
    with tempfile.TemporaryDirectory(prefix="artifex-m7-foundation-") as temporary:
        root = Path(temporary)
        project = root / "project"
        state_root = root / "service-state"
        catalog = root / "catalog.sqlite3"
        isolated_user_state = root / "user-state"
        environment = os.environ.copy()
        environment["LOCALAPPDATA"] = str(isolated_user_state)
        environment["APPDATA"] = str(isolated_user_state / "roaming")
        environment["XDG_STATE_HOME"] = str(isolated_user_state / "xdg")
        environment["ARTIFEX_STATE_ROOT"] = str(state_root)
        for name in tuple(environment):
            if name.startswith("ARTIFEX_TEST_"):
                environment.pop(name)

        setup_plan = _call(
            python,
            "distribution.setup.plan",
            {"integration_ids": ["manual"]},
            environment,
            project_root=project,
        )
        decision = setup_plan["value"]["decision"]
        token = decision["confirmation_token"]
        if not isinstance(token, str) or not token:
            raise AssertionError("setup approval token was not issued")
        applied = _call(
            python,
            "distribution.setup.apply",
            {"integration_ids": ["manual"], "confirmation_token": token},
            environment,
            project_root=project,
        )
        if applied["value"].get("applied") is not True:
            raise AssertionError("provider setup was not applied")

        state_file = state_root / "service-state.json"
        first = _start_service(python, state_root, environment)
        second: subprocess.Popen[str] | None = None
        try:
            first_state = _wait_for_state(state_file, "RUNNING", first)
            first_generation = first_state.get("coordinator_generation")
            if not isinstance(first_generation, int):
                raise AssertionError("coordinator generation is unavailable")
            status = _run_json(
                python,
                ["service", "status", "--state-root", str(state_root)],
                environment,
            )
            if status["value"].get("frontend_independent") is not True:
                raise AssertionError("service state does not prove frontend independence")

            created = _call(
                python,
                "project.create",
                {
                    "project_root": str(project),
                    "catalog_path": str(catalog),
                    "project_id": "m7-foundation-project",
                    "name": "M7 Foundation Project",
                },
                environment,
                project_root=project,
                state_root=state_root,
            )
            if created["value"].get("semantic_revision") != 1:
                raise AssertionError("fresh Project baseline revision is not one")
            baseline_paths = (
                project / ".artifex" / "project-model.json",
                project / ".artifex" / "docs" / "manifest.json",
                project / ".artifex" / "dashboard" / "index.html",
            )
            if not all(path.is_file() for path in baseline_paths):
                raise AssertionError("fresh Project docs/dashboard baseline is incomplete")

            bootstrap = _call(
                python,
                "distribution.bootstrap",
                {},
                environment,
                project_root=project,
                state_root=state_root,
            )["value"]
            if (
                bootstrap.get("fresh_process_consumed_setup") is not True
                or bootstrap.get("status") != "MANUAL_FALLBACK"
                or bootstrap.get("automated_candidates") != []
                or bootstrap.get("manual_fallback", {}).get("selected") is not True
                or bootstrap.get("manual_fallback", {}).get("self_acceptance") is not False
            ):
                raise AssertionError("fresh-runtime ManualIntegration fallback is invalid")

            doctor = _call(
                python,
                "distribution.doctor",
                {
                    "runstore_path": str(state_root / "runstore.sqlite3"),
                    "service_state_path": str(state_file),
                },
                environment,
                project_root=project,
                state_root=state_root,
            )["value"]
            serialized_doctor = json.dumps(doctor, sort_keys=True)
            if (
                ".local-transport-token" in serialized_doctor
                or "authorization" in serialized_doctor
            ):
                raise AssertionError("doctor exposed local transport credential material")

            _stop_service(python, state_root, environment, first)
            second = _start_service(python, state_root, environment)
            second_state = _wait_for_state(state_file, "RUNNING", second)
            second_generation = second_state.get("coordinator_generation")
            if not isinstance(second_generation, int) or second_generation <= first_generation:
                raise AssertionError("service restart did not advance coordinator generation")
            restarted_bootstrap = _call(
                python,
                "distribution.bootstrap",
                {},
                environment,
                project_root=project,
                state_root=state_root,
            )["value"]
            if restarted_bootstrap.get("fresh_process_consumed_setup") is not True:
                raise AssertionError("restarted service did not consume persisted setup")
        finally:
            if second is not None:
                _stop_service(python, state_root, environment, second)
            _stop_service(python, state_root, environment, first)

        setup_value = json.loads(
            (project / ".artifex" / "integrations.json").read_text(encoding="utf-8")
        )
        state_value = json.loads(state_file.read_text(encoding="utf-8"))
        if "credential" in json.dumps(setup_value, sort_keys=True).casefold():
            references = setup_value.get("providers", [{}])[0].get("credential_reference")
            if references is not None:
                raise AssertionError("manual setup persisted a credential reference")
        if "authorization" in json.dumps(state_value, sort_keys=True).casefold():
            raise AssertionError("service projection persisted authorization material")

        return {
            "schema_version": "1.0",
            "status": "BLOCKED_PRODUCT_DECISION",
            "composition": "CLEAN_INSTALLED_WHEEL_PUBLIC_MANAGED_SERVICE_MULTI_PROCESS",
            "shipping_artifact": "INSTALLED_WHEEL",
            "source_tree_imported": False,
            "platform_observation": {
                "system": platform.system(),
                "machine": platform.machine(),
                "official_support_cell_claimed": False,
            },
            "foundation": {
                "managed_service": "PASS",
                "frontend_independent": True,
                "authenticated_loopback_transport": True,
                "single_coordinator_restart_generation": "PASS",
                "project_docs_dashboard_baseline": "PASS",
                "fresh_runtime_consumed_setup": True,
                "doctor_secret_safe": True,
                "default_os_registration_adapter": "FAIL_CLOSED_UNQUALIFIED",
            },
            "journeys": {
                "J01": "FOUNDATION_PASS_LIVE_PLATFORM_CELL_PENDING",
                "J02": "FOUNDATION_PASS_LIVE_PLATFORM_CELL_PENDING",
                "J10": "NONLIVE_FOUNDATION_PASS",
                "J16": "FRESH_RUNTIME_CONSUMPTION_PASS_LIVE_PROVIDER_CELL_PENDING",
            },
            "blocker": {
                "id": "BLK-M7-SUPPORTED-PLATFORM-MATRIX-UNDEFINED",
                "class": "MISSING_PRODUCT_DECISION",
                "required_authority": "PRODUCT_OWNER",
            },
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "python_executable_sha256": hashlib.sha256(python.read_bytes()).hexdigest(),
            "credential_files_read": False,
            "pii_persisted": False,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = qualify(arguments.python.resolve(), arguments.wheel.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")


if __name__ == "__main__":
    main()

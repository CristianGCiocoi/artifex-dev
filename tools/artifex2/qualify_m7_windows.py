"""Bind one official M7 Windows cell capture to live fail-closed probes.

The input capture is produced by the public shipping-journey runner.  This
qualifier independently rechecks the host, installed distribution, provider
separation, managed service, fresh Capability Graph, doctor and artifact before
emitting a secret-safe outcome accepted by ``validate_m7``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.artifex2.validate_m7 import (
    CELL_CONTRACTS,
    DEFAULT_WINDOWS_VERSION,
    ELIGIBLE_WINDOWS_VERSIONS,
    M7EvidenceError,
    _selected_windows_target,
    canonical_sha256,
    validate_cell_outcome,
)

Runner = Callable[..., subprocess.CompletedProcess[str]]


def qualify_cell(
    capture: Mapping[str, Any],
    *,
    cell_id: str,
    artifex_executable: Path,
    artifact: Path,
    project_root: Path,
    state_root: Path,
    source_commit: str,
    disposition_sha256: str,
    selected_version: str = DEFAULT_WINDOWS_VERSION,
    selected_build: str | None = None,
    repo_root: Path | None = None,
    runner: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    host_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if cell_id not in CELL_CONTRACTS:
        raise M7EvidenceError(f"unsupported M7 cell: {cell_id}")
    selected_version, selected_build = _selected_windows_target(selected_version, selected_build)
    artifex_executable = artifex_executable.expanduser().resolve()
    artifact = artifact.expanduser().resolve()
    project_root = project_root.expanduser().resolve()
    state_root = state_root.expanduser().resolve()
    if not artifex_executable.is_file():
        raise M7EvidenceError("installed ARTIFEX executable is unavailable")
    if not artifact.is_file():
        raise M7EvidenceError("shipping artifact is unavailable")

    identity = dict(host_identity or probe_windows_host())
    _enforce_official_host(
        identity,
        selected_version=selected_version,
        selected_build=selected_build,
    )
    _enforce_provider_separation(cell_id, which=which)
    artifact_sha256 = _file_sha256(artifact)
    artifact_bytes = artifact.stat().st_size

    outcome = json.loads(json.dumps(capture))
    if not isinstance(outcome, dict):
        raise M7EvidenceError("cell capture must be an object")
    if "qualifier_probes" in outcome:
        raise M7EvidenceError("cell capture cannot self-issue qualifier probes")
    candidate = outcome.get("candidate")
    if not isinstance(candidate, dict):
        raise M7EvidenceError("cell capture candidate must be an object")
    expected_candidate = {
        "source_commit": source_commit,
        "artifact_name": artifact.name,
        "artifact_sha256": artifact_sha256,
        "artifact_bytes": artifact_bytes,
        "contract_digest": candidate.get("contract_digest"),
        "product_disposition_sha256": disposition_sha256,
    }
    if candidate != expected_candidate:
        raise M7EvidenceError("cell capture is not bound to the supplied candidate artifact")

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    origin = _installed_origin(
        artifex_executable,
        install_root=artifex_executable.parent,
        repo_root=repo_root,
    )
    probes = _live_public_probes(
        artifex_executable,
        cell_id=cell_id,
        project_root=project_root,
        state_root=state_root,
        environment=environment,
        runner=runner,
    )
    outcome["qualifier_probes"] = {
        "host": canonical_sha256(identity),
        "installed_origin": origin,
        **probes,
    }
    validate_cell_outcome(
        outcome,
        expected_cell=cell_id,
        selected_version=selected_version,
        selected_build=selected_build,
    )
    return outcome


def probe_windows_host() -> dict[str, Any]:
    if platform.system() != "Windows":
        raise M7EvidenceError("official M7 cells require Windows")
    try:
        winreg = importlib.import_module("winreg")
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )
        try:
            product_name = winreg.QueryValueEx(key, "ProductName")[0]
            display_version = winreg.QueryValueEx(key, "DisplayVersion")[0]
            build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            ubr = winreg.QueryValueEx(key, "UBR")[0]
        finally:
            winreg.CloseKey(key)
    except (ImportError, OSError) as exc:
        raise M7EvidenceError("Windows version identity is unavailable") from exc
    machine = platform.machine().casefold()
    architecture = "x86_64" if machine in {"amd64", "x86_64"} else machine
    return {
        "system": platform.system(),
        "release": platform.release(),
        "product_name": str(product_name),
        "display_version": str(display_version),
        "architecture": architecture,
        "os_build": str(build),
        "ubr": int(ubr),
    }


def _enforce_official_host(
    identity: Mapping[str, Any],
    *,
    selected_version: str = DEFAULT_WINDOWS_VERSION,
    selected_build: str | None = None,
) -> None:
    selected_version, selected_build = _selected_windows_target(selected_version, selected_build)
    required = {
        "system",
        "release",
        "product_name",
        "display_version",
        "architecture",
        "os_build",
        "ubr",
    }
    if set(identity) != required:
        raise M7EvidenceError("Windows host identity fields are incomplete")
    if identity.get("system") != "Windows" or identity.get("release") != "11":
        raise M7EvidenceError("official M7 cells require Windows 11")
    product_name = identity.get("product_name")
    # Windows 11 can retain the compatibility registry label "Windows 10 Pro".
    # ``platform.release()`` and the exact authorized build remain the OS-major
    # authority; ProductName is retained as a corroborating Windows SKU label.
    if not isinstance(product_name, str) or not product_name.startswith("Windows "):
        raise M7EvidenceError("Windows product identity is invalid")
    if identity.get("display_version") != selected_version:
        raise M7EvidenceError(f"official M7 cells require selected Windows 11 {selected_version}")
    if identity.get("architecture") != "x86_64":
        raise M7EvidenceError("official M7 cells require x86_64")
    build = identity.get("os_build")
    ubr = identity.get("ubr")
    if not isinstance(build, str) or not build.isdigit():
        raise M7EvidenceError("Windows build identity is invalid")
    if build != selected_build:
        raise M7EvidenceError(f"official M7 cells require selected Windows build {selected_build}")
    if not isinstance(ubr, int) or isinstance(ubr, bool) or ubr < 0:
        raise M7EvidenceError("Windows UBR identity is invalid")


def _enforce_provider_separation(cell_id: str, *, which: Callable[[str], str | None]) -> None:
    expected = str(CELL_CONTRACTS[cell_id]["provider"])
    observed = {provider: which(provider) is not None for provider in ("codex", "claude")}
    if expected == "none":
        if any(observed.values()):
            raise M7EvidenceError("no-provider cell contains a supported provider executable")
        return
    if not observed[expected]:
        raise M7EvidenceError(f"{expected} cell is missing its provider executable")
    other = "claude" if expected == "codex" else "codex"
    if observed[other]:
        raise M7EvidenceError(f"{expected} cell contains forbidden provider {other}")


def _installed_origin(
    artifex_executable: Path,
    *,
    install_root: Path,
    repo_root: Path | None,
) -> str:
    origin = artifex_executable.resolve()
    prefix = install_root.resolve()
    if origin.parent != prefix:
        raise M7EvidenceError("ARTIFEX executable is outside the installed distribution root")
    manifest = prefix / "artifex-install-manifest.json"
    if not manifest.is_file():
        raise M7EvidenceError("installed ARTIFEX manifest is unavailable")
    try:
        manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
        artifact_manifest = manifest_value["artifact_manifest"]
        files = manifest_value["files"]
        relative = origin.relative_to(prefix).as_posix()
        executable_entry = next(item for item in files if item.get("path") == relative)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, StopIteration, ValueError) as exc:
        raise M7EvidenceError("installed ARTIFEX manifest is invalid") from exc
    executable_sha256 = _file_sha256(origin)
    if (
        manifest_value.get("install_root") != str(prefix)
        or artifact_manifest.get("artifact") != relative
        or artifact_manifest.get("sha256") != executable_sha256
        or executable_entry.get("sha256") != executable_sha256
    ):
        raise M7EvidenceError("installed ARTIFEX manifest does not bind the native executable")
    if repo_root is not None:
        forbidden = repo_root.resolve()
        if origin == forbidden or forbidden in origin.parents or prefix == forbidden:
            raise M7EvidenceError("ARTIFEX executable originated from the source repository")
    return canonical_sha256(
        {
            "origin_sha256": hashlib.sha256(str(origin).encode()).hexdigest(),
            "prefix_sha256": hashlib.sha256(str(prefix).encode()).hexdigest(),
            "manifest_sha256": _file_sha256(manifest),
            "installed": True,
        }
    )


def _live_public_probes(
    artifex_executable: Path,
    *,
    cell_id: str,
    project_root: Path,
    state_root: Path,
    environment: Mapping[str, str],
    runner: Runner,
) -> dict[str, str]:
    provider = str(CELL_CONTRACTS[cell_id]["provider"])
    status = _run_json(
        artifex_executable,
        ["service", "status", "--state-root", str(state_root)],
        environment=environment,
        cwd=project_root.parent,
        runner=runner,
    )
    status_value = _value(status)
    if status_value.get("lifecycle_state") != "RUNNING":
        raise M7EvidenceError("managed service is not RUNNING")
    if status_value.get("frontend_independent") is not True:
        raise M7EvidenceError("managed service is not frontend independent")

    def service_call(operation: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        return _run_json(
            artifex_executable,
            [
                "service",
                "call",
                operation,
                "--arguments",
                json.dumps(arguments, separators=(",", ":")),
                "--project-root",
                str(project_root),
                "--state-root",
                str(state_root),
            ],
            environment=environment,
            cwd=project_root.parent,
            runner=runner,
        )

    bootstrap = service_call("distribution.bootstrap", {})
    doctor = service_call(
        "distribution.doctor",
        {
            "runstore_path": str(state_root / "runstore.sqlite3"),
            "service_state_path": str(state_root / "service-state.json"),
        },
    )
    graph_result = service_call("providers.graph", {})
    graph = _value(graph_result).get("graph")
    if not isinstance(graph, Mapping):
        raise M7EvidenceError("public Capability Graph is unavailable")
    providers = graph.get("providers")
    if not isinstance(providers, list):
        raise M7EvidenceError("public Capability Graph providers are invalid")
    observed_ids = sorted(
        str(item.get("provider_id")) for item in providers if isinstance(item, Mapping)
    )
    bootstrap_value = _value(bootstrap)
    result = {
        "service_status": canonical_sha256(status),
        "bootstrap": canonical_sha256(bootstrap),
        "doctor": canonical_sha256(doctor),
        "graph": canonical_sha256(graph_result),
    }
    doctor_serialized = json.dumps(doctor, sort_keys=True).casefold()
    if ".local-transport-token" in doctor_serialized or '"authorization"' in doctor_serialized:
        raise M7EvidenceError("doctor exposed local transport authorization")
    if provider == "none":
        if observed_ids or bootstrap_value.get("automated_candidates") != []:
            raise M7EvidenceError("no-provider cell exposed an automated provider")
        fallback = bootstrap_value.get("manual_fallback")
        if (
            bootstrap_value.get("status") != "MANUAL_FALLBACK"
            or not isinstance(fallback, Mapping)
            or fallback.get("selected") is not True
        ):
            raise M7EvidenceError("no-provider cell did not select ManualIntegration")
    else:
        if observed_ids != [provider]:
            raise M7EvidenceError("Capability Graph violates provider cell separation")
        candidates = bootstrap_value.get("automated_candidates")
        if candidates != [provider]:
            raise M7EvidenceError("expected provider is not the sole automated candidate")
        readiness = service_call("providers.readiness", {"provider_id": provider})
        readiness_value = _value(readiness).get("readiness")
        if not isinstance(readiness_value, Mapping) or readiness_value.get("state") != "AVAILABLE":
            raise M7EvidenceError("expected provider is not AVAILABLE")
        result["readiness"] = canonical_sha256(readiness)
    return result


def _run_json(
    artifex_executable: Path,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    runner: Runner,
) -> Mapping[str, Any]:
    completed = runner(
        [str(artifex_executable), *arguments],
        cwd=cwd,
        env=dict(environment),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise M7EvidenceError("public qualifier probe failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise M7EvidenceError("public qualifier probe did not return JSON") from exc
    if not isinstance(value, Mapping) or value.get("ok") is not True:
        raise M7EvidenceError("public qualifier probe did not succeed")
    return value


def _value(result: Mapping[str, Any]) -> Mapping[str, Any]:
    value = result.get("value")
    if not isinstance(value, Mapping):
        raise M7EvidenceError("public qualifier result has no value object")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise M7EvidenceError("capture must be a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--cell", choices=sorted(CELL_CONTRACTS), required=True)
    parser.add_argument("--artifex-executable", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--disposition-sha256", required=True)
    parser.add_argument(
        "--selected-version",
        choices=tuple(ELIGIBLE_WINDOWS_VERSIONS),
        default=DEFAULT_WINDOWS_VERSION,
    )
    parser.add_argument("--selected-build")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        result = qualify_cell(
            _read_object(arguments.capture),
            cell_id=arguments.cell,
            artifex_executable=arguments.artifex_executable,
            artifact=arguments.artifact,
            project_root=arguments.project_root,
            state_root=arguments.state_root,
            source_commit=arguments.source_commit,
            disposition_sha256=arguments.disposition_sha256,
            selected_version=arguments.selected_version,
            selected_build=arguments.selected_build,
            repo_root=arguments.repo_root,
        )
    except (OSError, json.JSONDecodeError, M7EvidenceError, subprocess.SubprocessError) as exc:
        result = {
            "schema_version": "1.0",
            "status": "FAIL",
            "error": type(exc).__name__,
        }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result.get("status") == "PASS" else 1)


if __name__ == "__main__":
    main()

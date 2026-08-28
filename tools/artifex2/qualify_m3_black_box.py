"""Qualify the M3 Codex vertical slice through an installed wheel's public CLI.

This harness intentionally imports no ARTIFEX product modules.  Every product
interaction crosses a new ``python -I -m artifex.cli`` process boundary.  The
Codex command is also an external command vector so Windows installations may
use a pinned npm CLI when an application-package alias is not executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

PROVIDER_GRAPH = "providers.graph"
PROVIDER_READINESS = "providers.readiness"
PROVIDER_RESOLVE = "providers.resolve"
PROVIDER_INTERACT = "providers.interact"
PROVIDER_EXECUTE = "runtime.provider.execute"
PROVIDER_CERTIFICATIONS = "providers.certifications"

COMPOSITION = "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_REAL_CODEX_MULTI_PROCESS"
J01_INTERPRETATION = {
    "status": "M3_VERTICAL_SLICE_ONLY",
    "full_journey_status": "NOT_CLAIMED",
    "primary_proving_milestone": "M7",
    "reason": (
        "M3 proves the installed-wheel Codex public vertical slice; the clean-machine "
        "installer and managed-service Journey remains an M7 acceptance claim."
    ),
}
_SEMVER = re.compile(r"(?<!\d)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)(?!\d)")
_SENSITIVE = re.compile(r"(?:token|secret|password|credential|api[_-]?key)", re.I)
_MAX_EXCERPT = 2_048
_MAX_INTERACTION_RESPONSE_BYTES = 512


def _sha256(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _scrub(text: str) -> str:
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1<redacted>", text)
    value = re.sub(
        r'(?i)(["\']?(?:token|secret|password|api[_-]?key)["\']?\s*[:=]\s*["\']?)[^\s,"\']+',
        r"\1<redacted>",
        value,
    )
    if len(value) <= _MAX_EXCERPT:
        return value
    half = _MAX_EXCERPT // 2
    return f"{value[:half]}\n[DIAGNOSTIC TRUNCATED]\n{value[-half:]}"


def _qualification_temporary_parent(repo_root: Path | None) -> Path | None:
    if os.name != "nt" or repo_root is None:
        return None
    return repo_root.resolve().parent


@contextmanager
def _qualification_directory(repo_root: Path | None) -> Iterator[Path]:
    parent = _qualification_temporary_parent(repo_root)
    if parent is None:
        with tempfile.TemporaryDirectory(
            prefix="artifex-m3-public-", ignore_cleanup_errors=True
        ) as directory:
            yield Path(directory).resolve()
        return

    # tempfile intentionally installs a restrictive owner-only DACL on
    # Windows.  Create an unguessable child normally so it inherits the
    # traversable parent ACL required by the supported unelevated sandbox.
    parent.mkdir(parents=True, exist_ok=True)
    root = (parent / f"artifex-m3-public-{uuid.uuid4().hex}").resolve()
    if root.parent != parent:
        raise ValueError("qualification directory escaped its authorized parent")
    root.mkdir()
    try:
        yield root
    finally:
        if root.parent == parent:
            shutil.rmtree(root, ignore_errors=True)


def _is_bounded_interaction_response(response: object, marker: str) -> bool:
    if not isinstance(response, str):
        return False
    normalized = response.strip()
    return (
        len(normalized.encode("utf-8", errors="replace")) <= _MAX_INTERACTION_RESPONSE_BYTES
        and normalized.count(marker) == 1
    )


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


def _blocked(code: str, detail: str, *, probe: dict[str, Any] | None = None) -> dict[str, Any]:
    blocker = {"code": code, "detail": _scrub(detail)}
    return {
        "schema_version": "1.0",
        "status": "BLOCKED",
        "composition": COMPOSITION,
        "shipping_artifact": "INSTALLED_WHEEL",
        "source_tree_imported": False,
        "custom_application_factory_used": False,
        "provider_injection_used": False,
        "simulated_provider": False,
        "live_gate": {"status": "BLOCKED", "blockers": [blocker], "codex_probe": probe},
        "j01_interpretation": dict(J01_INTERPRETATION),
        "journeys": {
            "J01": dict(J01_INTERPRETATION),
            "J16": {"status": "BLOCKED", "blocker": blocker},
            "M3_CODEX_VERTICAL_SLICE": {"status": "BLOCKED", "blocker": blocker},
        },
    }


def _command_vector(value: str | None) -> list[str]:
    raw = value or os.environ.get("ARTIFEX_CODEX_COMMAND_JSON")
    if raw:
        parsed = json.loads(raw)
        if (
            not isinstance(parsed, list)
            or not parsed
            or any(not isinstance(item, str) or not item for item in parsed)
        ):
            raise ValueError("Codex command JSON must be a non-empty string array")
        return list(parsed)
    resolved = shutil.which("codex")
    return [resolved] if resolved else []


def probe_codex(command: list[str], *, cwd: Path, environment: dict[str, str]) -> dict[str, Any]:
    """Run version and login-status probes without reading credential material."""

    if not command:
        return {
            "status": "BLOCKED",
            "blocker": {"code": "CODEX_EXECUTABLE_NOT_FOUND", "detail": "not on PATH"},
        }
    executable = shutil.which(command[0]) if not Path(command[0]).is_file() else command[0]
    if executable is None:
        return {
            "status": "BLOCKED",
            "command_sha256": _sha256(json.dumps(command, separators=(",", ":"))),
            "blocker": {
                "code": "CODEX_EXECUTABLE_NOT_FOUND",
                "detail": f"command executable is unavailable: {command[0]}",
            },
        }
    normalized = [str(executable), *command[1:]]
    try:
        version_result = _run(
            [*normalized, "--version"], cwd=cwd, environment=environment, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "BLOCKED",
            "command_sha256": _sha256(json.dumps(normalized, separators=(",", ":"))),
            "blocker": {
                "code": "CODEX_EXECUTABLE_NOT_CALLABLE",
                "detail": f"{type(exc).__name__}: {exc}",
            },
        }
    version_output = (version_result.stdout or version_result.stderr).strip()
    match = _SEMVER.search(version_output)
    if version_result.returncode != 0 or match is None:
        return {
            "status": "BLOCKED",
            "command_sha256": _sha256(json.dumps(normalized, separators=(",", ":"))),
            "version_exit_code": version_result.returncode,
            "version_output_sha256": _sha256(version_output),
            "blocker": {
                "code": "CODEX_VERSION_UNAVAILABLE",
                "detail": _scrub(version_output or "version probe failed"),
            },
        }
    try:
        auth_result = _run(
            [*normalized, "login", "status"], cwd=cwd, environment=environment, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "BLOCKED",
            "version": match.group(1),
            "command_sha256": _sha256(json.dumps(normalized, separators=(",", ":"))),
            "blocker": {
                "code": "CODEX_AUTH_STATUS_UNCALLABLE",
                "detail": f"{type(exc).__name__}: {exc}",
            },
        }
    auth_output = (auth_result.stdout or auth_result.stderr).strip()
    if auth_result.returncode != 0:
        return {
            "status": "BLOCKED",
            "version": match.group(1),
            "command_sha256": _sha256(json.dumps(normalized, separators=(",", ":"))),
            "auth_exit_code": auth_result.returncode,
            "auth_output_sha256": _sha256(auth_output),
            "blocker": {
                "code": "CODEX_AUTH_UNAVAILABLE",
                "detail": _scrub(auth_output or "login status is not authenticated"),
            },
        }
    return {
        "status": "PASS",
        "version": match.group(1),
        "command": normalized,
        "command_sha256": _sha256(json.dumps(normalized, separators=(",", ":"))),
        "version_exit_code": 0,
        "auth_exit_code": 0,
        "auth_mode_sha256": _sha256(auth_output),
        "credential_material_read": False,
    }


def _installed_origin(
    python: Path, *, cwd: Path, environment: dict[str, str], forbidden_root: Path | None
) -> dict[str, Any]:
    script = (
        "import json,pathlib,sys,artifex;"
        "print(json.dumps({'origin':str(pathlib.Path(artifex.__file__).resolve()),"
        "'prefix':str(pathlib.Path(sys.prefix).resolve())}))"
    )
    result = _run([str(python), "-I", "-c", script], cwd=cwd, environment=environment, timeout=30)
    if result.returncode != 0:
        raise AssertionError(f"installed ARTIFEX import failed: {_scrub(result.stderr)}")
    value = json.loads(result.stdout)
    origin = Path(value["origin"]).resolve()
    prefix = Path(value["prefix"]).resolve()
    if prefix != origin and prefix not in origin.parents:
        raise AssertionError(f"ARTIFEX module is outside installed Python prefix: {origin}")
    if forbidden_root is not None:
        root = forbidden_root.resolve()
        if origin == root or root in origin.parents:
            raise AssertionError(f"ARTIFEX imported from source repository: {origin}")
    return {"origin": str(origin), "prefix": str(prefix), "origin_sha256": _sha256(str(origin))}


class PublicCLI:
    def __init__(self, python: Path, cwd: Path, environment: dict[str, str]) -> None:
        self.python = python
        self.cwd = cwd
        self.environment = environment
        self.calls: list[dict[str, Any]] = []

    def call(
        self,
        operation: str,
        arguments: dict[str, Any],
        *,
        expect_ok: bool = True,
        timeout: int = 90,
    ) -> dict[str, Any]:
        command = [
            str(self.python),
            "-I",
            "-m",
            "artifex.cli",
            "call",
            operation,
            "--arguments",
            json.dumps(arguments, separators=(",", ":"), ensure_ascii=False),
        ]
        result = _run(command, cwd=self.cwd, environment=self.environment, timeout=timeout)
        stdout = result.stdout.strip()
        if not stdout:
            raise AssertionError(
                f"{operation} returned no JSON: exit={result.returncode} "
                f"stderr={_scrub(result.stderr)}"
            )
        parsed = json.loads(stdout)
        if not isinstance(parsed, dict):
            raise AssertionError(f"{operation} did not return a JSON object")
        payload = cast(dict[str, Any], parsed)
        observed_ok = bool(payload.get("ok"))
        self.calls.append(
            {
                "operation": operation,
                "returncode": result.returncode,
                "ok": observed_ok,
                "stdout_sha256": _sha256(result.stdout),
                "stderr_sha256": _sha256(result.stderr),
            }
        )
        if observed_ok is not expect_ok:
            raise AssertionError(
                f"{operation} expected ok={expect_ok}: {_scrub(json.dumps(payload))}"
            )
        if expect_ok and result.returncode != 0:
            raise AssertionError(f"{operation} succeeded but exited {result.returncode}")
        if not expect_ok and result.returncode == 0:
            raise AssertionError(f"{operation} failed semantically but exited zero")
        return payload


def _find_provider(graph: dict[str, Any], identifier: str) -> dict[str, Any]:
    providers = graph.get("providers")
    if not isinstance(providers, list):
        raise AssertionError("Capability Graph does not contain providers")
    matches = [
        item
        for item in providers
        if isinstance(item, dict) and item.get("provider_id") == identifier
    ]
    if len(matches) != 1:
        raise AssertionError(f"Capability Graph provider cardinality is not one: {identifier}")
    return matches[0]


def _value(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get("value")
    if not isinstance(value, dict) or not isinstance(value.get(key), dict):
        raise AssertionError(f"public operation result is missing value.{key}")
    return cast(dict[str, Any], value[key])


def _principal(actor_id: str, actor_type: str, *permissions: str) -> dict[str, Any]:
    return {
        "actor_id": actor_id,
        "actor_type": actor_type,
        "authenticated": True,
        "authentication_method": "m3-black-box-qualification",
        "direct_permissions": list(permissions),
    }


def _git(root: Path, *arguments: str, environment: dict[str, str]) -> str:
    result = _run(
        ["git", "-C", str(root), *arguments],
        cwd=root,
        environment=environment,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Git baseline operation failed: {_scrub(result.stderr or result.stdout)}"
        )
    return result.stdout.strip()


def _envelope(
    project_id: str, *, baseline_fingerprint: str, baseline_commit: str
) -> dict[str, Any]:
    return {
        "envelope_id": "m3-envelope",
        "version": 1,
        "project_id": project_id,
        "objective": "Create the bounded M3 Codex deliverable",
        "baseline_revision": 1,
        "actor_id": "m3-architect",
        "allowed_paths": ["deliverables/m3-codex.txt"],
        "allowed_capabilities": [
            "repository_read",
            "repository_write",
            "test_execution",
        ],
        "allowed_providers": ["codex"],
        "allowed_provider_roles": ["EXECUTION_IMPLEMENTER"],
        "allowed_workstreams": ["m3-workstream"],
        "required_gates": ["validation", "acceptance-authority", "project-authority"],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": ["PROVIDER_API"],
        "tool_permissions": ["codex.exec"],
        "data_classification": "INTERNAL",
        "credential_references": [
            {
                "reference_id": "codex-cli-session",
                "provider_id": "codex",
                "role": "EXECUTION_IMPLEMENTER",
                "project_id": project_id,
                "revoked": False,
            }
        ],
        "resource_budget": {"attempts": 1},
        "stop_conditions": ["MAX_ATTEMPTS", "UNKNOWN_OUTCOME"],
        "require_durable_evidence": True,
        "baseline_fingerprint": baseline_fingerprint,
        "baseline_commit": baseline_commit,
        "max_attempts": 1,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
        "supervision_level": "L2",
        "network_policy": "PROVIDER_ONLY",
        "materiality": "TACTICAL",
    }


def _j16(
    cli: PublicCLI,
    root: Path,
    codex_command: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    project_root = root / "project"
    catalog = root / "catalog.sqlite3"
    project_id = "m3-codex-project"
    created = cli.call(
        "project.create",
        {
            "project_root": str(project_root),
            "catalog_path": str(catalog),
            "name": "M3 Codex Public Outcome",
            "project_id": project_id,
        },
    )["value"]
    provider_spec = {
        "provider_id": "codex",
        "command": codex_command,
        "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "credential_reference": {
            "broker": "codex-native-session",
            "reference": "default-session",
            "provider_id": "codex",
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
            "secret_material_present": False,
        },
    }
    plan = cli.call(
        "distribution.setup.plan",
        {
            "project_root": str(project_root),
            "integration_ids": ["manual", "codex"],
            "provider_specs": [provider_spec],
        },
    )
    decision = _value(plan, "decision")
    token = decision.get("confirmation_token")
    if not isinstance(token, str) or not token.startswith("approve-"):
        raise AssertionError("setup plan did not issue a bounded approval token")
    cli.call(
        "distribution.setup.apply",
        {
            "project_root": str(project_root),
            "integration_ids": ["manual", "codex"],
            "provider_specs": [provider_spec],
            "confirmation_token": token,
        },
    )
    setup_path = project_root / ".artifex" / "integrations.json"
    if not setup_path.is_file():
        raise AssertionError("public setup did not persist ARTIFEX provider state")
    setup_text = setup_path.read_text(encoding="utf-8")
    for key in ("token", "secret", "password", "api_key"):
        if re.search(rf'(?i)["\']?{key}["\']?\s*:\s*["\']?(?!null|false)', setup_text):
            raise AssertionError(f"setup state appears to contain credential material: {key}")

    # The real execution workspace must derive from a clean, immutable Git
    # baseline.  This is repository setup, not a product API shortcut.
    _git(project_root, "config", "user.name", "ARTIFEX M3 Qualifier", environment=cli.environment)
    _git(
        project_root,
        "config",
        "user.email",
        "artifex-m3-qualifier@invalid.local",
        environment=cli.environment,
    )
    _git(project_root, "add", "--all", environment=cli.environment)
    _git(
        project_root,
        "commit",
        "-m",
        "Establish M3 black-box baseline",
        environment=cli.environment,
    )
    baseline_commit = _git(project_root, "rev-parse", "HEAD", environment=cli.environment)
    baseline_fingerprint = str(created.get("semantic_fingerprint", ""))
    if not re.fullmatch(r"[a-f0-9]{40}", baseline_commit):
        raise AssertionError("fresh Project Git baseline is not a full SHA-1")
    if not re.fullmatch(r"[a-f0-9]{64}", baseline_fingerprint):
        raise AssertionError("fresh Project semantic baseline is not a SHA-256")

    # Every call is a fresh public process.  These calls therefore prove consumption,
    # not an in-memory registration left behind by setup apply.
    graph = _value(cli.call(PROVIDER_GRAPH, {"project_root": str(project_root)}), "graph")
    node = _find_provider(graph, "codex")
    readiness = _value(
        cli.call(
            PROVIDER_READINESS,
            {"project_root": str(project_root), "provider_id": "codex"},
        ),
        "readiness",
    )
    resolve_args = {
        "project_root": str(project_root),
        "provider_id": "codex",
        "role": "EXECUTION_IMPLEMENTER",
        "capabilities": ["repository_write", "test_execution"],
        "project_id": project_id,
        "project_job_id": "m3-job",
        "envelope": _envelope(
            project_id,
            baseline_fingerprint=baseline_fingerprint,
            baseline_commit=baseline_commit,
        ),
        "actor": {
            "actor_id": "m3-coordinator",
            "actor_type": "SERVICE",
            "delegated_roles": ["EXECUTION_IMPLEMENTER"],
        },
        "data_classification": "INTERNAL",
    }
    eligible = _value(cli.call(PROVIDER_RESOLVE, resolve_args), "decision")
    excluded_args = json.loads(json.dumps(resolve_args))
    excluded_args["project_policy"] = {
        "allowed_providers": ["manual"],
        "allowed_roles": ["EXECUTION_IMPLEMENTER"],
    }
    excluded = _value(cli.call(PROVIDER_RESOLVE, excluded_args), "decision")
    readiness_state = str(readiness.get("state", readiness.get("status", ""))).upper()
    if readiness_state != "AVAILABLE":
        raise AssertionError(f"fresh runtime Codex readiness is not ready: {readiness_state}")
    if eligible.get("eligible") is not True or eligible.get("provider_id") != "codex":
        raise AssertionError("fresh runtime did not resolve configured Codex")
    if excluded.get("eligible") is not False:
        raise AssertionError("healthy Codex ignored contextual exclusion policy")
    return (
        {
            "status": "PASS",
            "fresh_process_consumed_setup": True,
            "provider_registered": node.get("provider_id") == "codex",
            "setup_sha256": _sha256(setup_text),
            "readiness_state": readiness_state,
            "eligible_context_passed": True,
            "healthy_but_ineligible_excluded": True,
        },
        {
            "project_root": project_root,
            "catalog": catalog,
            "project_id": project_id,
            "baseline_fingerprint": baseline_fingerprint,
            "baseline_commit": baseline_commit,
            "graph": graph,
        },
    )


def _vertical_slice(cli: PublicCLI, root: Path, context: dict[str, Any]) -> dict[str, Any]:
    project_root = Path(context["project_root"])
    project_id = str(context["project_id"])
    store = root / "runstore.sqlite3"
    workspaces = root / "workspaces"
    common = {
        "store_path": str(store),
        "service_id": "m3-managed-runtime",
        "workspace_root": str(workspaces),
    }
    envelope = _envelope(
        project_id,
        baseline_fingerprint=str(context["baseline_fingerprint"]),
        baseline_commit=str(context["baseline_commit"]),
    )
    automation = _principal(
        "m3-coordinator",
        "AUTOMATION_SYSTEM_ACTOR",
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
    )
    architect = _principal("m3-architect", "USER", "envelope:approve")
    provider_actor = _principal("m3-codex-provider", "PROVIDER", "result:submit")
    evidence_actor = _principal(
        "m3-evidence-service",
        "ARTIFEX_SERVICE",
        "workspace:access",
        "evidence:record",
    )
    acceptance_actor = _principal("m3-acceptance-authority", "USER", "acceptance:decide")
    promotion_actor = _principal("m3-project-authority", "USER", "project:promote")
    interaction = _value(
        cli.call(
            PROVIDER_INTERACT,
            {
                "project_root": str(project_root),
                "provider_id": "codex",
                "project_id": project_id,
                "role": "INTERACTION",
                "prompt": (
                    "Return exactly: ARTIFEX_INTERACTION "
                    "project_id=m3-codex-project semantic_revision=1. "
                    "Do not call tools and do not modify files."
                ),
            },
            timeout=600,
        ),
        "interaction",
    )
    if interaction.get("provider_id") != "codex" or interaction.get("live") is not True:
        raise AssertionError("Codex INTERACTION did not execute live")
    interaction_marker = "ARTIFEX_INTERACTION project_id=m3-codex-project semantic_revision=1"
    if not _is_bounded_interaction_response(interaction.get("response"), interaction_marker):
        raise AssertionError("Codex INTERACTION did not return the bounded live response")

    cli.call(
        "runtime.bootstrap",
        {
            **common,
            "envelope": envelope,
            "actor": automation,
            "approval_actor": architect,
            "workstream_id": "m3-workstream",
            "run_id": "m3-run",
            "project_job_id": "m3-job",
            "attempt_id": "m3-attempt",
            "purpose": "M3 real Codex public vertical slice",
        },
    )
    workspace = cli.call(
        "runtime.workspace.create",
        {
            **common,
            "workspace_id": "m3-workspace",
            "attempt_id": "m3-attempt",
            "project_root": str(project_root),
            "baseline_revision": 1,
            "actor": automation,
        },
    )["value"]
    execution = _value(
        cli.call(
            PROVIDER_EXECUTE,
            {
                **common,
                "project_root": str(project_root),
                "provider_id": "codex",
                "role": "EXECUTION_IMPLEMENTER",
                "run_id": "m3-run",
                "project_job_id": "m3-job",
                "attempt_id": "m3-attempt",
                "workspace_id": "m3-workspace",
                "objective": (
                    "Create deliverables/m3-codex.txt containing exactly "
                    "ARTIFEX M3 REAL CODEX EXECUTION followed by a newline."
                ),
                "owned_paths": ["deliverables/m3-codex.txt"],
                "credential_reference_id": "codex-cli-session",
                "capabilities": ["repository_write", "test_execution"],
                "filesystem_permissions": ["READ", "WRITE"],
                "network_permissions": ["PROVIDER_API"],
                "tool_permissions": ["codex.exec"],
                "actor": automation,
                "provider_actor": provider_actor,
                "evidence_actor": evidence_actor,
            },
            timeout=600,
        ),
        "execution",
    )
    if execution.get("provider_id") != "codex" or execution.get("live") is not True:
        raise AssertionError("Codex EXECUTION_IMPLEMENTER did not execute live")
    if str(execution.get("status", "")).upper() not in {"SUCCESS", "FINISHED", "PASS"}:
        provider_result = execution.get("result", {})
        provider_message = (
            provider_result.get("message", "") if isinstance(provider_result, dict) else ""
        )
        raise AssertionError(
            "Codex execution did not finish successfully: "
            f"{execution.get('status')}; message={provider_message}"
        )
    evidence = execution.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AssertionError("provider execution did not persist bound validation evidence")
    evidence_ids = [
        str(item.get("evidence_id"))
        for item in evidence
        if isinstance(item, dict) and item.get("evidence_id")
    ]
    if len(evidence_ids) != len(evidence):
        raise AssertionError("provider execution evidence identities are malformed")

    observed = cli.call("runtime.status", {**common, "run_id": "m3-run"})["value"]
    attempts = observed.get("attempts", [])
    jobs = observed.get("project_jobs", [])
    if not attempts or attempts[0].get("state") != "FINISHED":
        raise AssertionError("provider success did not produce a FINISHED Attempt")
    if not jobs or jobs[0].get("state") != "FINISHED":
        raise AssertionError("provider success did not leave the ProjectJob awaiting acceptance")
    if observed.get("acceptance_decisions"):
        raise AssertionError("provider/coordinator self-accepted the ProjectJob")

    cli.call(
        "runtime.accept",
        {
            **common,
            "project_job_id": "m3-job",
            "evidence_valid": True,
            "evidence_ids": evidence_ids,
            "actor": acceptance_actor,
            "reason": "independent M3 owned-path validation passed",
        },
    )
    model_path = project_root / ".artifex" / "project-model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["project"]["description"] = "Accepted real Codex M3 ProjectJob"
    promoted = cli.call(
        "runtime.workspace.promote",
        {
            **common,
            "workspace_id": "m3-workspace",
            "project_job_id": "m3-job",
            "model": model,
            "actor": promotion_actor,
        },
    )["value"]
    if promoted.get("semantic_revision") != 2:
        raise AssertionError("Project Authority did not promote semantic revision 2")

    certifications = _value(
        cli.call(
            PROVIDER_CERTIFICATIONS,
            {
                "project_root": str(project_root),
                "project_id": project_id,
                "provider_id": "codex",
            },
        ),
        "certifications",
    )
    roles = certifications.get("roles", certifications)
    if not isinstance(roles, (list, dict)):
        raise AssertionError("role-specific certification report is malformed")
    role_states: dict[str, str] = {}
    if isinstance(roles, list):
        for item in roles:
            if isinstance(item, dict):
                role_states[str(item.get("role"))] = str(item.get("state"))
    else:
        for role, item in roles.items():
            role_states[str(role)] = str(item.get("state") if isinstance(item, dict) else item)
    required = {"INTERACTION", "EXECUTION_IMPLEMENTER"}
    if {role for role, state in role_states.items() if state == "LIVE_ROLE_CERTIFIED"} != required:
        raise AssertionError(f"Codex roles are not independently live-certified: {role_states}")

    final_status = cli.call("runtime.status", {**common, "run_id": "m3-run"})["value"]
    audit_types = [str(item.get("event_type")) for item in final_status.get("audit", [])]
    required_audit = {
        "WORKSPACE_CREATED",
        "ATTEMPT_FINISHED",
        "ACCEPTANCE_DECIDED",
        "WORKSPACE_PROMOTED",
    }
    if not required_audit.issubset(set(audit_types)):
        raise AssertionError(f"runtime audit chain is incomplete: {audit_types}")
    return {
        "status": "PASS",
        "provider_execution": {
            "live": True,
            "simulated": False,
            "provider_id": "codex",
            "role": "EXECUTION_IMPLEMENTER",
        },
        "interaction": {"live": True, "role": "INTERACTION"},
        "workspace": {
            "isolated": bool(workspace.get("isolated")),
            "workspace_root_sha256": _sha256(str(workspace.get("workspace_root", ""))),
        },
        "provider_result_self_accepted": False,
        "semantic_revision": 2,
        "role_certifications": role_states,
        "audit_event_types": audit_types,
        "frontend_process_reconnect": True,
    }


def qualify(
    python: Path,
    *,
    codex_command: list[str],
    repo_root: Path | None = None,
) -> dict[str, Any]:
    python = python.resolve()
    if not python.is_file():
        return _blocked("INSTALLED_PYTHON_NOT_FOUND", str(python))
    with _qualification_directory(repo_root) as root:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        environment["LOCALAPPDATA"] = str(root / "local-state")
        environment["XDG_STATE_HOME"] = str(root / "xdg-state")
        environment["GIT_AUTHOR_NAME"] = "ARTIFEX M3 Outcome"
        environment["GIT_AUTHOR_EMAIL"] = "artifex-m3@local.invalid"
        environment["GIT_COMMITTER_NAME"] = "ARTIFEX M3 Outcome"
        environment["GIT_COMMITTER_EMAIL"] = "artifex-m3@local.invalid"
        for key in tuple(environment):
            if _SENSITIVE.search(key) and key.startswith("ARTIFEX_TEST_"):
                environment.pop(key)
        try:
            origin = _installed_origin(
                python, cwd=root, environment=environment, forbidden_root=repo_root
            )
        except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            return _blocked("INSTALLED_WHEEL_ORIGIN_INVALID", str(exc))
        probe = probe_codex(codex_command, cwd=root, environment=environment)
        if probe["status"] != "PASS":
            blocker = probe["blocker"]
            result = _blocked(str(blocker["code"]), str(blocker["detail"]), probe=probe)
            result["installed_package"] = origin
            return result
        cli = PublicCLI(python, root, environment)
        try:
            j16, context = _j16(cli, root, list(probe["command"]))
            vertical = _vertical_slice(cli, root, context)
        except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            result = _blocked("PUBLIC_COMPOSITION_GATE_FAILED", str(exc), probe=probe)
            result["installed_package"] = origin
            result["public_process_calls"] = cli.calls
            return result
        return {
            "schema_version": "1.0",
            "status": "PASS",
            "composition": COMPOSITION,
            "shipping_artifact": "INSTALLED_WHEEL",
            "installed_package": origin,
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "provider_injection_used": False,
            "simulated_provider": False,
            "live_gate": {"status": "PASS", "blockers": [], "codex_probe": probe},
            "j01_interpretation": dict(J01_INTERPRETATION),
            "journeys": {
                "J01": dict(J01_INTERPRETATION),
                "J16": j16,
                "M3_CODEX_VERTICAL_SLICE": vertical,
            },
            "public_process_calls": cli.calls,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--codex-command-json")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        command = _command_vector(arguments.codex_command_json)
        result = qualify(arguments.python, codex_command=command, repo_root=arguments.repo_root)
    except (ValueError, json.JSONDecodeError) as exc:
        result = _blocked("HARNESS_CONFIGURATION_INVALID", str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 2 if result["status"] == "BLOCKED" else 1)


if __name__ == "__main__":
    main()

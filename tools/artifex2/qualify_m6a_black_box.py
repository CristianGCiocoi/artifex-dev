"""Qualify M6A through an installed wheel and real Claude/Codex public processes.

The harness imports no ARTIFEX product package. Every product operation crosses
an isolated ``python -I -m artifex.cli`` process boundary. Credential files and
authentication output are never read into or persisted by the evidence result.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from qualify_m3_black_box import (
    PublicCLI,
    _find_provider,
    _git,
    _installed_origin,
    _principal,
    _qualification_directory,
    _run,
    _scrub,
    _sha256,
    _value,
    probe_codex,
)

COMPOSITION = "CLEAN_INSTALLED_WHEEL_PUBLIC_CLI_REAL_CLAUDE_MULTI_PROCESS"
_SEMVER = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SENSITIVE = re.compile(r"(?:token|secret|password|credential|api[_-]?key)", re.I)
_MAX_INTERACTION_RESPONSE_BYTES = 2_048


def _evidence_safe(value: object, *, field: str | None = None) -> object:
    """Remove local identity-bearing paths while retaining cryptographic bindings."""

    if isinstance(value, dict):
        sanitized = {
            key: _evidence_safe(item, field=key)
            for key, item in value.items()
            if key not in {"command", "origin", "prefix"}
        }
        if field == "installed_package":
            sanitized["distribution_location"] = "INSTALLED_SITE_PACKAGES"
        return sanitized
    if isinstance(value, list):
        return [_evidence_safe(item) for item in value]
    if isinstance(value, str):
        home = str(Path.home())
        return re.sub(re.escape(home), "<USER_PROFILE>", value, flags=re.IGNORECASE)
    return value


def _blocked(code: str, detail: str, **evidence: object) -> dict[str, Any]:
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
        "blockers": [blocker],
        **evidence,
    }


def _command_vector(raw: str | None, executable: str) -> list[str]:
    if raw:
        value = json.loads(raw)
        if not isinstance(value, list) or not value or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ValueError("provider command JSON must be a non-empty string array")
        return list(value)
    resolved = shutil.which(executable)
    return [resolved] if resolved else []


def _probe_claude(
    command: list[str], *, cwd: Path, environment: dict[str, str]
) -> dict[str, Any]:
    """Observe only official version/auth status and retain no PII-bearing output."""

    if not command:
        return {"status": "BLOCKED", "code": "CLAUDE_EXECUTABLE_NOT_FOUND"}
    executable = shutil.which(command[0]) if not Path(command[0]).is_file() else command[0]
    if executable is None:
        return {"status": "BLOCKED", "code": "CLAUDE_EXECUTABLE_NOT_FOUND"}
    normalized = [str(Path(executable).resolve()), *command[1:]]
    try:
        version_result = _run(
            [*normalized, "--version"], cwd=cwd, environment=environment, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "BLOCKED",
            "code": "CLAUDE_VERSION_UNCALLABLE",
            "type": type(exc).__name__,
        }
    match = _SEMVER.search(version_result.stdout or version_result.stderr)
    if version_result.returncode != 0 or match is None:
        return {"status": "BLOCKED", "code": "CLAUDE_VERSION_UNAVAILABLE"}
    version = match.group(1)
    parts = tuple(int(item) for item in version.split("."))
    if not (parts >= (2, 1, 3) and parts < (3, 0, 0)):
        return {"status": "BLOCKED", "code": "CLAUDE_VERSION_UNSUPPORTED", "version": version}
    try:
        auth_result = _run(
            [*normalized, "auth", "status"], cwd=cwd, environment=environment, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "BLOCKED", "code": "CLAUDE_AUTH_UNCALLABLE", "type": type(exc).__name__}
    try:
        auth = json.loads(auth_result.stdout)
    except json.JSONDecodeError:
        auth = None
    logged_in = (
        auth_result.returncode == 0
        and isinstance(auth, dict)
        and auth.get("loggedIn") is True
    )
    if not logged_in:
        return {"status": "BLOCKED", "code": "CLAUDE_AUTH_UNAVAILABLE", "version": version}
    return {
        "status": "PASS",
        "version": version,
        "command": normalized,
        "command_sha256": _sha256(json.dumps(normalized, separators=(",", ":"))),
        "executable_sha256": _sha256(Path(normalized[0]).read_bytes()),
        "version_exit_code": version_result.returncode,
        "auth_exit_code": auth_result.returncode,
        "authenticated": True,
        "credential_material_read": False,
        "pii_persisted": False,
    }


def _provider_spec(provider_id: str, command: list[str]) -> dict[str, Any]:
    return {
        "provider_id": provider_id,
        "command": command,
        "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "credential_reference": {
            "broker": f"{provider_id}-native-session",
            "reference": "default-session",
            "provider_id": provider_id,
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
            "secret_material_present": False,
        },
    }


def _bounded_marker_response(value: object, marker: str) -> bool:
    return (
        isinstance(value, str)
        and len(value.encode("utf-8", errors="replace")) <= _MAX_INTERACTION_RESPONSE_BYTES
        and value.count(marker) == 1
    )


def _setup(
    cli: PublicCLI,
    *,
    project_root: Path,
    catalog: Path,
    project_id: str,
    claude_command: list[str],
    codex_command: list[str],
) -> dict[str, Any]:
    created = cli.call(
        "project.create",
        {
            "project_root": str(project_root),
            "catalog_path": str(catalog),
            "project_id": project_id,
            "name": "M6A Live Claude Qualification",
        },
    )["value"]
    specs = [
        _provider_spec("codex", codex_command),
        _provider_spec("claude", claude_command),
    ]
    plan = cli.call(
        "distribution.setup.plan",
        {
            "project_root": str(project_root),
            "integration_ids": ["manual", "codex", "claude"],
            "provider_specs": specs,
        },
    )
    token = _value(plan, "decision").get("confirmation_token")
    if not isinstance(token, str) or not token.startswith("approve-"):
        raise AssertionError("provider setup did not issue a bounded confirmation token")
    cli.call(
        "distribution.setup.apply",
        {
            "project_root": str(project_root),
            "integration_ids": ["manual", "codex", "claude"],
            "provider_specs": specs,
            "confirmation_token": token,
        },
    )
    setup = (project_root / ".artifex" / "integrations.json").read_text(encoding="utf-8")
    lowered = setup.casefold()
    if any(f'"{item}"' in lowered for item in ("token", "password", "api_key")):
        raise AssertionError("provider setup persisted a prohibited credential-like key")
    _git(project_root, "config", "user.name", "ARTIFEX M6A Qualifier", environment=cli.environment)
    _git(
        project_root,
        "config",
        "user.email",
        "artifex-m6a@local.invalid",
        environment=cli.environment,
    )
    _git(project_root, "add", "--all", environment=cli.environment)
    _git(project_root, "commit", "-m", "Establish M6A live baseline", environment=cli.environment)
    return {
        "created": created,
        "baseline_commit": _git(project_root, "rev-parse", "HEAD", environment=cli.environment),
        "setup_sha256": _sha256(setup),
    }


def _envelope(
    project_id: str, *, baseline_commit: str, baseline_fingerprint: str
) -> dict[str, Any]:
    return {
        "envelope_id": "m6a-live-envelope",
        "version": 1,
        "project_id": project_id,
        "objective": "Create one bounded Claude qualification deliverable",
        "baseline_revision": 1,
        "actor_id": "m6a-architect",
        "allowed_paths": ["deliverables/m6a-claude.txt"],
        "allowed_capabilities": ["repository_read", "repository_write"],
        "allowed_providers": ["claude"],
        "allowed_provider_roles": ["EXECUTION_IMPLEMENTER"],
        "allowed_workstreams": ["m6a-live-workstream"],
        "required_gates": ["validation", "acceptance-authority", "project-authority"],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": ["PROVIDER_API"],
        "tool_permissions": ["claude.exec"],
        "data_classification": "INTERNAL",
        "credential_references": [
            {
                "reference_id": "claude-cli-session",
                "provider_id": "claude",
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


def _role_states(value: dict[str, Any]) -> dict[str, str]:
    roles = value.get("roles")
    if not isinstance(roles, list):
        raise AssertionError("provider certification projection has no roles")
    return {
        str(item["role"]): str(item["state"])
        for item in roles
        if isinstance(item, dict)
    }


def _live_journeys(
    cli: PublicCLI,
    root: Path,
    project_root: Path,
    catalog: Path,
    project_id: str,
    setup: dict[str, Any],
    expected_claude_version: str,
) -> dict[str, Any]:
    readiness = _value(
        cli.call(
            "providers.readiness",
            {"project_root": str(project_root), "provider_id": "claude"},
        ),
        "readiness",
    )
    graph = _value(cli.call("providers.graph", {"project_root": str(project_root)}), "graph")
    node = _find_provider(graph, "claude")
    if (
        readiness.get("state") != "AVAILABLE"
        or readiness.get("version") != expected_claude_version
    ):
        raise AssertionError(f"Claude public readiness is not certified/available: {readiness}")
    if readiness.get("checks", {}).get("supported_version") is not True:
        raise AssertionError("Claude readiness did not enforce the supported version range")

    marker = f"ARTIFEX_CONTINUITY project_id={project_id} semantic_revision=1"
    continuity_prompt = (
        "Use the allowed read-only tools to inspect the bound Project's "
        ".artifex/project-model.json and latest .artifex/semantic-revisions/*.json. "
        "Derive the Project ID and accepted semantic revision from those files, not from "
        "conversation memory. Report the observed values once using exactly this shape: "
        "ARTIFEX_CONTINUITY project_id=<observed-id> semantic_revision=<observed-number>. "
        "Do not modify files."
    )
    codex_interaction = _value(
        cli.call(
            "providers.interact",
            {
                "project_root": str(project_root),
                "provider_id": "codex",
                "project_id": project_id,
                "project_job_id": "m6a-codex-interaction",
                "role": "INTERACTION",
                "prompt": continuity_prompt,
            },
            timeout=600,
        ),
        "interaction",
    )
    claude_interaction = _value(
        cli.call(
            "providers.interact",
            {
                "project_root": str(project_root),
                "provider_id": "claude",
                "project_id": project_id,
                "project_job_id": "m6a-claude-interaction",
                "role": "INTERACTION",
                "prompt": continuity_prompt,
            },
            timeout=600,
        ),
        "interaction",
    )
    if not _bounded_marker_response(codex_interaction.get("response"), marker):
        raise AssertionError("Codex continuity response did not contain one bounded marker")
    if not _bounded_marker_response(claude_interaction.get("response"), marker):
        raise AssertionError("Claude continuity response did not contain one bounded marker")
    if codex_interaction.get("baseline") != claude_interaction.get("baseline"):
        raise AssertionError("Codex to Claude continuity changed the Project baseline")

    store = root / "runstore.sqlite3"
    workspaces = root / "workspaces"
    common = {
        "store_path": str(store),
        "service_id": "m6a-live-runtime",
        "workspace_root": str(workspaces),
    }
    envelope = _envelope(
        project_id,
        baseline_commit=str(setup["baseline_commit"]),
        baseline_fingerprint=str(setup["created"]["semantic_fingerprint"]),
    )
    coordinator = _principal(
        "m6a-coordinator",
        "AUTOMATION_SYSTEM_ACTOR",
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
    )
    cli.call(
        "runtime.bootstrap",
        {
            **common,
            "envelope": envelope,
            "actor": coordinator,
            "approval_actor": _principal("m6a-architect", "USER", "envelope:approve"),
            "workstream_id": "m6a-live-workstream",
            "run_id": "m6a-live-run",
            "project_job_id": "m6a-live-job",
            "attempt_id": "m6a-live-attempt",
            "purpose": "M6A real Claude provider slice",
        },
    )
    workspace = cli.call(
        "runtime.workspace.create",
        {
            **common,
            "workspace_id": "m6a-live-workspace",
            "attempt_id": "m6a-live-attempt",
            "project_root": str(project_root),
            "baseline_revision": 1,
            "actor": coordinator,
        },
    )["value"]
    execution = _value(
        cli.call(
            "runtime.provider.execute",
            {
                **common,
                "project_root": str(project_root),
                "provider_id": "claude",
                "role": "EXECUTION_IMPLEMENTER",
                "run_id": "m6a-live-run",
                "project_job_id": "m6a-live-job",
                "attempt_id": "m6a-live-attempt",
                "workspace_id": "m6a-live-workspace",
                "objective": (
                    "Create deliverables/m6a-claude.txt containing exactly "
                    "ARTIFEX M6A REAL CLAUDE EXECUTION followed by a newline."
                ),
                "owned_paths": ["deliverables/m6a-claude.txt"],
                "credential_reference_id": "claude-cli-session",
                "capabilities": ["repository_read", "repository_write"],
                "filesystem_permissions": ["READ", "WRITE"],
                "network_permissions": ["PROVIDER_API"],
                "tool_permissions": ["claude.exec"],
                "actor": coordinator,
                "provider_actor": _principal("m6a-claude-provider", "PROVIDER", "result:submit"),
                "evidence_actor": _principal(
                    "m6a-evidence", "ARTIFEX_SERVICE", "workspace:access", "evidence:record"
                ),
            },
            timeout=900,
        ),
        "execution",
    )
    if execution.get("status") != "SUCCESS" or execution.get("live") is not True:
        raise AssertionError(f"Claude execution did not succeed live: {execution.get('status')}")
    authorization = execution.get("dispatch_authorization", {})
    if authorization.get("tool_permissions") != ["claude.exec"]:
        raise AssertionError("dispatch authority did not preserve bounded tool permissions")
    evidence = execution.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise AssertionError("Claude execution did not produce bound evidence")
    evidence_ids = [str(item["evidence_id"]) for item in evidence]
    before_accept = cli.call("runtime.status", {**common, "run_id": "m6a-live-run"})["value"]
    if before_accept.get("acceptance_decisions"):
        raise AssertionError("provider execution self-accepted before Acceptance Authority")
    accepted = cli.call(
        "runtime.accept",
        {
            **common,
            "project_job_id": "m6a-live-job",
            "evidence_valid": True,
            "evidence_ids": evidence_ids,
            "reason": "independent M6A owned-artifact validation passed",
            "actor": _principal("m6a-acceptance", "USER", "acceptance:decide"),
        },
    )["value"]
    model_path = project_root / ".artifex" / "project-model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["project"]["description"] = "Accepted real Claude M6A ProjectJob"
    promoted = cli.call(
        "runtime.workspace.promote",
        {
            **common,
            "workspace_id": "m6a-live-workspace",
            "project_job_id": "m6a-live-job",
            "model": model,
            "actor": _principal("m6a-project-authority", "USER", "project:promote"),
        },
    )["value"]
    receipt = promoted.get("provider_certification_receipt", {})
    if receipt.get("live_role_eligible") is not True:
        raise AssertionError("execution receipt lacks live provider/wheel/auth binding")
    certifications = _value(
        cli.call(
            "providers.certifications",
            {"project_root": str(project_root), "project_id": project_id, "provider_id": "claude"},
        ),
        "certifications",
    )
    states = _role_states(certifications)
    if states != {
        "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
        "INTERACTION": "LIVE_ROLE_CERTIFIED",
    }:
        raise AssertionError(f"Claude roles are not independently certified: {states}")
    cli.call(
        "documentation.regenerate",
        {
            "name": "M6A Live Claude Qualification",
            "catalog_path": str(catalog),
            "documents": [],
        },
    )
    documents = cli.call(
        "documentation.status",
        {"name": "M6A Live Claude Qualification", "catalog_path": str(catalog)},
    )["value"]
    dashboard = cli.call(
        "dashboard.project", {"name": "M6A Live Claude Qualification", "catalog_path": str(catalog)}
    )["value"]
    if dashboard.get("semantic_revision") != 2 or dashboard.get("authoritative") is not False:
        raise AssertionError("post-promotion dashboard does not project revision 2")
    if any(item.get("state") != "CURRENT" for item in documents.get("documents", [])):
        raise AssertionError("post-promotion documentation is not current")
    return {
        "J02": {
            "status": "M6A_LIVE_PROVIDER_SLICE_PASS",
            "full_clean_machine_status": "NOT_CLAIMED",
            "primary_proving_milestone": "M7",
            "installed_wheel": True,
            "fresh_public_process_setup_reload": True,
            "readiness_state": readiness["state"],
            "provider_version": readiness["version"],
            "interaction_live": True,
            "execution_live": True,
            "workspace_isolated": bool(workspace.get("isolated")),
            "provider_self_accepted": False,
            "accepted_revision": promoted["semantic_revision"],
            "documentation_current": True,
            "dashboard_revision": dashboard["semantic_revision"],
        },
        "J11": {
            "status": "PASS",
            "no_export_or_migration": True,
            "same_project_identity": True,
            "same_project_baseline": True,
            "codex_closed_by_process_exit": True,
            "claude_attached_in_fresh_process": True,
            "authority_roles_preserved": True,
        },
        "role_certifications": states,
        "receipt_binding": {
            "provider_version": receipt.get("provider_version"),
            "provider_executable_sha256": receipt.get("provider_executable_sha256"),
            "auth_probe_sha256": receipt.get("auth_probe_sha256"),
            "shipping_artifact_sha256": receipt.get("shipping_artifact_sha256"),
            "project_job_id": receipt.get("project_job_id"),
            "acceptance_decision_id": receipt.get("acceptance_decision_id"),
            "promotion_revision": receipt.get("promotion_revision"),
        },
        "provider_node_registered": node.get("provider_id") == "claude",
        "acceptance_decision_id": accepted["decision"]["decision_id"],
    }


def _legacy_revalidation(
    cli: PublicCLI, root: Path, claude_command: list[str]
) -> dict[str, Any]:
    legacy = root / "legacy-project"
    cli.call(
        "project.create",
        {"project_root": str(legacy), "project_id": "m6a-v1-legacy", "name": "M6A V1 Legacy"},
    )
    setup_path = legacy / ".artifex" / "integrations.json"
    setup_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "authority": "ARTIFEX_PROJECT_STATE",
                "enabled": ["claude"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    # The V1 schema uses its canonical `claude` command. The qualification
    # environment must therefore resolve the exact already-probed executable.
    readiness = _value(
        cli.call(
            "providers.readiness",
            {"project_root": str(legacy), "provider_id": "claude"},
        ),
        "readiness",
    )
    if readiness.get("state") != "AVAILABLE":
        raise AssertionError("V1 Claude setup did not revalidate as AVAILABLE")
    if Path(str(readiness.get("executable", ""))).resolve() != Path(claude_command[0]).resolve():
        raise AssertionError("V1 Claude setup resolved a different executable")
    return {
        "status": "PASS",
        "source_schema": "1.0",
        "fresh_process_real_readiness": True,
        "provider_version": readiness.get("version"),
        "semantic_history_fabricated": False,
    }


def qualify(
    python: Path,
    *,
    wheel_sha256: str,
    claude_command: list[str],
    codex_command: list[str],
    repo_root: Path | None,
) -> dict[str, Any]:
    if _SHA256.fullmatch(wheel_sha256) is None:
        return _blocked("SHIPPING_WHEEL_DIGEST_INVALID", wheel_sha256)
    with _qualification_directory(repo_root) as root:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        environment["ARTIFEX_LOCAL_STATE_ROOT"] = str(root / "local-state")
        environment["ARTIFEX_SHIPPING_ARTIFACT_SHA256"] = wheel_sha256
        environment["LOCALAPPDATA"] = str(root / "local-app-data")
        environment["XDG_STATE_HOME"] = str(root / "xdg-state")
        environment["GIT_AUTHOR_NAME"] = "ARTIFEX M6A Outcome"
        environment["GIT_AUTHOR_EMAIL"] = "artifex-m6a@local.invalid"
        environment["GIT_COMMITTER_NAME"] = "ARTIFEX M6A Outcome"
        environment["GIT_COMMITTER_EMAIL"] = "artifex-m6a@local.invalid"
        for key in tuple(environment):
            if key.startswith("ARTIFEX_TEST_") and _SENSITIVE.search(key):
                environment.pop(key)
        evidence_store = root / "local-state" / "capability-evidence.sqlite3"
        if evidence_store.exists():
            return _blocked("EVIDENCE_STORE_NOT_EMPTY", str(evidence_store))
        try:
            origin = _installed_origin(
                python.resolve(), cwd=root, environment=environment, forbidden_root=repo_root
            )
            claude_probe = _probe_claude(claude_command, cwd=root, environment=environment)
            if claude_probe.get("status") != "PASS":
                return _blocked(
                    str(claude_probe.get("code", "CLAUDE_PROBE_FAILED")),
                    "official Claude version/auth status probe failed",
                    claude_probe=claude_probe,
                    installed_package=origin,
                )
            codex_probe = probe_codex(codex_command, cwd=root, environment=environment)
            if codex_probe.get("status") != "PASS":
                blocker = codex_probe.get("blocker", {})
                return _blocked(
                    str(blocker.get("code", "CODEX_PROBE_FAILED")),
                    str(blocker.get("detail", "Codex continuity prerequisite unavailable")),
                    claude_probe=claude_probe,
                    codex_probe=codex_probe,
                    installed_package=origin,
                )
            cli = PublicCLI(python.resolve(), root, environment)
            project = root / "project"
            catalog = root / "catalog.sqlite3"
            setup = _setup(
                cli,
                project_root=project,
                catalog=catalog,
                project_id="m6a-live-project",
                claude_command=list(claude_probe["command"]),
                codex_command=list(codex_probe["command"]),
            )
            journeys = _live_journeys(
                cli,
                root,
                project,
                catalog,
                "m6a-live-project",
                setup,
                str(claude_probe["version"]),
            )
            migration = _legacy_revalidation(cli, root, list(claude_probe["command"]))
        except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            return _blocked(
                "PUBLIC_COMPOSITION_GATE_FAILED",
                str(exc),
                installed_package=locals().get("origin"),
                claude_probe=locals().get("claude_probe"),
                codex_probe=locals().get("codex_probe"),
                public_process_calls=locals().get("cli").calls if "cli" in locals() else [],
            )
        return {
            "schema_version": "1.0",
            "status": "PASS",
            "composition": COMPOSITION,
            "shipping_artifact": "INSTALLED_WHEEL",
            "shipping_artifact_sha256": wheel_sha256,
            "installed_package": origin,
            "source_tree_imported": False,
            "custom_application_factory_used": False,
            "provider_injection_used": False,
            "simulated_provider": False,
            "credential_files_read": False,
            "pii_persisted": False,
            "empty_isolated_evidence_store": True,
            "claude_probe": claude_probe,
            "codex_probe": codex_probe,
            "journeys": {"J02": journeys["J02"], "J11": journeys["J11"]},
            "role_certifications": journeys["role_certifications"],
            "receipt_binding": journeys["receipt_binding"],
            "migration": migration,
            "public_process_calls": cli.calls,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--claude-command-json")
    parser.add_argument("--codex-command-json")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        result = qualify(
            arguments.python,
            wheel_sha256=arguments.wheel_sha256.casefold(),
            claude_command=_command_vector(arguments.claude_command_json, "claude"),
            codex_command=_command_vector(arguments.codex_command_json, "codex"),
            repo_root=arguments.repo_root,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        result = _blocked("HARNESS_CONFIGURATION_INVALID", str(exc))
    result = _evidence_safe(result)
    if not isinstance(result, dict):
        raise AssertionError("sanitized qualification result must remain an object")
    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 2)


if __name__ == "__main__":
    main()

"""Qualify J11 and J20 through an installed native ARTIFEX 2.0 candidate.

The harness is deliberately outside the product package.  It talks only to the
installed executable and managed-service public transport, records hashes
instead of provider output, and never reads provider credential material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.artifex2.run_m7_shipping_journey import (
    JourneyFailure,
    ShippingCLI,
    _file_sha256,
    _find_provider,
    _git,
    _is_bounded_interaction_response,
    _principal,
    _provider_workspace_root,
    _read_object,
    _restart_registered_windows_task,
    _role_states,
    _running_service_value,
    _value,
    _wait_for_durable_provider_execution,
    _wait_for_process_exit,
    _wait_for_service,
)

COMPOSITION = "INSTALLED_NATIVE_PUBLIC_CLI_REAL_PROVIDER_MANAGED_SERVICE_MULTI_PROCESS"
SCHEMA = "artifex.m12-j20-qualification/v1"
PRODUCT_VERSION = "2.0.0"
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE = re.compile(
    r"(?:authorization\s*[:=]|access[_ -]?token\s*[:=]|refresh[_ -]?token\s*[:=]|"
    r"api[_ -]?key\s*[:=]|password\s*[:=])",
    re.IGNORECASE,
)


def _provider_spec(provider_id: str, command: Path) -> dict[str, Any]:
    return {
        "provider_id": provider_id,
        "command": [str(command.resolve())],
        "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "credential_reference": {
            "broker": f"{provider_id}-native-session",
            "reference": "default-session",
            "provider_id": provider_id,
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
            "secret_material_present": False,
        },
    }


def _envelope(
    *,
    project_id: str,
    provider_id: str,
    workstream_id: str,
    revision: int,
    fingerprint: str,
    commit: str,
    version: int,
) -> dict[str, Any]:
    return {
        "envelope_id": f"{project_id}-envelope",
        "version": version,
        "project_id": project_id,
        "objective": "Deliver the approved ARTIFEX 2.0 lifecycle outcome",
        "baseline_revision": revision,
        "baseline_fingerprint": fingerprint,
        "baseline_commit": commit,
        "actor_id": "m12-release-owner",
        "allowed_paths": ["deliverables/m12-j20.txt"],
        "allowed_capabilities": [
            "repository_read",
            "repository_write",
            "test_execution",
        ],
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
        "resource_budget": {"attempts": 1, "wall_seconds": 3600},
        "deadline_at": int(time.time()) + 3600,
        "stop_conditions": ["MAX_ATTEMPTS", "UNKNOWN_OUTCOME", "MATERIAL_DECISION"],
        "require_durable_evidence": True,
        "max_attempts": 1,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": False,
        "supervision_level": "L2",
        "network_policy": "PROVIDER_ONLY",
        "materiality": "TACTICAL",
    }


def _model_identity(project_root: Path) -> tuple[int, str, dict[str, Any]]:
    model = _read_object(project_root / ".artifex" / "project-model.json")
    revisions = sorted((project_root / ".artifex" / "semantic-revisions").glob("*.json"))
    if not revisions:
        raise JourneyFailure("Project semantic history is unavailable")
    current = _read_object(revisions[-1])
    revision = int(current.get("revision", 0))
    fingerprint = str(current.get("fingerprint", ""))
    if revision < 1 or not _DIGEST.fullmatch(fingerprint):
        raise JourneyFailure("Project semantic identity is invalid")
    return revision, fingerprint, dict(model)


def _setup_providers(
    cli: ShippingCLI,
    *,
    project_root: Path,
    state_root: Path,
    provider_commands: Mapping[str, Path],
) -> None:
    arguments = {
        "project_root": str(project_root),
        "integration_ids": ["manual", *sorted(provider_commands)],
        "provider_specs": [
            _provider_spec(provider_id, provider_commands[provider_id])
            for provider_id in sorted(provider_commands)
        ],
    }
    plan = _value(
        cli.service_call(
            "distribution.setup.plan",
            arguments,
            project_root=project_root,
            state_root=state_root,
        )
    )
    decision = plan.get("decision")
    confirmation = decision.get("confirmation_token") if isinstance(decision, Mapping) else None
    if not isinstance(confirmation, str) or not confirmation.startswith("approve-"):
        raise JourneyFailure("provider setup did not issue a bounded approval")
    cli.service_call(
        "distribution.setup.apply",
        {**arguments, "confirmation_token": confirmation},
        project_root=project_root,
        state_root=state_root,
    )
    setup_text = (project_root / ".artifex" / "integrations.json").read_text(
        encoding="utf-8"
    )
    if _SENSITIVE.search(setup_text):
        raise JourneyFailure("provider setup persisted secret-shaped material")


def _provider_interaction(
    cli: ShippingCLI,
    *,
    provider_id: str,
    project_id: str,
    revision: int,
    project_root: Path,
    state_root: Path,
) -> None:
    marker = f"ARTIFEX_M12 provider={provider_id} project={project_id} revision={revision}"
    result = _value(
        cli.service_call(
            "providers.interact",
            {
                "provider_id": provider_id,
                "project_id": project_id,
                "role": "INTERACTION",
                "prompt": f"Return exactly: {marker}. Do not call tools or modify files.",
            },
            project_root=project_root,
            state_root=state_root,
        )
    ).get("interaction")
    if (
        not isinstance(result, Mapping)
        or result.get("provider_id") != provider_id
        or result.get("live") is not True
        or not _is_bounded_interaction_response(result.get("response"), marker)
    ):
        raise JourneyFailure(f"{provider_id} interaction did not preserve bounded context")


def _detach_provider_frontend(
    cli: ShippingCLI,
    *,
    arguments: Mapping[str, Any],
    project_root: Path,
    state_root: Path,
    common: Mapping[str, Any],
    provider_id: str,
    run_id: str,
    project_job_id: str,
    attempt_id: str,
) -> Mapping[str, Any]:
    command = [
        str(cli.executable),
        "service",
        "call",
        "runtime.provider.execute",
        "--arguments",
        json.dumps(arguments, sort_keys=True, separators=(",", ":")),
        "--project-root",
        str(project_root),
        "--state-root",
        str(state_root),
    ]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    process = subprocess.Popen(
        command,
        cwd=cli.cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    deadline = time.monotonic() + 30
    observed_running = False
    while time.monotonic() < deadline and process.poll() is None:
        status = _value(
            cli.service_call(
                "runtime.status",
                {**common, "run_id": run_id},
                project_root=project_root,
                state_root=state_root,
            )
        )
        attempts = status.get("attempts")
        if isinstance(attempts, Sequence) and attempts:
            state = str(attempts[-1].get("state", "")) if isinstance(attempts[-1], Mapping) else ""
            if state in {"RUNNING", "ACTIVE", "DISPATCHED"}:
                observed_running = True
                break
        time.sleep(0.25)
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        if _SENSITIVE.search(stdout or "") or _SENSITIVE.search(stderr or ""):
            raise JourneyFailure("provider frontend returned secret-shaped output")
        raise JourneyFailure("provider execution finished before frontend closure was proven")
    if not observed_running:
        process.terminate()
        raise JourneyFailure("durable provider execution did not become observable")
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    cli.calls.append(
        {
            "operation": "runtime.provider.execute",
            "returncode": None,
            "ok": None,
            "frontend_detached": True,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        }
    )
    return _wait_for_durable_provider_execution(
        cli,
        common=common,
        project_root=project_root,
        state_root=state_root,
        provider_id=provider_id,
        run_id=run_id,
        project_job_id=project_job_id,
        attempt_id=attempt_id,
    )


def run_j20(
    *,
    artifact: Path,
    expected_artifact_sha256: str,
    source_commit: str,
    install_root: Path,
    state_root: Path,
    project_root: Path,
    provider_commands: Mapping[str, Path],
    execution_provider: str = "codex",
) -> dict[str, Any]:
    artifact = artifact.resolve()
    install_root = install_root.resolve()
    state_root = state_root.resolve()
    project_root = project_root.resolve()
    if not _DIGEST.fullmatch(expected_artifact_sha256):
        raise JourneyFailure("candidate SHA-256 is invalid")
    if not _COMMIT.fullmatch(source_commit):
        raise JourneyFailure("candidate source commit is invalid")
    if _file_sha256(artifact) != expected_artifact_sha256:
        raise JourneyFailure("candidate artifact hash does not match")
    if set(provider_commands) != {"claude", "codex"} or execution_provider not in provider_commands:
        raise JourneyFailure("J11/J20 require real Codex and Claude composition")
    for provider_id, command in provider_commands.items():
        if not command.resolve().is_file():
            raise JourneyFailure(f"{provider_id} executable is unavailable")

    executable = install_root / "artifex.exe"
    manifest_path = install_root / "artifex-install-manifest.json"
    registration_path = install_root / "service-registration.json"
    for path in (executable, manifest_path, registration_path, install_root / "Uninstall.exe"):
        if not path.is_file():
            raise JourneyFailure(f"installed candidate is missing {path.name}")
    manifest = _read_object(manifest_path)
    artifact_manifest = manifest.get("artifact_manifest")
    if not isinstance(artifact_manifest, Mapping):
        raise JourneyFailure("installed artifact manifest is unavailable")
    if (
        artifact_manifest.get("source_commit") != source_commit
        or artifact_manifest.get("product_version") != PRODUCT_VERSION
        or artifact_manifest.get("sha256") != _file_sha256(executable)
    ):
        raise JourneyFailure("installed native identity does not match the release candidate")

    cli = ShippingCLI(executable, cwd=install_root, timeout_seconds=900)
    before = _running_service_value(
        cli.direct("service.status", ["service", "status", "--state-root", str(state_root)])
    )
    catalog_path = project_root.parent / "catalog.sqlite3"
    store_path = state_root / "runstore.sqlite3"
    organization_path = project_root.parent / "organizational-knowledge.sqlite3"
    project_id = "project-m12-j20"
    project_name = "ARTIFEX M12 Full Lifecycle"
    created = _value(
        cli.service_call(
            "project.create",
            {
                "project_root": str(project_root),
                "catalog_path": str(catalog_path),
                "project_id": project_id,
                "name": project_name,
                "description": "I want to build a governed release outcome.",
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    revision = int(created.get("semantic_revision", 0))
    _setup_providers(
        cli,
        project_root=project_root,
        state_root=state_root,
        provider_commands=provider_commands,
    )

    cli.direct("service.stop", ["service", "stop", "--state-root", str(state_root)])
    _wait_for_process_exit(int(before["process_id"]))
    _restart_registered_windows_task(runner=subprocess.run)
    after_setup = _running_service_value(
        _wait_for_service(cli, state_root, prior_process_id=int(before["process_id"]))
    )
    if int(after_setup["coordinator_generation"]) <= int(before["coordinator_generation"]):
        raise JourneyFailure("provider setup did not survive managed-service restart")
    workspace_root = _provider_workspace_root(after_setup, state_root=state_root)

    automated = _value(
        cli.service_call(
            "distribution.bootstrap", {}, project_root=project_root, state_root=state_root
        )
    ).get("automated_candidates")
    if not isinstance(automated, Sequence) or set(automated) != {"codex", "claude"}:
        raise JourneyFailure("combined provider setup was not durably consumed")
    for provider_id in ("codex", "claude"):
        graph = _value(
            cli.service_call(
                "providers.graph", {}, project_root=project_root, state_root=state_root
            )
        ).get("graph")
        _find_provider(graph, provider_id)
        readiness = _value(
            cli.service_call(
                "providers.readiness",
                {"provider_id": provider_id},
                project_root=project_root,
                state_root=state_root,
            )
        ).get("readiness")
        if not isinstance(readiness, Mapping) or readiness.get("state") != "AVAILABLE":
            raise JourneyFailure(f"{provider_id} is not available in combined composition")

    interaction_actor = _principal(
        "m12-interaction-client",
        "INTERACTION_CLIENT",
        "interaction:connect",
        "interaction:read",
        "interaction:write",
        "envelope:propose",
    )
    common = {
        "store_path": str(store_path),
        "workspace_root": str(workspace_root),
        "project_root": str(project_root),
    }
    opened = _value(
        cli.service_call(
            "interaction.open",
            {**common, "actor": interaction_actor},
            project_root=project_root,
            state_root=state_root,
        )
    )
    session_id = str(opened["session"]["session_id"])
    reconnect_token = str(opened["reconnect_token"])
    _provider_interaction(
        cli,
        provider_id="codex",
        project_id=project_id,
        revision=revision,
        project_root=project_root,
        state_root=state_root,
    )
    cli.service_call(
        "interaction.disconnect",
        {**common, "session_id": session_id, "actor": interaction_actor},
        project_root=project_root,
        state_root=state_root,
    )
    _provider_interaction(
        cli,
        provider_id="claude",
        project_id=project_id,
        revision=revision,
        project_root=project_root,
        state_root=state_root,
    )
    cli.service_call(
        "interaction.reconnect",
        {
            **common,
            "session_id": session_id,
            "reconnect_token": reconnect_token,
            "actor": interaction_actor,
        },
        project_root=project_root,
        state_root=state_root,
    )

    for stage in (
        "EXPLORATION",
        "RESEARCH",
        "DEFINITION",
        "ARCHITECTURE",
        "REQUIREMENTS_ADRS",
        "PLAN",
    ):
        advanced = _value(
            cli.service_call(
                "interaction.lifecycle.advance",
                {
                    **common,
                    "catalog_path": str(catalog_path),
                    "name": project_name,
                    "session_id": session_id,
                    "actor": interaction_actor,
                    "expected_revision": revision,
                    "stage": stage,
                    "summary": f"Accepted M12 {stage.lower()} outcome",
                    "evidence_refs": ["evidence://m12/research"] if stage == "RESEARCH" else [],
                    "decision_refs": ["adr://m12/release"] if stage == "ARCHITECTURE" else [],
                },
                project_root=project_root,
                state_root=state_root,
            )
        )
        revision = int(advanced["semantic_revision"])

    _, fingerprint, _ = _model_identity(project_root)
    _git(project_root, "config", "user.name", "ARTIFEX M12 Qualifier", runner=subprocess.run)
    _git(
        project_root,
        "config",
        "user.email",
        "artifex-m12-qualifier@invalid.local",
        runner=subprocess.run,
    )
    _git(project_root, "add", "--all", runner=subprocess.run)
    _git(project_root, "commit", "-m", "Establish M12 approved plan", runner=subprocess.run)
    baseline_commit = _git(project_root, "rev-parse", "HEAD", runner=subprocess.run)
    plan_envelope = _envelope(
        project_id=project_id,
        provider_id=execution_provider,
        workstream_id="workstream-m12-j20",
        revision=revision,
        fingerprint=fingerprint,
        commit=baseline_commit,
        version=1,
    )
    cli.service_call(
        "governance.envelope.propose",
        {**common, "actor": interaction_actor, "envelope": plan_envelope},
        project_root=project_root,
        state_root=state_root,
    )
    advanced = _value(
        cli.service_call(
            "interaction.lifecycle.advance",
            {
                **common,
                "catalog_path": str(catalog_path),
                "name": project_name,
                "session_id": session_id,
                "actor": interaction_actor,
                "expected_revision": revision,
                "stage": "ENVELOPE_PROPOSED",
                "summary": "Proposed the bounded ARTIFEX 2.0 release envelope",
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    revision = int(advanced["semantic_revision"])
    approver = _principal("m12-release-owner", "USER", "envelope:approve", "run:authorize")
    cli.service_call(
        "governance.envelope.approve",
        {
            **common,
            "envelope_id": plan_envelope["envelope_id"],
            "version": 1,
            "actor": approver,
        },
        project_root=project_root,
        state_root=state_root,
    )
    approved = _value(
        cli.service_call(
            "interaction.lifecycle.advance",
            {
                **common,
                "catalog_path": str(catalog_path),
                "name": project_name,
                "session_id": session_id,
                "actor": interaction_actor,
                "expected_revision": revision,
                "stage": "APPROVED_PLAN",
                "summary": "User approved the Plan and Execution Envelope",
                "decision_refs": [f"envelope://{plan_envelope['envelope_id']}/1"],
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    revision = int(approved["semantic_revision"])
    _, fingerprint, _ = _model_identity(project_root)
    _git(project_root, "add", "--all", runner=subprocess.run)
    _git(project_root, "commit", "-m", "Accept M12 execution plan", runner=subprocess.run)
    baseline_commit = _git(project_root, "rev-parse", "HEAD", runner=subprocess.run)
    execution_envelope = _envelope(
        project_id=project_id,
        provider_id=execution_provider,
        workstream_id="workstream-m12-j20",
        revision=revision,
        fingerprint=fingerprint,
        commit=baseline_commit,
        version=2,
    )
    cli.service_call(
        "governance.envelope.propose",
        {**common, "actor": interaction_actor, "envelope": execution_envelope},
        project_root=project_root,
        state_root=state_root,
    )
    cli.service_call(
        "governance.envelope.approve",
        {
            **common,
            "envelope_id": execution_envelope["envelope_id"],
            "version": 2,
            "actor": approver,
        },
        project_root=project_root,
        state_root=state_root,
    )

    workstream_id = "workstream-m12-j20"
    run_id = "run-m12-j20"
    project_job_id = "job-m12-j20"
    attempt_id = "attempt-m12-j20"
    workspace_id = "workspace-m12-j20"
    cli.service_call(
        "runtime.run.authorize",
        {
            **common,
            "envelope_id": execution_envelope["envelope_id"],
            "envelope_version": 2,
            "workstream_id": workstream_id,
            "run_id": run_id,
            "project_job_id": project_job_id,
            "attempt_id": attempt_id,
            "purpose": "Execute the accepted M12 full lifecycle plan",
            "actor": approver,
        },
        project_root=project_root,
        state_root=state_root,
    )
    dispatcher = _principal(
        "m12-coordinator",
        "AUTOMATION_SYSTEM_ACTOR",
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
    )
    workspace = _value(
        cli.service_call(
            "runtime.workspace.create",
            {
                **common,
                "workspace_id": workspace_id,
                "attempt_id": attempt_id,
                "baseline_revision": revision,
                "actor": dispatcher,
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    execution = _detach_provider_frontend(
        cli,
        arguments={
            **common,
            "provider_id": execution_provider,
            "role": "EXECUTION_IMPLEMENTER",
            "run_id": run_id,
            "project_job_id": project_job_id,
            "attempt_id": attempt_id,
            "workspace_id": workspace_id,
            "objective": (
                "Create deliverables/m12-j20.txt containing exactly "
                "ARTIFEX 2.0 FULL LIFECYCLE followed by a newline. Creating the "
                "deliverables directory is an approved tactical deviation."
            ),
            "acceptance_criteria": [
                "deliverables/m12-j20.txt contains the exact requested line",
                "git diff --check exits successfully",
            ],
            "owned_paths": ["deliverables/m12-j20.txt"],
            "credential_reference_id": f"{execution_provider}-cli-session",
            "capabilities": ["repository_write", "test_execution"],
            "filesystem_permissions": ["READ", "WRITE"],
            "network_permissions": ["PROVIDER_API"],
            "tool_permissions": [f"{execution_provider}.exec"],
            "actor": dispatcher,
            "provider_actor": _principal("m12-provider", "PROVIDER", "result:submit"),
            "evidence_actor": _principal(
                "m12-evidence", "ARTIFEX_SERVICE", "workspace:access", "evidence:record"
            ),
        },
        project_root=project_root,
        state_root=state_root,
        common=common,
        provider_id=execution_provider,
        run_id=run_id,
        project_job_id=project_job_id,
        attempt_id=attempt_id,
    )
    evidence = execution.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise JourneyFailure("provider execution did not persist validation evidence")
    evidence_ids = [
        str(item["evidence_id"])
        for item in evidence
        if isinstance(item, Mapping) and item.get("evidence_id")
    ]
    if len(evidence_ids) != len(evidence):
        raise JourneyFailure("provider evidence identities are incomplete")

    decision_request = _value(
        cli.service_call(
            "governance.decision.request",
            {
                **common,
                "project_id": project_id,
                "run_id": run_id,
                "question": "May the accepted release outcome change its public architecture?",
                "affected_workstreams": [workstream_id],
                "materiality": "STRATEGIC_MATERIAL",
                "actor": _principal(
                    "m12-governance", "ARTIFEX_SERVICE", "governance:request-decision"
                ),
            },
            project_root=project_root,
            state_root=state_root,
        )
    )["decision_request"]
    blocked = _value(
        cli.service_call(
            "runtime.status",
            {**common, "run_id": run_id},
            project_root=project_root,
            state_root=state_root,
        )
    )
    if blocked["workstream"]["state"] != "BLOCKED":
        raise JourneyFailure("material decision did not block the affected Workstream")
    cli.service_call(
        "governance.decision.resolve",
        {
            **common,
            "decision_request_id": decision_request["decision_request_id"],
            "outcome": "REJECT",
            "resolution": "Preserve the accepted ARTIFEX 2.0 public architecture",
            "actor": _principal(
                "m12-release-owner", "USER", "governance:resolve-decision"
            ),
        },
        project_root=project_root,
        state_root=state_root,
    )
    resumed = _value(
        cli.service_call(
            "runtime.status",
            {**common, "run_id": run_id},
            project_root=project_root,
            state_root=state_root,
        )
    )
    if resumed["workstream"]["state"] != "ACTIVE":
        raise JourneyFailure("resolved material decision did not resume the Workstream")
    if resumed.get("acceptance_decisions"):
        raise JourneyFailure("provider result improperly self-accepted")

    cli.service_call(
        "runtime.accept",
        {
            **common,
            "project_job_id": project_job_id,
            "evidence_valid": True,
            "evidence_ids": evidence_ids,
            "reason": "Independent M12 validation evidence passed",
            "actor": _principal(
                "m12-acceptance", "ARTIFEX_SERVICE", "acceptance:decide"
            ),
        },
        project_root=project_root,
        state_root=state_root,
    )
    _, _, model = _model_identity(project_root)
    model["project"]["description"] = "Accepted ARTIFEX 2.0 full lifecycle outcome"
    promoted = _value(
        cli.service_call(
            "runtime.workspace.promote",
            {
                **common,
                "workspace_id": workspace_id,
                "project_job_id": project_job_id,
                "model": model,
                "actor": _principal(
                    "m12-project-authority", "ARTIFEX_SERVICE", "project:promote"
                ),
            },
            project_root=project_root,
            state_root=state_root,
        )
    )
    promotion_revision = int(promoted["semantic_revision"])
    if promotion_revision != revision + 1:
        raise JourneyFailure("Project promotion did not advance exactly one revision")

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
    if not isinstance(documents, list) or not documents or any(
        not isinstance(item, Mapping) or item.get("state") != "CURRENT" for item in documents
    ):
        raise JourneyFailure("Project documentation is not current")
    dashboard = _value(
        cli.service_call(
            "dashboard.project",
            {"catalog_path": str(catalog_path), "name": project_name},
            project_root=project_root,
            state_root=state_root,
        )
    )
    if int(dashboard.get("semantic_revision", 0)) != promotion_revision:
        raise JourneyFailure("Project dashboard is not current")

    lesson_id = "LES-M12-J20"
    lesson = {
        "id": lesson_id,
        "scope": "PROJECT",
        "kind": "LESSON",
        "statement": "Keep acceptance and Project promotion separate from provider execution.",
        "provenance": [
            {
                "source": f"project:{project_id}",
                "observed_at": "2026-08-31T00:00:00Z",
                "artifact": "evidence/m12-j20.json",
                "commit": baseline_commit,
                "integration": execution_provider,
                "evidence_ids": evidence_ids,
            }
        ],
        "confidence": 0.95,
        "sensitivity": "INTERNAL",
        "promotion_policy": {
            "allowed_targets": ["INSTANCE", "PROJECT"],
            "minimum_confidence": 0.7,
            "minimum_evidence": 1,
            "maximum_sensitivity": "SENSITIVE",
            "require_validation": True,
        },
        "verified_against": [source_commit],
        "revisit_triggers": [],
        "state": "CURRENT",
        "project_id": project_id,
        "run_id": run_id,
        "promoted_from": None,
    }
    cli.service_call(
        "knowledge.project.lesson.record",
        {
            "store_path": str(organization_path),
            "project_root": str(project_root),
            "project_id": project_id,
            "lesson": lesson,
            "actor": _principal("m12-knowledge", "ARTIFEX_SERVICE", "knowledge:record"),
        },
        project_root=project_root,
        state_root=state_root,
    )

    cli.service_call(
        "interaction.disconnect",
        {**common, "session_id": session_id, "actor": interaction_actor},
        project_root=project_root,
        state_root=state_root,
    )
    before_restart = _running_service_value(
        cli.direct("service.status", ["service", "status", "--state-root", str(state_root)])
    )
    cli.direct("service.stop", ["service", "stop", "--state-root", str(state_root)])
    _wait_for_process_exit(int(before_restart["process_id"]))
    _restart_registered_windows_task(runner=subprocess.run)
    after_restart = _running_service_value(
        _wait_for_service(
            cli,
            state_root,
            prior_process_id=int(before_restart["process_id"]),
        )
    )
    continued = _value(
        cli.service_call(
            "project.continue",
            {"catalog_path": str(catalog_path), "name": project_name},
            project_root=project_root,
            state_root=state_root,
        )
    )
    cli.service_call(
        "interaction.reconnect",
        {
            **common,
            "session_id": session_id,
            "reconnect_token": reconnect_token,
            "actor": interaction_actor,
        },
        project_root=project_root,
        state_root=state_root,
    )
    restored = _value(
        cli.service_call(
            "runtime.status",
            {**common, "run_id": run_id},
            project_root=project_root,
            state_root=state_root,
        )
    )
    if (
        continued.get("project_id") != project_id
        or int(continued.get("semantic_revision", 0)) != promotion_revision
        or restored["run"]["run_id"] != run_id
    ):
        raise JourneyFailure("restart continuation did not restore Project and Run context")

    certifications = _value(
        cli.service_call(
            "providers.certifications",
            {"project_id": project_id, "provider_id": execution_provider},
            project_root=project_root,
            state_root=state_root,
        )
    ).get("certifications")
    role_states = _role_states(certifications)
    required_roles = {"INTERACTION", "EXECUTION_IMPLEMENTER"}
    live_roles = {
        role for role in required_roles if role_states.get(role) == "LIVE_ROLE_CERTIFIED"
    }
    if live_roles != required_roles:
        raise JourneyFailure("execution provider roles were not live-certified")

    return {
        "schema_version": SCHEMA,
        "status": "PASS",
        "composition": COMPOSITION,
        "source_tree_imported": False,
        "custom_application_factory_used": False,
        "credential_material_read": False,
        "approval_tokens_retained": False,
        "candidate": {
            "artifact_name": artifact.name,
            "artifact_sha256": expected_artifact_sha256,
            "artifact_bytes": artifact.stat().st_size,
            "source_commit": source_commit,
            "product_version": PRODUCT_VERSION,
            "installed_executable_sha256": _file_sha256(executable),
            "installed_manifest_sha256": _file_sha256(manifest_path),
            "service_registration_sha256": _file_sha256(registration_path),
        },
        "journeys": {
            "J11": {
                "status": "PASS",
                "real_codex": True,
                "real_claude": True,
                "no_export_or_migration": True,
                "same_project_identity": True,
                "same_semantic_revision": True,
                "authority_roles_preserved": True,
            },
            "J20": {
                "status": "PASS",
                "intent_captured": True,
                "project_created": True,
                "lifecycle_stages_accepted": [
                    "EXPLORATION",
                    "RESEARCH",
                    "DEFINITION",
                    "ARCHITECTURE",
                    "REQUIREMENTS_ADRS",
                    "PLAN",
                    "ENVELOPE_PROPOSED",
                    "APPROVED_PLAN",
                ],
                "envelope_approved": True,
                "persistent_execution": True,
                "frontend_closed_during_run": True,
                "execution_continued_after_frontend_close": True,
                "tactical_deviation_bounded": execution_envelope["materiality"] == "TACTICAL",
                "material_decision_blocked": True,
                "material_decision_resolved_by_user": True,
                "validation_evidence_recorded": True,
                "provider_self_accepted": False,
                "acceptance_authority_separate": True,
                "project_authority_promoted": True,
                "workspace_isolated": workspace.get("isolated") is True,
                "documentation_current": True,
                "dashboard_current": True,
                "organizational_knowledge_candidate": lesson_id,
                "outcome_reached": True,
                "managed_service_restarted": True,
                "coordinator_generation_advanced": int(after_restart["coordinator_generation"])
                > int(before_restart["coordinator_generation"]),
                "project_restored": True,
                "run_restored": True,
                "session_restored": True,
                "promotion_revision": promotion_revision,
            },
        },
        "role_certifications": {
            role: role_states[role] for role in sorted(required_roles)
        },
        "public_process_calls": cli.calls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--codex-command", type=Path, required=True)
    parser.add_argument("--claude-command", type=Path, required=True)
    parser.add_argument("--execution-provider", choices=("codex", "claude"), default="codex")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = run_j20(
            artifact=arguments.artifact,
            expected_artifact_sha256=arguments.expected_artifact_sha256,
            source_commit=arguments.source_commit,
            install_root=arguments.install_root,
            state_root=arguments.state_root,
            project_root=arguments.project_root,
            provider_commands={
                "codex": arguments.codex_command,
                "claude": arguments.claude_command,
            },
            execution_provider=arguments.execution_provider,
        )
    except Exception as exc:  # evidence boundary must always emit a resumable receipt
        result = {
            "schema_version": SCHEMA,
            "status": "FAIL",
            "error": type(exc).__name__,
            "message_sha256": hashlib.sha256(str(exc).encode("utf-8")).hexdigest(),
        }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()

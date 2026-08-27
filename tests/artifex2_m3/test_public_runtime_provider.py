from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from time import time
from typing import Any

from artifex.application import Application, OperationContext, OperationRequest
from artifex.capabilities import (
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    ProviderCompositionLoader,
)
from artifex.integrations.codex import CodexProcessRunner
from artifex.project import ProjectAuthority, ProjectRepository
from artifex.runtime import ActorType


def _actor(
    actor_id: str,
    actor_type: ActorType,
    *permissions: str,
    delegated: bool = False,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "actor_id": actor_id,
        "actor_type": actor_type.value,
        "authenticated": True,
        "authentication_method": "test-authentication",
        "direct_permissions": [] if delegated else list(permissions),
    }
    if delegated:
        value["delegation"] = {
            "grant_id": f"grant-{actor_id}",
            "delegator_id": "architect",
            "delegate_id": actor_id,
            "project_id": "project-public-provider",
            "allowed_actions": list(permissions),
            "issued_at": 1,
            "expires_at": int(time()) + 3600,
        }
    return value


def _provider_loader() -> ProviderCompositionLoader:
    def probe(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "codex-cli 0.150.1\n", "")
        return subprocess.CompletedProcess(arguments, 0, "Logged in\n", "")

    return ProviderCompositionLoader(
        which=lambda executable: executable,
        runner=probe,
        certified_roles={"codex": CODEX_DISPATCH_AUTHORIZED_ROLES},
    )


def _project(tmp_path: Path) -> tuple[Path, ProjectAuthority, str]:
    root = tmp_path / "project"
    repository = ProjectRepository.initialize(
        root, project_id="project-public-provider", name="Public Provider"
    )
    authority = ProjectAuthority.bootstrap(repository)
    setup = {
        "schema_version": "2.0",
        "authority": "ARTIFEX_PROJECT_STATE",
        "providers": [
            {
                "provider_id": "codex",
                "enabled": True,
                "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
                "governance_mode": "STANDALONE",
                "command": ["codex"],
                "credential_reference": {
                    "broker": "codex-native-session",
                    "reference": "default",
                    "provider_id": "codex",
                    "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
                    "secret_material_present": False,
                },
            }
        ],
    }
    (root / ".artifex" / "integrations.json").write_text(json.dumps(setup), encoding="utf-8")
    subprocess.run(("git", "-C", str(root), "config", "user.name", "ARTIFEX Test"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "artifex@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(root), "add", "."), check=True)
    subprocess.run(("git", "-C", str(root), "commit", "-m", "provider baseline"), check=True)
    head = subprocess.run(
        ("git", "-C", str(root), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return root, authority, head


def _envelope(authority: ProjectAuthority, head: str) -> dict[str, Any]:
    current = authority.current()
    return {
        "envelope_id": "envelope-public-provider",
        "version": 1,
        "project_id": "project-public-provider",
        "objective": "create one bounded deliverable",
        "baseline_revision": current.number,
        "actor_id": "architect",
        "allowed_paths": ["deliverables/result.txt"],
        "allowed_capabilities": ["repository_write", "test_execution"],
        "required_gates": ["validation", "acceptance", "project-authority"],
        "max_attempts": 1,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
        "supervision_level": "L2",
        "materiality": "TACTICAL",
        "allowed_workstreams": ["workstream-public-provider"],
        "allowed_providers": ["codex"],
        "allowed_provider_roles": ["EXECUTION_IMPLEMENTER"],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": [],
        "tool_permissions": ["pytest"],
        "data_classification": "INTERNAL",
        "credential_references": [
            {
                "reference_id": "credential/codex/public-provider",
                "provider_id": "codex",
                "role": "EXECUTION_IMPLEMENTER",
                "project_id": "project-public-provider",
                "expires_at": int(time()) + 3600,
                "revoked": False,
            }
        ],
        "resource_budget": {"max_seconds": 120},
        "deadline_at": int(time()) + 3600,
        "stop_conditions": ["MAX_ATTEMPTS", "UNKNOWN_OUTCOME"],
        "require_durable_evidence": True,
        "baseline_fingerprint": current.fingerprint,
        "baseline_commit": head,
    }


def _bootstrap_and_workspace(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    project_root, authority, head = _project(tmp_path)
    common = {
        "store_path": str(tmp_path / "runstore.sqlite3"),
        "service_id": "public-provider-runtime",
        "workspace_root": str(tmp_path / "workspaces"),
    }
    dispatch_actor = _actor(
        "coordinator",
        ActorType.AUTOMATION_SYSTEM_ACTOR,
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
        delegated=True,
    )
    bootstrap = Application().dispatch(
        OperationRequest(
            "runtime.bootstrap",
            {
                **common,
                "envelope": _envelope(authority, head),
                "workstream_id": "workstream-public-provider",
                "run_id": "run-public-provider",
                "project_job_id": "job-public-provider",
                "attempt_id": "attempt-public-provider",
                "purpose": "public provider execution",
                "actor": dispatch_actor,
                "approval_actor": _actor("architect", ActorType.USER, "envelope:approve"),
            },
        )
    )
    assert bootstrap.ok
    workspace = Application().dispatch(
        OperationRequest(
            "runtime.workspace.create",
            {
                **common,
                "workspace_id": "workspace-public-provider",
                "attempt_id": "attempt-public-provider",
                "project_root": str(project_root),
                "baseline_revision": 1,
                "actor": dispatch_actor,
            },
        )
    )
    assert workspace.ok
    return {**common, "project_root": str(project_root), "actor": dispatch_actor}, project_root


def _execution_arguments(common: dict[str, Any]) -> dict[str, Any]:
    return {
        **common,
        "provider_id": "codex",
        "role": "EXECUTION_IMPLEMENTER",
        "run_id": "run-public-provider",
        "project_job_id": "job-public-provider",
        "attempt_id": "attempt-public-provider",
        "workspace_id": "workspace-public-provider",
        "objective": "create deliverables/result.txt",
        "owned_paths": ["deliverables/result.txt"],
        "credential_reference_id": "credential/codex/public-provider",
        "tool_permissions": ["pytest"],
        "provider_actor": _actor("codex-provider", ActorType.PROVIDER, "result:submit"),
        "evidence_actor": _actor(
            "validator",
            ActorType.ARTIFEX_SERVICE,
            "workspace:access",
            "evidence:record",
        ),
    }


def test_public_provider_execution_is_bound_evidenced_and_not_accepted(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("ARTIFEX_LOCAL_STATE_ROOT", str(tmp_path / "local-state"))
    common, project_root = _bootstrap_and_workspace(tmp_path)
    observed_commands: list[list[str]] = []

    def process_runner(arguments: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        observed_commands.append(arguments)
        prompt = arguments[-1]
        assert '"acceptance_criteria":["gate:validation"]' in prompt
        assert "gate:acceptance" not in prompt
        assert "gate:project-authority" not in prompt
        root = Path(options["cwd"])
        artifact = root / "deliverables" / "result.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("bounded provider result\n", encoding="utf-8")
        output = Path(arguments[arguments.index("--output-last-message") + 1])
        schema = Path(arguments[arguments.index("--output-schema") + 1])
        assert schema.is_file()
        packet_fingerprint = json.loads(schema.read_text(encoding="utf-8"))["properties"][
            "execution_contract_fingerprint"
        ]["const"]
        model_fingerprint = json.loads(schema.read_text(encoding="utf-8"))["properties"][
            "project_model_fingerprint"
        ]["const"]
        base_commit = json.loads(schema.read_text(encoding="utf-8"))["properties"]["base_commit"][
            "const"
        ]
        output.write_text(
            json.dumps(
                {
                    "status": "SUCCESS",
                    "base_commit": base_commit,
                    "execution_contract_fingerprint": packet_fingerprint,
                    "project_model_fingerprint": model_fingerprint,
                    "artifacts": [{"path": "deliverables/result.txt"}],
                    "validation": {"tests": "PASS"},
                    "message": "completed",
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(arguments, 0, '{"type":"turn.completed"}\n', "")

    application = Application(
        provider_loader=_provider_loader(),
        codex_runner_factory=lambda command: CodexProcessRunner(
            command=command, process_runner=process_runner
        ),
    )
    result = application.dispatch(
        OperationRequest(
            "runtime.provider.execute",
            _execution_arguments(common),
            OperationContext(correlation_id="correlation-public-provider"),
        )
    )
    assert result.ok, result.to_dict()
    execution = result.value["execution"]
    assert execution["status"] == "SUCCESS"
    assert execution["accepted"] is False
    assert execution["promoted"] is False
    assert execution["evidence"][0]["gate"] == "validation"
    assert execution["owned_artifacts"][0]["path"] == "deliverables/result.txt"
    assert observed_commands[0][0] == "codex"
    assert observed_commands[0][observed_commands[0].index("-C") + 1] == str(
        (tmp_path / "workspaces" / "workspace-public-provider").resolve()
    )

    status = Application().dispatch(
        OperationRequest(
            "runtime.status",
            {**common, "run_id": "run-public-provider"},
        )
    )
    assert status.value["attempts"][0]["state"] == "FINISHED"
    assert status.value["project_jobs"][0]["state"] == "FINISHED"
    assert status.value["acceptance_decisions"] == []
    assert len(status.value["dispatch_authorizations"]) == 1
    assert len(status.value["evidence_records"]) == 1

    evidence_id = execution["evidence"][0]["evidence_id"]
    missing_acceptor = Application().dispatch(
        OperationRequest(
            "runtime.accept",
            {
                **common,
                "project_job_id": "job-public-provider",
                "evidence_valid": True,
                "evidence_ids": [evidence_id],
                "reason": "bound validation passed",
            },
        )
    )
    assert missing_acceptor.ok is False
    accepted = Application().dispatch(
        OperationRequest(
            "runtime.accept",
            {
                **common,
                "project_job_id": "job-public-provider",
                "evidence_valid": True,
                "evidence_ids": [evidence_id],
                "reason": "bound validation passed",
                "actor": _actor(
                    "acceptance-authority",
                    ActorType.ARTIFEX_SERVICE,
                    "acceptance:decide",
                ),
            },
        )
    )
    assert accepted.ok, accepted.to_dict()
    model = json.loads((project_root / ".artifex" / "project-model.json").read_text())
    model["project"]["description"] = "accepted provider execution"
    promoted = Application().dispatch(
        OperationRequest(
            "runtime.workspace.promote",
            {
                **common,
                "workspace_id": "workspace-public-provider",
                "project_job_id": "job-public-provider",
                "model": model,
                "actor": _actor(
                    "project-authority",
                    ActorType.ARTIFEX_SERVICE,
                    "project:promote",
                ),
            },
        )
    )
    assert promoted.ok, promoted.to_dict()
    assert promoted.value["semantic_revision"] == 2
    receipt = promoted.value["provider_certification_receipt"]
    assert receipt["role"] == "EXECUTION_IMPLEMENTER"
    assert receipt["acceptance_decision_id"] == accepted.value["decision"]["decision_id"]
    certifications = Application().dispatch(
        OperationRequest(
            "providers.certifications",
            {"project_id": "project-public-provider"},
        )
    )
    assert certifications.ok
    roles = certifications.value["certifications"]["roles"]
    execution_role = next(item for item in roles if item["role"] == "EXECUTION_IMPLEMENTER")
    assert execution_role["state"] == "LIVE_ROLE_CERTIFIED"


def test_public_provider_timeout_is_durably_unknown(tmp_path: Path) -> None:
    common, _ = _bootstrap_and_workspace(tmp_path)

    def process_runner(arguments: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        del options
        raise subprocess.TimeoutExpired(arguments, timeout=1)

    application = Application(
        provider_loader=_provider_loader(),
        codex_runner_factory=lambda command: CodexProcessRunner(
            command=command, process_runner=process_runner
        ),
    )
    result = application.dispatch(
        OperationRequest("runtime.provider.execute", _execution_arguments(common))
    )
    assert result.ok is False
    assert result.error is not None
    assert "UNKNOWN" in result.error.message
    status = Application().dispatch(
        OperationRequest(
            "runtime.status",
            {**common, "run_id": "run-public-provider"},
        )
    )
    assert status.value["attempts"][0]["state"] == "UNKNOWN"
    assert status.value["project_jobs"][0]["state"] == "UNKNOWN"
    assert status.value["run"]["state"] == "WAITING_RECONCILIATION"


def test_automated_public_paths_reject_legacy_actor_strings(tmp_path: Path) -> None:
    project_root, authority, head = _project(tmp_path)
    result = Application().dispatch(
        OperationRequest(
            "runtime.bootstrap",
            {
                "store_path": str(tmp_path / "runstore.sqlite3"),
                "envelope": _envelope(authority, head),
                "workstream_id": "workstream-public-provider",
                "run_id": "run-public-provider",
                "project_job_id": "job-public-provider",
                "attempt_id": "attempt-public-provider",
                "purpose": "must not use legacy identity",
                "project_root": str(project_root),
            },
            OperationContext(actor="legacy-operator"),
        )
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.details["type"] in {"TypeError", "ValueError"}

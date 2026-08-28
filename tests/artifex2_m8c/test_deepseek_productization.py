from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from time import time
from typing import Any

import pytest

from artifex.application import Application, OperationRequest
from artifex.capabilities import (
    DEEPSEEK_DISPATCH_AUTHORIZED_ROLES,
    DEEPSEEK_PRODUCTIZED_ROLES,
    CapabilityEvidenceStore,
    ProviderCompositionLoader,
    ProviderRole,
    ReadinessState,
    deepseek_certification_projection,
    record_execution_implementer_evidence,
)
from artifex.distribution import apply_integration_setup, plan_integration_setup
from artifex.distribution.approvals import ApprovalStore
from artifex.project import ProjectAuthority, ProjectRepository
from artifex.runtime import ActorType


def _completed(
    arguments: Sequence[str], *, returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(arguments), returncode, stdout, "")


def _deepseek_spec() -> dict[str, object]:
    return {
        "provider_id": "deepseek",
        "command": ["deepseek"],
        "roles": ["EXECUTION_IMPLEMENTER"],
        "governance_mode": "PROVIDER_MANAGED",
        "credential_reference": {
            "broker": "deepseek-native-session",
            "reference": "default",
            "provider_id": "deepseek",
            "scopes": ["EXECUTION_IMPLEMENTER"],
        },
    }


def _persist_setup(root: Path) -> None:
    approvals = ApprovalStore(root / "approval-store")
    plan = plan_integration_setup(
        root,
        ("deepseek",),
        provider_specs=(_deepseek_spec(),),
        approval_store=approvals,
    )
    apply_integration_setup(
        plan,
        confirmation_token=plan.decision.confirmation_token,
        approval_store=approvals,
    )


def _loader(
    *,
    authenticated: bool = True,
    version: str = "1.4.0",
    executable: str = "C:/fixture/deepseek.exe",
    authorize_candidate: bool = True,
    auth_stdout: str | None = None,
) -> ProviderCompositionLoader:
    def probe(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        suffix = tuple(arguments[-2:])
        if arguments[-1] == "--version":
            return _completed(arguments, stdout=f"DeepSeek {version}\n")
        if suffix == ("run", "--help"):
            return _completed(
                arguments,
                stdout="run --headless --format json; repository write; test command\n",
            )
        assert suffix == ("auth", "status")
        return _completed(
            arguments,
            returncode=0 if authenticated else 1,
            stdout=(
                auth_stdout
                if auth_stdout is not None
                else json.dumps({"authenticated": authenticated})
            ),
        )

    return ProviderCompositionLoader(
        which=lambda requested: executable if requested == "deepseek" else None,
        runner=probe,
        certified_roles={
            "deepseek": DEEPSEEK_PRODUCTIZED_ROLES if authorize_candidate else frozenset()
        },
    )


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
        "authentication_method": "m8c-test-authentication",
        "direct_permissions": [] if delegated else list(permissions),
    }
    if delegated:
        value["delegation"] = {
            "grant_id": f"grant-{actor_id}",
            "delegator_id": "architect",
            "delegate_id": actor_id,
            "project_id": "m8c-project",
            "allowed_actions": list(permissions),
            "issued_at": 1,
            "expires_at": int(time()) + 3600,
        }
    return value


def _project(tmp_path: Path) -> tuple[Path, ProjectAuthority, str]:
    root = tmp_path / "project"
    repository = ProjectRepository.initialize(root, project_id="m8c-project", name="M8C")
    authority = ProjectAuthority.bootstrap(repository)
    _persist_setup(root)
    subprocess.run(("git", "-C", str(root), "config", "user.name", "ARTIFEX Test"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "artifex@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(root), "add", "."), check=True)
    subprocess.run(("git", "-C", str(root), "commit", "-m", "M8C baseline"), check=True)
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
        "envelope_id": "m8c-envelope",
        "version": 1,
        "project_id": "m8c-project",
        "objective": "create one bounded DeepSeek deliverable",
        "baseline_revision": current.number,
        "actor_id": "architect",
        "allowed_paths": ["deliverables/deepseek.txt"],
        "allowed_capabilities": ["repository_write", "test_execution"],
        "required_gates": ["validation", "acceptance", "project-authority"],
        "max_attempts": 2,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
        "supervision_level": "L2",
        "materiality": "TACTICAL",
        "allowed_workstreams": ["m8c-workstream"],
        "allowed_providers": ["deepseek"],
        "allowed_provider_roles": ["EXECUTION_IMPLEMENTER"],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": ["PROVIDER_API"],
        "tool_permissions": ["pytest"],
        "data_classification": "INTERNAL",
        "credential_references": [
            {
                "reference_id": "credential/deepseek/m8c",
                "provider_id": "deepseek",
                "role": "EXECUTION_IMPLEMENTER",
                "project_id": "m8c-project",
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


def _bootstrap(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    root, authority, head = _project(tmp_path)
    common = {
        "store_path": str(tmp_path / "runstore.sqlite3"),
        "service_id": "m8c-runtime",
        "workspace_root": str(tmp_path / "workspaces"),
    }
    coordinator = _actor(
        "coordinator",
        ActorType.AUTOMATION_SYSTEM_ACTOR,
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
        delegated=True,
    )
    result = Application().dispatch(
        OperationRequest(
            "runtime.bootstrap",
            {
                **common,
                "envelope": _envelope(authority, head),
                "workstream_id": "m8c-workstream",
                "run_id": "m8c-run",
                "project_job_id": "m8c-job",
                "attempt_id": "m8c-attempt",
                "purpose": "M8C public DeepSeek execution",
                "actor": coordinator,
                "approval_actor": _actor("architect", ActorType.USER, "envelope:approve"),
            },
        )
    )
    assert result.ok, result.to_dict()
    workspace = Application().dispatch(
        OperationRequest(
            "runtime.workspace.create",
            {
                **common,
                "workspace_id": "m8c-workspace",
                "attempt_id": "m8c-attempt",
                "project_root": str(root),
                "baseline_revision": 1,
                "actor": coordinator,
            },
        )
    )
    assert workspace.ok, workspace.to_dict()
    return {**common, "project_root": str(root), "actor": coordinator}, root


def _execute_arguments(common: dict[str, Any]) -> dict[str, Any]:
    return {
        **common,
        "provider_id": "deepseek",
        "role": "EXECUTION_IMPLEMENTER",
        "run_id": "m8c-run",
        "project_job_id": "m8c-job",
        "attempt_id": "m8c-attempt",
        "workspace_id": "m8c-workspace",
        "objective": "create deliverables/deepseek.txt",
        "owned_paths": ["deliverables/deepseek.txt"],
        "credential_reference_id": "credential/deepseek/m8c",
        "provider_actor": _actor("deepseek-provider", ActorType.PROVIDER, "result:submit"),
        "evidence_actor": _actor(
            "validator", ActorType.ARTIFEX_SERVICE, "workspace:access", "evidence:record"
        ),
    }


def _successful_runner(
    arguments: Sequence[str], **options: Any
) -> subprocess.CompletedProcess[str]:
    workspace = Path(options["cwd"])
    artifact = workspace / "deliverables" / "deepseek.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("bounded DeepSeek result\n", encoding="utf-8")
    packet = json.loads(options["input"])
    result = {
        "status": "SUCCESS",
        "base_commit": packet["base_commit"],
        "execution_contract_fingerprint": packet["execution_contract_fingerprint"],
        "project_model_fingerprint": packet["project_model_fingerprint"],
        "artifacts": [{"path": "deliverables/deepseek.txt"}],
        "validation": {"tests": "PASS"},
        "message": "completed",
    }
    return _completed(arguments, stdout=json.dumps(result))


def test_setup_readiness_migration_and_claims_are_fail_closed(tmp_path: Path) -> None:
    default = plan_integration_setup(tmp_path / "default", ("deepseek",))
    configuration = default.actions[0].provider_configuration
    assert configuration["roles"] == ["EXECUTION_IMPLEMENTER"]
    assert configuration["governance_mode"] == "PROVIDER_MANAGED"
    assert configuration["credential_reference"]["secret_material_present"] is False

    _persist_setup(tmp_path)
    ready = _loader().load(tmp_path).provider("deepseek")
    assert ready is not None
    assert ready.readiness.state is ReadinessState.AVAILABLE
    assert ready.certified_roles == DEEPSEEK_PRODUCTIZED_ROLES
    assert frozenset() == DEEPSEEK_DISPATCH_AUTHORIZED_ROLES

    unauthenticated = _loader(authenticated=False).load(tmp_path).provider("deepseek")
    assert unauthenticated is not None
    assert unauthenticated.readiness.state is ReadinessState.CONFIGURED
    assert unauthenticated.globally_available is False

    ambiguous_auth = _loader(auth_stdout="authenticated\n").load(tmp_path).provider(
        "deepseek"
    )
    assert ambiguous_auth is not None
    assert ambiguous_auth.readiness.state is ReadinessState.CONFIGURED
    assert ambiguous_auth.readiness.checks["authenticated"] is False

    explicit_denial = _loader(auth_stdout='{"authenticated": false}').load(
        tmp_path
    ).provider("deepseek")
    assert explicit_denial is not None
    assert explicit_denial.readiness.state is ReadinessState.CONFIGURED
    assert explicit_denial.readiness.checks["authenticated"] is False

    blocked_candidate = _loader(authorize_candidate=False).load(tmp_path).provider(
        "deepseek"
    )
    assert blocked_candidate is not None
    assert blocked_candidate.readiness.state is ReadinessState.AVAILABLE
    assert blocked_candidate.certified_roles == frozenset()
    resolution = Application(
        provider_loader=_loader(authorize_candidate=False)
    ).dispatch(
        OperationRequest(
            "providers.resolve",
            {
                "project_root": str(tmp_path),
                "project_id": "m8c-project",
                "project_job_id": "m8c-job",
                "provider_id": "deepseek",
                "role": "EXECUTION_IMPLEMENTER",
                "capabilities": ["repository_write"],
                "data_classification": "INTERNAL",
                "envelope": {
                    "allowed_providers": ["deepseek"],
                    "allowed_capabilities": ["repository_write"],
                },
                "actor": {
                    "actor_id": "candidate-auditor",
                    "actor_type": "AUTOMATION_SYSTEM_ACTOR",
                    "delegated_roles": ["EXECUTION_IMPLEMENTER"],
                },
            },
        )
    )
    assert resolution.ok, resolution.to_dict()
    decision = resolution.value["decision"]
    assert decision["eligible"] is False
    assert "ROLE_NOT_CERTIFIED" in decision["evaluated"][0]["reasons"]

    incompatible = _loader(version="2.0.0").load(tmp_path).provider("deepseek")
    assert incompatible is not None
    assert incompatible.readiness.state is ReadinessState.CONFIGURED
    assert incompatible.readiness.checks["stable_headless_boundary"] is False

    legacy = tmp_path / "legacy"
    (legacy / ".artifex").mkdir(parents=True)
    (legacy / ".artifex" / "integrations.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "authority": "ARTIFEX_PROJECT_STATE",
                "enabled": ["deepseek"],
            }
        ),
        encoding="utf-8",
    )
    migrated = _loader().load(legacy).provider("deepseek")
    assert migrated is not None
    assert migrated.readiness.state is ReadinessState.AVAILABLE
    assert migrated.configuration.credential_reference is not None
    assert migrated.configuration.credential_reference.broker == "deepseek-native-session"

    projection = deepseek_certification_projection()
    assert [item["role"] for item in projection["roles"]] == ["EXECUTION_IMPLEMENTER"]
    assert projection["roles"][0]["state"] == "PUBLIC_COMPOSITION_VERIFIED"
    assert {item["role"] for item in projection["omitted_roles"]} == {
        "INTERACTION",
        "HARNESS",
    }


def test_execution_isolated_separately_accepted_and_role_certified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARTIFEX_LOCAL_STATE_ROOT", str(tmp_path / "local-state"))
    monkeypatch.setenv("ARTIFEX_SHIPPING_ARTIFACT_SHA256", "b" * 64)
    common, project_root = _bootstrap(tmp_path)
    executable = tmp_path / "deepseek.exe"
    executable.write_bytes(b"fixture DeepSeek executable")
    app = Application(
        provider_loader=_loader(executable=str(executable)),
        deepseek_runner=_successful_runner,
    )
    executed = app.dispatch(
        OperationRequest("runtime.provider.execute", _execute_arguments(common))
    )
    assert executed.ok, executed.to_dict()
    execution = executed.value["execution"]
    assert execution["provider_id"] == "deepseek"
    assert execution["status"] == "SUCCESS"
    assert execution["accepted"] is execution["promoted"] is False
    assert not (project_root / "deliverables" / "deepseek.txt").exists()

    evidence_id = execution["evidence"][0]["evidence_id"]
    accepted = Application().dispatch(
        OperationRequest(
            "runtime.accept",
            {
                **common,
                "project_job_id": "m8c-job",
                "evidence_valid": True,
                "evidence_ids": [evidence_id],
                "reason": "independent validation passed",
                "actor": _actor(
                    "acceptance-authority", ActorType.ARTIFEX_SERVICE, "acceptance:decide"
                ),
            },
        )
    )
    assert accepted.ok, accepted.to_dict()
    model = json.loads((project_root / ".artifex" / "project-model.json").read_text())
    model["project"]["description"] = "accepted DeepSeek result"
    promoted = app.dispatch(
        OperationRequest(
            "runtime.workspace.promote",
            {
                **common,
                "workspace_id": "m8c-workspace",
                "project_job_id": "m8c-job",
                "model": model,
                "actor": _actor(
                    "project-authority", ActorType.ARTIFEX_SERVICE, "project:promote"
                ),
            },
        )
    )
    assert promoted.ok, promoted.to_dict()
    receipt = promoted.value["provider_certification_receipt"]
    assert receipt["provider_id"] == "deepseek"
    assert receipt["role"] == "EXECUTION_IMPLEMENTER"
    assert receipt["provider_version"] == "1.4.0"
    assert receipt["provider_executable_sha256"]
    assert receipt["auth_probe_sha256"]
    assert receipt["shipping_artifact_sha256"] == "b" * 64
    assert receipt["live_role_eligible"] is True
    stored = CapabilityEvidenceStore(
        tmp_path / "local-state" / "capability-evidence.sqlite3"
    ).valid_receipts(provider_id="deepseek", project_id="m8c-project")
    assert len(stored) == 1
    assert stored[0].role is ProviderRole.EXECUTION_IMPLEMENTER
    assert stored[0].live_role_eligible is True

    certifications = app.dispatch(
        OperationRequest(
            "providers.certifications",
            {"provider_id": "deepseek", "project_id": "m8c-project"},
        )
    )
    assert certifications.ok, certifications.to_dict()
    assert certifications.value["certifications"]["roles"][0]["state"] == (
        "LIVE_ROLE_CERTIFIED"
    )


def test_unbound_promoted_style_receipt_never_grants_live_certification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARTIFEX_LOCAL_STATE_ROOT", str(tmp_path / "local-state"))
    store = CapabilityEvidenceStore(
        tmp_path / "local-state" / "capability-evidence.sqlite3"
    )
    legacy = record_execution_implementer_evidence(
        project_id="m8c-project",
        project_job_id="m8c-job",
        accepted_result_sha256="a" * 64,
        promoted_baseline_sha256="b" * 64,
        acceptance_decision_id="acceptance-m8c",
        promotion_revision=2,
        provider_id="deepseek",
        store=store,
    )
    assert legacy.live_role_eligible is False

    certifications = Application().dispatch(
        OperationRequest(
            "providers.certifications",
            {"provider_id": "deepseek", "project_id": "m8c-project"},
        )
    )
    assert certifications.ok, certifications.to_dict()
    role = certifications.value["certifications"]["roles"][0]
    assert role["state"] == "PUBLIC_COMPOSITION_VERIFIED"
    assert role["steps"]["LIVE_ROLE_CERTIFIED"] == "IN_PROGRESS"
    assert role["evidence"] == []


def test_unowned_workspace_mutation_is_unknown_and_never_accepts(tmp_path: Path) -> None:
    common, project_root = _bootstrap(tmp_path)
    canonical_before = (project_root / ".artifex" / "project-model.json").read_bytes()

    def mutate_authority(
        arguments: Sequence[str], **options: Any
    ) -> subprocess.CompletedProcess[str]:
        workspace = Path(options["cwd"])
        model_path = workspace / ".artifex" / "project-model.json"
        model_path.write_text("{}\n", encoding="utf-8")
        return _successful_runner(arguments, **options)

    result = Application(
        provider_loader=_loader(),
        deepseek_runner=mutate_authority,
    ).dispatch(OperationRequest("runtime.provider.execute", _execute_arguments(common)))
    assert result.ok is False
    assert result.error is not None
    assert "outside its Execution Envelope ownership" in result.error.message
    assert (project_root / ".artifex" / "project-model.json").read_bytes() == canonical_before
    status = Application().dispatch(
        OperationRequest("runtime.status", {**common, "run_id": "m8c-run"})
    )
    assert status.value["attempts"][0]["state"] == "UNKNOWN"
    assert status.value["acceptance_decisions"] == []

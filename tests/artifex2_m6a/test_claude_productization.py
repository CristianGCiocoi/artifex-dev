from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from time import sleep, time
from typing import Any

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.capabilities import (
    CLAUDE_DISPATCH_AUTHORIZED_ROLES,
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    CapabilityEvidenceStore,
    ProviderCompositionLoader,
    ProviderInteractionService,
    ProviderRole,
    ReadinessState,
    claude_certification_projection,
)
from artifex.distribution import apply_integration_setup, plan_integration_setup
from artifex.distribution.approvals import ApprovalStore
from artifex.integrations.claude import ClaudeProcessRunner
from artifex.project import ProjectAuthority, ProjectRepository
from artifex.runtime import ActorType, ManagedRuntimeService


def _completed(
    arguments: Sequence[str], *, returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(arguments), returncode, stdout, "")


def _claude_spec() -> dict[str, object]:
    return {
        "provider_id": "claude",
        "command": ["claude"],
        "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "governance_mode": "STANDALONE",
        "credential_reference": {
            "broker": "claude-native-session",
            "reference": "default",
            "provider_id": "claude",
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        },
    }


def _persist_claude_setup(root: Path) -> None:
    approvals = ApprovalStore(root / "approval-store")
    plan = plan_integration_setup(
        root,
        ("claude",),
        provider_specs=(_claude_spec(),),
        approval_store=approvals,
    )
    apply_integration_setup(
        plan,
        confirmation_token=plan.decision.confirmation_token,
        approval_store=approvals,
    )


def _claude_loader(
    *, authenticated: bool = True, executable: str = "C:/fixture/claude.exe"
) -> ProviderCompositionLoader:
    def probe(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if arguments[-1] == "--version":
            return _completed(arguments, stdout="Claude Code 2.1.3\n")
        assert tuple(arguments[-2:]) == ("auth", "status")
        return _completed(
            arguments,
            returncode=0 if authenticated else 1,
            stdout=json.dumps({"loggedIn": authenticated}),
        )

    return ProviderCompositionLoader(
        which=lambda requested: executable if requested == "claude" else None,
        runner=probe,
        certified_roles={"claude": CLAUDE_DISPATCH_AUTHORIZED_ROLES},
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
        "authentication_method": "m6a-test-authentication",
        "direct_permissions": [] if delegated else list(permissions),
    }
    if delegated:
        value["delegation"] = {
            "grant_id": f"grant-{actor_id}",
            "delegator_id": "architect",
            "delegate_id": actor_id,
            "project_id": "m6a-project",
            "allowed_actions": list(permissions),
            "issued_at": 1,
            "expires_at": int(time()) + 3600,
        }
    return value


def _project(tmp_path: Path, *, dual_provider: bool = False) -> tuple[Path, ProjectAuthority, str]:
    root = tmp_path / "project"
    repository = ProjectRepository.initialize(root, project_id="m6a-project", name="M6A")
    authority = ProjectAuthority.bootstrap(repository)
    _persist_claude_setup(root)
    if dual_provider:
        setup_path = root / ".artifex" / "integrations.json"
        setup = json.loads(setup_path.read_text(encoding="utf-8"))
        setup["enabled"].insert(0, "codex")
        setup["providers"].insert(
            0,
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
            },
        )
        setup_path.write_text(json.dumps(setup, sort_keys=True) + "\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(root), "config", "user.name", "ARTIFEX Test"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "artifex@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(root), "add", "."), check=True)
    subprocess.run(("git", "-C", str(root), "commit", "-m", "M6A baseline"), check=True)
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
        "envelope_id": "m6a-envelope",
        "version": 1,
        "project_id": "m6a-project",
        "objective": "create one bounded Claude deliverable",
        "baseline_revision": current.number,
        "actor_id": "architect",
        "allowed_paths": ["deliverables/claude.txt"],
        "allowed_capabilities": ["repository_write", "test_execution"],
        "required_gates": ["validation", "acceptance", "project-authority"],
        "max_attempts": 2,
        "recovery_policy": "RECONCILE_BEFORE_RETRY",
        "stop_on_unknown": True,
        "approved": True,
        "supervision_level": "L2",
        "materiality": "TACTICAL",
        "allowed_workstreams": ["m6a-workstream"],
        "allowed_providers": ["claude"],
        "allowed_provider_roles": ["EXECUTION_IMPLEMENTER"],
        "filesystem_permissions": ["READ", "WRITE"],
        "network_permissions": [],
        "tool_permissions": ["pytest"],
        "data_classification": "INTERNAL",
        "credential_references": [
            {
                "reference_id": "credential/claude/m6a",
                "provider_id": "claude",
                "role": "EXECUTION_IMPLEMENTER",
                "project_id": "m6a-project",
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
        "service_id": "m6a-runtime",
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
                "workstream_id": "m6a-workstream",
                "run_id": "m6a-run",
                "project_job_id": "m6a-job",
                "attempt_id": "m6a-attempt",
                "purpose": "M6A public Claude execution",
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
                "workspace_id": "m6a-workspace",
                "attempt_id": "m6a-attempt",
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
        "provider_id": "claude",
        "role": "EXECUTION_IMPLEMENTER",
        "run_id": "m6a-run",
        "project_job_id": "m6a-job",
        "attempt_id": "m6a-attempt",
        "workspace_id": "m6a-workspace",
        "objective": "create deliverables/claude.txt",
        "owned_paths": ["deliverables/claude.txt"],
        "credential_reference_id": "credential/claude/m6a",
        "tool_permissions": ["pytest"],
        "provider_actor": _actor("claude-provider", ActorType.PROVIDER, "result:submit"),
        "evidence_actor": _actor(
            "validator", ActorType.ARTIFEX_SERVICE, "workspace:access", "evidence:record"
        ),
    }


def test_claude_setup_discovery_auth_and_readiness_are_distinct(tmp_path: Path) -> None:
    default_plan = plan_integration_setup(tmp_path / "default-setup", ("claude",))
    default_reference = default_plan.actions[0].provider_configuration["credential_reference"]
    assert default_reference == {
        "broker": "claude-native-session",
        "reference": "default",
        "provider_id": "claude",
        "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "secret_material_present": False,
    }
    _persist_claude_setup(tmp_path)
    state = json.loads((tmp_path / ".artifex" / "integrations.json").read_text())
    assert state["providers"][0]["provider_id"] == "claude"
    assert state["providers"][0]["credential_reference"]["secret_material_present"] is False
    assert "token" not in json.dumps(state).casefold()
    assert "api_key" not in json.dumps(state).casefold()

    ready = _claude_loader().load(tmp_path).provider("claude")
    assert ready is not None
    assert ready.readiness.state is ReadinessState.AVAILABLE
    assert ready.certified_roles == CLAUDE_DISPATCH_AUTHORIZED_ROLES

    unauthenticated = _claude_loader(authenticated=False).load(tmp_path).provider("claude")
    assert unauthenticated is not None
    assert unauthenticated.readiness.state is ReadinessState.CONFIGURED
    assert unauthenticated.globally_available is False

    absent = (
        ProviderCompositionLoader(
            which=lambda _: None,
            certified_roles={"claude": CLAUDE_DISPATCH_AUTHORIZED_ROLES},
        )
        .load(tmp_path)
        .provider("claude")
    )
    assert absent is not None
    assert absent.readiness.state is ReadinessState.NOT_DETECTED

    legacy = tmp_path / "legacy"
    (legacy / ".artifex").mkdir(parents=True)
    (legacy / ".artifex" / "integrations.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "authority": "ARTIFEX_PROJECT_STATE",
                "enabled": ["claude"],
            }
        ),
        encoding="utf-8",
    )
    migrated = _claude_loader().load(legacy).provider("claude")
    assert migrated is not None
    assert migrated.readiness.state is ReadinessState.AVAILABLE
    assert migrated.configuration.credential_reference is not None
    assert migrated.configuration.credential_reference.broker == "claude-native-session"


def test_unsupported_claude_version_never_becomes_available(tmp_path: Path) -> None:
    _persist_claude_setup(tmp_path)
    auth_probed = False

    def probe(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        nonlocal auth_probed
        if arguments[-1] == "--version":
            return _completed(arguments, stdout="Claude Code 3.0.0\n")
        auth_probed = True
        return _completed(arguments, stdout=json.dumps({"loggedIn": True}))

    provider = ProviderCompositionLoader(
        which=lambda _: "C:/fixture/claude.exe",
        runner=probe,
        certified_roles={"claude": CLAUDE_DISPATCH_AUTHORIZED_ROLES},
    ).load(tmp_path).provider("claude")
    assert provider is not None
    assert provider.readiness.state is ReadinessState.CONFIGURED
    assert provider.readiness.checks["supported_version"] is False
    assert provider.globally_available is False
    assert auth_probed is False


def test_public_claude_interaction_preserves_project_identity_and_baseline(
    tmp_path: Path,
) -> None:
    root, _, _ = _project(tmp_path, dual_provider=True)
    store = CapabilityEvidenceStore(tmp_path / "local-state" / "capabilities.sqlite3")

    def probe(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if arguments[-1] == "--version":
            output = "codex-cli 0.150.1\n" if "codex" in arguments[0] else "Claude Code 2.1.3\n"
            return _completed(arguments, stdout=output)
        return _completed(
            arguments,
            stdout=(
                json.dumps({"loggedIn": True})
                if "claude" in arguments[0]
                else "authenticated\n"
            ),
        )

    loader = ProviderCompositionLoader(
        which=lambda executable: executable,
        runner=probe,
        certified_roles={
            "codex": CODEX_DISPATCH_AUTHORIZED_ROLES,
            "claude": CLAUDE_DISPATCH_AUTHORIZED_ROLES,
        },
    )

    def interaction(
        arguments: Sequence[str], observed_root: Path, stdin_prompt: str | None
    ) -> subprocess.CompletedProcess[str]:
        assert observed_root == root.resolve()
        if "codex" in arguments[0]:
            assert stdin_prompt is None
            events = (
                {"type": "thread.started", "thread_id": "m6a-thread"},
                {"type": "turn.started"},
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": "m6a-project revision 1"},
                },
                {"type": "turn.completed"},
            )
            return _completed(arguments, stdout="\n".join(map(json.dumps, events)) + "\n")
        assert arguments[arguments.index("--permission-mode") + 1] == "plan"
        interaction_schema = json.loads(arguments[arguments.index("--json-schema") + 1])
        assert interaction_schema["required"] == ["response"]
        assert interaction_schema["additionalProperties"] is False
        assert "Read the durable project identity and revision." not in arguments
        assert stdin_prompt == (
            "Return the user-visible answer only through the required JSON schema's "
            "response field. The response field value must satisfy the following "
            "user request exactly.\n"
            'USER_REQUEST_JSON="Read the durable project identity and revision."'
        )
        return _completed(
            arguments,
            stdout=json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "structured_output": {"response": "m6a-project revision 1"},
                }
            ),
        )

    app = Application(
        project_root=str(root),
        provider_loader=loader,
        provider_interaction=ProviderInteractionService(store=store, runner=interaction),
    )
    codex = app.dispatch(
        OperationRequest(
            "providers.interact",
            {
                "provider_id": "codex",
                "project_id": "m6a-project",
                "project_root": str(root),
                "prompt": "Read the durable project identity and revision.",
            },
            OperationContext(actor="client-codex"),
        )
    )
    assert codex.ok, codex.to_dict()
    result = app.dispatch(
        OperationRequest(
            "providers.interact",
            {
                "provider_id": "claude",
                "project_id": "m6a-project",
                "project_root": str(root),
                "prompt": "Read the durable project identity and revision.",
            },
            OperationContext(actor="client-claude"),
        )
    )
    assert result.ok, result.to_dict()
    interaction_value = result.value["interaction"]
    assert interaction_value["provider_id"] == "claude"
    assert interaction_value["response"] == "m6a-project revision 1"
    assert interaction_value["canonical_acceptance"] is False
    assert interaction_value["baseline"] == codex.value["interaction"]["baseline"]
    assert len(store.valid_receipts(provider_id="claude", project_id="m6a-project")) == 1
    assert len(store.valid_receipts(provider_id="codex", project_id="m6a-project")) == 1
    assert (
        subprocess.run(
            ("git", "-C", str(root), "status", "--porcelain"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )


def test_hosted_claude_interaction_renews_coordinator_during_long_provider_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _ = _project(tmp_path)
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"fixture claude executable")
    monkeypatch.setenv("ARTIFEX_SHIPPING_ARTIFACT_SHA256", "b" * 64)
    runtime = ManagedRuntimeService(
        tmp_path / "runtime" / "runstore.sqlite3",
        lease_seconds=3,
    )

    def delayed_interaction(
        arguments: Sequence[str], observed_root: Path, stdin_prompt: str | None
    ) -> subprocess.CompletedProcess[str]:
        assert observed_root == root.resolve()
        assert stdin_prompt == (
            "Return the user-visible answer only through the required JSON schema's "
            "response field. The response field value must satisfy the following "
            "user request exactly.\n"
            'USER_REQUEST_JSON="Return the bounded response."'
        )
        sleep(3.5)
        return _completed(
            arguments,
            stdout=json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "structured_output": {"response": "bounded response"},
                }
            ),
        )

    application = Application(
        project_root=str(root),
        provider_loader=_claude_loader(executable=str(executable)),
        provider_interaction=ProviderInteractionService(
            store=CapabilityEvidenceStore(tmp_path / "capability-evidence.sqlite3"),
            runner=delayed_interaction,
        ),
        runtime_service=runtime,
    )
    prior_expiry = runtime.coordinator.token.expires_at
    result = application.dispatch(
        OperationRequest(
            "providers.interact",
            {
                "provider_id": "claude",
                "project_id": "m6a-project",
                "project_root": str(root),
                "prompt": "Return the bounded response.",
            },
            OperationContext(actor="m7-qualifier"),
        )
    )

    assert result.ok, result.to_dict()
    assert result.value["interaction"]["response"] == "bounded response"
    assert runtime.coordinator.token.expires_at > prior_expiry
    runtime.coordinator.renew()


def test_public_claude_execution_uses_isolated_workspace_and_separate_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ARTIFEX_LOCAL_STATE_ROOT", str(tmp_path / "local-state"))
    monkeypatch.setenv("ARTIFEX_SHIPPING_ARTIFACT_SHA256", "b" * 64)
    common, project_root = _bootstrap(tmp_path)
    observed: dict[str, Any] = {}

    def process(arguments: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        workspace = Path(options["cwd"])
        observed.update({"arguments": arguments, "cwd": workspace, "prompt": options["input"]})
        assert arguments[arguments.index("--tools") + 1] == "Write,Edit"
        assert "Bash" not in arguments[arguments.index("--tools") + 1]
        assert workspace != project_root
        artifact = workspace / "deliverables" / "claude.txt"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("bounded Claude result\n", encoding="utf-8")
        schema = json.loads(arguments[arguments.index("--json-schema") + 1])
        assert "$schema" not in schema
        result = {
            "status": "SUCCESS",
            "base_commit": schema["properties"]["base_commit"]["const"],
            "execution_contract_fingerprint": schema["properties"][
                "execution_contract_fingerprint"
            ]["const"],
            "project_model_fingerprint": schema["properties"]["project_model_fingerprint"]["const"],
            "artifacts": [{"path": "deliverables/claude.txt"}],
            "validation": {"tests": "PASS"},
            "message": "completed",
        }
        return _completed(
            arguments,
            stdout=json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "structured_output": result,
                }
            ),
        )

    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"fixture claude executable")
    app = Application(
        provider_loader=_claude_loader(executable=str(executable)),
        claude_runner_factory=lambda command: ClaudeProcessRunner(
            command=command, process_runner=process
        ),
    )
    executed = app.dispatch(
        OperationRequest("runtime.provider.execute", _execute_arguments(common))
    )
    assert executed.ok, executed.to_dict()
    execution = executed.value["execution"]
    assert execution["provider_id"] == "claude"
    assert execution["status"] == "SUCCESS"
    assert execution["accepted"] is execution["promoted"] is False
    assert observed["cwd"] == (tmp_path / "workspaces" / "m6a-workspace").resolve()
    assert "ARTIFEX_EXECUTION_PACKET" not in observed["prompt"]
    assert '"execution_envelope_id": "m6a-envelope"' in observed["prompt"]

    evidence_id = execution["evidence"][0]["evidence_id"]
    accepted = Application().dispatch(
        OperationRequest(
            "runtime.accept",
            {
                **common,
                "project_job_id": "m6a-job",
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
    model["project"]["description"] = "accepted Claude result"
    promoted = app.dispatch(
        OperationRequest(
            "runtime.workspace.promote",
            {
                **common,
                "workspace_id": "m6a-workspace",
                "project_job_id": "m6a-job",
                "model": model,
                "actor": _actor("project-authority", ActorType.ARTIFEX_SERVICE, "project:promote"),
            },
        )
    )
    assert promoted.ok, promoted.to_dict()
    assert promoted.value["provider_certification_receipt"]["provider_id"] == "claude"
    certifications = app.dispatch(
        OperationRequest(
            "providers.certifications",
            {"provider_id": "claude", "project_id": "m6a-project"},
        )
    )
    states = {
        item["role"]: item["state"] for item in certifications.value["certifications"]["roles"]
    }
    assert states == {
        "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
        "INTERACTION": "PUBLIC_COMPOSITION_VERIFIED",
    }


def test_claude_timeout_is_unknown_then_reconciled_before_retry(tmp_path: Path) -> None:
    common, _ = _bootstrap(tmp_path)

    def timeout(arguments: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(arguments, timeout=1)

    app = Application(
        provider_loader=_claude_loader(),
        claude_runner_factory=lambda command: ClaudeProcessRunner(
            command=command, process_runner=timeout
        ),
    )
    failed = app.dispatch(OperationRequest("runtime.provider.execute", _execute_arguments(common)))
    assert failed.ok is False
    assert failed.error is not None and "UNKNOWN" in failed.error.message
    status = Application().dispatch(
        OperationRequest("runtime.status", {**common, "run_id": "m6a-run"})
    )
    assert status.value["attempts"][0]["state"] == "UNKNOWN"

    reconciled = Application().dispatch(
        OperationRequest(
            "runtime.attempt.reconcile",
            {
                **common,
                "attempt_id": "m6a-attempt",
                "outcome": "SAFE_TO_RETRY",
            },
            OperationContext(actor="reconciler"),
        )
    )
    assert reconciled.ok, reconciled.to_dict()
    retried = Application().dispatch(
        OperationRequest(
            "runtime.attempt.retry",
            {
                **common,
                "previous_attempt_id": "m6a-attempt",
                "new_attempt_id": "m6a-attempt-2",
            },
            OperationContext(actor="coordinator"),
        )
    )
    assert retried.ok, retried.to_dict()


def test_claude_cancelled_result_is_durably_cancelled(tmp_path: Path) -> None:
    common, _ = _bootstrap(tmp_path)

    def cancelled(arguments: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        schema = json.loads(arguments[arguments.index("--json-schema") + 1])
        result = {
            "status": "CANCELLED",
            "base_commit": schema["properties"]["base_commit"]["const"],
            "execution_contract_fingerprint": schema["properties"][
                "execution_contract_fingerprint"
            ]["const"],
            "project_model_fingerprint": schema["properties"]["project_model_fingerprint"]["const"],
            "artifacts": [],
            "validation": {"tests": "NOT_RUN"},
            "message": "cancelled by provider",
        }
        return _completed(
            arguments,
            stdout=json.dumps({"is_error": False, "structured_output": result}),
        )

    app = Application(
        provider_loader=_claude_loader(),
        claude_runner_factory=lambda command: ClaudeProcessRunner(
            command=command, process_runner=cancelled
        ),
    )
    result = app.dispatch(OperationRequest("runtime.provider.execute", _execute_arguments(common)))
    assert result.ok, result.to_dict()
    assert result.value["execution"]["status"] == "CANCELLED"
    status = Application().dispatch(
        OperationRequest("runtime.status", {**common, "run_id": "m6a-run"})
    )
    assert status.value["attempts"][0]["state"] == "CANCELLED"
    assert status.value["project_jobs"][0]["state"] == "CANCELLED"
    assert status.value["acceptance_decisions"] == []


def test_claude_cannot_mutate_project_authority_from_execution_workspace(
    tmp_path: Path,
) -> None:
    common, project_root = _bootstrap(tmp_path)
    canonical_before = (project_root / ".artifex" / "project-model.json").read_bytes()

    def authority_mutation(
        arguments: list[str], **options: Any
    ) -> subprocess.CompletedProcess[str]:
        workspace = Path(options["cwd"])
        model_path = workspace / ".artifex" / "project-model.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["project"]["description"] = "provider self-accepted"
        model_path.write_text(json.dumps(model), encoding="utf-8")
        schema = json.loads(arguments[arguments.index("--json-schema") + 1])
        result = {
            "status": "SUCCESS",
            "base_commit": schema["properties"]["base_commit"]["const"],
            "execution_contract_fingerprint": schema["properties"][
                "execution_contract_fingerprint"
            ]["const"],
            "project_model_fingerprint": schema["properties"]["project_model_fingerprint"]["const"],
            "artifacts": [{"path": "deliverables/claude.txt"}],
            "validation": {"tests": "PASS"},
            "message": "attempted authority mutation",
        }
        return _completed(
            arguments,
            stdout=json.dumps({"is_error": False, "structured_output": result}),
        )

    app = Application(
        provider_loader=_claude_loader(),
        claude_runner_factory=lambda command: ClaudeProcessRunner(
            command=command, process_runner=authority_mutation
        ),
    )
    result = app.dispatch(OperationRequest("runtime.provider.execute", _execute_arguments(common)))
    assert result.ok is False
    assert result.error is not None
    assert "Project Model fingerprint" in result.error.message
    assert (project_root / ".artifex" / "project-model.json").read_bytes() == canonical_before
    status = Application().dispatch(
        OperationRequest("runtime.status", {**common, "run_id": "m6a-run"})
    )
    assert status.value["attempts"][0]["state"] == "UNKNOWN"


def test_claude_certification_is_role_specific_and_not_live_without_evidence() -> None:
    projection = claude_certification_projection()
    assert {item["provider"] for item in projection["roles"]} == {"claude"}
    assert {item["state"] for item in projection["roles"]} == {"PUBLIC_COMPOSITION_VERIFIED"}
    interaction_only = claude_certification_projection(
        {ProviderRole.INTERACTION: ("capability-receipt:fixture",)}
    )
    assert {item["role"]: item["state"] for item in interaction_only["roles"]} == {
        "EXECUTION_IMPLEMENTER": "PUBLIC_COMPOSITION_VERIFIED",
        "INTERACTION": "LIVE_ROLE_CERTIFIED",
    }

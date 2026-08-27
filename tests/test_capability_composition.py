from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.capabilities import (
    ActorContext,
    CapabilityRequest,
    CapabilityResolver,
    DataClassification,
    ProviderCompositionLoader,
    ProviderRole,
    ReadinessState,
)
from artifex.distribution import apply_integration_setup, plan_integration_setup
from artifex.distribution.approvals import ApprovalStore

PINNED_CODEX_COMMAND = ("npx", "--yes", "@openai/codex@0.150.1")


def _completed(
    arguments: tuple[str, ...], *, returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(arguments, returncode, stdout=stdout, stderr="")


def _provider_spec() -> dict[str, object]:
    return {
        "provider_id": "codex",
        "command": list(PINNED_CODEX_COMMAND),
        "roles": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        "governance_mode": "STANDALONE",
        "credential_reference": {
            "broker": "codex-native-session",
            "reference": "default",
            "provider_id": "codex",
            "scopes": ["INTERACTION", "EXECUTION_IMPLEMENTER"],
        },
    }


def _persist_setup(root: Path) -> None:
    approvals = ApprovalStore(root / "approval-store")
    plan = plan_integration_setup(
        root,
        ("codex",),
        provider_specs=(_provider_spec(),),
        approval_store=approvals,
    )
    apply_integration_setup(
        plan,
        confirmation_token=plan.decision.confirmation_token,
        approval_store=approvals,
    )


def _ready_loader(
    observed: list[tuple[str, ...]],
    *,
    certified: bool = True,
    authenticated: bool = True,
) -> ProviderCompositionLoader:
    def runner(arguments: object) -> subprocess.CompletedProcess[str]:
        command = tuple(str(item) for item in arguments)  # type: ignore[arg-type]
        observed.append(command)
        if command[-1] == "--version":
            return _completed(command, stdout="codex-cli 0.150.1\n")
        assert command[-2:] == ("login", "status")
        return _completed(
            command,
            returncode=0 if authenticated else 1,
            stdout="Logged in using ChatGPT\n" if authenticated else "",
        )

    roles = (
        frozenset({ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER})
        if certified
        else frozenset()
    )
    return ProviderCompositionLoader(
        which=lambda value: "C:/fixture/npx.exe" if value == "npx" else None,
        runner=runner,  # type: ignore[arg-type]
        certified_roles={"codex": roles},
    )


@pytest.mark.integration
def test_secret_free_setup_persists_command_vector_and_fresh_loader_consumes_it(
    tmp_path: Path,
) -> None:
    _persist_setup(tmp_path)
    state_path = tmp_path / ".artifex" / "integrations.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["schema_version"] == "2.0"
    assert state["providers"][0]["command"] == list(PINNED_CODEX_COMMAND)
    assert "token" not in state_path.read_text(encoding="utf-8").casefold()

    observed: list[tuple[str, ...]] = []
    graph = _ready_loader(observed).load(tmp_path)
    codex = graph.provider("codex")
    assert codex is not None
    assert codex.readiness.state is ReadinessState.AVAILABLE
    assert codex.readiness.checks == {
        "detected": True,
        "configured": True,
        "authenticated": True,
        "healthy": True,
        "registered": True,
        "available": True,
    }
    assert observed == [
        ("C:/fixture/npx.exe", "--yes", "@openai/codex@0.150.1", "--version"),
        (
            "C:/fixture/npx.exe",
            "--yes",
            "@openai/codex@0.150.1",
            "login",
            "status",
        ),
    ]


@pytest.mark.adversarial
def test_authentication_is_distinct_and_unauthenticated_codex_never_becomes_available(
    tmp_path: Path,
) -> None:
    _persist_setup(tmp_path)
    provider = _ready_loader([], authenticated=False).load(tmp_path).provider("codex")
    assert provider is not None
    assert provider.readiness.state is ReadinessState.CONFIGURED
    assert provider.readiness.checks["detected"] is True
    assert provider.readiness.checks["configured"] is True
    assert provider.readiness.checks["authenticated"] is False
    assert provider.globally_available is False


@pytest.mark.adversarial
def test_setup_rejects_secret_fields_and_malformed_persisted_authority(tmp_path: Path) -> None:
    secret_spec = {**_provider_spec(), "api_key": "must-not-enter-project-state"}
    with pytest.raises(ValueError, match="unknown fields"):
        plan_integration_setup(tmp_path, ("codex",), provider_specs=(secret_spec,))
    state = tmp_path / ".artifex" / "integrations.json"
    state.parent.mkdir()
    state.write_text(
        json.dumps({"schema_version": "2.0", "authority": "VENDOR", "providers": []}),
        encoding="utf-8",
    )
    result = Application(
        project_root=str(tmp_path), provider_loader=_ready_loader([])
    ).dispatch(OperationRequest("providers.graph"))
    assert result.ok is False
    assert result.error is not None
    assert result.error.details["type"] == "ProviderSetupError"


@pytest.mark.conformance
def test_contextual_resolver_separates_global_readiness_certification_and_policy(
    tmp_path: Path,
) -> None:
    _persist_setup(tmp_path)
    uncertified = _ready_loader([], certified=False).load(tmp_path)
    request = CapabilityRequest(
        "PROJECT-1",
        "JOB-1",
        ProviderRole.EXECUTION_IMPLEMENTER,
        frozenset({"repository_write"}),
        frozenset({"codex"}),
        frozenset({"repository_write"}),
        ActorContext(
            "automation-1",
            "AUTOMATION",
            frozenset({ProviderRole.EXECUTION_IMPLEMENTER}),
        ),
        DataClassification.INTERNAL,
        preferred_provider="codex",
    )
    denied = CapabilityResolver().resolve(uncertified, request)
    assert denied.eligible is False
    assert denied.evaluated[0]["reasons"] == ["ROLE_NOT_CERTIFIED"]

    certified = _ready_loader([]).load(tmp_path)
    allowed = CapabilityResolver().resolve(certified, request)
    assert allowed.eligible is True and allowed.provider_id == "codex"
    excluded = CapabilityResolver().resolve(
        certified,
        CapabilityRequest(
            "PROJECT-1",
            "JOB-1",
            ProviderRole.EXECUTION_IMPLEMENTER,
            frozenset({"repository_write"}),
            frozenset({"claude"}),
            frozenset({"repository_write"}),
            request.actor,
            DataClassification.INTERNAL,
        ),
    )
    assert excluded.eligible is False
    assert excluded.evaluated[0]["reasons"] == ["PROVIDER_NOT_AUTHORIZED_BY_ENVELOPE"]


@pytest.mark.integration
def test_public_application_reloads_setup_and_exposes_graph_readiness_and_resolver(
    tmp_path: Path,
) -> None:
    _persist_setup(tmp_path)
    application = Application(
        project_root=str(tmp_path), provider_loader=_ready_loader([])
    )
    operations = set(application.operation_names)
    assert {"providers.graph", "providers.readiness", "providers.resolve"} <= operations
    graph = application.dispatch(OperationRequest("providers.graph"))
    assert graph.ok and graph.value["graph"]["providers"][0]["provider_id"] == "codex"
    readiness = application.dispatch(
        OperationRequest("providers.readiness", {"provider_id": "codex"})
    )
    assert readiness.value["readiness"]["state"] == "AVAILABLE"
    decision = application.dispatch(
        OperationRequest(
            "providers.resolve",
            {
                "provider_id": "codex",
                "project_id": "PROJECT-1",
                "project_job_id": "JOB-1",
                "role": "EXECUTION_IMPLEMENTER",
                "capabilities": ["repository_write"],
                "envelope": {
                    "allowed_providers": ["codex"],
                    "allowed_capabilities": ["repository_write"],
                },
                "actor": {
                    "actor_id": "automation-1",
                    "actor_type": "AUTOMATION",
                    "delegated_roles": ["EXECUTION_IMPLEMENTER"],
                },
                "data_classification": "INTERNAL",
            },
            OperationContext(actor="automation-1"),
        )
    )
    assert decision.ok and decision.value["decision"]["eligible"] is True

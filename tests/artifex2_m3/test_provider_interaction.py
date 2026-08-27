from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.capabilities import (
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    CapabilityEvidenceStore,
    CapabilityReceipt,
    GovernanceMode,
    ProviderCompositionLoader,
    ProviderConfiguration,
    ProviderInstance,
    ProviderInteractionService,
    ProviderReadiness,
    ProviderRole,
    ReadinessState,
    record_execution_implementer_evidence,
)

_HASH = "a" * 64


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / ".artifex").mkdir(parents=True)
    (root / ".artifex" / "project-model.json").write_text(
        json.dumps({"schema_version": "1.0", "project": {"id": "PRJ-1"}}) + "\n",
        encoding="utf-8",
    )
    (root / ".artifex" / "integrations.json").write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "authority": "ARTIFEX_PROJECT_STATE",
                "vendor_configuration_mutated": False,
                "enabled": ["codex"],
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
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "artifex@example.invalid")
    _git(root, "config", "user.name", "ARTIFEX Test")
    _git(root, "add", ".artifex")
    _git(root, "commit", "-m", "baseline")
    return root


def _provider() -> ProviderInstance:
    configuration = ProviderConfiguration(
        "codex",
        True,
        frozenset({ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}),
        GovernanceMode.STANDALONE,
        ("codex",),
    )
    readiness = ProviderReadiness(
        "codex",
        ReadinessState.AVAILABLE,
        {
            "detected": True,
            "configured": True,
            "authenticated": True,
            "healthy": True,
            "registered": True,
            "available": True,
        },
        "codex",
        ("codex",),
        "0.150.1",
        "native Codex session authenticated",
    )
    return ProviderInstance(
        "codex:local",
        configuration,
        readiness,
        frozenset({"interactive"}),
        frozenset({ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}),
    )


def _live_runner(observed: list[tuple[str, ...]], response: str = "Safe response"):
    def run(arguments: Sequence[str], root: Path) -> subprocess.CompletedProcess[str]:
        assert root.is_dir()
        observed.append(tuple(arguments))
        events = (
            {"type": "thread.started", "thread_id": "thread-1"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {"id": "item-1", "type": "agent_message", "text": response},
            },
            {"type": "turn.completed", "usage": {}},
        )
        return subprocess.CompletedProcess(
            list(arguments), 0, "\n".join(json.dumps(item) for item in events) + "\n", ""
        )

    return run


def test_read_only_interaction_preserves_baseline_and_stores_hashes_only(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    observed: list[tuple[str, ...]] = []
    store = CapabilityEvidenceStore(tmp_path / "local-state" / "evidence.sqlite3")
    service = ProviderInteractionService(store=store, runner=_live_runner(observed))

    result = service.interact(
        provider=_provider(),
        project_root=root,
        project_id="PRJ-1",
        project_job_id="JOB-1",
        prompt="Explain the current project without editing it.",
    )

    command = observed[0]
    assert command[1:7] == (
        "exec",
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--json",
        "--color",
    )
    assert result["live"] is True
    assert result["response"] == "Safe response"
    assert _git(root, "status", "--porcelain") == ""
    receipts = store.valid_receipts(provider_id="codex", project_id="PRJ-1")
    assert len(receipts) == 1
    assert receipts[0].role is ProviderRole.INTERACTION
    database = store.path.read_bytes()
    assert b"Explain the current project" not in database
    assert b"Safe response" not in database


def test_interaction_fails_closed_on_multiple_messages_or_baseline_change(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    store = CapabilityEvidenceStore(tmp_path / "state" / "evidence.sqlite3")

    def multiple(_: Sequence[str], __: Path) -> subprocess.CompletedProcess[str]:
        events = [
            {"type": "item.completed", "item": {"type": "agent_message", "text": "one"}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "two"}},
            {"type": "turn.completed"},
        ]
        return subprocess.CompletedProcess([], 0, "\n".join(map(json.dumps, events)), "")

    with pytest.raises(ValueError, match="exactly one final agent response"):
        ProviderInteractionService(store=store, runner=multiple).interact(
            provider=_provider(),
            project_root=root,
            project_id="PRJ-1",
            project_job_id="JOB-1",
            prompt="read only",
        )

    def mutating(_: Sequence[str], project_root: Path) -> subprocess.CompletedProcess[str]:
        (project_root / ".artifex" / "project-model.json").write_text("{}\n", encoding="utf-8")
        events = [
            {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
            {"type": "turn.completed"},
        ]
        return subprocess.CompletedProcess([], 0, "\n".join(map(json.dumps, events)), "")

    with pytest.raises(ValueError, match="changed the Git or Project baseline"):
        ProviderInteractionService(store=store, runner=mutating).interact(
            provider=_provider(),
            project_root=root,
            project_id="PRJ-1",
            project_job_id="JOB-1",
            prompt="read only",
        )
    assert store.valid_receipts(provider_id="codex") == ()


def test_public_application_loads_setup_resolves_context_and_certifies_by_role(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    store = CapabilityEvidenceStore(tmp_path / "machine-state" / "evidence.sqlite3")
    observed: list[tuple[str, ...]] = []

    def probe(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(list(arguments), 0, "codex-cli 0.150.1\n", "")
        return subprocess.CompletedProcess(list(arguments), 0, "Logged in\n", "")

    loader = ProviderCompositionLoader(
        which=lambda _: "codex",
        runner=probe,
        certified_roles={"codex": CODEX_DISPATCH_AUTHORIZED_ROLES},
    )
    service = ProviderInteractionService(store=store, runner=_live_runner(observed))
    application = Application(
        project_root=str(root), provider_loader=loader, provider_interaction=service
    )
    arguments = {
        "project_root": str(root),
        "project_id": "PRJ-1",
        "provider_id": "codex",
        "prompt": "Summarize this project.",
    }
    result = application.dispatch(
        OperationRequest("providers.interact", arguments, OperationContext(actor="human-1"))
    )
    assert result.ok is True
    assert result.value["interaction"]["live"] is True  # type: ignore[index]

    projection = application.dispatch(
        OperationRequest("providers.certifications", {"project_id": "PRJ-1"})
    )
    states = {
        item["role"]: item["state"]
        for item in projection.value["certifications"]["roles"]  # type: ignore[index]
    }
    assert states == {
        "EXECUTION_IMPLEMENTER": "PUBLIC_COMPOSITION_VERIFIED",
        "INTERACTION": "LIVE_ROLE_CERTIFIED",
    }

    record_execution_implementer_evidence(
        project_id="PRJ-1",
        project_job_id="JOB-2",
        accepted_result_sha256=_HASH,
        promoted_baseline_sha256="b" * 64,
        acceptance_decision_id="DEC-1",
        promotion_revision=2,
        store=store,
    )
    promoted = application.dispatch(
        OperationRequest("providers.certifications", {"project_id": "PRJ-1"})
    )
    assert {
        item["role"]: item["state"]
        for item in promoted.value["certifications"]["roles"]  # type: ignore[index]
    } == {
        "EXECUTION_IMPLEMENTER": "LIVE_ROLE_CERTIFIED",
        "INTERACTION": "LIVE_ROLE_CERTIFIED",
    }


def test_execution_evidence_requires_acceptance_and_promotion() -> None:
    with pytest.raises(ValueError, match="independent acceptance and promotion"):
        CapabilityReceipt.issue(
            provider_id="codex",
            role=ProviderRole.EXECUTION_IMPLEMENTER,
            project_id="PRJ-1",
            project_job_id="JOB-1",
            input_sha256=_HASH,
            output_sha256=_HASH,
            baseline_sha256=_HASH,
        )

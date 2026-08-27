from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from artifex.project import ProjectAuthority, ProjectRepository
from artifex.runtime import (
    ActorPrincipal,
    ActorType,
    CredentialReference,
    DelegationGrant,
    EnvelopeError,
    EvidenceBindingError,
    EvidenceRecord,
    ExecutionEnvelope,
    ManagedRuntimeService,
    RuntimeAuthorizationError,
)


class Clock:
    def __init__(self, value: int = 100) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _commit_project(root: Path) -> tuple[ProjectAuthority, str]:
    repository = ProjectRepository.initialize(root, project_id="project-secure", name="Secure")
    authority = ProjectAuthority.bootstrap(repository)
    subprocess.run(("git", "-C", str(root), "config", "user.name", "ARTIFEX Test"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "artifex@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(root), "add", "."), check=True)
    subprocess.run(("git", "-C", str(root), "commit", "-m", "secure baseline"), check=True)
    head = subprocess.run(
        ("git", "-C", str(root), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return authority, head


def _principal(
    actor_id: str,
    actor_type: ActorType,
    *,
    permissions: tuple[str, ...] = (),
    delegation: DelegationGrant | None = None,
) -> ActorPrincipal:
    return ActorPrincipal(
        actor_id,
        actor_type,
        True,
        "test-authentication",
        direct_permissions=permissions,
        delegation=delegation,
    )


def _delegated(
    actor_id: str,
    actor_type: ActorType,
    *actions: str,
) -> ActorPrincipal:
    return _principal(
        actor_id,
        actor_type,
        delegation=DelegationGrant(
            f"grant-{actor_id}",
            "architect",
            actor_id,
            "project-secure",
            tuple(actions),
            issued_at=1,
            expires_at=200,
        ),
    )


def _envelope(authority: ProjectAuthority, head: str) -> ExecutionEnvelope:
    current = authority.current()
    return ExecutionEnvelope(
        envelope_id="envelope-secure",
        version=1,
        project_id="project-secure",
        objective="Execute one bounded Codex change",
        baseline_revision=current.number,
        actor_id="architect",
        allowed_paths=("src",),
        allowed_capabilities=("repository_write", "test_execution"),
        required_gates=("validation", "acceptance", "project-authority"),
        max_attempts=1,
        recovery_policy="RECONCILE_BEFORE_RETRY",
        allowed_workstreams=("workstream-secure",),
        allowed_providers=("codex",),
        allowed_provider_roles=("EXECUTION",),
        filesystem_permissions=("READ", "WRITE"),
        tool_permissions=("pytest",),
        credential_references=(
            CredentialReference(
                "credential/codex/project-secure",
                "codex",
                "EXECUTION",
                "project-secure",
                expires_at=200,
            ),
        ),
        resource_budget=(("max_seconds", 120),),
        deadline_at=200,
        require_durable_evidence=True,
        baseline_fingerprint=current.fingerprint,
        baseline_commit=head,
    )


def _bootstrap_secure(
    tmp_path: Path,
) -> tuple[
    ManagedRuntimeService,
    ProjectAuthority,
    ExecutionEnvelope,
    ActorPrincipal,
    ActorPrincipal,
]:
    authority, head = _commit_project(tmp_path / "project")
    envelope = _envelope(authority, head)
    approval = _principal(
        "architect", ActorType.USER, permissions=("envelope:approve",)
    )
    automation = _delegated(
        "automation",
        ActorType.AUTOMATION_SYSTEM_ACTOR,
        "runtime:dispatch",
        "workspace:create",
        "workspace:access",
    )
    service = ManagedRuntimeService(
        tmp_path / "runstore.sqlite3",
        workspace_root=tmp_path / "workspaces",
        clock=Clock(),
    )
    service.bootstrap_run(
        envelope,
        workstream_id="workstream-secure",
        run_id="run-secure",
        project_job_id="job-secure",
        attempt_id="attempt-secure",
        purpose="bounded Codex execution",
        actor_id=automation,
        approval_actor=approval,
        correlation_id="correlation-secure",
    )
    return service, authority, envelope, approval, automation


@pytest.mark.adversarial
def test_envelope_paths_approval_and_version_are_authority_bound(tmp_path: Path) -> None:
    authority, head = _commit_project(tmp_path / "project")
    envelope = _envelope(authority, head)
    service = ManagedRuntimeService(tmp_path / "runstore.sqlite3", clock=Clock())

    with pytest.raises(EnvelopeError, match="escapes workspace"):
        replace(envelope, allowed_paths=("../outside",))
    with pytest.raises(EnvelopeError, match="secret-like"):
        replace(envelope, objective="execute with token=raw-secret-value")
    with pytest.raises(ValueError, match="explicit authenticated Envelope approver"):
        service.bootstrap_run(
            envelope,
            workstream_id="workstream-secure",
            run_id="run-secure",
            project_job_id="job-secure",
            attempt_id="attempt-secure",
            purpose="must not self approve",
            actor_id="automation",
        )

    approval = _principal(
        "architect", ActorType.USER, permissions=("envelope:approve",)
    )
    automation = _delegated(
        "automation", ActorType.AUTOMATION_SYSTEM_ACTOR, "envelope:approve"
    )
    with pytest.raises(RuntimeAuthorizationError, match="cannot approve"):
        service.coordinator.approve_envelope(envelope, actor=automation)

    service.coordinator.approve_envelope(envelope, actor=approval)
    with pytest.raises(RuntimeAuthorizationError, match="immutable"):
        service.coordinator.approve_envelope(
            replace(envelope, objective="mutated after approval"), actor=approval
        )


@pytest.mark.adversarial
def test_dispatch_requires_delegation_envelope_permissions_and_scoped_credential(
    tmp_path: Path,
) -> None:
    service, _, envelope, _, automation = _bootstrap_secure(tmp_path)
    service.create_workspace(
        "workspace-secure",
        "attempt-secure",
        tmp_path / "project",
        envelope.baseline_revision,
        actor_id=automation,
    )

    with pytest.raises(RuntimeAuthorizationError, match="provider role"):
        service.authorize_dispatch(
            "attempt-secure",
            provider_id="codex",
            provider_role="INTERACTION",
            requested_capabilities=("repository_write",),
            filesystem_permissions=("READ",),
            actor=automation,
        )
    with pytest.raises(RuntimeAuthorizationError, match="network permission"):
        service.authorize_dispatch(
            "attempt-secure",
            provider_id="codex",
            provider_role="EXECUTION",
            requested_capabilities=("repository_write",),
            filesystem_permissions=("READ",),
            network_permissions=("internet",),
            actor=automation,
        )
    with pytest.raises(RuntimeAuthorizationError, match="credential reference"):
        service.authorize_dispatch(
            "attempt-secure",
            provider_id="codex",
            provider_role="EXECUTION",
            requested_capabilities=("repository_write",),
            filesystem_permissions=("READ",),
            credential_reference_ids=("credential/wrong",),
            actor=automation,
        )

    authorization = service.authorize_dispatch(
        "attempt-secure",
        provider_id="codex",
        provider_role="EXECUTION",
        requested_capabilities=("repository_write",),
        filesystem_permissions=("READ", "WRITE"),
        tool_permissions=("pytest",),
        credential_reference_ids=("credential/codex/project-secure",),
        actor=automation,
        correlation_id="correlation-secure",
    )
    assert authorization.envelope_fingerprint == envelope.fingerprint
    status = service.status("run-secure")
    assert status["attempts"][0]["state"] == "RUNNING"  # type: ignore[index]
    assert status["dispatch_authorizations"][0]["credential_reference_ids"] == [  # type: ignore[index]
        "credential/codex/project-secure"
    ]


@pytest.mark.adversarial
def test_workspace_is_git_isolated_baseline_bound_and_path_scoped(tmp_path: Path) -> None:
    service, _, envelope, _, automation = _bootstrap_secure(tmp_path)
    with pytest.raises(RuntimeAuthorizationError, match="safe path component"):
        service.create_workspace(
            "../escape",
            "attempt-secure",
            tmp_path / "project",
            envelope.baseline_revision,
            actor_id=automation,
        )
    with pytest.raises(RuntimeAuthorizationError, match="baseline"):
        service.create_workspace(
            "wrong-baseline",
            "attempt-secure",
            tmp_path / "project",
            envelope.baseline_revision + 1,
            actor_id=automation,
        )

    workspace = service.create_workspace(
        "workspace-secure",
        "attempt-secure",
        tmp_path / "project",
        envelope.baseline_revision,
        actor_id=automation,
    )
    assert workspace.parent == (tmp_path / "workspaces").resolve()
    assert (workspace / ".git").exists()
    assert subprocess.run(
        ("git", "-C", str(workspace), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() == envelope.baseline_commit
    allowed = service.workspaces.assert_allowed_path(
        "workspace-secure", "src/change.py", permission="WRITE", actor_id=automation
    )
    assert allowed == workspace / "src" / "change.py"
    with pytest.raises(RuntimeAuthorizationError, match="outside Execution Envelope"):
        service.workspaces.assert_allowed_path(
            "workspace-secure", "tests/change.py", permission="WRITE", actor_id=automation
        )
    with pytest.raises(RuntimeAuthorizationError, match="escapes managed root"):
        service.workspaces.assert_allowed_path(
            "workspace-secure", "../outside.txt", permission="WRITE", actor_id=automation
        )


@pytest.mark.adversarial
def test_acceptance_requires_bound_evidence_and_audit_is_secret_safe(tmp_path: Path) -> None:
    service, authority, envelope, _, automation = _bootstrap_secure(tmp_path)
    service.create_workspace(
        "workspace-secure",
        "attempt-secure",
        tmp_path / "project",
        envelope.baseline_revision,
        actor_id=automation,
    )
    service.authorize_dispatch(
        "attempt-secure",
        provider_id="codex",
        provider_role="EXECUTION",
        requested_capabilities=("repository_write",),
        filesystem_permissions=("READ", "WRITE"),
        credential_reference_ids=("credential/codex/project-secure",),
        actor=automation,
        correlation_id="correlation-secure",
    )
    provider = _delegated("codex-provider", ActorType.PROVIDER, "result:submit")
    service.finish(
        "attempt-secure",
        "completed token=supersecret-value",
        actor_id=provider,
        correlation_id="correlation-secure",
    )
    acceptor = _principal(
        "acceptance-authority",
        ActorType.ARTIFEX_SERVICE,
        permissions=("acceptance:decide",),
    )
    with pytest.raises(EvidenceBindingError, match="complete durable evidence"):
        service.accept(
            "job-secure",
            evidence_valid=True,
            actor_id=acceptor,
            reason="missing durable evidence",
        )

    validator = _principal(
        "validator",
        ActorType.ARTIFEX_SERVICE,
        permissions=("evidence:record",),
    )
    evidence = EvidenceRecord(
        "evidence-validation",
        "job-secure",
        "attempt-secure",
        "validation",
        True,
        envelope.fingerprint,
        envelope.baseline_revision,
        "evidence://validation/report",
        "a" * 64,
        "validator",
        100,
    )
    service.record_evidence(
        evidence, actor=validator, correlation_id="correlation-secure"
    )
    with pytest.raises(RuntimeAuthorizationError, match="cannot decide"):
        service.accept(
            "job-secure",
            evidence_valid=True,
            evidence_ids=(evidence.evidence_id,),
            actor_id=automation,
            reason="automation must not self-accept",
        )
    decision = service.accept(
        "job-secure",
        evidence_valid=True,
        evidence_ids=(evidence.evidence_id,),
        actor_id=acceptor,
        reason="bound evidence passed",
        correlation_id="correlation-secure",
    )
    fabricated = replace(decision, decision_id="decision-forged")
    model = replace(
        authority.current().model,
        project=replace(
            authority.current().model.project,
            description="accepted secure execution",
        ),
    )
    promoter = _principal(
        "project-authority",
        ActorType.ARTIFEX_SERVICE,
        permissions=("project:promote",),
    )
    with pytest.raises(RuntimeAuthorizationError, match="persisted"):
        service.promote_workspace(
            "workspace-secure", model, fabricated, actor_id=promoter
        )
    assert service.promote_workspace(
        "workspace-secure", model, decision, actor_id=promoter
    ) == 2

    audit = service.store.audit()
    serialized = json.dumps(audit, sort_keys=True)
    assert "supersecret-value" not in serialized
    assert "[REDACTED]" in serialized
    assert "supersecret-value" not in json.dumps(service.status("run-secure"), sort_keys=True)
    events = {item["event_type"] for item in audit}
    assert {
        "ENVELOPE_APPROVED",
        "ATTEMPT_DISPATCH_AUTHORIZED",
        "PROVIDER_RESULT_RECORDED",
        "EVIDENCE_RECORDED",
        "ACCEPTANCE_DECIDED",
        "WORKSPACE_TRANSITION",
    } <= events
    correlated = [item for item in audit if item["correlation_id"] == "correlation-secure"]
    assert {item["actor_id"] for item in correlated} >= {
        "architect",
        "automation",
        "codex-provider",
        "validator",
        "acceptance-authority",
    }
    assert all(item["authentication_method"] == "test-authentication" for item in correlated)


@pytest.mark.adversarial
def test_anonymous_actor_name_is_not_authentication(tmp_path: Path) -> None:
    service, _, _, _, _ = _bootstrap_secure(tmp_path)
    with pytest.raises(RuntimeAuthorizationError, match="authenticated"):
        service.coordinator.create_workstream(
            "anonymous-workstream", "project-secure", actor_id="anonymous"
        )

from __future__ import annotations

from dataclasses import replace

import pytest

from artifex.runtime.models import (
    ActorPrincipal,
    ActorType,
    CredentialReference,
    DelegationGrant,
    EnvelopeError,
    EvidenceBindingError,
    EvidenceRecord,
    ExecutionEnvelope,
    RuntimeAuthorizationError,
    actor_principal,
)


def _envelope() -> ExecutionEnvelope:
    return ExecutionEnvelope(
        envelope_id="envelope-contract",
        version=1,
        project_id="project-contract",
        objective="exercise the durable contract",
        baseline_revision=1,
        actor_id="operator",
        allowed_paths=("src",),
        allowed_capabilities=("repository_read",),
        required_gates=("validation",),
        max_attempts=1,
        recovery_policy="RECONCILE_BEFORE_RETRY",
    )


@pytest.mark.unit
def test_delegation_and_actor_authority_contracts() -> None:
    with pytest.raises(RuntimeAuthorizationError, match="identity"):
        DelegationGrant("", "owner", "agent", "project-contract", ("read",), 1)
    with pytest.raises(RuntimeAuthorizationError, match="explicit actions"):
        DelegationGrant("grant", "owner", "agent", "project-contract", (), 1)
    with pytest.raises(RuntimeAuthorizationError, match="expiry"):
        DelegationGrant("grant", "owner", "agent", "project-contract", ("read",), 2, 2)

    grant = DelegationGrant(
        "grant", "owner", "agent", "project-contract", ("read",), 1, 10
    )
    assert grant.permits("agent", "project-contract", "read", now=9)
    assert not grant.permits("other", "project-contract", "read", now=9)
    assert not grant.permits("agent", "other", "read", now=9)
    assert not grant.permits("agent", "project-contract", "write", now=9)
    assert not grant.permits("agent", "project-contract", "read", now=10)
    assert grant.to_dict()["allowed_actions"] == ["read"]

    wildcard = replace(grant, allowed_actions=("*",), expires_at=None)
    principal = ActorPrincipal(
        "agent", ActorType.AGENT, True, "test", delegation=wildcard
    )
    principal.require("write", "project-contract", now=100)
    assert principal.to_audit_dict()["delegation_id"] == "grant"
    with pytest.raises(RuntimeAuthorizationError, match="explicit actor"):
        ActorPrincipal("", ActorType.USER, True, "test")
    with pytest.raises(RuntimeAuthorizationError, match="authentication method"):
        ActorPrincipal("actor", ActorType.USER, True, "")
    with pytest.raises(RuntimeAuthorizationError, match="does not match"):
        ActorPrincipal("other", ActorType.AGENT, True, "test", delegation=grant)
    with pytest.raises(RuntimeAuthorizationError, match="authenticated actor"):
        ActorPrincipal("anonymous", ActorType.USER, False, "").require(
            "read", "project-contract", now=1
        )
    with pytest.raises(RuntimeAuthorizationError, match="lacks write"):
        principal.require("write", "other-project", now=1)

    assert actor_principal(principal) is principal
    assert not actor_principal(" ").authenticated
    assert actor_principal("managed-service-local-client").actor_type is ActorType.USER
    assert actor_principal("legacy-service").direct_permissions == ("*",)


@pytest.mark.unit
def test_credential_reference_is_scoped_revocable_and_secret_safe() -> None:
    with pytest.raises(RuntimeAuthorizationError, match="scope"):
        CredentialReference("", "codex", "EXECUTION", "project-contract")
    with pytest.raises(RuntimeAuthorizationError, match="secret-like"):
        CredentialReference(
            "token=super-secret-material", "codex", "EXECUTION", "project-contract"
        )
    credential = CredentialReference(
        "credential/codex/project-contract", "codex", "EXECUTION", "project-contract", 10
    )
    assert credential.permits("codex", "EXECUTION", "project-contract", now=9)
    assert not credential.permits("claude", "EXECUTION", "project-contract", now=9)
    assert not credential.permits("codex", "REVIEW", "project-contract", now=9)
    assert not credential.permits("codex", "EXECUTION", "other", now=9)
    assert not credential.permits("codex", "EXECUTION", "project-contract", now=10)
    assert not replace(credential, revoked=True).permits(
        "codex", "EXECUTION", "project-contract", now=9
    )
    assert credential.to_dict()["provider_id"] == "codex"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"envelope_id": ""}, "identity"),
        ({"version": 0}, "positive"),
        ({"baseline_revision": 0}, "positive"),
        ({"max_attempts": 0}, "positive"),
        ({"allowed_paths": ()}, "scope"),
        ({"allowed_paths": ("src", "./src")}, "unique"),
        ({"allowed_paths": ("../escape",)}, "escapes workspace"),
        ({"allowed_paths": ("C:/escape",)}, "escapes workspace"),
        ({"allowed_capabilities": ("",)}, "non-empty"),
        ({"required_gates": ("",)}, "non-empty"),
        ({"data_classification": ""}, "data rules"),
        ({"stop_conditions": ()}, "data rules"),
        ({"objective": "token=super-secret-material"}, "secret-like"),
        ({"filesystem_permissions": ("EXECUTE",)}, "READ and/or WRITE"),
        ({"allowed_providers": ("codex",)}, "explicit provider role"),
        ({"allowed_provider_roles": ("EXECUTION",)}, "explicit provider"),
        (
            {"allowed_capabilities": ("provider:codex",)},
            "outside M2",
        ),
        (
            {"allowed_providers": ("codex",), "allowed_provider_roles": ("EXECUTION",)},
            "semantic fingerprint",
        ),
        ({"baseline_fingerprint": "bad"}, "SHA-256"),
        ({"baseline_commit": "bad"}, "SHA-1"),
        ({"resource_budget": (("", 1),)}, "resource budget"),
        ({"resource_budget": (("seconds", -1),)}, "resource budget"),
        ({"deadline_at": 0}, "positive timestamp"),
    ],
)
def test_execution_envelope_rejects_invalid_authority(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(EnvelopeError, match=message):
        replace(_envelope(), **changes)


@pytest.mark.unit
def test_execution_envelope_serialization_and_bounded_access() -> None:
    credential = CredentialReference(
        "credential/codex/project-contract", "codex", "EXECUTION", "project-contract"
    )
    envelope = replace(
        _envelope(),
        allowed_paths=(".", "docs"),
        allowed_providers=("codex",),
        allowed_provider_roles=("EXECUTION",),
        credential_references=(credential,),
        resource_budget=(("seconds", 30),),
        baseline_fingerprint="a" * 64,
        baseline_commit="b" * 40,
    )
    value = envelope.to_dict()
    assert len(value["fingerprint"]) == 64
    assert value["resource_budget"] == {"seconds": 30}
    assert envelope.authorizes_path("docs/guide.md", permission="READ")
    assert not envelope.authorizes_path("docs/guide.md", permission="EXECUTE")
    assert envelope.credential(credential.reference_id) is credential
    assert envelope.credential("missing") is None
    with pytest.raises(EnvelopeError, match="scoped"):
        replace(
            envelope,
            credential_references=(replace(credential, project_id="other"),),
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"evidence_id": ""}, "identity"),
        ({"baseline_revision": 0}, "baseline"),
        ({"artifact_digest": "not-a-digest"}, "SHA-256"),
        ({"artifact_ref": "token=super-secret-material"}, "secret-like"),
    ],
)
def test_evidence_records_reject_unbound_or_unsafe_evidence(
    changes: dict[str, object], message: str
) -> None:
    evidence = EvidenceRecord(
        "evidence-1",
        "job-1",
        "attempt-1",
        "validation",
        True,
        "a" * 64,
        1,
        "evidence://validation/report",
        "b" * 64,
        "validator",
        1,
    )
    with pytest.raises(EvidenceBindingError, match=message):
        replace(evidence, **changes)
    assert evidence.to_dict()["passed"] is True

from artifex.application import Application
from artifex.capabilities import (
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    ProviderRole,
    codex_certification_projection,
)


def test_default_public_composition_uses_role_conformance_authority() -> None:
    assert {
        ProviderRole.INTERACTION,
        ProviderRole.EXECUTION_IMPLEMENTER,
    } == CODEX_DISPATCH_AUTHORIZED_ROLES
    assert "providers.resolve" in Application().operation_names


def test_live_role_certification_remains_role_specific_and_evidence_bound() -> None:
    before = codex_certification_projection()
    assert {item["state"] for item in before["roles"]} == {
        "PUBLIC_COMPOSITION_VERIFIED"
    }

    after = codex_certification_projection(
        {ProviderRole.INTERACTION: ("evidence:interaction-receipt",)}
    )
    states = {item["role"]: item["state"] for item in after["roles"]}
    assert states == {
        "EXECUTION_IMPLEMENTER": "PUBLIC_COMPOSITION_VERIFIED",
        "INTERACTION": "LIVE_ROLE_CERTIFIED",
    }

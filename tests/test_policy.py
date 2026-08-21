from __future__ import annotations

import pytest

from artifex.policy import (
    AcceptanceAuthority,
    InstructionTrust,
    PrivilegePolicy,
    can_supply_instructions,
    can_transition_canonical_acceptance,
    scrub_secrets,
)


@pytest.mark.unit
def test_secret_scrubbing() -> None:
    assert "super-secret" not in scrub_secrets("token=super-secret")


@pytest.mark.unit
def test_overlay_cannot_expand_privileges() -> None:
    policy = PrivilegePolicy(frozenset({"repository_read"}))
    assert policy.permits_overlay({"repository_read"})
    assert not policy.permits_overlay({"repository_read", "repository_write"})


@pytest.mark.unit
def test_only_core_transitions_canonical_acceptance() -> None:
    assert can_transition_canonical_acceptance(AcceptanceAuthority.CORE)
    for authority in AcceptanceAuthority:
        if authority is not AcceptanceAuthority.CORE:
            assert not can_transition_canonical_acceptance(authority)


@pytest.mark.unit
def test_external_data_never_supplies_instructions() -> None:
    assert not can_supply_instructions(InstructionTrust.EXTERNAL_DATA)
    assert can_supply_instructions(InstructionTrust.ACCEPTED_AUTHORITY)
    assert can_supply_instructions(InstructionTrust.USER)

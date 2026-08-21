from __future__ import annotations

import pytest

from artifex.policy import PrivilegePolicy, scrub_secrets


@pytest.mark.unit
def test_secret_scrubbing() -> None:
    assert "super-secret" not in scrub_secrets("token=super-secret")


@pytest.mark.unit
def test_overlay_cannot_expand_privileges() -> None:
    policy = PrivilegePolicy(frozenset({"repository_read"}))
    assert policy.permits_overlay({"repository_read"})
    assert not policy.permits_overlay({"repository_read", "repository_write"})


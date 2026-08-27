"""Packaged role-conformance authority and live-certification ladder helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from artifex.capabilities.models import ProviderRole

CODEX_SUPPORTED_VERSION_RANGE = ">=0.150.1,<0.151"
CODEX_DISPATCH_AUTHORIZED_ROLES = frozenset(
    {ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}
)
CERTIFICATION_LADDER = (
    "ADAPTER_IMPLEMENTED",
    "ROLE_CONFORMANCE_VERIFIED",
    "PACKAGED",
    "PUBLIC_COMPOSITION_VERIFIED",
    "LIVE_ROLE_CERTIFIED",
)


def codex_certification_projection(
    live_evidence: Mapping[ProviderRole, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Project role-specific release state without conflating readiness or roles."""

    observed = dict(live_evidence or {})
    roles = []
    for role in sorted(CODEX_DISPATCH_AUTHORIZED_ROLES, key=lambda item: item.value):
        evidence = observed.get(role, ())
        steps = {
            "ADAPTER_IMPLEMENTED": "PASS",
            "ROLE_CONFORMANCE_VERIFIED": "PASS",
            "PACKAGED": "PASS",
            "PUBLIC_COMPOSITION_VERIFIED": "PASS",
            "LIVE_ROLE_CERTIFIED": "PASS" if evidence else "IN_PROGRESS",
        }
        roles.append(
            {
                "provider": "codex",
                "role": role.value,
                "state": (
                    "LIVE_ROLE_CERTIFIED" if evidence else "PUBLIC_COMPOSITION_VERIFIED"
                ),
                "supported_version_range": CODEX_SUPPORTED_VERSION_RANGE,
                "steps": steps,
                "evidence": list(evidence),
            }
        )
    return {"ladder": list(CERTIFICATION_LADDER), "roles": roles}

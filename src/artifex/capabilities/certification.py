"""Packaged role-conformance authority and live-certification ladder helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from artifex.capabilities.models import ProviderRole

CODEX_SUPPORTED_VERSION_RANGE = ">=0.150.1,<0.151"
CODEX_DISPATCH_AUTHORIZED_ROLES = frozenset(
    {ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}
)
CLAUDE_SUPPORTED_VERSION_RANGE = ">=2.1.3,<3"
CLAUDE_DISPATCH_AUTHORIZED_ROLES = frozenset(
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

    return provider_certification_projection(
        provider_id="codex",
        supported_version_range=CODEX_SUPPORTED_VERSION_RANGE,
        authorized_roles=CODEX_DISPATCH_AUTHORIZED_ROLES,
        live_evidence=live_evidence,
    )


def claude_certification_projection(
    live_evidence: Mapping[ProviderRole, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    return provider_certification_projection(
        provider_id="claude",
        supported_version_range=CLAUDE_SUPPORTED_VERSION_RANGE,
        authorized_roles=CLAUDE_DISPATCH_AUTHORIZED_ROLES,
        live_evidence=live_evidence,
    )


def provider_certification_projection(
    *,
    provider_id: str,
    supported_version_range: str,
    authorized_roles: frozenset[ProviderRole],
    live_evidence: Mapping[ProviderRole, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Project one provider's role-specific state without conflating live evidence."""

    observed = dict(live_evidence or {})
    roles = []
    for role in sorted(authorized_roles, key=lambda item: item.value):
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
                "provider": provider_id,
                "role": role.value,
                "state": (
                    "LIVE_ROLE_CERTIFIED" if evidence else "PUBLIC_COMPOSITION_VERIFIED"
                ),
                "supported_version_range": supported_version_range,
                "steps": steps,
                "evidence": list(evidence),
            }
        )
    return {"ladder": list(CERTIFICATION_LADDER), "roles": roles}

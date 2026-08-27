"""Contextual AVAILABLE_FOR resolver over global provider readiness."""

from __future__ import annotations

from artifex.capabilities.models import (
    CapabilityRequest,
    DataClassification,
    EligibilityDecision,
    GovernanceMode,
    ProviderInstance,
)
from artifex.capabilities.registry import CapabilityGraph


class CapabilityResolver:
    def resolve(
        self, graph: CapabilityGraph, request: CapabilityRequest
    ) -> EligibilityDecision:
        evaluated: list[dict[str, object]] = []
        candidates: list[ProviderInstance] = []
        for provider in graph.providers:
            reasons = self._ineligibility_reasons(provider, request)
            evaluated.append(
                {
                    "provider_id": provider.provider_id,
                    "eligible": not reasons,
                    "reasons": list(reasons),
                }
            )
            if not reasons:
                candidates.append(provider)
        if not candidates:
            return EligibilityDecision(
                False,
                None,
                None,
                ("NO_CONTEXTUALLY_ELIGIBLE_PROVIDER",),
                tuple(evaluated),
            )
        candidates.sort(
            key=lambda item: (
                item.provider_id != request.preferred_provider,
                item.provider_id,
                item.instance_id,
            )
        )
        selected = candidates[0]
        return EligibilityDecision(
            True,
            selected.provider_id,
            selected.instance_id,
            ("AVAILABLE_FOR_CONTEXT",),
            tuple(evaluated),
        )

    @staticmethod
    def _ineligibility_reasons(
        provider: ProviderInstance, request: CapabilityRequest
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if not provider.globally_available:
            reasons.append("NOT_GLOBALLY_AVAILABLE")
        if request.role not in provider.configuration.roles:
            reasons.append("ROLE_NOT_CONFIGURED")
        if request.role not in provider.certified_roles:
            reasons.append("ROLE_NOT_CERTIFIED")
        if request.role not in request.actor.delegated_roles:
            reasons.append("ACTOR_ROLE_NOT_DELEGATED")
        if not request.capabilities.issubset(provider.capabilities):
            reasons.append("CAPABILITIES_NOT_PROVIDED")
        if not request.capabilities.issubset(request.envelope_capabilities):
            reasons.append("CAPABILITIES_NOT_AUTHORIZED_BY_ENVELOPE")
        if request.allowed_providers and provider.provider_id not in request.allowed_providers:
            reasons.append("PROVIDER_NOT_AUTHORIZED_BY_ENVELOPE")
        if (
            request.project_allowed_providers
            and provider.provider_id not in request.project_allowed_providers
        ):
            reasons.append("PROVIDER_NOT_AUTHORIZED_BY_PROJECT")
        if request.project_allowed_roles and request.role not in request.project_allowed_roles:
            reasons.append("ROLE_NOT_AUTHORIZED_BY_PROJECT")
        if (
            provider.configuration.governance_mode is GovernanceMode.ATLAS_GOVERNED
            and provider.provider_id != "atlas"
        ):
            reasons.append("ATLAS_GOVERNANCE_BOUNDARY_INVALID")
        if (
            request.data_classification is DataClassification.RESTRICTED
            and provider.configuration.governance_mode is not GovernanceMode.ATLAS_GOVERNED
        ):
            reasons.append("DATA_CLASSIFICATION_INELIGIBLE")
        return tuple(reasons)

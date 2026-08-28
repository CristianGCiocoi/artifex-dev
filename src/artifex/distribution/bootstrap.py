"""Public fresh-process bootstrap projection and deliberate manual fallback."""

from __future__ import annotations

from dataclasses import dataclass

from artifex.capabilities.models import ProviderRole, ReadinessState
from artifex.capabilities.registry import CapabilityGraph


@dataclass(frozen=True, slots=True)
class ManualFallback:
    selected: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "selected": self.selected,
            "integration_id": "manual",
            "status": "READY",
            "reason": self.reason,
            "message": (
                "No certified automated provider is ready. Continue with "
                "ManualIntegration by creating a portable execution packet, run the "
                "work with a person or external tool, then submit the result for "
                "validation. ARTIFEX acceptance remains separate."
                if self.selected
                else "A certified automated provider is ready; ManualIntegration remains "
                "available as an explicit fallback."
            ),
            "actions": [
                {
                    "step": 1,
                    "operation": "manual.packet.create",
                    "description": "Create a portable execution packet.",
                },
                {
                    "step": 2,
                    "operation": "manual.result.submit",
                    "description": (
                        "Submit the completed packet result as a claim for independent validation."
                    ),
                },
            ],
            "self_acceptance": False,
        }


@dataclass(frozen=True, slots=True)
class DistributionBootstrapReport:
    graph: CapabilityGraph
    setup_present: bool
    automated_candidates: tuple[str, ...]
    fallback: ManualFallback

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "READY" if self.automated_candidates else "MANUAL_FALLBACK",
            "fresh_process_consumed_setup": self.setup_present,
            "capability_graph": self.graph.to_dict(),
            "automated_candidates": list(self.automated_candidates),
            "manual_fallback": self.fallback.to_dict(),
            "authority": {
                "provider_readiness": "CapabilityRegistry",
                "provider_certification_required": True,
                "contextual_dispatch_requires_resolver": True,
                "manual_result_self_accepts": False,
            },
        }


def build_distribution_bootstrap_report(
    graph: CapabilityGraph,
    *,
    setup_present: bool,
) -> DistributionBootstrapReport:
    """Project a graph loaded by this process without granting contextual dispatch."""

    candidates = tuple(
        provider.provider_id
        for provider in graph.providers
        if provider.readiness.state is ReadinessState.AVAILABLE
        and bool(
            provider.certified_roles
            & {ProviderRole.INTERACTION, ProviderRole.EXECUTION_IMPLEMENTER}
        )
    )
    selected = not candidates
    reason = (
        "NO_CERTIFIED_AUTOMATED_PROVIDER_READY"
        if selected
        else "AUTOMATED_PROVIDER_CANDIDATE_READY"
    )
    return DistributionBootstrapReport(
        graph,
        setup_present,
        candidates,
        ManualFallback(selected, reason),
    )


__all__ = [
    "DistributionBootstrapReport",
    "ManualFallback",
    "build_distribution_bootstrap_report",
]

"""Deterministic global provider registry and Capability Graph projection."""

from __future__ import annotations

from dataclasses import dataclass

from artifex.capabilities.models import ProviderInstance


@dataclass(frozen=True, slots=True)
class CapabilityGraph:
    providers: tuple[ProviderInstance, ...]
    source: str

    def provider(self, provider_id: str) -> ProviderInstance | None:
        return next((item for item in self.providers if item.provider_id == provider_id), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "providers": [provider.to_dict() for provider in self.providers],
            "source": self.source,
            "authoritative": False,
            "authority": "CapabilityRegistry",
        }


class CapabilityRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ProviderInstance] = {}

    def register(self, provider: ProviderInstance) -> None:
        if provider.provider_id in self._providers:
            raise ValueError(f"provider already registered: {provider.provider_id}")
        self._providers[provider.provider_id] = provider

    def graph(self, *, source: str) -> CapabilityGraph:
        return CapabilityGraph(
            tuple(self._providers[key] for key in sorted(self._providers)),
            source,
        )

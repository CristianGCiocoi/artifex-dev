"""Credential-reference brokers that never return secret material to Core context."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from artifex.capabilities.models import CredentialReference


@dataclass(frozen=True, slots=True)
class AuthenticationAssertion:
    authenticated: bool
    method: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "authenticated": self.authenticated,
            "method": self.method,
            "detail": self.detail,
            "secret_material_present": False,
        }


CredentialProbe = Callable[[CredentialReference, tuple[str, ...]], AuthenticationAssertion]


class CredentialBroker:
    """Resolves scoped references into secret-free authentication assertions."""

    def __init__(self, probes: dict[str, CredentialProbe] | None = None) -> None:
        self._probes = dict(probes or {})

    def resolve(
        self, reference: CredentialReference, command: tuple[str, ...]
    ) -> AuthenticationAssertion:
        probe = self._probes.get(reference.broker)
        if probe is None:
            return AuthenticationAssertion(False, reference.broker, "credential broker unavailable")
        return probe(reference, command)

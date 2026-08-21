"""Authority, trust, secret, and privilege-ceiling primitives."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class InstructionTrust(StrEnum):
    ACCEPTED_AUTHORITY = "ACCEPTED_AUTHORITY"
    USER = "USER"
    IMPLEMENTATION = "IMPLEMENTATION"
    EXTERNAL_DATA = "EXTERNAL_DATA"


class AcceptanceAuthority(StrEnum):
    CORE = "CORE"
    INDEPENDENT_VALIDATOR = "INDEPENDENT_VALIDATOR"
    ARCHITECT = "ARCHITECT"
    HUMAN = "HUMAN"


_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?P<label>api[_-]?key|token|password|secret)\s*[:=]\s*(?P<value>[^\s,;]+)",
        r"(?P<value>gh[opusr]_[A-Za-z0-9_]{20,})",
        r"(?P<value>sk-[A-Za-z0-9_-]{20,})",
    )
)


def scrub_secrets(text: str) -> str:
    """Remove common credential forms before evidence or memory persistence."""

    scrubbed = text
    for pattern in _SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed


@dataclass(frozen=True, slots=True)
class PrivilegePolicy:
    """Enforce the self-improvement privilege ceiling."""

    allowed: frozenset[str]

    def permits_overlay(self, requested: set[str]) -> bool:
        return requested.issubset(self.allowed)


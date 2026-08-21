"""Stable identifier parsing and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"REQ-(?:F|NF)-\d{3}",
        r"ADR-[A-Z0-9][A-Z0-9-]*-\d{3}",
        r"INV-\d{3}",
        r"M\d{2}",
        r"M\d{2}-T\d{2}",
        r"(?:VAL|EVD|WAV|LES|IMP|CHG|ART|STG|INT|RSR|RBL)-[A-Z0-9][A-Z0-9-]*",
    )
)


@dataclass(frozen=True, order=True, slots=True)
class StableId:
    """A validated, serialization-safe ARTIFEX identifier."""

    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip().upper()
        if not any(pattern.fullmatch(normalized) for pattern in _PATTERNS):
            raise ValueError(f"invalid ARTIFEX identifier: {self.value!r}")
        object.__setattr__(self, "value", normalized)

    @classmethod
    def parse(cls, value: str) -> StableId:
        return cls(value)

    def __str__(self) -> str:
        return self.value


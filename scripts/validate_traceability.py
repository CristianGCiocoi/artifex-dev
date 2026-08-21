"""Deterministically verify accepted-requirement milestone ownership."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
REQUIREMENTS = ROOT / "docs" / "requirements" / "REQUIREMENTS_BASELINE.md"
TRACEABILITY = ROOT / ".artifex" / "implementation" / "traceability.yaml"
ID_PATTERN = re.compile(r"REQ-(?:F|NF)-\d{3}")
RANGE_PATTERN = re.compile(r"^(REQ-(?:F|NF)-)(\d{3})\.\.(\d{3})$")


def expand(key: str) -> set[str]:
    """Expand a compact same-domain requirement range."""

    match = RANGE_PATTERN.fullmatch(key)
    if match is None:
        return {key}
    prefix, start, end = match.groups()
    return {f"{prefix}{number:03d}" for number in range(int(start), int(end) + 1)}


def measure() -> tuple[set[str], set[str]]:
    accepted = set(ID_PATTERN.findall(REQUIREMENTS.read_text(encoding="utf-8")))
    payload = yaml.safe_load(TRACEABILITY.read_text(encoding="utf-8"))
    traced: set[str] = set()
    for key, milestones in payload["ownership"].items():
        if not milestones:
            raise ValueError(f"requirement ownership has no milestone: {key}")
        traced.update(expand(str(key)))
    return accepted, traced


def main() -> int:
    accepted, traced = measure()
    orphan = sorted(accepted - traced)
    unknown = sorted(traced - accepted)
    print(
        f"requirements_total={len(accepted)} requirements_traced={len(accepted & traced)} "
        f"orphan_requirements={len(orphan)} unknown_requirements={len(unknown)}"
    )
    if orphan:
        print(f"orphan={','.join(orphan)}")
    if unknown:
        print(f"unknown={','.join(unknown)}")
    return 1 if orphan or unknown else 0


if __name__ == "__main__":
    sys.exit(main())


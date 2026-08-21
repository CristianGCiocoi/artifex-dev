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


def _expand_mapping(mapping: dict[str, object]) -> set[str]:
    expanded: set[str] = set()
    for key, owners in mapping.items():
        if not owners:
            raise ValueError(f"traceability entry has no owner: {key}")
        expanded.update(expand(str(key)))
    return expanded


def measure() -> tuple[set[str], set[str], set[str]]:
    accepted = set(ID_PATTERN.findall(REQUIREMENTS.read_text(encoding="utf-8")))
    payload = yaml.safe_load(TRACEABILITY.read_text(encoding="utf-8"))
    milestones = _expand_mapping(payload["ownership"])
    architecture = _expand_mapping(payload["architecture"])
    return accepted, milestones, architecture


def main() -> int:
    accepted, traced, architecture = measure()
    orphan = sorted(accepted - traced)
    unknown = sorted(traced - accepted)
    architecture_orphan = sorted(accepted - architecture)
    architecture_unknown = sorted(architecture - accepted)
    print(
        f"requirements_total={len(accepted)} requirements_traced={len(accepted & traced)} "
        f"orphan_requirements={len(orphan)} unknown_requirements={len(unknown)} "
        f"architecture_orphans={len(architecture_orphan)}"
    )
    if orphan:
        print(f"orphan={','.join(orphan)}")
    if unknown:
        print(f"unknown={','.join(unknown)}")
    if architecture_orphan:
        print(f"architecture_orphan={','.join(architecture_orphan)}")
    if architecture_unknown:
        print(f"architecture_unknown={','.join(architecture_unknown)}")
    return 1 if orphan or unknown or architecture_orphan or architecture_unknown else 0


if __name__ == "__main__":
    sys.exit(main())

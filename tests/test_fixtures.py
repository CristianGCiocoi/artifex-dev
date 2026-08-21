from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.mark.unit
def test_required_fixture_taxonomy_is_present_and_exercised() -> None:
    root = Path(__file__).parent / "fixtures"
    required = {"valid", "minimal", "deep", "malformed", "stale", "brownfield"}
    assert {path.name for path in root.iterdir() if path.is_dir()} == required

    for name in required - {"brownfield"}:
        artifact = root / name / ".artifex" / ("status.yaml" if name == "stale" else "project.yaml")
        assert yaml.safe_load(artifact.read_text(encoding="utf-8")) is not None

    malformed = yaml.safe_load(
        (root / "malformed" / ".artifex" / "project.yaml").read_text(encoding="utf-8")
    )
    assert not isinstance(malformed["project"], dict)
    assert "Existing content" in (root / "brownfield" / "README.md").read_text(encoding="utf-8")

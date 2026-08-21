from __future__ import annotations

import ast
from pathlib import Path

import pytest


@pytest.mark.architecture
def test_core_components_do_not_import_application_layer() -> None:
    root = Path(__file__).parents[1] / "src" / "artifex"
    components = ("project", "workflow", "validation", "integrations", "compilation", "knowledge")
    violations: list[str] = []
    for component in components:
        for source in (root / component).rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                    "artifex.application"
                ):
                    violations.append(str(source.relative_to(root)))
                if isinstance(node, ast.Import):
                    violations.extend(
                        str(source.relative_to(root))
                        for alias in node.names
                        if alias.name.startswith("artifex.application")
                    )
    assert not violations, f"Core components import Application layer: {violations}"


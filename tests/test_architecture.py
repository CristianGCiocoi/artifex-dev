from __future__ import annotations

import ast
from collections import defaultdict
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


def _component_dependencies(root: Path, components: tuple[str, ...]) -> dict[str, set[str]]:
    dependencies: dict[str, set[str]] = defaultdict(set)
    for component in components:
        for source in (root / component).rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            imported: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
                elif isinstance(node, ast.Import):
                    imported.extend(alias.name for alias in node.names)
            for module in imported:
                parts = module.split(".")
                if len(parts) >= 2 and parts[0] == "artifex" and parts[1] in components:
                    dependency = parts[1]
                    if dependency != component:
                        dependencies[component].add(dependency)
    return dependencies


@pytest.mark.architecture
def test_core_component_dependency_graph_is_acyclic() -> None:
    root = Path(__file__).parents[1] / "src" / "artifex"
    components = ("project", "workflow", "validation", "integrations", "compilation", "knowledge")
    graph = _component_dependencies(root, components)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(component: str) -> None:
        if component in visiting:
            raise AssertionError(f"Core dependency cycle includes {component}")
        if component in visited:
            return
        visiting.add(component)
        for dependency in graph[component]:
            visit(dependency)
        visiting.remove(component)
        visited.add(component)

    for component in components:
        visit(component)

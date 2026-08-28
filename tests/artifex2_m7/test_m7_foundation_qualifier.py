from __future__ import annotations

import ast
from pathlib import Path


def test_m7_foundation_harness_imports_no_product_modules() -> None:
    root = Path(__file__).parents[2]
    source = root / "tools" / "artifex2" / "qualify_m7_foundation.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(name == "artifex" or name.startswith("artifex.") for name in imported)


def test_m7_foundation_harness_cannot_claim_m7_acceptance() -> None:
    root = Path(__file__).parents[2]
    source = (root / "tools" / "artifex2" / "qualify_m7_foundation.py").read_text(
        encoding="utf-8"
    )
    assert '"status": "BLOCKED_PRODUCT_DECISION"' in source
    assert '"official_support_cell_claimed": False' in source
    assert '"credential_files_read": False' in source

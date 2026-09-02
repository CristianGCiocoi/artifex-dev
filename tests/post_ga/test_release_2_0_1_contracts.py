"""Current ARTIFEX patch-release identity and smoke contracts."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from artifex import __version__

ROOT = Path(__file__).resolve().parents[2]


def _smoke_module() -> ModuleType:
    path = ROOT / "scripts" / "smoke_public_composition.py"
    spec = importlib.util.spec_from_file_location("smoke_public_composition", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _windows_builder_module() -> ModuleType:
    path = ROOT / "packaging" / "build_windows_installer.py"
    spec = importlib.util.spec_from_file_location("build_windows_installer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_version_sources_and_windows_installer_are_consistent() -> None:
    assert __version__ == "2.0.2"
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    installer = (ROOT / "packaging" / "windows" / "ARTIFEX-Setup.nsi").read_text(
        encoding="utf-8"
    )
    builder = (ROOT / "packaging" / "build_windows_installer.py").read_text(
        encoding="utf-8"
    )
    assert f'version = "{__version__}"' in project
    assert f'!define ARTIFEX_VERSION "{__version__}"' in installer
    assert 'VIProductVersion "${ARTIFEX_VERSION}.0"' in installer
    assert '"DisplayVersion" "${ARTIFEX_VERSION}"' in installer
    assert '"product_version": __version__' in builder


def test_public_composition_smoke_supports_native_and_module_launchers() -> None:
    module = _smoke_module()
    native = Path("artifex")
    python = Path("python")
    assert module._command(native, None, "system", "version") == [
        "artifex",
        "system",
        "version",
    ]
    assert module._command(python, "artifex.cli", "system", "version") == [
        "python",
        "-m",
        "artifex.cli",
        "system",
        "version",
    ]
    source = (ROOT / "scripts" / "smoke_public_composition.py").read_text(
        encoding="utf-8"
    )
    assert "arguments.launcher.absolute()" in source
    assert "arguments.launcher.resolve()" not in source


def test_windows_installer_smoke_accepts_mcp_status_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _windows_builder_module()
    completed = subprocess.CompletedProcess(
        ("artifex.exe", "mcp", "test"),
        0,
        '{"status":"PASS","transport":"stdio"}\n',
        "",
    )
    def completed_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return completed

    monkeypatch.setattr(module.subprocess, "run", completed_run)

    result = module._run_json(
        Path("artifex.exe"), ("mcp", "test"), require_ok=False
    )

    assert result["status"] == "PASS"


def test_combined_provider_journey_requires_explicit_patch_version() -> None:
    source = (ROOT / "tools" / "artifex2" / "run_m12_shipping_journey.py").read_text(
        encoding="utf-8"
    )
    assert 'parser.add_argument("--expected-product-version", required=True)' in source
    assert 'artifact_manifest.get("product_version") != expected_product_version' in source
    assert 'PRODUCT_VERSION = "2.0.0"' not in source

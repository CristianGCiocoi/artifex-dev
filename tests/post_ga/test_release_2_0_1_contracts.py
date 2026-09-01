"""ARTIFEX 2.0.1 maintenance release identity and smoke contracts."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from artifex import __version__

ROOT = Path(__file__).resolve().parents[2]


def _smoke_module():  # type: ignore[no-untyped-def]
    path = ROOT / "scripts" / "smoke_public_composition.py"
    spec = importlib.util.spec_from_file_location("smoke_public_composition", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_version_sources_and_windows_installer_are_consistent() -> None:
    assert __version__ == "2.0.1"
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

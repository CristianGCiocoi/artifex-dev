"""Capture a secret-safe M12 Windows qualification-cell preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

EXPECTED_ARTIFACT_SHA256 = (
    "130eb9804369e1ba655fa11ed98be54e606c948b78c30ba297f20d838faca720"
)
MEDIA_ROOT = Path(r"C:\ARTIFEX-M12-Media")
FORBIDDEN_PATHS = (
    Path(r"C:\Program Files\ARTIFEX"),
    Path(r"C:\Users\crugger\AppData\Local\ARTIFEX"),
    Path(r"C:\Users\crugger\AppData\Local\ARTIFEX-M12-Project-VM106"),
    Path(r"C:\Users\crugger\AppData\Local\ARTIFEX-M12-Project-VM106-catalog.sqlite3"),
    Path(r"C:\Users\crugger\AppData\Local\ARTIFEX-M12-Evidence"),
    Path(r"C:\ARTIFEX-M12-M7-Staging-VM106"),
    Path(r"C:\ARTIFEX-M7-Qualification"),
    Path(r"C:\ARTIFEX-M12-Qualification"),
    Path(r"C:\ARTIFEX-M12-J09-Qualification"),
    Path(r"C:\ARTIFEX-M12-J09-Qualification-V2"),
    Path(r"C:\ARTIFEX-M9-Qualification"),
    Path(r"C:\aidev\artifex"),
)


def _present_forbidden_paths(paths: tuple[Path, ...]) -> list[str]:
    """Return every residual product path, including standalone catalog files."""
    return [str(path) for path in paths if path.exists()]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _provider(provider_id: str) -> dict[str, object] | None:
    command = shutil.which(provider_id)
    if command is None:
        return None
    path = Path(command).resolve()
    completed = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    version = (completed.stdout or completed.stderr or "").strip().splitlines()
    if completed.returncode != 0 or not version:
        raise RuntimeError(f"{provider_id} version probe failed")
    return {
        "id": provider_id,
        "command": str(path),
        "executable_sha256": _sha256(path),
        "version": version[0],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--expected-provider", choices=("codex", "claude", "none"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    artifact = MEDIA_ROOT / "ARTIFEX-Setup.exe"
    providers = {name: _provider(name) for name in ("codex", "claude")}
    present = [name for name, value in providers.items() if value is not None]
    expected_present = (
        [] if arguments.expected_provider == "none" else [arguments.expected_provider]
    )
    present_forbidden_paths = _present_forbidden_paths(FORBIDDEN_PATHS)
    artifact_sha256 = _sha256(artifact) if artifact.is_file() else None
    status = (
        "PASS"
        if artifact_sha256 == EXPECTED_ARTIFACT_SHA256
        and present == expected_present
        and not present_forbidden_paths
        and shutil.which("artifex") is None
        and shutil.which("artifex.exe") is None
        and os.environ.get("USERNAME", "").casefold() != "system"
        else "FAIL"
    )
    value = {
        "schema_version": "1.0",
        "status": status,
        "cell": arguments.cell,
        "expected_provider": arguments.expected_provider,
        "present_providers": present,
        "providers": providers,
        "candidate": {
            "path": str(artifact),
            "sha256": artifact_sha256,
            "source_commit": "498cd012830748ea5c492c466146e4129cdbe455",
        },
        "interactive_session": {
            "username": os.environ.get("USERNAME"),
            "session_name": os.environ.get("SESSIONNAME"),
            "non_system_token": os.environ.get("USERNAME", "").casefold() != "system",
            "active_rdp_verified_separately": True,
        },
        "windows": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
        },
        "artifex_command_absent": shutil.which("artifex") is None
        and shutil.which("artifex.exe") is None,
        "present_forbidden_paths": present_forbidden_paths,
        "credential_material_read": False,
        "source_tree_imported": False,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(value, sort_keys=True))
    raise SystemExit(0 if status == "PASS" else 1)


if __name__ == "__main__":
    main()

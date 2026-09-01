"""Smoke an installed ARTIFEX public CLI and managed-service composition."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _command(launcher: Path, module: str | None, *arguments: str) -> list[str]:
    prefix = [str(launcher)]
    if module is not None:
        prefix.extend(("-m", module))
    return [*prefix, *arguments]


def _json_call(launcher: Path, module: str | None, *arguments: str) -> dict[str, object]:
    completed = subprocess.run(
        _command(launcher, module, *arguments),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError(f"public command failed: {' '.join(arguments)}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("public command did not return JSON") from exc
    if not isinstance(value, dict) or value.get("ok") is False:
        raise RuntimeError("public command returned a failure payload")
    return value


def smoke(launcher: Path, module: str | None, expected_version: str) -> None:
    version = _json_call(launcher, module, "system", "version")
    if expected_version not in json.dumps(version, sort_keys=True):
        raise RuntimeError("public version identity differs from the release candidate")
    with tempfile.TemporaryDirectory(prefix="artifex-public-composition-") as directory:
        state_root = Path(directory) / "state"
        service = subprocess.Popen(
            _command(
                launcher,
                module,
                "service",
                "serve",
                "--state-root",
                str(state_root),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if service.poll() is not None:
                    raise RuntimeError("managed service exited before becoming ready")
                try:
                    status = _json_call(
                        launcher,
                        module,
                        "service",
                        "status",
                        "--state-root",
                        str(state_root),
                    )
                except RuntimeError:
                    time.sleep(0.2)
                    continue
                if status.get("ok") is True:
                    break
            else:
                raise RuntimeError("managed service did not become ready")
            stopped = _json_call(
                launcher,
                module,
                "service",
                "stop",
                "--state-root",
                str(state_root),
            )
            if stopped.get("ok") is not True:
                raise RuntimeError("managed service did not accept controlled shutdown")
            service.wait(timeout=30)
            if service.returncode != 0:
                raise RuntimeError("managed service did not stop cleanly")
        finally:
            if service.poll() is None:
                service.terminate()
                try:
                    service.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    service.kill()
                    service.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, default=Path(sys.executable))
    parser.add_argument("--module")
    parser.add_argument("--expected-version", required=True)
    arguments = parser.parse_args()
    smoke(arguments.launcher.resolve(), arguments.module, arguments.expected_version)
    print(
        json.dumps(
            {
                "status": "PASS",
                "version": arguments.expected_version,
                "public_cli": True,
                "managed_service_startup": True,
                "controlled_shutdown": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

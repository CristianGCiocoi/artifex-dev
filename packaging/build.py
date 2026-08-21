"""Build and smoke-test a self-contained native ARTIFEX executable."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("dist/native"))
    parser.add_argument("--work", type=Path, default=Path("build/native"))
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = (root / args.output).resolve() if not args.output.is_absolute() else args.output
    work = (root / args.work).resolve() if not args.work.is_absolute() else args.work
    spec = work / "spec"
    if args.clean:
        shutil.rmtree(output, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "artifex",
        "--paths",
        str(root / "src"),
        "--distpath",
        str(output),
        "--workpath",
        str(work),
        "--specpath",
        str(spec),
        str(root / "src" / "artifex" / "cli.py"),
    ]
    subprocess.run(command, cwd=root, check=True)
    executable = output / ("artifex.exe" if os.name == "nt" else "artifex")
    if not executable.is_file():
        raise FileNotFoundError(f"PyInstaller did not produce {executable}")
    manifest = {
        "schema_version": "1.0",
        "format": "pyinstaller-onefile",
        "platform": sys.platform,
        "artifact": executable.name,
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "requires_user_python": False,
        "requires_user_pip": False,
        "requires_user_venv": False,
    }
    (output / "artifex-artifact.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    if args.smoke:
        for arguments in (("system", "version"), ("mode", "BEGINNER")):
            result = subprocess.run(
                [str(executable), *arguments],
                cwd=output,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"frozen smoke failed for {arguments}: {result.stdout} {result.stderr}"
                )
            payload = json.loads(result.stdout)
            if payload.get("ok") is not True:
                raise RuntimeError(f"frozen smoke returned non-PASS payload: {payload}")
    print(json.dumps({"artifact": str(executable), "manifest": manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

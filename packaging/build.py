"""Build and smoke-test a self-contained native ARTIFEX executable."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from artifex.distribution.artifact import create_artifact_manifest


def validated_clean_targets(root: Path, output: Path, work: Path) -> tuple[Path, Path]:
    """Authorize only the two dedicated repository-local build directories."""

    canonical_root = root.resolve(strict=True)
    expected = (
        (canonical_root / "dist" / "native").resolve(strict=False),
        (canonical_root / "build" / "native").resolve(strict=False),
    )
    observed = (output.resolve(strict=False), work.resolve(strict=False))
    if observed != expected:
        raise ValueError(
            "--clean may only remove the dedicated repository-local "
            "dist/native and build/native directories"
        )
    for lexical, target in zip((output, work), observed, strict=True):
        lexical_absolute = Path(os.path.abspath(lexical))
        try:
            lexical_parts = lexical_absolute.relative_to(canonical_root).parts
        except ValueError as exc:
            raise ValueError("clean target must remain inside the repository") from exc
        cursor = canonical_root
        for part in lexical_parts:
            if part == "..":
                raise ValueError("refusing clean target containing parent traversal")
            cursor = cursor / part
            if cursor.exists() and cursor.is_symlink():
                raise ValueError("refusing clean target containing a symlink")
        if lexical.is_symlink() or target in {canonical_root, Path(target.anchor)}:
            raise ValueError("refusing unsafe or symlinked clean target")
        if (
            canonical_root not in target.parents
            or len(target.relative_to(canonical_root).parts) < 2
        ):
            raise ValueError("clean target must be a sufficiently deep repository child")
    return observed


def _run_frozen_json(executable: Path, arguments: tuple[str, ...]) -> dict[str, object]:
    result = subprocess.run(
        [str(executable), *arguments],
        cwd=executable.parent,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"frozen command failed for {arguments}: {result.stdout} {result.stderr}"
        )
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise RuntimeError(f"frozen command returned non-PASS payload: {payload}")
    return payload


def _source_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _wait_for_lifecycle(executable: Path, manifest: Path, *, operation: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if operation == "upgrade" and executable.is_file() and manifest.is_file():
            try:
                lifecycle_value = json.loads(manifest.read_text(encoding="utf-8"))
                if not lifecycle_value.get("backups"):
                    time.sleep(0.2)
                    continue
                _run_frozen_json(executable, ("system", "version"))
            except (json.JSONDecodeError, OSError, RuntimeError, subprocess.SubprocessError):
                time.sleep(0.2)
                continue
            return
        if operation == "uninstall" and not executable.exists() and not manifest.exists():
            return
        time.sleep(0.2)
    raise RuntimeError(f"frozen self-{operation} helper did not complete")


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
        clean_output, clean_work = validated_clean_targets(root, output, work)
        for clean_target in (clean_output, clean_work):
            if clean_target.exists():
                shutil.rmtree(clean_target)
    output.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--contents-directory",
        "_internal",
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
    bundle = output / "artifex"
    executable = bundle / ("artifex.exe" if os.name == "nt" else "artifex")
    if not executable.is_file():
        raise FileNotFoundError(f"PyInstaller did not produce {executable}")
    manifest = create_artifact_manifest(
        executable,
        pyinstaller_version=importlib.metadata.version("pyinstaller"),
        source_commit=_source_commit(root),
    )
    artifact_manifest_path = bundle / "artifex-artifact.json"
    artifact_manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    if args.smoke:
        for arguments in (("system", "version"), ("mode", "BEGINNER")):
            _run_frozen_json(executable, arguments)
        lifecycle_root = work / f"frozen-lifecycle-smoke-{uuid.uuid4().hex}"
        install_arguments = (
            "install",
            "--install-root",
            str(lifecycle_root),
            "--source-executable",
            str(executable),
        )
        install_plan_payload = _run_frozen_json(executable, install_arguments)
        install_value = install_plan_payload.get("value")
        if not isinstance(install_value, dict):
            raise RuntimeError("frozen install plan did not return a value")
        install_token = install_value.get("confirmation_token")
        if not isinstance(install_token, str):
            raise RuntimeError("frozen install plan did not return a confirmation token")
        _run_frozen_json(
            executable, (*install_arguments, "--apply", "--confirm", install_token)
        )
        installed = lifecycle_root / executable.name
        _run_frozen_json(installed, ("system", "version"))
        upgrade_arguments = (
            "upgrade",
            "--install-root",
            str(lifecycle_root),
            "--source-executable",
            str(executable),
        )
        upgrade_plan_payload = _run_frozen_json(installed, upgrade_arguments)
        upgrade_value = upgrade_plan_payload.get("value")
        if not isinstance(upgrade_value, dict):
            raise RuntimeError("frozen upgrade plan did not return a value")
        upgrade_token = upgrade_value.get("confirmation_token")
        if not isinstance(upgrade_token, str):
            raise RuntimeError("frozen upgrade plan did not return a confirmation token")
        _run_frozen_json(
            installed, (*upgrade_arguments, "--apply", "--confirm", upgrade_token)
        )
        installed_manifest = lifecycle_root / "artifex-install-manifest.json"
        _wait_for_lifecycle(installed, installed_manifest, operation="upgrade")
        unrelated = lifecycle_root / "unmanaged-user-file.txt"
        unrelated.write_text("preserve", encoding="utf-8")
        uninstall_arguments = ("uninstall", "--install-root", str(lifecycle_root))
        uninstall_plan_payload = _run_frozen_json(installed, uninstall_arguments)
        uninstall_value = uninstall_plan_payload.get("value")
        if not isinstance(uninstall_value, dict):
            raise RuntimeError("frozen uninstall plan did not return a value")
        uninstall_token = uninstall_value.get("confirmation_token")
        if not isinstance(uninstall_token, str):
            raise RuntimeError("frozen uninstall plan did not return a confirmation token")
        _run_frozen_json(
            installed, (*uninstall_arguments, "--apply", "--confirm", uninstall_token)
        )
        _wait_for_lifecycle(installed, installed_manifest, operation="uninstall")
        if unrelated.read_text(encoding="utf-8") != "preserve":
            raise RuntimeError("frozen uninstall changed an unmanaged file")
    print(json.dumps({"artifact": str(executable), "manifest": manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

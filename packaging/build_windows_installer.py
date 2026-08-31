"""Build the M7 Windows candidate with Nuitka standalone and NSIS."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from artifex.distribution.artifact import create_artifact_manifest

NSIS_VERSION = "3.12"
NSIS_URL = (
    "https://downloads.sourceforge.net/project/nsis/NSIS%203/"
    f"{NSIS_VERSION}/nsis-{NSIS_VERSION}.zip"
)
NSIS_SHA256 = "56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _commit(root: Path) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _validated_targets(root: Path) -> tuple[Path, Path]:
    targets = (root / "dist" / "windows", root / "build" / "windows")
    canonical = root.resolve(strict=True)
    for target in targets:
        resolved = target.resolve(strict=False)
        if canonical not in resolved.parents or len(resolved.relative_to(canonical).parts) < 2:
            raise ValueError("refusing unsafe Windows packaging target")
        if target.is_symlink():
            raise ValueError("refusing symlinked Windows packaging target")
    return targets


def _nsis(root: Path) -> Path:
    cache = root / "build" / "toolchains"
    archive = cache / f"nsis-{NSIS_VERSION}.zip"
    extracted = cache / f"nsis-{NSIS_VERSION}"
    executable = extracted / "makensis.exe"
    cache.mkdir(parents=True, exist_ok=True)
    if archive.is_file() and _sha256(archive) != NSIS_SHA256:
        archive.unlink()
    if not archive.is_file():
        with urllib.request.urlopen(NSIS_URL, timeout=120) as response:
            payload = response.read()
        if hashlib.sha256(payload).hexdigest() != NSIS_SHA256:
            raise RuntimeError("downloaded NSIS archive digest mismatch")
        archive.write_bytes(payload)
    if not executable.is_file():
        shutil.rmtree(extracted, ignore_errors=True)
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            prefix = f"nsis-{NSIS_VERSION}/"
            if any(
                not member.filename.startswith(prefix)
                or ".." in Path(member.filename).parts
                for member in members
            ):
                raise RuntimeError("NSIS archive contains an unsafe path")
            source.extractall(cache)
    if not executable.is_file():
        raise FileNotFoundError("NSIS makensis.exe is unavailable after verified extraction")
    return executable


def _run_json(executable: Path, arguments: tuple[str, ...]) -> dict[str, object]:
    result = subprocess.run(
        (str(executable), *arguments),
        cwd=executable.parent,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"candidate smoke failed: {result.stdout} {result.stderr}")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError("candidate smoke did not return a successful ARTIFEX result")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output, work = _validated_targets(root)
    if args.clean:
        for target in (output, work):
            shutil.rmtree(target, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    report = work / "nuitka-compilation-report.xml"
    command = (
        sys.executable,
        "-m",
        "nuitka",
        "--mode=standalone",
        "--mingw64",
        "--assume-yes-for-downloads",
        "--output-dir=" + str(work),
        "--output-filename=artifex.exe",
        "--report=" + str(report),
        # Migration backups call sqlite3.iterdump(), which imports sqlite3.dump
        # dynamically. Keep the standard-library helper in the native bundle.
        "--include-module=sqlite3.dump",
        "--include-data-dir=" + str(root / "schemas") + "=artifex/schemas",
        "--include-data-dir=" + str(root / "interface_packs") + "=interface_packs",
        "--product-name=ARTIFEX",
        "--company-name=ARTIFEX Contributors",
        "--file-description=ARTIFEX",
        "--product-version=2.0.0.0",
        "--file-version=2.0.0.0",
        "--copyright=Apache-2.0",
        str(root / "src" / "artifex" / "cli.py"),
    )
    build_environment = os.environ.copy()
    # The Microsoft Store-hosted Codex process has a deeply nested default cache.
    # MinGW cannot resolve its SDK headers reliably from that path, so keep the
    # reproducible Nuitka toolchain cache inside this build tree.
    build_environment["NUITKA_CACHE_DIR"] = str(
        root / "build" / "toolchains" / "nuitka-cache"
    )
    subprocess.run(command, cwd=root, env=build_environment, check=True)
    generated = work / "cli.dist"
    if not generated.is_dir():
        matches = tuple(work.glob("*.dist"))
        if len(matches) != 1:
            raise FileNotFoundError("Nuitka standalone directory was not produced")
        generated = matches[0]
    bundle = output / "artifex"
    if bundle.exists():
        shutil.rmtree(bundle)
    shutil.copytree(generated, bundle)
    executable = bundle / "artifex.exe"
    if not executable.is_file():
        raise FileNotFoundError("Nuitka standalone executable was not produced")
    source_commit = _commit(root)
    manifest = create_artifact_manifest(
        executable,
        packager="nuitka",
        packager_version=importlib.metadata.version("nuitka"),
        source_commit=source_commit,
    )
    (bundle / "artifex-artifact.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    if args.smoke:
        _run_json(executable, ("system", "version"))
        _run_json(executable, ("mode", "BEGINNER"))
    nsis = _nsis(root)
    installer = output / "ARTIFEX-Setup.exe"
    script = root / "packaging" / "windows" / "ARTIFEX-Setup.nsi"
    subprocess.run(
        (
            str(nsis),
            "/V2",
            f"/DARTIFEX_BUNDLE={bundle}",
            f"/DARTIFEX_OUTPUT={installer}",
            str(script),
        ),
        cwd=root,
        check=True,
    )
    provenance = {
        "schema_version": "artifex.windows-installer-provenance/v1",
        "product": "ARTIFEX",
        "product_version": "2.0.0",
        "source_commit": source_commit,
        "build_timestamp_utc": datetime.now(UTC).isoformat(),
        "packaging": {
            "format": "nuitka-standalone+nsis",
            "onefile": False,
            "nuitka_version": importlib.metadata.version("nuitka"),
            "nsis_version": NSIS_VERSION,
            "nsis_archive_sha256": NSIS_SHA256,
            "python_version": sys.version.split()[0],
        },
        "bundle_manifest": manifest,
        "installer": {
            "name": installer.name,
            "sha256": _sha256(installer),
            "bytes": installer.stat().st_size,
        },
    }
    provenance_path = output / "ARTIFEX-Setup.provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "installer": str(installer),
                "installer_sha256": provenance["installer"]["sha256"],
                "provenance": str(provenance_path),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

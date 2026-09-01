"""Validate current ARTIFEX 2.x CI artifacts without changing the V1 verifier.

The historical ``validate_release.py`` remains authoritative for the immutable
V1 candidate contract. This module derives the current version from the exact
candidate commit and validates the source/native artifacts produced by CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Mapping
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from artifex.distribution.artifact import verify_artifact

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCHEMA = "schemas/acceptance-evidence.schema.json"


class CurrentArtifactError(RuntimeError):
    """Current-generation artifact validation failed closed."""


def _git_bytes(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise CurrentArtifactError("candidate Git authority is unavailable")
    return result.stdout


def candidate_version(root: Path, candidate: str) -> str:
    try:
        project = tomllib.loads(
            _git_bytes(root, "show", f"{candidate}:pyproject.toml").decode("utf-8")
        )["project"]
        package_version = project["version"]
        source = _git_bytes(root, "show", f"{candidate}:src/artifex/_version.py").decode(
            "utf-8"
        )
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CurrentArtifactError("candidate version authority is malformed") from exc
    match = re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(package_version))
    source_match = re.search(
        r'^__version__\s*=\s*["\']([^"\']+)["\']', source, flags=re.MULTILINE
    )
    if match is None or source_match is None or source_match.group(1) != package_version:
        raise CurrentArtifactError("candidate version sources disagree")
    if int(str(package_version).split(".", 1)[0]) < 2:
        raise CurrentArtifactError("current artifact validator requires ARTIFEX 2.x or newer")
    return str(package_version)


def _candidate_files(root: Path, candidate: str, prefix: str) -> dict[str, bytes]:
    listing = _git_bytes(root, "ls-tree", "-r", "--name-only", candidate, "--", prefix)
    paths = tuple(path for path in listing.decode("utf-8").splitlines() if path)
    if not paths:
        raise CurrentArtifactError(f"candidate inventory is empty: {prefix}")
    return {path: _git_bytes(root, "show", f"{candidate}:{path}") for path in paths}


def _source_paths(root: Path, candidate: str) -> dict[str, bytes]:
    values = _candidate_files(root, candidate, "src/artifex")
    values[SOURCE_SCHEMA] = _git_bytes(root, "show", f"{candidate}:{SOURCE_SCHEMA}")
    return values


def _validate_schema(content: bytes) -> None:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CurrentArtifactError("packaged acceptance schema is invalid") from exc
    properties = value.get("properties") if isinstance(value, Mapping) else None
    required = value.get("required") if isinstance(value, Mapping) else None
    schema_version = properties.get("schema_version") if isinstance(properties, Mapping) else None
    if (
        not isinstance(schema_version, Mapping)
        or schema_version.get("const") != "2.0"
        or not isinstance(required, list)
        or "independent_of_executor" not in required
    ):
        raise CurrentArtifactError("packaged acceptance schema identity mismatch")


def _wheel_source_name(source: str) -> str:
    if source == SOURCE_SCHEMA:
        return "artifex/schemas/acceptance-evidence.schema.json"
    return source.removeprefix("src/")


def _same_text_source(left: bytes, right: bytes) -> bool:
    """Compare tracked text independently of the checkout newline policy."""

    return left.replace(b"\r\n", b"\n") == right.replace(b"\r\n", b"\n")


def validate_source(root: Path, output: Path, candidate: str) -> dict[str, str]:
    version = candidate_version(root, candidate)
    wheel = output / f"artifex_dev-{version}-py3-none-any.whl"
    sdist = output / f"artifex_dev-{version}.tar.gz"
    if not wheel.is_file() or not sdist.is_file():
        raise CurrentArtifactError("current source build outputs are missing")
    sources = _source_paths(root, candidate)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise CurrentArtifactError("wheel contains duplicate archive members")
        packaged = {
            source: archive.read(_wheel_source_name(source))
            for source in sources
            if _wheel_source_name(source) in names
        }
        if set(packaged) != set(sources) or any(
            not _same_text_source(packaged[source], expected)
            for source, expected in sources.items()
        ):
            raise CurrentArtifactError("wheel source inventory differs from candidate")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata_names) != 1 or len(entry_names) != 1:
            raise CurrentArtifactError("wheel metadata identity is ambiguous")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        if metadata.get("Name") != "artifex-dev" or metadata.get("Version") != version:
            raise CurrentArtifactError("wheel package identity differs from candidate")
        entries = archive.read(entry_names[0]).decode("utf-8")
        for expected in (
            "artifex = artifex.cli:app",
            "artifex-mcp = artifex.mcp:main",
        ):
            if expected not in entries:
                raise CurrentArtifactError("wheel console entry points differ from candidate")
    with tarfile.open(sdist, mode="r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if roots != {f"artifex_dev-{version}"}:
            raise CurrentArtifactError("sdist root identity is ambiguous")
        by_name = {member.name: member for member in members}
        if len(by_name) != len(members):
            raise CurrentArtifactError("sdist contains duplicate archive members")
        prefix = f"artifex_dev-{version}/"
        for source, expected_bytes in sources.items():
            member = by_name.get(prefix + source)
            stream = archive.extractfile(member) if member is not None else None
            if stream is None or not _same_text_source(stream.read(), expected_bytes):
                raise CurrentArtifactError("sdist source inventory differs from candidate")
    _validate_schema(sources[SOURCE_SCHEMA])
    return {
        wheel.name: hashlib.sha256(wheel.read_bytes()).hexdigest(),
        sdist.name: hashlib.sha256(sdist.read_bytes()).hexdigest(),
    }


def smoke_source(root: Path, output: Path, candidate: str) -> None:
    version = candidate_version(root, candidate)
    artifacts = (
        output.resolve() / f"artifex_dev-{version}-py3-none-any.whl",
        output.resolve() / f"artifex_dev-{version}.tar.gz",
    )
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("COV_CORE_") or name == "COVERAGE_PROCESS_START":
            environment.pop(name)
    probe = (
        "import artifex,importlib.resources,json;"
        f"assert artifex.__version__=={version!r};"
        "p=json.loads(importlib.resources.files('artifex').joinpath("
        "'schemas/acceptance-evidence.schema.json').read_text());"
        "assert p['properties']['schema_version']['const']=='2.0';"
        "assert 'independent_of_executor' in p['required']"
    )
    with tempfile.TemporaryDirectory(prefix="artifex-current-source-smoke-") as directory:
        for artifact in artifacts:
            if not artifact.is_file():
                raise CurrentArtifactError(f"source smoke artifact missing: {artifact.name}")
            base = ("uv", "run", "--isolated", "--no-project", "--with", str(artifact))
            measured = subprocess.run(
                (*base, "python", "-c", probe),
                cwd=directory,
                check=False,
                capture_output=True,
                env=environment,
            )
            if measured.returncode != 0:
                raise CurrentArtifactError(
                    f"isolated current source smoke failed: {artifact.name}"
                )
            public_composition = subprocess.run(
                (
                    *base,
                    "python",
                    str(root / "scripts" / "smoke_public_composition.py"),
                    "--module",
                    "artifex.cli",
                    "--expected-version",
                    version,
                ),
                cwd=directory,
                check=False,
                capture_output=True,
                env=environment,
            )
            if public_composition.returncode != 0:
                raise CurrentArtifactError(
                    "isolated public-composition smoke failed: "
                    f"{artifact.name}: "
                    f"{public_composition.stdout.decode(errors='replace')} "
                    f"{public_composition.stderr.decode(errors='replace')}"
                )


def validate_native(root: Path, source: Path, candidate: str, kind: str) -> dict[str, object]:
    identities = {
        "native-windows-x64": ("windows", "x86_64", "artifex.exe"),
        "native-linux-x64": ("linux", "x86_64", "artifex"),
        "native-macos-arm64": ("macos", "arm64", "artifex"),
    }
    if kind not in identities:
        raise CurrentArtifactError("unknown current native artifact kind")
    platform_name, architecture, executable_name = identities[kind]
    executable = source.resolve() / executable_name
    verified = verify_artifact(executable)
    manifest = verified.manifest
    version = candidate_version(root, candidate)
    if (
        manifest.get("product_version") != version
        or manifest.get("source_commit") != candidate
        or manifest.get("platform") != platform_name
        or manifest.get("architecture") != architecture
    ):
        raise CurrentArtifactError("native artifact identity differs from exact candidate")
    return {
        "kind": kind,
        "version": version,
        "source_commit": candidate,
        "sha256": manifest["sha256"],
        "file_count": len(verified.files),
    }


def validate_windows_installer(
    root: Path, source: Path, candidate: str
) -> dict[str, object]:
    output = source.resolve()
    installer = output / "ARTIFEX-Setup.exe"
    provenance_path = output / "ARTIFEX-Setup.provenance.json"
    bundle = output / "artifex"
    if not installer.is_file() or not provenance_path.is_file() or not bundle.is_dir():
        raise CurrentArtifactError("Windows installer outputs are incomplete")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CurrentArtifactError("Windows installer provenance is invalid") from exc
    if not isinstance(provenance, Mapping):
        raise CurrentArtifactError("Windows installer provenance is not an object")
    version = candidate_version(root, candidate)
    if (
        provenance.get("schema_version")
        != "artifex.windows-installer-provenance/v1"
        or provenance.get("product") != "ARTIFEX"
        or provenance.get("product_version") != version
        or provenance.get("source_commit") != candidate
    ):
        raise CurrentArtifactError("Windows installer identity differs from exact candidate")
    packaging = provenance.get("packaging")
    installer_identity = provenance.get("installer")
    if (
        not isinstance(packaging, Mapping)
        or packaging.get("format") != "nuitka-standalone+nsis"
        or not isinstance(installer_identity, Mapping)
        or installer_identity.get("name") != installer.name
    ):
        raise CurrentArtifactError("Windows installer packaging identity is invalid")
    installer_sha256 = hashlib.sha256(installer.read_bytes()).hexdigest()
    if (
        installer_identity.get("sha256") != installer_sha256
        or installer_identity.get("bytes") != installer.stat().st_size
    ):
        raise CurrentArtifactError("Windows installer content differs from provenance")
    verified = verify_artifact(bundle / "artifex.exe")
    if verified.manifest != provenance.get("bundle_manifest"):
        raise CurrentArtifactError("Windows installer bundle differs from provenance")
    if (
        verified.manifest.get("product_version") != version
        or verified.manifest.get("source_commit") != candidate
        or verified.manifest.get("platform") != "windows"
        or verified.manifest.get("architecture") != "x86_64"
    ):
        raise CurrentArtifactError("Windows bundle identity differs from exact candidate")
    return {
        "version": version,
        "source_commit": candidate,
        "installer_sha256": installer_sha256,
        "provenance_sha256": hashlib.sha256(provenance_path.read_bytes()).hexdigest(),
        "bundle_sha256": verified.manifest["sha256"],
        "bundle_file_count": len(verified.files),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "validate-source",
            "smoke-source",
            "validate-native",
            "validate-windows-installer",
        ),
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--kind")
    arguments = parser.parse_args()
    try:
        if arguments.command == "validate-source":
            if arguments.output is None:
                parser.error("validate-source requires --output")
            result: object = validate_source(ROOT, arguments.output, arguments.candidate)
        elif arguments.command == "smoke-source":
            if arguments.output is None:
                parser.error("smoke-source requires --output")
            smoke_source(ROOT, arguments.output, arguments.candidate)
            result = {"smoke": "PASS"}
        elif arguments.command == "validate-native":
            if arguments.input is None or arguments.kind is None:
                parser.error("validate-native requires --input and --kind")
            result = validate_native(ROOT, arguments.input, arguments.candidate, arguments.kind)
        else:
            if arguments.input is None:
                parser.error("validate-windows-installer requires --input")
            result = validate_windows_installer(ROOT, arguments.input, arguments.candidate)
    except (OSError, CurrentArtifactError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "value": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

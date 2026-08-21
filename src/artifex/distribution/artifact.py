"""Strict one-directory artifact provenance and executable attestation."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifex import __version__

ARTIFACT_MANIFEST_NAME = "artifex-artifact.json"
ARTIFACT_SCHEMA_VERSION = "3.0"
ARTIFACT_FORMAT = "pyinstaller-onedir"
PRODUCT_ID = "ARTIFEX"
MAX_IDENTITY_OUTPUT_BYTES = 4096
IDENTITY_PROBE_TIMEOUT_SECONDS = 10.0
_FIELDS = frozenset(
    {
        "schema_version",
        "product",
        "product_version",
        "build_id",
        "format",
        "platform",
        "architecture",
        "artifact",
        "sha256",
        "files",
        "python_version",
        "pyinstaller_version",
        "source_commit",
        "requires_user_python",
        "requires_user_pip",
        "requires_user_venv",
    }
)
_FILE_FIELDS = frozenset({"path", "sha256"})

IdentityProbe = Callable[[Path, float], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    source: Path
    bundle_root: Path
    manifest_path: Path
    manifest: Mapping[str, Any]
    manifest_fingerprint: str
    files: tuple[Mapping[str, str], ...]


def canonical_platform() -> str:
    observed = platform.system().casefold()
    values = {"windows": "windows", "linux": "linux", "darwin": "macos"}
    try:
        return values[observed]
    except KeyError as exc:
        raise ValueError(f"unsupported native artifact platform: {observed}") from exc


def canonical_architecture() -> str:
    observed = platform.machine().casefold().replace("-", "_")
    aliases = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    try:
        return aliases[observed]
    except KeyError as exc:
        raise ValueError(f"unsupported native artifact architecture: {observed}") from exc


def create_artifact_manifest(
    source: str | Path,
    *,
    pyinstaller_version: str | None = None,
    source_commit: str | None = None,
) -> dict[str, Any]:
    artifact = Path(source).resolve()
    if not artifact.is_file() or artifact.is_symlink():
        raise FileNotFoundError(f"native ARTIFEX artifact not found: {artifact}")
    bundle_root = artifact.parent
    files = _bundle_files(bundle_root)
    digest = _sha256(artifact)
    operating_system = canonical_platform()
    architecture = canonical_architecture()
    observed_pyinstaller = pyinstaller_version or importlib.metadata.version("pyinstaller")
    observed_commit = source_commit or _source_commit(Path.cwd())
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "product": PRODUCT_ID,
        "product_version": __version__,
        "build_id": _build_id(__version__, operating_system, architecture, digest),
        "format": ARTIFACT_FORMAT,
        "platform": operating_system,
        "architecture": architecture,
        "artifact": artifact.name,
        "sha256": digest,
        "files": [dict(item) for item in files],
        "python_version": platform.python_version(),
        "pyinstaller_version": observed_pyinstaller,
        "source_commit": observed_commit,
        "requires_user_python": False,
        "requires_user_pip": False,
        "requires_user_venv": False,
    }


def verify_artifact(
    source: str | Path,
    *,
    identity_probe: IdentityProbe | None = None,
) -> VerifiedArtifact:
    artifact = Path(source).resolve()
    bundle_root = artifact.parent
    manifest_path = bundle_root / ARTIFACT_MANIFEST_NAME
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"valid adjacent artifact manifest required: {manifest_path}") from exc
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("artifact manifest schema or fields are invalid")
    files = _validate_manifest_identity(artifact, value)
    probe = identity_probe or probe_artifact_identity
    observed = probe(artifact, IDENTITY_PROBE_TIMEOUT_SECONDS)
    _validate_probe_identity(value, observed)
    return VerifiedArtifact(
        artifact,
        bundle_root,
        manifest_path,
        value,
        hashlib.sha256(_canonical(value)).hexdigest(),
        files,
    )


def probe_artifact_identity(source: Path, timeout_seconds: float) -> Mapping[str, Any]:
    try:
        result = subprocess.run(
            [str(source), "system", "version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"artifact identity probe failed: {type(exc).__name__}") from exc
    output = result.stdout[:MAX_IDENTITY_OUTPUT_BYTES]
    if result.returncode != 0:
        raise ValueError(f"artifact identity probe exited with code {result.returncode}")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError("artifact identity probe did not return JSON") from exc
    if not isinstance(payload, Mapping) or payload.get("ok") is not True:
        raise ValueError("artifact identity probe did not return a successful ARTIFEX result")
    identity = payload.get("value")
    if not isinstance(identity, Mapping):
        raise ValueError("artifact identity probe did not return identity metadata")
    return identity


def runtime_release_identity() -> dict[str, Any]:
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        digest = _sha256(executable)
        operating_system = canonical_platform()
        architecture = canonical_architecture()
        return {
            "product": PRODUCT_ID,
            "version": __version__,
            "build_id": _build_id(__version__, operating_system, architecture, digest),
            "format": ARTIFACT_FORMAT,
            "platform": operating_system,
            "architecture": architecture,
            "artifact": executable.name,
            "sha256": digest,
        }
    return {
        "product": PRODUCT_ID,
        "version": __version__,
        "build_id": "source-development",
        "format": "python-source",
        "platform": canonical_platform(),
        "architecture": canonical_architecture(),
        "artifact": executable.name,
        "sha256": None,
    }


def _validate_manifest_identity(
    artifact: Path, value: Mapping[str, Any]
) -> tuple[Mapping[str, str], ...]:
    if value.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
        raise ValueError("unsupported artifact manifest schema")
    if value.get("product") != PRODUCT_ID or value.get("product_version") != __version__:
        raise ValueError("artifact product or release version does not match this installer")
    if value.get("format") != ARTIFACT_FORMAT:
        raise ValueError("artifact format must be pyinstaller-onedir")
    if value.get("platform") != canonical_platform():
        raise ValueError("artifact platform is incompatible with this system")
    if value.get("architecture") != canonical_architecture():
        raise ValueError("artifact architecture is incompatible with this system")
    if value.get("artifact") != artifact.name:
        raise ValueError("artifact filename does not match its manifest")
    digest = value.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or digest != _sha256(artifact):
        raise ValueError("artifact SHA-256 does not match its manifest")
    expected_build = _build_id(
        __version__, canonical_platform(), canonical_architecture(), digest
    )
    if value.get("build_id") != expected_build:
        raise ValueError("artifact build identity does not match its content")
    for field in ("python_version", "pyinstaller_version"):
        if not isinstance(value.get(field), str) or not str(value[field]).strip():
            raise ValueError(f"artifact provenance field is invalid: {field}")
    commit = value.get("source_commit")
    if not isinstance(commit, str) or re.fullmatch(r"[a-f0-9]{40}", commit) is None:
        raise ValueError("artifact source commit is invalid")
    for field in ("requires_user_python", "requires_user_pip", "requires_user_venv"):
        if value.get(field) is not False:
            raise ValueError(f"artifact manifest must declare {field}=false")
    files = _file_entries(value.get("files"))
    expected_files = _bundle_files(artifact.parent)
    if tuple(files) != tuple(expected_files):
        raise ValueError("artifact bundle file inventory does not match its manifest")
    if not any(item["path"] == artifact.name and item["sha256"] == digest for item in files):
        raise ValueError("artifact executable is absent from the bundle inventory")
    return files


def _validate_probe_identity(
    manifest: Mapping[str, Any], observed: Mapping[str, Any]
) -> None:
    expected = {
        "product": manifest["product"],
        "version": manifest["product_version"],
        "build_id": manifest["build_id"],
        "format": manifest["format"],
        "platform": manifest["platform"],
        "architecture": manifest["architecture"],
        "artifact": manifest["artifact"],
        "sha256": manifest["sha256"],
    }
    if dict(observed) != expected:
        raise ValueError("artifact executable identity does not match its build manifest")


def _bundle_files(root: Path) -> tuple[Mapping[str, str], ...]:
    files: list[Mapping[str, str]] = []
    paths = sorted(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("artifact bundles may not contain symlinks")
    for path in (item for item in paths if item.is_file()):
        if path.name == ARTIFACT_MANIFEST_NAME:
            continue
        files.append(
            {"path": path.relative_to(root).as_posix(), "sha256": _sha256(path)}
        )
    return tuple(files)


def _file_entries(value: object) -> tuple[Mapping[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("artifact file inventory must be an array")
    entries: list[Mapping[str, str]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _FILE_FIELDS:
            raise ValueError("artifact file inventory entry is invalid")
        relative = str(item["path"])
        digest = str(item["sha256"])
        path = Path(relative)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not relative
            or relative in seen
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("artifact file inventory path or digest is invalid")
        seen.add(relative)
        entries.append({"path": path.as_posix(), "sha256": digest})
    return tuple(entries)


def _source_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5,
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[a-f0-9]{40}", commit) is None:
        raise ValueError("cannot determine source Git commit for artifact provenance")
    return commit


def _build_id(version: str, system: str, architecture: str, digest: str) -> str:
    return f"artifex-{version}-{system}-{architecture}-{digest[:16]}"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")

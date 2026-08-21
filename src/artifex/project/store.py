"""Filesystem implementation of the frozen M0 :class:`ProjectStore` seam."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from artifex.project.errors import ArtifactNotFoundError, ProjectError
from artifex.project.paths import normalize_relative_path, resolve_inside


class FileSystemProjectStore:
    """Canonical repository-backed storage with atomic replacement writes."""

    def __init__(self, root: str | Path, *, create: bool = False) -> None:
        candidate = Path(root).expanduser()
        if create:
            candidate.mkdir(parents=True, exist_ok=True)
        if not candidate.exists():
            raise ArtifactNotFoundError(f"project root does not exist: {candidate}")
        if not candidate.is_dir():
            raise ProjectError(f"project root is not a directory: {candidate}")
        self._root = candidate.resolve()

    @property
    def root(self) -> Path:
        return self._root

    def read(self, relative_path: str) -> bytes:
        normalized, target = resolve_inside(self._root, relative_path)
        try:
            return target.read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactNotFoundError(f"artifact does not exist: {normalized}") from exc
        except IsADirectoryError as exc:
            raise ArtifactNotFoundError(f"artifact is not a file: {normalized}") from exc

    def write_atomic(self, relative_path: str, content: bytes) -> None:
        if not isinstance(content, bytes):
            raise TypeError("ProjectStore content must be bytes")
        _, target = resolve_inside(self._root, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Re-resolve after mkdir to guard against a concurrently introduced
        # symlink ancestor before creating the temporary file.
        _, target = resolve_inside(self._root, relative_path)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            _sync_directory(target.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def exists(self, relative_path: str) -> bool:
        _, target = resolve_inside(self._root, relative_path)
        return target.is_file()

    def iter_files(self) -> Iterable[str]:
        files: list[str] = []
        for candidate in self._root.rglob("*"):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            relative = candidate.relative_to(self._root)
            if relative.parts and relative.parts[0] == ".git":
                continue
            files.append(normalize_relative_path(relative.as_posix()))
        return iter(sorted(files))

    def fingerprint(self, relative_path: str) -> str:
        return hashlib.sha256(self.read(relative_path)).hexdigest()


def _sync_directory(directory: Path) -> None:
    """Best-effort directory sync; Windows cannot open directories this way."""

    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

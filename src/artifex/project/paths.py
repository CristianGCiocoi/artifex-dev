"""Cross-platform repository path validation."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from artifex.project.errors import UnsafePathError

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def normalize_relative_path(relative_path: str) -> str:
    """Return a canonical POSIX repository path or reject an unsafe path.

    Backslashes are accepted as separators so a path produced on Windows has
    identical semantics on POSIX. Absolute, drive-qualified, UNC, empty and
    parent-traversing paths are rejected on every host platform.
    """

    if not isinstance(relative_path, str):
        raise UnsafePathError("repository path must be a string")
    if not relative_path or "\x00" in relative_path:
        raise UnsafePathError("repository path must be non-empty and contain no NUL")
    portable = relative_path.replace("\\", "/")
    if portable.startswith(("/", "//")) or _WINDOWS_DRIVE.match(portable):
        raise UnsafePathError(f"absolute repository path is forbidden: {relative_path!r}")
    parts = portable.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafePathError(f"path is not normalized: {relative_path!r}")
    for part in parts:
        if part.endswith((" ", ".")) or any(
            character in _WINDOWS_FORBIDDEN or ord(character) < 32 for character in part
        ):
            raise UnsafePathError(f"path is not portable across supported hosts: {relative_path!r}")
        reserved_name = part.split(".", 1)[0].upper()
        if reserved_name in _WINDOWS_RESERVED:
            raise UnsafePathError(f"reserved Windows path is forbidden: {relative_path!r}")
    return PurePosixPath(*parts).as_posix()


def resolve_inside(root: Path, relative_path: str) -> tuple[str, Path]:
    """Resolve *relative_path* and prove that it stays beneath *root*.

    ``Path.resolve(strict=False)`` resolves any existing symlink ancestors,
    preventing writes through a repository symlink into an external location.
    """

    normalized = normalize_relative_path(relative_path)
    canonical_root = root.resolve()
    target = canonical_root.joinpath(*normalized.split("/")).resolve(strict=False)
    if not target.is_relative_to(canonical_root):
        raise UnsafePathError(f"path escapes project root: {relative_path!r}")
    return normalized, target

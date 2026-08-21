"""Storage seams frozen at M0."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Protocol


class ProjectStore(Protocol):
    """Semantic state store backed by inspectable repository files."""

    @property
    def root(self) -> Path: ...

    def read(self, relative_path: str) -> bytes: ...

    def write_atomic(self, relative_path: str, content: bytes) -> None: ...

    def exists(self, relative_path: str) -> bool: ...

    def iter_files(self) -> Iterable[str]: ...

    def fingerprint(self, relative_path: str) -> str: ...


class RunStore(Protocol):
    """Replaceable coordination state seam; V1 requires no database."""

    def put(self, run_id: str, value: Mapping[str, Any]) -> None: ...

    def get(self, run_id: str) -> Mapping[str, Any] | None: ...

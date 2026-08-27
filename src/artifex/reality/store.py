"""Append-only repository-local Observation and Divergence stores."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TypeVar

from artifex.project.errors import ArtifactCorruptError
from artifex.project.paths import resolve_inside
from artifex.reality.models import Divergence, Observation

OBSERVATION_STORE_PATH = ".artifex/reality/observations.jsonl"
DIVERGENCE_STORE_PATH = ".artifex/reality/divergences.jsonl"

Record = TypeVar("Record", Observation, Divergence)


class RealityStore:
    """Durable sourced facts; it is intentionally not Project semantic authority."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise FileNotFoundError(f"Project root does not exist: {self.root}")

    def append_observation(self, observation: Observation) -> None:
        self._append(OBSERVATION_STORE_PATH, observation.to_dict())

    def append_divergence(self, divergence: Divergence) -> None:
        self._append(DIVERGENCE_STORE_PATH, divergence.to_dict())

    def observations(self) -> tuple[Observation, ...]:
        return tuple(
            Observation.from_dict(item) for item in self._read(OBSERVATION_STORE_PATH)
        )

    def divergences(self) -> tuple[Divergence, ...]:
        by_id: dict[str, Divergence] = {}
        for item in self._read(DIVERGENCE_STORE_PATH):
            divergence = Divergence.from_dict(item)
            by_id[divergence.divergence_id] = divergence
        return tuple(by_id[key] for key in sorted(by_id))

    def _append(self, relative_path: str, value: Mapping[str, object]) -> None:
        self._read(relative_path)
        _, target = resolve_inside(self.root, relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        _, target = resolve_inside(self.root, relative_path)
        encoded = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode("utf-8")
        descriptor = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise OSError("partial Observed Reality append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _read(self, relative_path: str) -> tuple[Mapping[str, object], ...]:
        _, target = resolve_inside(self.root, relative_path)
        if not target.exists():
            return ()
        values: list[Mapping[str, object]] = []
        try:
            with target.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.endswith("\n"):
                        raise ArtifactCorruptError(
                            f"Observed Reality store has a truncated line at {line_number}"
                        )
                    value = json.loads(line)
                    if not isinstance(value, Mapping):
                        raise ValueError("Observed Reality entry is not an object")
                    values.append(value)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ArtifactCorruptError):
                raise
            raise ArtifactCorruptError(
                f"invalid Observed Reality store: {relative_path}"
            ) from exc
        return tuple(values)


__all__ = ["DIVERGENCE_STORE_PATH", "OBSERVATION_STORE_PATH", "RealityStore"]

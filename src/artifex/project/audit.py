"""Append-only JSONL audit history for significant Project Model events."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from artifex.project.errors import ArtifactCorruptError
from artifex.project.paths import resolve_inside


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    actor: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    commit: str | None = None
    occurred_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if not self.event_type.strip() or not self.actor.strip():
            raise ValueError("audit event type and actor must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "commit": self.commit,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AuditEvent:
        payload = value.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ValueError("audit payload must be an object")
        return cls(
            event_id=str(value["event_id"]),
            event_type=str(value["event_type"]),
            occurred_at=str(value["occurred_at"]),
            actor=str(value["actor"]),
            commit=str(value["commit"]) if value.get("commit") is not None else None,
            payload=dict(payload),
        )


class AuditLog:
    """Write-only-at-the-tail audit file with corruption detection."""

    def __init__(self, root: str | Path, path: str = ".artifex/audit.jsonl") -> None:
        self.root = Path(root).resolve()
        self.path, self._target = resolve_inside(self.root, path)

    def append(self, event: AuditEvent) -> None:
        # Refuse to append after malformed history; silently extending a broken
        # ledger would make provenance ambiguous.
        self.read_all()
        self._target.parent.mkdir(parents=True, exist_ok=True)
        _, target = resolve_inside(self.root, self.path)
        encoded = (
            json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
        descriptor = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise OSError("partial audit event append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def read_all(self) -> tuple[AuditEvent, ...]:
        _, target = resolve_inside(self.root, self.path)
        if not target.exists():
            return ()
        events: list[AuditEvent] = []
        try:
            with target.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.endswith("\n"):
                        raise ArtifactCorruptError(
                            f"audit history has a truncated line at {line_number}"
                        )
                    value = json.loads(line)
                    if not isinstance(value, Mapping):
                        raise ValueError("audit entry is not an object")
                    events.append(AuditEvent.from_dict(value))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ArtifactCorruptError):
                raise
            raise ArtifactCorruptError(f"invalid audit history: {self.path}") from exc
        return tuple(events)

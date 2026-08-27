"""Dependency-aware lifecycle for non-authoritative Project documentation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifex.compilation import (
    GeneratedViewState,
    compile_human_documentation,
    fingerprint_sources,
    human_document_sources,
    render_human_document,
)
from artifex.project.authority import SemanticRevision
from artifex.project.store import FileSystemProjectStore

DOCUMENTATION_DIRECTORY = ".artifex/docs"
DOCUMENTATION_MANIFEST_PATH = f"{DOCUMENTATION_DIRECTORY}/manifest.json"


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class DocumentationStatus:
    name: str
    path: str
    state: GeneratedViewState
    generated_for_revision: int | None
    source_fingerprints: Mapping[str, str]
    content_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "state": self.state.value,
            "generated_for_revision": self.generated_for_revision,
            "source_fingerprints": dict(self.source_fingerprints),
            "content_sha256": self.content_sha256,
        }


class DocumentationLifecycle:
    """Maintain documentation provenance without treating generated files as truth."""

    def __init__(self, root: str | Path) -> None:
        self.store = FileSystemProjectStore(root)

    def establish_baseline(self, revision: SemanticRevision) -> tuple[DocumentationStatus, ...]:
        rendered = compile_human_documentation(revision.model.to_dict())
        entries: dict[str, dict[str, Any]] = {}
        for name, content in rendered.items():
            path = f"{DOCUMENTATION_DIRECTORY}/{name}"
            encoded = content.encode("utf-8")
            self.store.write_atomic(path, encoded)
            entries[name] = self._entry(revision, name, encoded, GeneratedViewState.CURRENT)
        self._write_manifest(revision, entries)
        return self.status(revision)

    def mark_accepted_change(
        self, previous: SemanticRevision, current: SemanticRevision
    ) -> tuple[DocumentationStatus, ...]:
        """Mark only documents whose consumed semantic inputs changed as STALE."""

        entries = self._entries()
        if not entries:
            self.establish_baseline(previous)
            entries = self._entries()
        before = previous.model.to_dict()
        after = current.model.to_dict()
        for name, entry in entries.items():
            old_sources = fingerprint_sources(human_document_sources(before, name))
            new_sources = fingerprint_sources(human_document_sources(after, name))
            if old_sources != new_sources:
                entry["state"] = GeneratedViewState.STALE.value
            entry["current_source_fingerprints"] = new_sources
        self._write_manifest(current, entries)
        return self.status(current)

    def regenerate(
        self,
        revision: SemanticRevision,
        names: Sequence[str] | None = None,
    ) -> tuple[DocumentationStatus, ...]:
        """Regenerate a requested stale subset, or every stale/missing document."""

        current = {item.name: item for item in self.status(revision)}
        available = tuple(compile_human_documentation(revision.model.to_dict()))
        requested = tuple(dict.fromkeys(names or ()))
        unknown = sorted(set(requested) - set(available))
        if unknown:
            raise ValueError(f"unsupported documentation targets: {', '.join(unknown)}")
        selected = requested or tuple(
            name
            for name in available
            if name not in current
            or current[name].state in {GeneratedViewState.STALE, GeneratedViewState.MISSING}
        )
        entries = self._entries()
        for name in selected:
            content = render_human_document(revision.model.to_dict(), name).encode("utf-8")
            self.store.write_atomic(f"{DOCUMENTATION_DIRECTORY}/{name}", content)
            entries[name] = self._entry(revision, name, content, GeneratedViewState.CURRENT)
        self._write_manifest(revision, entries)
        return self.status(revision)

    def status(self, revision: SemanticRevision) -> tuple[DocumentationStatus, ...]:
        entries = self._entries()
        available = tuple(compile_human_documentation(revision.model.to_dict()))
        statuses: list[DocumentationStatus] = []
        for name in available:
            path = f"{DOCUMENTATION_DIRECTORY}/{name}"
            entry = entries.get(name)
            expected_sources = fingerprint_sources(
                human_document_sources(revision.model.to_dict(), name)
            )
            generated_revision: int | None = None
            recorded_sources: dict[str, str] = {}
            recorded_digest: str | None = None
            state = GeneratedViewState.MISSING
            if entry is not None:
                generated = entry.get("generated_for_revision")
                generated_revision = int(generated) if isinstance(generated, int) else None
                sources = entry.get("source_fingerprints", {})
                if isinstance(sources, Mapping):
                    recorded_sources = {str(key): str(value) for key, value in sources.items()}
                digest = entry.get("content_sha256")
                recorded_digest = str(digest) if isinstance(digest, str) else None
                state = GeneratedViewState(str(entry.get("state", "STALE")))
            if not self.store.exists(path):
                state = GeneratedViewState.MISSING
            else:
                actual_digest = self.store.fingerprint(path)
                if recorded_digest != actual_digest or recorded_sources != expected_sources:
                    state = GeneratedViewState.STALE
            statuses.append(
                DocumentationStatus(
                    name=name,
                    path=path,
                    state=state,
                    generated_for_revision=generated_revision,
                    source_fingerprints=recorded_sources,
                    content_sha256=recorded_digest,
                )
            )
        return tuple(statuses)

    def _entry(
        self,
        revision: SemanticRevision,
        name: str,
        content: bytes,
        state: GeneratedViewState,
    ) -> dict[str, Any]:
        return {
            "path": f"{DOCUMENTATION_DIRECTORY}/{name}",
            "state": state.value,
            "generated_for_revision": revision.number,
            "source_fingerprints": fingerprint_sources(
                human_document_sources(revision.model.to_dict(), name)
            ),
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "generator": f"human-renderer-v1:{name}",
        }

    def _entries(self) -> dict[str, dict[str, Any]]:
        if not self.store.exists(DOCUMENTATION_MANIFEST_PATH):
            return {}
        try:
            value = json.loads(self.store.read(DOCUMENTATION_MANIFEST_PATH))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("documentation lifecycle manifest is corrupt") from exc
        if not isinstance(value, Mapping) or not isinstance(value.get("documents"), Mapping):
            raise ValueError("documentation lifecycle manifest is invalid")
        result: dict[str, dict[str, Any]] = {}
        for name, entry in value["documents"].items():
            if not isinstance(name, str) or not isinstance(entry, Mapping):
                raise ValueError("documentation lifecycle manifest entry is invalid")
            result[name] = dict(entry)
        return result

    def _write_manifest(
        self, revision: SemanticRevision, entries: Mapping[str, Mapping[str, Any]]
    ) -> None:
        value = {
            "schema_version": "2.0",
            "kind": "PROJECT_DOCUMENTATION_LIFECYCLE",
            "authoritative": False,
            "derived_from": "PROJECT_AUTHORITY",
            "project_id": revision.project_id,
            "current_semantic_revision": revision.number,
            "current_semantic_fingerprint": revision.fingerprint,
            "documents": {name: dict(entries[name]) for name in sorted(entries)},
        }
        self.store.write_atomic(DOCUMENTATION_MANIFEST_PATH, _json_bytes(value))


__all__ = [
    "DOCUMENTATION_DIRECTORY",
    "DOCUMENTATION_MANIFEST_PATH",
    "DocumentationLifecycle",
    "DocumentationStatus",
]

"""Filesystem stores with mechanical project/instance/integration isolation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar

from artifex.project import FileSystemProjectStore

from .model import CandidateOverlay, ImprovementProposal, KnowledgeItem, KnowledgeScope

_NAMESPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_T = TypeVar("_T", KnowledgeItem, ImprovementProposal, CandidateOverlay)


class KnowledgeIsolationError(ValueError):
    """Raised when a write would cross a project, instance, or Core boundary."""


class _JsonCollection:
    def __init__(self, root: Path, filename: str) -> None:
        self._store = FileSystemProjectStore(root, create=True)
        self._filename = filename

    @property
    def root(self) -> Path:
        return self._store.root

    def load(self) -> list[Mapping[str, Any]]:
        if not self._store.exists(self._filename):
            return []
        value = json.loads(self._store.read(self._filename))
        if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
            raise ValueError(f"invalid knowledge collection: {self._filename}")
        return list(value)

    def append_unique(self, identifier: str, value: Mapping[str, Any]) -> None:
        records = self.load()
        if any(item.get("id") == identifier for item in records):
            raise ValueError(f"duplicate knowledge identifier: {identifier}")
        records.append(value)
        content = json.dumps(records, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        self._store.write_atomic(self._filename, content + b"\n")


class ProjectLessonStore:
    """Canonical PROJECT-scoped lessons beneath one repository root."""

    def __init__(self, project_root: str | Path, project_id: str) -> None:
        self.project_id = _namespace(project_id, "project_id")
        root = Path(project_root).resolve() / ".artifex" / "knowledge" / "project"
        self._lessons = _JsonCollection(root, "lessons.json")

    @property
    def root(self) -> Path:
        return self._lessons.root

    def add(self, lesson: KnowledgeItem) -> None:
        if lesson.scope is not KnowledgeScope.PROJECT or lesson.project_id != self.project_id:
            raise KnowledgeIsolationError("project store accepts only its own PROJECT knowledge")
        self._lessons.append_unique(str(lesson.id), lesson.to_dict())

    def list(self) -> tuple[KnowledgeItem, ...]:
        items = tuple(KnowledgeItem.from_dict(item) for item in self._lessons.load())
        if any(
            item.scope is not KnowledgeScope.PROJECT or item.project_id != self.project_id
            for item in items
        ):
            raise KnowledgeIsolationError("project knowledge collection is scope-contaminated")
        return items


class InstanceKnowledgeStore:
    """One instance namespace, physically separated from Core and peers."""

    def __init__(
        self,
        state_root: str | Path,
        instance_id: str,
        *,
        core_root: str | Path | None = None,
    ) -> None:
        self.instance_id = _namespace(instance_id, "instance_id")
        state = Path(state_root).resolve()
        self.core_root = Path(core_root).resolve() if core_root is not None else None
        instance_root = (state / "instances" / self.instance_id).resolve()
        if self.core_root is not None and (
            instance_root == self.core_root
            or instance_root.is_relative_to(self.core_root)
            or self.core_root.is_relative_to(instance_root)
        ):
            raise KnowledgeIsolationError("instance state and installed Core must be disjoint")
        self._root = instance_root
        self._knowledge = _JsonCollection(instance_root, "knowledge.json")
        self._proposals = _JsonCollection(instance_root, "improvement-proposals.json")
        self._overlays = _JsonCollection(instance_root, "candidate-overlays.json")
        self._core_fingerprint = _tree_fingerprint(self.core_root) if self.core_root else None

    @property
    def root(self) -> Path:
        return self._root

    def add(self, item: KnowledgeItem) -> None:
        if item.scope is not KnowledgeScope.INSTANCE:
            raise KnowledgeIsolationError("instance store accepts only INSTANCE knowledge")
        self._knowledge.append_unique(str(item.id), item.to_dict())
        self.assert_core_unchanged()

    def list(self) -> tuple[KnowledgeItem, ...]:
        items = tuple(KnowledgeItem.from_dict(item) for item in self._knowledge.load())
        if any(item.scope is not KnowledgeScope.INSTANCE for item in items):
            raise KnowledgeIsolationError("instance knowledge collection is scope-contaminated")
        return items

    def add_proposal(self, proposal: ImprovementProposal) -> None:
        self._proposals.append_unique(str(proposal.id), proposal.to_dict())
        self.assert_core_unchanged()

    def list_proposals(self) -> tuple[ImprovementProposal, ...]:
        return tuple(ImprovementProposal.from_dict(item) for item in self._proposals.load())

    def add_overlay(self, overlay: CandidateOverlay) -> None:
        self._overlays.append_unique(overlay.id, overlay.to_dict())
        self.assert_core_unchanged()

    def list_overlays(self) -> tuple[CandidateOverlay, ...]:
        return tuple(CandidateOverlay.from_dict(item) for item in self._overlays.load())

    def add_integration_memory(self, integration: str, item: KnowledgeItem) -> None:
        """Persist auxiliary harness memory in a provider-specific namespace."""

        provider = _namespace(integration.lower(), "integration")
        if item.scope is not KnowledgeScope.HARNESS:
            raise KnowledgeIsolationError("integration memory must remain HARNESS-scoped")
        declared = {
            provenance.integration.lower()
            for provenance in item.provenance
            if provenance.integration
        }
        if declared != {provider}:
            raise KnowledgeIsolationError(
                "integration provenance must match its isolated namespace"
            )
        collection = _JsonCollection(self._root / "integrations" / provider, "memory.json")
        collection.append_unique(str(item.id), item.to_dict())
        self.assert_core_unchanged()

    def list_integration_memory(self, integration: str) -> tuple[KnowledgeItem, ...]:
        provider = _namespace(integration.lower(), "integration")
        collection = _JsonCollection(self._root / "integrations" / provider, "memory.json")
        items = tuple(KnowledgeItem.from_dict(item) for item in collection.load())
        if any(
            item.scope is not KnowledgeScope.HARNESS
            or {p.integration.lower() for p in item.provenance if p.integration} != {provider}
            for item in items
        ):
            raise KnowledgeIsolationError("integration memory collection is contaminated")
        return items

    def assert_core_unchanged(self) -> None:
        if (
            self.core_root is not None
            and _tree_fingerprint(self.core_root) != self._core_fingerprint
        ):
            raise KnowledgeIsolationError("installed Core changed while writing instance evolution")


def _namespace(value: str, name: str) -> str:
    if not _NAMESPACE.fullmatch(value):
        raise KnowledgeIsolationError(f"invalid {name}: {value!r}")
    return value


def _tree_fingerprint(root: Path | None) -> str | None:
    if root is None:
        return None
    digest = hashlib.sha256()
    if not root.exists():
        raise FileNotFoundError(f"Core root does not exist: {root}")
    for path in sorted(
        item for item in root.rglob("*") if item.is_file() and not item.is_symlink()
    ):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

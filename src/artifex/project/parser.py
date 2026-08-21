"""Parsers for canonical Markdown, YAML, and JSON artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any

import yaml  # type: ignore[import-untyped]

from artifex.ids import StableId
from artifex.project.errors import ArtifactCorruptError
from artifex.project.model import Artifact, ArtifactStatus, Provenance
from artifex.project.paths import normalize_relative_path

_SUPPORTED_SUFFIXES = {".md", ".markdown", ".yaml", ".yml", ".json"}
_ID_TOKEN = re.compile(
    r"(?<![A-Z0-9-])(?:REQ-(?:F|NF)-\d{3}|ADR-[A-Z0-9][A-Z0-9-]*-\d{3}|INV-\d{3}|"
    r"M\d{2}(?:-T\d{2})?|(?:VAL|EVD|WAV|LES|IMP|CHG|ART|STG|INT|RSR|RBL)-"
    r"[A-Z0-9][A-Z0-9-]*)(?![A-Z0-9-])"
)


class ArtifactParser:
    """Parse one managed artifact without granting its content authority."""

    def parse(self, path: str, content: bytes, *, commit: str | None = None) -> Artifact:
        normalized = normalize_relative_path(path)
        suffix = PurePosixPath(normalized).suffix.lower()
        if suffix not in _SUPPORTED_SUFFIXES:
            raise ArtifactCorruptError(f"unsupported artifact format: {normalized}")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactCorruptError(f"artifact is not UTF-8: {normalized}") from exc
        metadata: Mapping[str, Any]
        if suffix in {".md", ".markdown"}:
            metadata = self._markdown_metadata(text, normalized)
        else:
            metadata = self._structured_metadata(text, normalized, suffix)
        try:
            json.dumps(metadata)
        except (TypeError, ValueError) as exc:
            raise ArtifactCorruptError(
                f"artifact metadata is not JSON-compatible: {normalized}"
            ) from exc
        artifact_id = self._artifact_id(metadata, normalized, text)
        dependencies = self._dependencies(metadata, normalized)
        status_value = str(metadata.get("status", "DRAFT")).upper()
        try:
            status = ArtifactStatus(status_value)
        except ValueError as exc:
            raise ArtifactCorruptError(
                f"invalid artifact status in {normalized}: {status_value}"
            ) from exc
        return Artifact(
            id=artifact_id,
            type=str(metadata.get("type", _default_type(suffix))),
            path=normalized,
            status=status,
            fingerprint=hashlib.sha256(content).hexdigest(),
            depends_on=dependencies,
            provenance=Provenance(normalized, commit),
            metadata=dict(metadata),
        )

    @staticmethod
    def _markdown_metadata(text: str, path: str) -> Mapping[str, Any]:
        if not text.startswith("---"):
            return {}
        lines = text.splitlines()
        if not lines or lines[0].strip() != "---":
            return {}
        try:
            end = next(index for index, line in enumerate(lines[1:], 1) if line.strip() == "---")
        except StopIteration as exc:
            raise ArtifactCorruptError(f"unterminated Markdown front matter: {path}") from exc
        try:
            value = yaml.safe_load("\n".join(lines[1:end]))
        except yaml.YAMLError as exc:
            raise ArtifactCorruptError(f"invalid Markdown front matter: {path}") from exc
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ArtifactCorruptError(f"Markdown front matter must be an object: {path}")
        return value

    @staticmethod
    def _structured_metadata(text: str, path: str, suffix: str) -> Mapping[str, Any]:
        try:
            value = json.loads(text) if suffix == ".json" else yaml.safe_load(text)
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            raise ArtifactCorruptError(f"invalid structured artifact: {path}") from exc
        if not isinstance(value, Mapping):
            raise ArtifactCorruptError(f"structured artifact must be an object: {path}")
        return value

    @staticmethod
    def _artifact_id(metadata: Mapping[str, Any], path: str, text: str) -> StableId:
        candidate = metadata.get("id")
        if candidate is None:
            filename_match = _ID_TOKEN.search(PurePosixPath(path).stem.upper())
            heading_match = _ID_TOKEN.search(text[:2048].upper())
            match = filename_match or heading_match
            candidate = match.group(0) if match else None
        if not isinstance(candidate, str):
            raise ArtifactCorruptError(f"managed artifact has no stable id: {path}")
        try:
            return StableId.parse(candidate)
        except ValueError as exc:
            raise ArtifactCorruptError(f"invalid stable id in {path}: {candidate!r}") from exc

    @staticmethod
    def _dependencies(metadata: Mapping[str, Any], path: str) -> tuple[StableId, ...]:
        raw = metadata.get("depends_on", [])
        if raw is None:
            return ()
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            raise ArtifactCorruptError(f"depends_on must be an array: {path}")
        try:
            return tuple(StableId.parse(str(value)) for value in raw)
        except ValueError as exc:
            raise ArtifactCorruptError(f"invalid dependency id: {path}") from exc


def _default_type(suffix: str) -> str:
    return "markdown" if suffix in {".md", ".markdown"} else "structured"

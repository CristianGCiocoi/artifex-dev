"""Pure projection from the typed Project Model to the compilation read model."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from artifex.compilation._util import canonical_json, copy_json

# This vocabulary is the union of the semantic fields consumed by the V1
# renderers, packets, dashboard, and comprehension gates.  Keeping it explicit
# prevents an accepted artifact from introducing a new instruction surface by
# placing arbitrary keys in the reserved namespace.
UNDERSTANDING_FIELDS: frozenset[str] = frozenset(
    {
        "acceptance_contracts",
        "admin_guide",
        "architecture",
        "authority",
        "capabilities",
        "components",
        "concepts",
        "core_components",
        "decisions",
        "deployment",
        "developer_guide",
        "extension_points",
        "extensions",
        "history",
        "implementation",
        "integrations",
        "interfaces",
        "invariants",
        "known_limitations",
        "limitations",
        "migration",
        "milestones",
        "operations",
        "paper",
        "permissions",
        "project_history",
        "purpose",
        "recovery",
        "requirements",
        "runbook",
        "security",
        "status",
        "tasks",
        "testing",
        "upgrade",
        "user_guide",
        "validation",
        "versioning",
        "workflow",
        "workflows",
    }
)

_TYPED_MODEL_FIELDS = frozenset({"schema_version", "project", "git", "artifacts", "entities"})
_ENTITY_COLLECTIONS: dict[str, str] = {
    "requirement": "requirements",
    "invariant": "invariants",
    "capability": "capabilities",
    "interface": "interfaces",
    "milestone": "milestones",
    "task": "tasks",
}


def _is_typed_project_model(project_model: Mapping[str, Any]) -> bool:
    """Recognize the closed V1 schema without changing rich-mapping callers."""

    required = {"schema_version", "project", "git", "artifacts", "entities"}
    if not required <= set(project_model) or not set(project_model) <= _TYPED_MODEL_FIELDS:
        return False
    artifacts = project_model.get("artifacts")
    entities = project_model.get("entities")
    return (
        isinstance(artifacts, Sequence)
        and not isinstance(artifacts, (str, bytes, bytearray))
        and isinstance(entities, Sequence)
        and not isinstance(entities, (str, bytes, bytearray))
    )


def _accepted_understanding(project_model: Mapping[str, Any]) -> dict[str, Any]:
    artifacts = project_model["artifacts"]
    assert isinstance(artifacts, Sequence)
    accepted = sorted(
        (
            artifact
            for artifact in artifacts
            if isinstance(artifact, Mapping) and artifact.get("status") == "ACCEPTED"
        ),
        key=lambda artifact: str(artifact.get("id", "")),
    )
    projected: dict[str, Any] = {}
    contributors: dict[str, str] = {}
    for artifact in accepted:
        metadata = artifact.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError(f"accepted artifact {artifact.get('id')} has invalid metadata")
        if "understanding" not in metadata:
            continue
        understanding = metadata["understanding"]
        if not isinstance(understanding, Mapping):
            raise ValueError(
                f"accepted artifact {artifact.get('id')} has invalid metadata.understanding"
            )
        unknown = sorted(str(key) for key in understanding if str(key) not in UNDERSTANDING_FIELDS)
        if unknown:
            raise ValueError(
                f"accepted artifact {artifact.get('id')} has unknown understanding fields: "
                + ", ".join(unknown)
            )
        for field in sorted(understanding, key=str):
            name = str(field)
            value = copy_json(understanding[field])
            if name in projected and canonical_json(projected[name]) != canonical_json(value):
                raise ValueError(
                    f"conflicting accepted understanding field {name}: "
                    f"{contributors[name]} and {artifact.get('id')}"
                )
            projected[name] = value
            contributors[name] = str(artifact.get("id", ""))
    return projected


def _entity_fallbacks(project_model: Mapping[str, Any]) -> dict[str, list[Any]]:
    entities = project_model["entities"]
    assert isinstance(entities, Sequence)
    collections: dict[str, list[Any]] = {
        collection: [] for collection in _ENTITY_COLLECTIONS.values()
    }
    typed = sorted(
        (entity for entity in entities if isinstance(entity, Mapping)),
        key=lambda entity: (str(entity.get("id", "")), str(entity.get("kind", ""))),
    )
    for entity in typed:
        collection = _ENTITY_COLLECTIONS.get(str(entity.get("kind", "")))
        if collection is not None:
            collections[collection].append(copy_json(entity))
    return collections


def project_understanding(project_model: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached deterministic read model for compilation.

    Schema-valid typed inputs receive accepted semantic contributions and typed
    entity fallbacks.  Existing rich mappings are copied unchanged.  The caller
    must retain the raw input for provenance and fingerprint generation.
    """

    if not isinstance(project_model, Mapping):
        raise TypeError("project_model must be a Mapping")
    copied = copy_json(project_model)
    assert isinstance(copied, dict)
    if not _is_typed_project_model(project_model):
        return copied

    projected = _accepted_understanding(project_model)
    for field, value in _entity_fallbacks(project_model).items():
        if field not in projected and value:
            projected[field] = value
    project = project_model.get("project")
    if "purpose" not in projected and isinstance(project, Mapping):
        description = project.get("description")
        if description is not None:
            projected["purpose"] = copy_json(description)
    copied.update(projected)
    return copied


__all__ = ["UNDERSTANDING_FIELDS", "project_understanding"]

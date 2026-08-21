"""Deterministic, side-effect-free helpers used by compilation views."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any, cast

JSONScalar = str | int | float | bool | None
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def copy_json(value: Any) -> JSONValue:
    """Return a detached JSON-shaped value or fail at the compilation boundary."""

    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("compilation inputs must be JSON-serializable") from exc
    return cast(JSONValue, json.loads(serialized))


def canonical_json(value: Any) -> str:
    """Serialize a JSON-shaped value in the canonical ARTIFEX view format."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def fingerprint_value(value: Any) -> str:
    if isinstance(value, bytes):
        content = value
    elif isinstance(value, str):
        content = value.encode("utf-8")
    else:
        content = canonical_json(value).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def model_fingerprint(project_model: Mapping[str, Any]) -> str:
    return fingerprint_value(project_model)


def as_mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a Mapping")
    return value


def as_sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()


def lookup(model: Mapping[str, Any], *paths: str) -> Any:
    """Return the first present dotted path without treating false values as absent."""

    for path in paths:
        current: Any = model
        found = True
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                found = False
                break
            current = current[part]
        if found:
            return current
    return None


def project_identity(model: Mapping[str, Any]) -> dict[str, JSONValue]:
    project = lookup(model, "project")
    if not isinstance(project, Mapping):
        project = model
    keys = (
        "id",
        "name",
        "description",
        "lifecycle",
        "workflow_depth",
        "experience_mode",
        "autonomy_mode",
        "architecture_version",
        "implementation_plan_version",
    )
    result = {key: copy_json(project[key]) for key in keys if key in project}
    if not result:
        raise ValueError("project_model must contain project identity data")
    return result


def title(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").strip().title()


def stable_items(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return [value[key] for key in sorted(value, key=str)]
    return list(as_sequence(value))


def detached_mapping(value: Mapping[str, Any]) -> dict[str, JSONValue]:
    copied = copy_json(deepcopy(dict(value)))
    assert isinstance(copied, dict)
    return copied

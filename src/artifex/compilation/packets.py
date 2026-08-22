"""Context and immutable execution packet compilers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from artifex.compilation._util import copy_json, lookup, model_fingerprint, project_identity
from artifex.compilation.freshness import generation_manifest
from artifex.compilation.projection import project_understanding

_CONTEXT_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("purpose", ("purpose", "project.description")),
    ("architecture", ("architecture",)),
    ("core_components", ("core_components", "architecture.components", "components")),
    ("workflows", ("workflows", "workflow.stages")),
    ("capabilities", ("capabilities",)),
    ("interfaces", ("interfaces", "integrations.interfaces")),
    ("invariants", ("invariants",)),
    ("extension_points", ("extension_points", "extensions")),
    ("known_limitations", ("known_limitations", "limitations")),
    ("implementation_state", ("implementation", "status")),
)


def _find_task(project_model: Mapping[str, Any], task_id: str) -> Any:
    tasks = lookup(project_model, "tasks", "implementation.tasks")
    if isinstance(tasks, Mapping):
        return tasks.get(task_id)
    if isinstance(tasks, Sequence) and not isinstance(tasks, (str, bytes, bytearray)):
        return next(
            (task for task in tasks if isinstance(task, Mapping) and task.get("id") == task_id),
            None,
        )
    return None


def _select_context(project_model: Mapping[str, Any]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for output_name, source_paths in _CONTEXT_PATHS:
        value = lookup(project_model, *source_paths)
        if value is not None:
            selected[output_name] = copy_json(value)
    return selected


def _relevant_artifacts(
    project_model: Mapping[str, Any], relevant_ids: Sequence[str]
) -> list[Any]:
    artifacts = lookup(project_model, "artifacts.items", "artifacts")
    if isinstance(artifacts, Mapping):
        items = [
            {"id": str(identifier), **dict(value)}
            if isinstance(value, Mapping) and "id" not in value
            else value
            for identifier, value in artifacts.items()
        ]
    elif isinstance(artifacts, Sequence) and not isinstance(artifacts, (str, bytes, bytearray)):
        items = list(artifacts)
    else:
        return []
    by_id = {
        str(item["id"]): item for item in items if isinstance(item, Mapping) and "id" in item
    }
    selected: set[str] = set(relevant_ids)
    pending = list(relevant_ids)
    while pending:
        item = by_id.get(pending.pop())
        if not isinstance(item, Mapping):
            continue
        dependencies = item.get("depends_on", item.get("dependencies", ()))
        if not isinstance(dependencies, Sequence) or isinstance(
            dependencies, (str, bytes, bytearray)
        ):
            continue
        for dependency in map(str, dependencies):
            if dependency not in selected:
                selected.add(dependency)
                pending.append(dependency)
    return [copy_json(by_id[identifier]) for identifier in sorted(selected) if identifier in by_id]


def compile_context_packet(
    project_model: Mapping[str, Any],
    *,
    task_id: str | None = None,
    relevant_ids: Sequence[str] = (),
    additional_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile minimum sufficient semantic context, excluding history by default."""

    if not isinstance(project_model, Mapping):
        raise TypeError("project_model must be a Mapping")
    read_model = project_understanding(project_model)
    context = _select_context(read_model)
    if task_id is not None:
        task = _find_task(read_model, task_id)
        context["focus"] = {"task_id": task_id}
        if isinstance(task, Mapping):
            dependencies = task.get("dependencies", task.get("depends_on", ()))
            context["focus"]["dependencies"] = copy_json(dependencies)
    if relevant_ids:
        context.setdefault("focus", {})["relevant_ids"] = sorted(set(relevant_ids))
        artifacts = _relevant_artifacts(read_model, relevant_ids)
        if artifacts:
            context["relevant_artifacts"] = artifacts
    if additional_context:
        # Explicit caller-provided context is accepted, but cannot replace provenance.
        context["additional"] = copy_json(additional_context)
    return {
        "schema_version": "1.0",
        "kind": "CONTEXT_PACKET",
        "generated_view": generation_manifest(project_model, generator="context-packet-v1"),
        "project": project_identity(read_model),
        "context": context,
        "project_model_fingerprint": model_fingerprint(project_model),
    }


def compile_execution_packet(
    project_model: Mapping[str, Any],
    task: Mapping[str, Any],
    acceptance_contract: Mapping[str, Any],
    *,
    ownership: Mapping[str, Any] | None = None,
    permissions: Sequence[str] = (),
    expected_output: Any = None,
    relevant_ids: Sequence[str] = (),
    context_packet: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile an executor-neutral, fingerprinted execution contract view."""

    if not isinstance(project_model, Mapping):
        raise TypeError("project_model must be a Mapping")
    if not isinstance(task, Mapping) or not task:
        raise ValueError("task must be a non-empty Mapping")
    if not isinstance(acceptance_contract, Mapping) or not acceptance_contract:
        raise ValueError("acceptance_contract must be a non-empty Mapping")
    task_id = task.get("id")
    packet = (
        copy_json(context_packet)
        if context_packet is not None
        else compile_context_packet(
            project_model,
            task_id=str(task_id) if task_id is not None else None,
            relevant_ids=relevant_ids,
        )
    )
    if not isinstance(packet, dict) or packet.get("kind") != "CONTEXT_PACKET":
        raise ValueError("context_packet must be a compiled CONTEXT_PACKET")
    execution = {
        "schema_version": "1.0",
        "kind": "EXECUTION_PACKET",
        "generated_view": generation_manifest(project_model, generator="execution-packet-v1"),
        "context_packet": packet,
        "task": copy_json(task),
        "acceptance_contract": copy_json(acceptance_contract),
        "ownership": copy_json(ownership or {}),
        "permissions": sorted(set(permissions)),
        "expected_output": copy_json(expected_output),
    }
    # Fingerprinting the entire immutable contract makes later weakening observable.
    execution["execution_contract_fingerprint"] = model_fingerprint(execution)
    return execution


__all__ = ["compile_context_packet", "compile_execution_packet"]

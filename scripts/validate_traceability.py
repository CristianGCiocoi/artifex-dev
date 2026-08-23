"""Deterministically verify full V1 requirement traceability."""

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import jsonschema  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]

from artifex.project import ProjectRepository
from artifex.validation import (
    EvidenceClassification,
    ValidationError,
    classify_evidence_payload,
    evidence_from_payload,
)

ROOT = Path(__file__).parents[1]
ID_PATTERN = re.compile(r"REQ-(?:F|NF)-\d{3}")
RANGE_PATTERN = re.compile(r"^(REQ-(?:F|NF)-)(\d{3})\.\.(\d{3})$")
TRACE_MAPS = ("architecture", "ownership", "tasks", "evidence", "gates")
CATALOG_KEYS = {
    "architecture": "architecture",
    "ownership": "milestones",
    "tasks": "tasks",
    "evidence": "evidence",
    "gates": "gates",
}


class _UniqueYamlLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _unique_yaml_mapping(
    loader: _UniqueYamlLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    value: dict[object, object] = {}
    for key_node, item_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in value:
            raise ValueError(f"duplicate YAML key: {key}")
        value[key] = loader.construct_object(item_node, deep=deep)
    return value


_UniqueYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_yaml_mapping
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _json_loads(value: str | bytes) -> object:
    return json.loads(value, object_pairs_hook=_unique_json_object)


def _canonical_model_digest(value: object) -> str:
    if not isinstance(value, Mapping):
        raise ValueError("canonical Project Model is not an object")
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _committed_blob(root: Path, relative: str) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(root), "show", f"HEAD:{relative}"),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"committed traceability source unavailable: {relative}")
    return result.stdout


def _normalized_architecture(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("&", "and")).strip().casefold()


def _safe_authority_file(root: Path, path: Path) -> Path:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("authority path escapes repository") from exc
    cursor = root
    for part in relative.parts:
        if part in {"", ".", ".."}:
            raise ValueError("authority path contains unsafe components")
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("authority path contains a symlink")
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("authority path escapes repository") from exc
    if not path.is_file():
        raise ValueError("authority path is not a file")
    return path


def _authoritative_definitions(
    root: Path,
) -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]], tuple[str, ...]]:
    evidence_root = root / ".artifex" / "validation" / "evidence"
    gate_root = root / ".artifex" / "validation" / "gates"
    errors: list[str] = []
    model = _json_loads((root / ".artifex/project-model.json").read_bytes())
    if not isinstance(model, Mapping):
        raise ValueError("canonical Project Model is not an object")
    schema = _json_loads((root / "schemas/project-model.schema.json").read_bytes())
    if not isinstance(schema, Mapping):
        raise ValueError("canonical Project Model schema is not an object")
    jsonschema.Draft202012Validator(schema).validate(model)
    typed_model = ProjectRepository(root).load()
    entities = model.get("entities")
    artifacts = model.get("artifacts")
    if not isinstance(entities, list) or not isinstance(artifacts, list):
        raise ValueError("canonical Project Model typed collections missing")
    accepted_artifact_ids = {
        str(artifact.id)
        for artifact in typed_model.artifacts
        if artifact.status.value == "ACCEPTED"
    }
    entity_ids: dict[str, set[str]] = {"requirement": set(), "milestone": set(), "task": set()}
    entity_artifacts: dict[str, str] = {}
    task_dependencies: dict[str, set[str]] = {}
    for entity in entities:
        if not isinstance(entity, Mapping):
            raise ValueError("canonical Project Model entity is malformed")
        kind, entity_id = entity.get("kind"), entity.get("id")
        if (
            kind in entity_ids
            and isinstance(entity_id, str)
            and entity.get("artifact_id") in accepted_artifact_ids
        ):
            entity_ids[str(kind)].add(entity_id)
            entity_artifacts[entity_id] = str(entity["artifact_id"])
            if kind == "task" and isinstance(entity.get("depends_on"), list):
                task_dependencies[entity_id] = {
                    item for item in entity["depends_on"] if isinstance(item, str)
                }
    architecture: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or artifact.get("status") != "ACCEPTED":
            continue
        metadata = artifact.get("metadata")
        understanding = metadata.get("understanding") if isinstance(metadata, Mapping) else None
        components = (
            understanding.get("core_components") if isinstance(understanding, Mapping) else None
        )
        if isinstance(components, list):
            if (
                any(not isinstance(item, str) or not item.strip() for item in components)
                or len(set(components)) != len(components)
            ):
                errors.append("Project Model architecture authority is malformed")
                continue
            normalized = {_normalized_architecture(item) for item in components}
            if len(normalized) != len(components):
                errors.append("Project Model architecture normalization is not injective")
                continue
            architecture.update(normalized)
    evidence_ids: set[str] = set()
    evidence_contracts: dict[str, str] = {}
    for path in (
        *tuple(evidence_root.glob("EVD-*.yaml")),
        *tuple(evidence_root.glob("EVD-*.json")),
    ):
        if path.stem == "EVD-M10" or path.stem.startswith("EVD-M10-"):
            continue
        try:
            path = _safe_authority_file(root, path)
            payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueYamlLoader)
            if not isinstance(payload, Mapping):
                raise ValidationError("document is not an object")
            classification = classify_evidence_payload(payload)
            internal_id: object
            outcome: object
            contract_hash: object
            if classification is EvidenceClassification.CANONICAL:
                validator_id, version = (
                    payload.get("validator_id"),
                    payload.get("validator_version"),
                )
                if not isinstance(validator_id, str) or not isinstance(version, str):
                    raise ValidationError("validator identity missing")
                entry = evidence_from_payload(
                    payload,
                    trusted_validators={validator_id: version},
                    require_independent=False,
                )
                internal_id = entry.evidence_id
                outcome = entry.outcome.value
                contract_hash = entry.binding.contract_hash
            else:
                wrapped = payload.get("evidence")
                if isinstance(wrapped, Mapping):
                    source, result = wrapped.get("source"), wrapped.get("result")
                    internal_id = wrapped.get("id")
                    outcome = result.get("status") if isinstance(result, Mapping) else None
                    contract_hash = (
                        source.get("contract_hash") if isinstance(source, Mapping) else None
                    )
                else:
                    binding = payload.get("binding")
                    internal_id = payload.get("evidence_id")
                    outcome = payload.get("outcome")
                    contract_hash = (
                        binding.get("contract_hash") if isinstance(binding, Mapping) else None
                    )
            if (
                internal_id != path.stem
                or outcome != "PASS"
                or not isinstance(contract_hash, str)
                or len(contract_hash) != 64
            ):
                raise ValidationError("internal ID does not match filename")
            evidence_ids.add(path.stem)
            evidence_contracts[path.stem] = contract_hash
        except (OSError, ValueError, yaml.YAMLError, ValidationError) as exc:
            errors.append(f"invalid evidence authority {path.name}: {exc}")
    gate_ids: set[str] = set()
    gate_targets: dict[str, str] = {}
    gate_evidence: dict[str, set[str]] = {}
    for path in gate_root.glob("G-*.yaml"):
        if path.stem == "G-M10-MILESTONE":
            continue
        try:
            path = _safe_authority_file(root, path)
            payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueYamlLoader)
            gate = payload.get("gate") if isinstance(payload, Mapping) else None
            if not isinstance(gate, Mapping):
                raise ValueError("gate object missing")
            if (
                gate.get("id") != path.stem
                or not isinstance(gate.get("target"), str)
                or gate.get("state") != "PASS"
                or not isinstance(gate.get("required_evidence"), list)
                or not gate.get("required_evidence")
                or any(
                    not isinstance(item, str) or not item
                    for item in gate.get("required_evidence", ())
                )
                or gate.get("waiver_allowed") is not False
                or not isinstance(gate.get("contract_hash"), str)
                or len(str(gate.get("contract_hash"))) != 64
            ):
                raise ValueError("gate identity/schema invalid")
            contract_hash = str(gate["contract_hash"])
            if any(
                evidence_contracts.get(str(evidence_id)) != contract_hash
                for evidence_id in gate["required_evidence"]
            ):
                raise ValueError("gate evidence/contract binding mismatch")
            gate_ids.add(path.stem)
            gate_targets[path.stem] = str(gate["target"])
            gate_evidence[path.stem] = {str(item) for item in gate["required_evidence"]}
        except (OSError, ValueError, yaml.YAMLError) as exc:
            errors.append(f"invalid gate authority {path.name}: {exc}")
    authority = {
        "requirements": entity_ids["requirement"],
        "architecture": architecture,
        "milestones": entity_ids["milestone"],
        "tasks": entity_ids["task"],
        "evidence": evidence_ids,
        "gates": gate_ids,
    }
    expected: dict[str, dict[str, set[str]]] = {}
    artifact_payloads = {
        str(artifact["id"]): artifact
        for artifact in artifacts
        if isinstance(artifact, Mapping)
        and isinstance(artifact.get("id"), str)
        and artifact.get("status") == "ACCEPTED"
    }
    requirements_by_artifact: dict[str, set[str]] = {}
    for requirement in entity_ids["requirement"]:
        requirements_by_artifact.setdefault(entity_artifacts[requirement], set()).add(requirement)
    for artifact_id, artifact in artifact_payloads.items():
        metadata = artifact.get("metadata")
        manifest = metadata.get("traceability_expected") if isinstance(metadata, Mapping) else None
        owned_requirements = requirements_by_artifact.get(artifact_id, set())
        if not owned_requirements:
            if manifest is not None:
                errors.append(
                    f"traceability authority declared by non-requirements artifact: {artifact_id}"
                )
            continue
        if not isinstance(manifest, Mapping) or set(manifest) != {
            "schema_version",
            "requirements",
        }:
            errors.append(f"traceability authority manifest missing or malformed: {artifact_id}")
            continue
        declared_requirements = manifest.get("requirements")
        if manifest.get("schema_version") != "1.0" or not isinstance(
            declared_requirements, Mapping
        ):
            errors.append(f"traceability authority manifest schema mismatch: {artifact_id}")
            continue
        declared_ids = {
            item for item in declared_requirements if isinstance(item, str)
        }
        if declared_ids != owned_requirements or len(declared_ids) != len(declared_requirements):
            errors.append(f"traceability authority requirement catalog mismatch: {artifact_id}")
        for requirement in owned_requirements:
            raw_mapping = declared_requirements.get(requirement)
            if not isinstance(raw_mapping, Mapping) or set(raw_mapping) != set(TRACE_MAPS):
                errors.append(f"traceability authority mapping malformed: {requirement}")
                continue
            parsed: dict[str, set[str]] = {}
            malformed = False
            for map_name in TRACE_MAPS:
                values = raw_mapping.get(map_name)
                if (
                    not isinstance(values, list)
                    or not values
                    or any(not isinstance(item, str) or not item for item in values)
                    or len(set(values)) != len(values)
                ):
                    errors.append(
                        f"traceability authority values malformed: {requirement}:{map_name}"
                    )
                    malformed = True
                    continue
                parsed[map_name] = {
                    _normalized_architecture(item) if map_name == "architecture" else item
                    for item in values
                }
                if len(parsed[map_name]) != len(values):
                    errors.append(
                        f"traceability authority normalization collision: "
                        f"{requirement}:{map_name}"
                    )
                    malformed = True
                    continue
                unknown = parsed[map_name] - authority[CATALOG_KEYS[map_name]]
                if unknown:
                    errors.append(
                        f"traceability authority references unknown {map_name}: "
                        f"{requirement}:{','.join(sorted(unknown))}"
                    )
                    malformed = True
            if malformed:
                continue
            milestones = parsed["ownership"]
            if any(
                task.split("-T", 1)[0] not in milestones
                or (
                    task_dependencies.get(task)
                    and not (task_dependencies[task] & milestones)
                )
                for task in parsed["tasks"]
            ):
                errors.append(f"traceability authority task/milestone mismatch: {requirement}")
            if any(gate_targets.get(gate) not in milestones for gate in parsed["gates"]):
                errors.append(f"traceability authority gate/milestone mismatch: {requirement}")
            required_evidence = set().union(
                *(gate_evidence[gate] for gate in parsed["gates"])
            )
            if parsed["evidence"] != required_evidence:
                errors.append(f"traceability authority gate/evidence mismatch: {requirement}")
            expected[requirement] = parsed
    missing_authority = entity_ids["requirement"] - set(expected)
    if missing_authority:
        errors.append(
            "requirements missing accepted traceability authority: "
            f"{','.join(sorted(missing_authority))}"
        )
    return authority, expected, tuple(errors)


@dataclass(frozen=True, slots=True)
class TraceabilityReport:
    requirements_total: int
    traced_by_map: Mapping[str, int]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


def expand(key: str) -> set[str]:
    match = RANGE_PATTERN.fullmatch(key)
    if match is None:
        return {key}
    prefix, start, end = match.groups()
    if int(start) > int(end):
        raise ValueError(f"descending requirement range: {key}")
    return {f"{prefix}{number:03d}" for number in range(int(start), int(end) + 1)}


def _expanded_keys(mapping: Mapping[object, object]) -> set[str]:
    expanded: set[str] = set()
    for key in mapping:
        expanded.update(expand(str(key)))
    return expanded


def measure(root: Path = ROOT) -> tuple[set[str], set[str], set[str]]:
    """Preserve the V0 ownership/architecture measurement API."""

    requirements = root / "docs" / "requirements" / "REQUIREMENTS_BASELINE.md"
    traceability = root / ".artifex" / "implementation" / "traceability.yaml"
    accepted = set(ID_PATTERN.findall(requirements.read_text(encoding="utf-8")))
    payload = yaml.safe_load(traceability.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("traceability document is not an object")
    maps = payload.get("maps") if payload.get("schema_version") == "2.0" else payload
    ownership = maps.get("ownership") if isinstance(maps, Mapping) else None
    architecture = maps.get("architecture") if isinstance(maps, Mapping) else None
    if not isinstance(ownership, Mapping) or not isinstance(architecture, Mapping):
        raise ValueError("ownership and architecture maps are required")
    return accepted, _expanded_keys(ownership), _expanded_keys(architecture)


def validate_traceability(root: Path = ROOT) -> TraceabilityReport:
    requirements_path = root / "docs" / "requirements" / "REQUIREMENTS_BASELINE.md"
    traceability_path = root / ".artifex" / "implementation" / "traceability.yaml"
    try:
        documented = set(ID_PATTERN.findall(requirements_path.read_text(encoding="utf-8")))
        payload = yaml.load(
            traceability_path.read_text(encoding="utf-8"), Loader=_UniqueYamlLoader
        )
        authoritative, expected_mappings, authority_errors = _authoritative_definitions(root)
        accepted = authoritative["requirements"]
    except (OSError, yaml.YAMLError) as exc:
        return TraceabilityReport(0, {}, (f"cannot read traceability inputs: {exc}",))
    except (ValueError, jsonschema.ValidationError) as exc:
        return TraceabilityReport(0, {}, (f"cannot derive typed traceability authority: {exc}",))
    if not isinstance(payload, Mapping):
        return TraceabilityReport(len(accepted), {}, ("traceability document is not an object",))

    if set(payload) != {"schema_version", "source", "policy", "definitions", "maps", "metrics"}:
        return TraceabilityReport(len(accepted), {}, ("traceability v2 top-level schema mismatch",))
    source, policy, metrics = payload.get("source"), payload.get("policy"), payload.get("metrics")
    requirements_raw = _committed_blob(root, "docs/requirements/REQUIREMENTS_BASELINE.md")
    if (
        payload.get("schema_version") != "2.0"
        or source
        != {
            "project_model_sha256": _canonical_model_digest(
                _json_loads((root / ".artifex/project-model.json").read_bytes())
            ),
            "requirements_baseline_sha256": hashlib.sha256(requirements_raw).hexdigest(),
        }
        or policy
        != {
            "mapping": "accepted-project-model-traceability-manifest",
            "catalogs_exact": True,
        }
    ):
        return TraceabilityReport(len(accepted), {}, ("traceability v2 source/policy mismatch",))
    definitions = payload.get("definitions")
    maps = payload.get("maps")
    errors: list[str] = list(authority_errors)
    if documented != accepted:
        errors.append("requirements baseline differs from typed Project Model")
    if not isinstance(definitions, Mapping):
        errors.append("missing definitions catalog")
        definitions = {}
    elif set(definitions) != set(CATALOG_KEYS.values()):
        errors.append("definition catalog keys are not exact")
    if not isinstance(maps, Mapping) or set(maps) != set(TRACE_MAPS):
        errors.append("traceability map keys are not exact")
    traced_by_map: dict[str, int] = {}
    for map_name in TRACE_MAPS:
        raw_mapping = maps.get(map_name) if isinstance(maps, Mapping) else None
        if not isinstance(raw_mapping, Mapping):
            errors.append(f"missing traceability map: {map_name}")
            traced_by_map[map_name] = 0
            continue
        expanded: set[str] = set()
        referenced: set[str] = set()
        owners_by_requirement: dict[str, list[str]] = {}
        for raw_key, raw_owners in raw_mapping.items():
            key = str(raw_key)
            try:
                key_requirements = expand(key)
                collisions = sorted(key_requirements & set(owners_by_requirement))
                if collisions:
                    errors.append(
                        f"{map_name} overlapping requirement keys: {','.join(collisions)}"
                    )
                expanded.update(key_requirements)
            except ValueError as exc:
                errors.append(str(exc))
                key_requirements = set()
            if (
                not isinstance(raw_owners, list)
                or not raw_owners
                or any(not isinstance(owner, str) or not owner for owner in raw_owners)
                or len(set(raw_owners)) != len(raw_owners)
            ):
                errors.append(f"traceability entry has no valid owner: {map_name}:{key}")
            else:
                referenced.update(raw_owners)
                for requirement in key_requirements:
                    owners_by_requirement.setdefault(requirement, raw_owners)
        orphan = sorted(accepted - expanded)
        unknown = sorted(expanded - accepted)
        if orphan:
            errors.append(f"{map_name} orphan requirements: {','.join(orphan)}")
        if unknown:
            errors.append(f"{map_name} unknown requirements: {','.join(unknown)}")
        catalog_key = CATALOG_KEYS[map_name]
        catalog = definitions.get(catalog_key)
        if (
            not isinstance(catalog, list)
            or any(not isinstance(item, str) for item in catalog)
            or len(set(catalog)) != len(catalog)
        ):
            errors.append(f"missing definition catalog: {catalog_key}")
        else:
            authoritative_catalog = authoritative[catalog_key]
            declared = {
                _normalized_architecture(item) if catalog_key == "architecture" else item
                for item in catalog
            }
            normalized_references = {
                _normalized_architecture(item) if catalog_key == "architecture" else item
                for item in referenced
            }
            if catalog_key == "architecture" and len(declared) != len(catalog):
                errors.append("architecture definition normalization collision")
            if catalog_key == "architecture" and len(normalized_references) != len(referenced):
                errors.append("architecture reference normalization collision")
            invented_definitions = sorted(declared - authoritative_catalog)
            missing_definitions = sorted(authoritative_catalog - declared)
            unknown_references = sorted(normalized_references - declared)
            if invented_definitions:
                errors.append(
                    f"{map_name} definitions absent from repository: "
                    f"{','.join(invented_definitions)}"
                )
            if missing_definitions:
                errors.append(
                    f"{map_name} definitions missing from exact catalog: "
                    f"{','.join(missing_definitions)}"
                )
            if unknown_references:
                errors.append(f"{map_name} unknown references: {','.join(unknown_references)}")
        traced_by_map[map_name] = len(accepted & expanded)
        for requirement in accepted:
            owners = owners_by_requirement.get(requirement)
            expected = expected_mappings.get(requirement, {}).get(map_name, set())
            normalized = (
                {
                    _normalized_architecture(item) if map_name == "architecture" else item
                    for item in owners
                }
                if isinstance(owners, list)
                else set()
            )
            if normalized != expected:
                errors.append(f"{map_name} semantic mapping mismatch: {requirement}")
    expected_metrics = {"requirements_total": len(accepted)} | {
        f"{name}_traced": traced_by_map.get(name, 0) for name in TRACE_MAPS
    }
    if metrics != expected_metrics:
        errors.append("traceability metrics mismatch")
    return TraceabilityReport(len(accepted), traced_by_map, tuple(errors))


def main() -> int:
    report = validate_traceability(ROOT)
    counts = " ".join(f"{name}={report.traced_by_map.get(name, 0)}" for name in TRACE_MAPS)
    print(f"requirements_total={report.requirements_total} {counts}")
    for error in report.errors:
        print(f"BLOCKER {error}")
    print("traceability=PASS" if report.passed else "traceability=BLOCKED")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())

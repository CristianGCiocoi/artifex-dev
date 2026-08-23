"""Canonical, fail-closed persistence for ARTIFEX acceptance evidence."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]

from artifex.validation.core import (
    EvidenceBinding,
    EvidenceEntry,
    EvidenceOutcome,
    MeasuredFact,
    ValidationError,
    ValidatorKind,
)

EVIDENCE_SCHEMA_VERSION = "2.0"
_PACKAGED_SCHEMA = Path(__file__).parents[1] / "schemas" / "acceptance-evidence.schema.json"
_SOURCE_SCHEMA = Path(__file__).parents[3] / "schemas" / "acceptance-evidence.schema.json"
DEFAULT_SCHEMA = _PACKAGED_SCHEMA if _PACKAGED_SCHEMA.is_file() else _SOURCE_SCHEMA


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects ambiguous last-key-wins documents."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValidationError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_unique_json_object)


class EvidenceClassification(StrEnum):
    """Persistence trust class; only CANONICAL may satisfy current gates."""

    CANONICAL = "CANONICAL"
    LEGACY_HISTORICAL = "LEGACY_HISTORICAL"


@dataclass(frozen=True, slots=True)
class DecodedEvidence:
    classification: EvidenceClassification
    entry: EvidenceEntry | None
    reason: str | None = None


_EVIDENCE_ID = re.compile(r"EVD-[A-Z0-9][A-Z0-9-]*")
_GATE_ID = re.compile(r"G-[A-Z0-9][A-Z0-9-]*")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _aware_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.tzinfo is not None and timestamp.utcoffset() is not None


def _finite_json_value(value: object) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_finite_json_value(item) for item in value)
    if isinstance(value, Mapping):
        return all(
            isinstance(key, str) and _finite_json_value(item)
            for key, item in value.items()
        )
    return False


def _flat_legacy_integrity(payload: Mapping[str, Any]) -> bool:
    try:
        validator = payload["validator"]
        binding = payload["binding"]
        facts = payload["facts"]
        assert isinstance(validator, Mapping)
        assert isinstance(binding, Mapping)
        assert isinstance(facts, list)
        entry = EvidenceEntry(
            evidence_id=payload["evidence_id"],
            validator_id=validator["id"],
            validator_version=validator["version"],
            validator_kind=ValidatorKind(validator["kind"]),
            claim=payload["claim"],
            outcome=EvidenceOutcome(payload["outcome"]),
            facts=tuple(MeasuredFact(item["name"], item["value"]) for item in facts),
            binding=EvidenceBinding(
                binding["base_commit"],
                binding["contract_hash"],
                tuple(binding["project_model_fingerprints"]),
            ),
            output=payload["output"],
            recorded_at=datetime.fromisoformat(payload["recorded_at"].replace("Z", "+00:00")),
            producer_id=payload["producer_id"],
            independent_of_executor=True,
            entry_hash=payload["entry_hash"],
        )
    except (AssertionError, KeyError, TypeError, ValueError):
        return False
    return entry.verify_integrity()


def evidence_to_payload(entry: EvidenceEntry) -> dict[str, Any]:
    """Return the schema-2.0 representation used by YAML, JSON, and journals."""

    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_id": entry.evidence_id,
        "validator_id": entry.validator_id,
        "validator_version": entry.validator_version,
        "validator_kind": entry.validator_kind.value,
        "claim": entry.claim,
        "outcome": entry.outcome.value,
        "facts": [{"name": fact.name, "value": fact.value} for fact in entry.facts],
        "binding": {
            "base_commit": entry.binding.base_commit,
            "contract_hash": entry.binding.contract_hash,
            "project_model_fingerprints": list(entry.binding.project_model_fingerprints),
        },
        "output": entry.output,
        "recorded_at": entry.recorded_at.isoformat(),
        "producer_id": entry.producer_id,
        "independent_of_executor": entry.independent_of_executor,
        "entry_hash": entry.entry_hash,
    }


def _schema(path: Path = DEFAULT_SCHEMA) -> Mapping[str, Any]:
    try:
        value = _strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read canonical evidence schema: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValidationError("canonical evidence schema is not an object")
    return value


def evidence_from_payload(
    payload: Mapping[str, Any],
    *,
    trusted_validators: Mapping[str, str],
    expected_binding: EvidenceBinding | None = None,
    require_independent: bool = True,
    schema_path: Path = DEFAULT_SCHEMA,
) -> EvidenceEntry:
    """Decode canonical evidence and verify every current-evidence trust boundary."""

    try:
        jsonschema.Draft202012Validator(
            _schema(schema_path), format_checker=jsonschema.FormatChecker()
        ).validate(payload)
        binding_value = payload["binding"]
        facts_value = payload["facts"]
        assert isinstance(binding_value, Mapping)
        assert isinstance(facts_value, list)
        entry = EvidenceEntry(
            evidence_id=payload["evidence_id"],
            validator_id=payload["validator_id"],
            validator_version=payload["validator_version"],
            validator_kind=ValidatorKind(payload["validator_kind"]),
            claim=payload["claim"],
            outcome=EvidenceOutcome(payload["outcome"]),
            facts=tuple(
                MeasuredFact(item["name"], item["value"])
                for item in facts_value
                if isinstance(item, Mapping)
            ),
            binding=EvidenceBinding(
                binding_value["base_commit"],
                binding_value["contract_hash"],
                tuple(binding_value["project_model_fingerprints"]),
            ),
            output=payload["output"],
            recorded_at=datetime.fromisoformat(payload["recorded_at"]),
            producer_id=payload["producer_id"],
            independent_of_executor=payload["independent_of_executor"],
            entry_hash=payload["entry_hash"],
        )
    except (AssertionError, KeyError, TypeError, ValueError, jsonschema.ValidationError) as exc:
        raise ValidationError(f"invalid canonical evidence: {exc}") from exc
    if trusted_validators.get(entry.validator_id) != entry.validator_version:
        raise ValidationError("untrusted or spoofed validator identity")
    if not entry.verify_integrity():
        raise ValidationError("evidence integrity check failed")
    if require_independent and not entry.independent_of_executor:
        raise ValidationError("current evidence must be independent of executor")
    if expected_binding is not None and entry.binding != expected_binding:
        raise ValidationError("stale evidence binding")
    return entry


def classify_evidence_payload(payload: Mapping[str, Any]) -> EvidenceClassification:
    """Classify only the two documented pre-2.0 historical shapes."""

    if payload.get("schema_version") == EVIDENCE_SCHEMA_VERSION:
        return EvidenceClassification.CANONICAL
    wrapped = payload.get("evidence")
    if (
        set(payload) == {"schema_version", "evidence"}
        and payload.get("schema_version") == "1.0"
        and isinstance(wrapped, Mapping)
    ):
        validator, source, result = (
            wrapped.get("validator"),
            wrapped.get("source"),
            wrapped.get("result"),
        )
        if (
            set(wrapped)
            == {
                "id",
                "gate",
                "claim",
                "validator",
                "source",
                "result",
                "evidence_excerpt",
                "scrubbed",
                "created_at",
            }
            and isinstance(wrapped.get("id"), str)
            and _EVIDENCE_ID.fullmatch(wrapped["id"]) is not None
            and isinstance(wrapped.get("gate"), str)
            and _GATE_ID.fullmatch(wrapped["gate"]) is not None
            and _nonempty_text(wrapped.get("claim"))
            and isinstance(validator, Mapping)
            and set(validator) == {"id", "version", "type"}
            and _nonempty_text(validator.get("id"))
            and _nonempty_text(validator.get("version"))
            and validator.get("type") == "independent_agent"
            and isinstance(source, Mapping)
            and set(source) == {"commit", "contract_hash", "project_model_fingerprint"}
            and isinstance(source.get("commit"), str)
            and _HEX40.fullmatch(source["commit"]) is not None
            and isinstance(source.get("contract_hash"), str)
            and _HEX64.fullmatch(source["contract_hash"]) is not None
            and isinstance(source.get("project_model_fingerprint"), str)
            and _HEX64.fullmatch(source["project_model_fingerprint"]) is not None
            and isinstance(result, Mapping)
            and set(result) == {"status", "measured"}
            and result.get("status") in {"PASS", "FAIL", "BLOCKED"}
            and isinstance(result.get("measured"), Mapping)
            and _finite_json_value(result["measured"])
            and _nonempty_text(wrapped.get("evidence_excerpt"))
            and wrapped.get("scrubbed") is True
            and _aware_timestamp(wrapped.get("created_at"))
        ):
            return EvidenceClassification.LEGACY_HISTORICAL
    validator = payload.get("validator")
    binding = payload.get("binding")
    facts = payload.get("facts")
    if (
        set(payload)
        == {
            "evidence_id",
            "validator",
            "claim",
            "outcome",
            "facts",
            "binding",
            "output",
            "recorded_at",
            "producer_id",
            "entry_hash",
        }
        and isinstance(validator, Mapping)
        and set(validator) == {"id", "version", "kind"}
        and _nonempty_text(validator.get("id"))
        and _nonempty_text(validator.get("version"))
        and validator.get("kind") in {item.value for item in ValidatorKind}
        and isinstance(payload.get("evidence_id"), str)
        and _EVIDENCE_ID.fullmatch(payload["evidence_id"]) is not None
        and _nonempty_text(payload.get("claim"))
        and payload.get("outcome") in {item.value for item in EvidenceOutcome}
        and isinstance(facts, list)
        and all(
            isinstance(item, Mapping)
            and set(item) == {"name", "value"}
            and _nonempty_text(item.get("name"))
            and _finite_json_value(item.get("value"))
            and not isinstance(item.get("value"), (list, Mapping))
            for item in facts
        )
        and isinstance(binding, Mapping)
        and set(binding) == {
            "base_commit",
            "contract_hash",
            "project_model_fingerprints",
        }
        and isinstance(binding.get("base_commit"), str)
        and _HEX40.fullmatch(binding["base_commit"]) is not None
        and isinstance(binding.get("contract_hash"), str)
        and _HEX64.fullmatch(binding["contract_hash"]) is not None
        and isinstance(binding.get("project_model_fingerprints"), list)
        and bool(binding["project_model_fingerprints"])
        and all(
            isinstance(item, str) and _HEX64.fullmatch(item) is not None
            for item in binding["project_model_fingerprints"]
        )
        and isinstance(payload.get("output"), str)
        and _aware_timestamp(payload.get("recorded_at"))
        and _nonempty_text(payload.get("producer_id"))
        and isinstance(payload.get("entry_hash"), str)
        and _HEX64.fullmatch(payload["entry_hash"]) is not None
        and _flat_legacy_integrity(payload)
    ):
        return EvidenceClassification.LEGACY_HISTORICAL
    raise ValidationError("unknown evidence format")


def decode_evidence(
    payload: Mapping[str, Any],
    *,
    trusted_validators: Mapping[str, str],
    expected_binding: EvidenceBinding | None = None,
    require_independent: bool = True,
    schema_path: Path = DEFAULT_SCHEMA,
) -> DecodedEvidence:
    classification = classify_evidence_payload(payload)
    if classification is EvidenceClassification.LEGACY_HISTORICAL:
        return DecodedEvidence(classification, None, "legacy evidence cannot satisfy current gates")
    return DecodedEvidence(
        classification,
        evidence_from_payload(
            payload,
            trusted_validators=trusted_validators,
            expected_binding=expected_binding,
            require_independent=require_independent,
            schema_path=schema_path,
        ),
    )


def load_evidence(
    path: Path,
    *,
    trusted_validators: Mapping[str, str],
    expected_binding: EvidenceBinding | None = None,
    require_independent: bool = True,
    schema_path: Path = DEFAULT_SCHEMA,
) -> DecodedEvidence:
    """Load JSON/YAML without accepting sequences or unknown formats."""

    try:
        text = path.read_text(encoding="utf-8")
        payload = (
            _strict_json_loads(text)
            if path.suffix.lower() == ".json"
            else yaml.load(text, Loader=_UniqueKeyLoader)
        )
    except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise ValidationError(f"cannot parse evidence: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValidationError("evidence document must be an object")
    return decode_evidence(
        payload,
        trusted_validators=trusted_validators,
        expected_binding=expected_binding,
        require_independent=require_independent,
        schema_path=schema_path,
    )


def dump_evidence(entry: EvidenceEntry, path: Path) -> None:
    """Atomically persist canonical evidence in a deterministic representation."""

    payload = evidence_to_payload(entry)
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
        if path.suffix.lower() == ".json"
        else yaml.safe_dump(payload, sort_keys=True, allow_unicode=False)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(encoded, encoding="utf-8", newline="\n")
    temporary.replace(path)


def validate_evidence_set(
    paths: list[Path],
    *,
    trusted_validators: Mapping[str, str],
    expected_binding: EvidenceBinding,
) -> tuple[EvidenceEntry, ...]:
    """Validate a current set and reject legacy entries and duplicate IDs."""

    entries: list[EvidenceEntry] = []
    seen: set[str] = set()
    for path in paths:
        decoded = load_evidence(
            path,
            trusted_validators=trusted_validators,
            expected_binding=expected_binding,
        )
        if decoded.entry is None:
            raise ValidationError(f"legacy evidence cannot be current: {path}")
        if decoded.entry.evidence_id in seen:
            raise ValidationError(f"duplicate evidence ID: {decoded.entry.evidence_id}")
        seen.add(decoded.entry.evidence_id)
        entries.append(decoded.entry)
    return tuple(entries)

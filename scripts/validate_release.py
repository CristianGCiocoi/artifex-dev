"""Read-only, deterministic V1 candidate release verifier."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import importlib.metadata
import io
import json
import math
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from pathlib import Path, PurePosixPath

import jsonschema  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]
from validate_traceability import validate_traceability

from artifex.knowledge import (
    ImprovementProposal,
    KnowledgeItem,
    KnowledgeKind,
    KnowledgeScope,
)
from artifex.project import AuditEvent, AuditLog, ProjectRepository
from artifex.project.errors import ArtifactCorruptError
from artifex.validation import (
    EvidenceBinding,
    EvidenceClassification,
    EvidenceEntry,
    EvidenceLedger,
    ValidationError,
    classify_evidence_payload,
    evidence_from_payload,
    evidence_to_payload,
    load_evidence,
)

ROOT = Path(__file__).parents[1]
VERSION = "1.0.0"
MANDATORY_GATES = (
    *tuple(f"G-M{number:02d}-MILESTONE" for number in range(10)),
    "G-M11-MILESTONE",
    "G-V1-RELEASE",
)
OPTIONAL_GATES = ("G-M10-MILESTONE",)
EVIDENCE_CATEGORIES = {
    "EVD-M11-BUILD": "build",
    "EVD-M11-VALIDATION": "validation",
    "EVD-M11-UNDERSTANDING": "understanding",
    "EVD-M11-CONTINUITY": "continuity",
    "EVD-M11-PORTABILITY": "portability",
    "EVD-M11-PACKAGING": "packaging",
    "EVD-M11-SELFHOST": "selfhost",
    "EVD-M11-SECURITY": "security",
    "EVD-V1-RELEASE": "release",
}
REQUIRED_GUIDES = (
    "docs/guides/USER_GUIDE.md",
    "docs/guides/ADMIN_GUIDE.md",
    "docs/guides/DEVELOPER_GUIDE.md",
    "docs/guides/OPERATIONS_GUIDE.md",
    "docs/guides/SECURITY_GUIDE.md",
    "docs/guides/UPGRADE_GUIDE.md",
)
REQUIRED_GENERATED = (
    ".artifex/generated/understanding/README.md",
    ".artifex/generated/understanding/ARCHITECTURE.md",
    ".artifex/generated/understanding/INVARIANTS.md",
    ".artifex/generated/understanding/WORKFLOWS.md",
    ".artifex/generated/understanding/OPERATIONS.md",
    ".artifex/generated/understanding/SECURITY.md",
    ".artifex/generated/understanding/EXTENSIONS.md",
    ".artifex/generated/understanding/HISTORY.md",
    ".artifex/generated/understanding/LIMITATIONS.md",
)
REQUIRED_MACHINE = tuple(
    f".artifex/generated/understanding/machine/{Path(relative).stem.casefold()}.json"
    for relative in REQUIRED_GENERATED
)
COMPREHENSION_ARTIFACTS = (
    ".artifex/generated/understanding/comprehension/prompt.json",
    ".artifex/generated/understanding/comprehension/response.json",
    ".artifex/generated/understanding/comprehension/result.json",
)
REQUIRED_DASHBOARD = (
    "docs/implementation/dashboard/index.html",
    "docs/implementation/dashboard/state.json",
)
DOCUMENT_TOPIC_TERMS = {
    "USER_GUIDE": ("user", "workflow", "evidence"),
    "ADMIN_GUIDE": ("admin", "policy", "gate"),
    "DEVELOPER_GUIDE": ("developer", "source", "validation"),
    "OPERATIONS_GUIDE": ("operations", "rollback", "audit"),
    "SECURITY_GUIDE": ("security", "trust", "secret"),
    "UPGRADE_GUIDE": ("upgrade", "compatibility", "rollback"),
    "README": ("artifex", "governance", "evidence"),
    "ARCHITECTURE": ("architecture", "component", "invariant"),
    "INVARIANTS": ("invariant", "authority", "fail-closed"),
    "WORKFLOWS": ("workflow", "gate", "validation"),
    "OPERATIONS": ("operations", "audit", "recovery"),
    "SECURITY": ("security", "trust", "secret"),
    "EXTENSIONS": ("extension", "integration", "compatibility"),
    "HISTORY": ("history", "milestone", "evidence"),
    "LIMITATIONS": ("limitation", "blocker", "scope"),
}
DOCUMENTATION_MANIFEST = "docs/implementation/dashboard/documentation-manifest.json"
CATEGORY_REPORTS = {
    category: f"docs/implementation/dashboard/release-reports/{category}.json"
    for category in EVIDENCE_CATEGORIES.values()
    if category not in {"understanding", "release"}
}
REQUIRED_KNOWLEDGE = (
    ".artifex/knowledge/project/lessons.json",
    ".artifex/knowledge/instances/artifex-self/improvement-proposals.json",
)
FINAL_LEDGER = ".artifex/validation/ledger-v2.jsonl"
REQUIRED_ARTIFACT_KINDS = (
    "native-linux-x64",
    "native-macos-arm64",
    "native-windows-x64",
    "sdist",
    "wheel",
)
CONTRACT_GOVERNANCE_ALLOWLIST = (
    ".artifex/audit.jsonl",
    ".artifex/generated/understanding/**",
    ".artifex/implementation/traceability.yaml",
    ".artifex/knowledge/instances/artifex-self/improvement-proposals.json",
    ".artifex/knowledge/project/lessons.json",
    ".artifex/releases/v1.0.0.yaml",
    ".artifex/status.yaml",
    ".artifex/validation/contracts/V1-RELEASE.yaml",
    ".artifex/validation/evidence/<FINAL>.yaml",
    ".artifex/validation/gates/G-M11-MILESTONE.yaml",
    ".artifex/validation/gates/G-M05..M07-MILESTONE.yaml",
    ".artifex/validation/gates/G-V1-RELEASE.yaml",
    FINAL_LEDGER,
    "docs/guides/**",
    "docs/implementation/dashboard/**",
)
SECURITY_ATTACK_IDS = (
    "absolute-evidence-path",
    "archive-alias-collision",
    "archive-special-file",
    "audit-order-spoof",
    "category-report-missing",
    "category-report-stale",
    "category-report-tamper",
    "duplicate-evidence-key",
    "duplicate-gate-evidence",
    "duplicate-ledger-event",
    "historical-gate-tamper",
    "legacy-ledger-corruption",
    "native-provenance-spoof",
    "package-extra-payload",
    "package-source-tamper",
    "release-binding-spoof",
    "secret-persistence",
    "traceability-overlap",
    "traceability-semantic-laundering",
    "understanding-placeholder",
)


@dataclass(frozen=True, slots=True)
class ReleaseReport:
    checks: tuple[str, ...]
    blockers: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.blockers


@dataclass(frozen=True, slots=True)
class TrustedValidatorSpec:
    version: str
    kind: str
    producers: frozenset[str]


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _json_loads(value: str | bytes) -> object:
    return json.loads(value, object_pairs_hook=_unique_json_object)


def _portable_text_digest(value: bytes) -> str:
    return hashlib.sha256(value.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


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
            raise ValidationError(f"duplicate YAML key: {key}")
        value[key] = loader.construct_object(item_node, deep=deep)
    return value


_UniqueYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_yaml_mapping
)


def _locked_pyinstaller(root: Path) -> str:
    try:
        lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
        versions = [
            item.get("version")
            for item in lock.get("package", [])
            if isinstance(item, Mapping) and item.get("name") == "pyinstaller"
        ]
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError("PyInstaller lock authority is unreadable") from exc
    if len(versions) != 1 or not isinstance(versions[0], str):
        raise ValidationError("PyInstaller lock authority is ambiguous")
    return versions[0]


def _yaml(path: Path) -> Mapping[str, object] | None:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueYamlLoader)
    except (OSError, yaml.YAMLError, ValidationError):
        return None
    return value if isinstance(value, Mapping) else None


def _safe_relative_file(root: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValidationError(f"{label} path must be nonempty and relative")
    lexical = root / value
    cursor = root
    for part in Path(value).parts:
        if part in {"", ".", ".."}:
            raise ValidationError(f"{label} path has unsafe components: {value}")
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValidationError(f"{label} path must not contain symlinks: {value}")
    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValidationError(f"{label} path escapes repository: {value}") from exc
    if not lexical.is_file():
        raise ValidationError(f"{label} file missing: {value}")
    return lexical


def _canonical_model(value: object) -> tuple[bytes, str]:
    if not isinstance(value, Mapping):
        raise ValidationError("canonical Project Model must be an object")
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return encoded, hashlib.sha256(encoded).hexdigest()


def _validate_project_model(root: Path, value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValidationError("canonical Project Model must be an object")
    try:
        schema = _json_loads(
            (root / "schemas/project-model.schema.json").read_text(encoding="utf-8")
        )
        if not isinstance(schema, Mapping):
            raise ValidationError("canonical Project Model schema is not an object")
        jsonschema.Draft202012Validator(schema).validate(value)
    except (OSError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        raise ValidationError(f"canonical Project Model schema validation failed: {exc}") from exc
    return value


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("git", "-C", str(root), *arguments),
        capture_output=True,
        check=False,
        timeout=10,
    )


def _derived_authority(
    root: Path,
) -> tuple[EvidenceBinding, dict[str, TrustedValidatorSpec], str]:
    try:
        completed = _git(root, "rev-parse", "HEAD")
        governance_head = completed.stdout.decode().strip()
        if completed.returncode != 0 or not governance_head:
            raise ValidationError("governance repository HEAD is unavailable")
        authority_paths = (
            ".artifex/project-model.json",
            ".artifex/validation/contracts/V1-RELEASE.yaml",
        )
        for arguments in (
            ("ls-files", "--error-unmatch", *authority_paths),
            ("diff", "--quiet", "HEAD", "--", *authority_paths),
        ):
            authority_check = _git(root, *arguments)
            if authority_check.returncode != 0:
                raise ValidationError("release model and contract must be committed at HEAD")
        model = _validate_project_model(
            root,
            _json_loads((root / ".artifex/project-model.json").read_text(encoding="utf-8")),
        )
        ProjectRepository(root).load()
        model_bytes, model_fingerprint = _canonical_model(model)
        contract_blob = _git(
            root, "show", f"{governance_head}:.artifex/validation/contracts/V1-RELEASE.yaml"
        )
        if contract_blob.returncode != 0:
            raise ValidationError("release contract Git blob is unavailable")
        contract_bytes = contract_blob.stdout
        contract_hash = hashlib.sha256(contract_bytes).hexdigest()
        contract_payload = yaml.load(contract_bytes, Loader=_UniqueYamlLoader)
        contract = (
            contract_payload.get("contract") if isinstance(contract_payload, Mapping) else None
        )
        if (
            not isinstance(contract_payload, Mapping)
            or set(contract_payload) != {"schema_version", "contract"}
            or contract_payload.get("schema_version") != "1.0"
            or not isinstance(contract, Mapping)
        ):
            raise ValidationError("release contract object missing")
        expected_contract_keys = {
            "id",
            "version",
            "state",
            "candidate_commit",
            "project_model_fingerprint",
            "product_version",
            "evidence_categories",
            "artifact_kinds",
            "governance_allowlist",
            "trusted_validators",
        }
        if (
            set(contract) != expected_contract_keys
            or contract.get("id") != "VAL-V1-RELEASE"
            or contract.get("version") != 1
            or contract.get("state") != "FROZEN"
            or contract.get("product_version") != VERSION
            or contract.get("evidence_categories") != EVIDENCE_CATEGORIES
            or contract.get("artifact_kinds") != list(REQUIRED_ARTIFACT_KINDS)
            or contract.get("governance_allowlist") != list(CONTRACT_GOVERNANCE_ALLOWLIST)
        ):
            raise ValidationError("release contract identity/scope is invalid")
        candidate_commit = contract.get("candidate_commit")
        contracted_model = contract.get("project_model_fingerprint")
        trusted = contract.get("trusted_validators")
        if (
            not isinstance(candidate_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", candidate_commit) is None
        ):
            raise ValidationError("release contract candidate commit missing")
        resolved_candidate = _git(
            root, "rev-parse", "--verify", f"{candidate_commit}^{{commit}}"
        )
        if (
            resolved_candidate.returncode != 0
            or resolved_candidate.stdout.decode().strip() != candidate_commit
        ):
            raise ValidationError("release contract candidate commit does not resolve exactly")
        if contracted_model != model_fingerprint:
            raise ValidationError("release contract Project Model fingerprint mismatch")
        if not isinstance(trusted, list) or not trusted:
            raise ValidationError("release contract trusted validator registry missing")
        trusted_validators: dict[str, TrustedValidatorSpec] = {}
        for item in trusted:
            if not isinstance(item, Mapping):
                raise ValidationError("release contract validator specification invalid")
            validator_id, version, kind, producers = (
                item.get("id"),
                item.get("version"),
                item.get("kind"),
                item.get("producers"),
            )
            if (
                set(item) != {"id", "version", "kind", "producers"}
                or not isinstance(validator_id, str)
                or not isinstance(version, str)
                or not isinstance(kind, str)
                or kind
                not in {"DETERMINISTIC", "STRUCTURED_INSPECTION", "INDEPENDENT_AGENT", "MANUAL"}
                or not isinstance(producers, list)
                or not producers
                or any(not isinstance(producer, str) or not producer for producer in producers)
                or validator_id in trusted_validators
            ):
                raise ValidationError("release contract validator specification invalid")
            trusted_validators[validator_id] = TrustedValidatorSpec(
                version, kind, frozenset(producers)
            )
        if _git(root, "merge-base", "--is-ancestor", candidate_commit, governance_head).returncode:
            raise ValidationError("release candidate is not an ancestor of governance HEAD")
        source_model = _git(root, "show", f"{candidate_commit}:.artifex/project-model.json")
        if source_model.returncode != 0:
            raise ValidationError("candidate Project Model is unavailable")
        source_model_value = _validate_project_model(root, _json_loads(source_model.stdout))
        source_model_bytes, source_model_fingerprint = _canonical_model(source_model_value)
        if source_model_bytes != model_bytes or source_model_fingerprint != model_fingerprint:
            raise ValidationError("governance Project Model differs from source candidate")
        changed = _git(root, "diff", "--name-only", f"{candidate_commit}..{governance_head}")
        if changed.returncode != 0:
            raise ValidationError("cannot inspect source-to-governance delta")
        forbidden = [
            path
            for path in changed.stdout.decode().splitlines()
            if not _governance_path_allowed(path)
        ]
        if forbidden:
            raise ValidationError(
                f"source-to-governance delta escapes allowlist: {','.join(sorted(forbidden))}"
            )
        _validate_governance_delta(root, candidate_commit, governance_head)
    except (OSError, json.JSONDecodeError, TypeError, yaml.YAMLError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(f"cannot derive release authority: {exc}") from exc
    return (
        EvidenceBinding(candidate_commit, contract_hash, (model_fingerprint,)),
        trusted_validators,
        governance_head,
    )


def _governance_path_allowed(path: str) -> bool:
    exact = {
        ".artifex/status.yaml",
        ".artifex/audit.jsonl",
        ".artifex/validation/contracts/V1-RELEASE.yaml",
        ".artifex/releases/v1.0.0.yaml",
        ".artifex/implementation/traceability.yaml",
        FINAL_LEDGER,
        *REQUIRED_KNOWLEDGE,
    }
    prefixes = (
        ".artifex/validation/evidence/",
        ".artifex/validation/gates/",
        ".artifex/generated/understanding/",
        "docs/guides/",
        "docs/implementation/dashboard/",
    )
    return path in exact or path.startswith(prefixes)


def _validate_governance_delta(root: Path, source: str, governance: str) -> None:
    result = _git(
        root,
        "diff",
        "--name-status",
        "--no-renames",
        f"{source}..{governance}",
        "--",
        ".artifex/validation/evidence",
        ".artifex/validation/gates",
    )
    if result.returncode != 0:
        raise ValidationError("cannot inspect historical governance delta")
    final_evidence = {
        f".artifex/validation/evidence/{evidence_id}.yaml" for evidence_id in EVIDENCE_CATEGORIES
    }
    final_gates = {
        ".artifex/validation/gates/G-M11-MILESTONE.yaml",
        ".artifex/validation/gates/G-V1-RELEASE.yaml",
    }
    backfilled_gates = {
        f".artifex/validation/gates/G-M{number:02d}-MILESTONE.yaml" for number in range(5, 8)
    }
    allowed_additions = final_evidence | final_gates | backfilled_gates
    violations: list[str] = []
    for line in result.stdout.decode().splitlines():
        try:
            status, path = line.split("\t", 1)
        except ValueError:
            violations.append(line)
            continue
        if status != "A" or path not in allowed_additions:
            violations.append(f"{status}:{path}")
    if violations:
        raise ValidationError(
            "historical evidence/gate authority changed after S: " + ",".join(sorted(violations))
        )


def _version_checks(root: Path, blockers: list[str], checks: list[str]) -> None:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        package_version = str(project["project"]["version"])
        version_source = (root / "src/artifex/_version.py").read_text(encoding="utf-8")
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        blockers.append(f"package identity unreadable: {exc}")
        return
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', version_source, re.MULTILINE)
    core_version = match.group(1) if match else None
    if package_version != VERSION or core_version != VERSION:
        blockers.append(
            "version identity mismatch: "
            f"package={package_version} core={core_version} expected={VERSION}"
        )
    else:
        checks.append("version identity 1.0.0")


def _evidence(
    root: Path,
    manifest: Mapping[str, object],
    binding: EvidenceBinding,
    trusted_validators: Mapping[str, TrustedValidatorSpec],
    blockers: list[str],
    checks: list[str],
) -> dict[str, EvidenceEntry]:
    manifest_binding = manifest.get("binding")
    expected_binding_payload = {
        "base_commit": binding.base_commit,
        "contract_hash": binding.contract_hash,
        "project_model_fingerprints": list(binding.project_model_fingerprints),
    }
    if manifest_binding != expected_binding_payload:
        blockers.append("release record binding does not match derived repository authority")
    evidence_values = manifest.get("evidence")
    if not isinstance(evidence_values, list):
        blockers.append("release evidence paths missing")
        return {}
    entries: dict[str, EvidenceEntry] = {}
    for value in evidence_values:
        try:
            path = _safe_relative_file(root, value, label="evidence")
            decoded = load_evidence(
                path,
                trusted_validators={
                    validator_id: spec.version for validator_id, spec in trusted_validators.items()
                },
                expected_binding=binding,
            )
            if decoded.entry is None:
                raise ValidationError("legacy evidence cannot be current")
            entry = decoded.entry
            spec = trusted_validators.get(entry.validator_id)
            if (
                spec is None
                or entry.validator_kind.value != spec.kind
                or entry.producer_id not in spec.producers
            ):
                raise ValidationError(
                    f"validator kind or producer authority mismatch: {entry.evidence_id}"
                )
            if entry.evidence_id in entries:
                raise ValidationError(f"duplicate evidence ID: {entry.evidence_id}")
            entries[entry.evidence_id] = entry
        except ValidationError as exc:
            blockers.append(f"release evidence invalid: {exc}")
    missing = set(EVIDENCE_CATEGORIES) - set(entries)
    extra = set(entries) - set(EVIDENCE_CATEGORIES)
    if missing:
        blockers.append(f"missing final evidence IDs: {','.join(sorted(missing))}")
    if extra:
        blockers.append(f"unknown final evidence IDs: {','.join(sorted(extra))}")
    for evidence_id, category in EVIDENCE_CATEGORIES.items():
        current_entry = entries.get(evidence_id)
        if current_entry is None:
            continue
        facts = {fact.name: fact.value for fact in current_entry.facts}
        if len(facts) != len(current_entry.facts):
            blockers.append(f"final evidence has duplicate fact names: {evidence_id}")
        normalized_claim = re.sub(r"[^a-z0-9]+", "", current_entry.claim.lower())
        if current_entry.outcome.value != "PASS" or not current_entry.independent_of_executor:
            blockers.append(f"final evidence is not independent PASS: {evidence_id}")
        if facts.get("category") != category:
            blockers.append(f"final evidence category fact mismatch: {evidence_id}")
        if category not in normalized_claim:
            blockers.append(f"final evidence claim/category mismatch: {evidence_id}")
        if category != "release":
            _validate_category_facts(root, manifest, binding, current_entry, category, blockers)
    aggregate = entries.get("EVD-V1-RELEASE")
    category_entries = {
        evidence_id: entry
        for evidence_id, entry in entries.items()
        if evidence_id.startswith("EVD-M11-")
    }
    if aggregate is not None:
        aggregation = {
            fact.name.removeprefix("aggregate:"): fact.value
            for fact in aggregate.facts
            if fact.name.startswith("aggregate:")
        }
        expected_aggregation = {
            evidence_id: entry.entry_hash for evidence_id, entry in category_entries.items()
        }
        if aggregation != expected_aggregation:
            blockers.append("V1 aggregate evidence hashes do not exactly bind all M11 evidence")
    if not (set(EVIDENCE_CATEGORIES) - set(entries)):
        checks.append("canonical current independent categorized release evidence")
    return entries


def _strict_report(
    root: Path,
    binding: EvidenceBinding,
    entry: EvidenceEntry,
    category: str,
) -> tuple[Mapping[str, object], str]:
    relative = CATEGORY_REPORTS[category]
    _safe_relative_file(root, relative, label=f"{category} release report")
    for arguments in (
        ("ls-files", "--error-unmatch", relative),
        ("diff", "--quiet", "HEAD", "--", relative),
    ):
        if _git(root, *arguments).returncode != 0:
            raise ValidationError(f"{category} release report must be tracked and clean at G")
    committed = _git(root, "show", f"HEAD:{relative}")
    if committed.returncode != 0:
        raise ValidationError(f"{category} release report is unavailable at G")
    raw = committed.stdout
    try:
        report = _json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{category} release report is invalid JSON") from exc
    if not isinstance(report, Mapping) or set(report) != {
        "schema_version",
        "category",
        "binding",
        "attestation",
        "results",
    }:
        raise ValidationError(f"{category} release report schema is invalid")
    expected_binding = {
        "candidate_commit": binding.base_commit,
        "contract_hash": binding.contract_hash,
        "project_model_fingerprint": binding.project_model_fingerprints[0],
    }
    expected_attestation = {
        "validator_id": entry.validator_id,
        "validator_version": entry.validator_version,
        "validator_kind": entry.validator_kind.value,
        "producer_id": entry.producer_id,
    }
    results = report.get("results")
    if (
        report.get("schema_version") != "1.0"
        or report.get("category") != category
        or report.get("binding") != expected_binding
        or report.get("attestation") != expected_attestation
        or not isinstance(results, Mapping)
    ):
        raise ValidationError(f"{category} release report authority binding is invalid")
    return results, hashlib.sha256(raw).hexdigest()


def _report_facts(
    root: Path,
    manifest: Mapping[str, object],
    binding: EvidenceBinding,
    entry: EvidenceEntry,
    category: str,
) -> dict[str, object]:
    results, digest = _strict_report(root, binding, entry, category)
    report_fact = {f"{category}_report_sha256": digest}
    if category == "build":
        jobs = results.get("jobs")
        run_id = results.get("run_id")
        expected_matrix = {
            *(
                f"test-{os_name}-{python}"
                for os_name in ("linux", "windows", "macos")
                for python in ("3.12", "3.13")
            ),
            "native-linux",
            "native-windows",
            "native-macos",
            "source-package-linux",
        }
        if (
            set(results) != {"run_id", "jobs"}
            or type(run_id) is not int
            or run_id <= 0
            or not isinstance(jobs, list)
            or {item.get("id") for item in jobs if isinstance(item, Mapping)} != expected_matrix
            or len(jobs) != len(expected_matrix)
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"id", "status", "source_commit"}
                or item.get("status") != "PASS"
                or item.get("source_commit") != binding.base_commit
                for item in jobs
            )
        ):
            raise ValidationError("build release report results are invalid")
        return {
            "source_commit": binding.base_commit,
            "ci_run": run_id,
            "ci_jobs_passed": len(jobs),
            "ci_jobs_total": len(expected_matrix),
            **report_fact,
        }
    if category == "validation":
        commands, summary = results.get("commands"), results.get("summary")
        if (
            set(results) != {"commands", "summary"}
            or not isinstance(commands, list)
            or commands
            != [
                {"name": "ruff", "exit_code": 0},
                {"name": "mypy", "exit_code": 0},
                {"name": "pytest-full", "exit_code": 0},
            ]
            or not isinstance(summary, Mapping)
            or set(summary) != {"tests_passed", "coverage_percent"}
            or type(summary.get("tests_passed")) is not int
            or summary["tests_passed"] <= 0
            or type(summary.get("coverage_percent")) not in {int, float}
            or not math.isfinite(float(summary["coverage_percent"]))
            or summary["coverage_percent"] < 85
        ):
            raise ValidationError("validation release report results are invalid")
        return {
            "ruff": "PASS",
            "mypy": "PASS",
            "tests_passed": summary["tests_passed"],
            "coverage_percent": summary["coverage_percent"],
            **report_fact,
        }
    if category == "continuity":
        integrations = results.get("integrations")
        expected = {"manual", "hermes", "codex", "claude", "deepseek", "pandora"}
        if (
            set(results) != {"integrations"}
            or not isinstance(integrations, list)
            or {item.get("id") for item in integrations if isinstance(item, Mapping)} != expected
            or len(integrations) != len(expected)
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"id", "version", "status"}
                or item.get("version") != VERSION
                or item.get("status") != "PASS"
                for item in integrations
            )
        ):
            raise ValidationError("continuity release report results are invalid")
        return {"integrations_passed": len(integrations), "integrations_total": 6, **report_fact}
    if category == "portability":
        source_jobs, native_jobs = results.get("source_jobs"), results.get("native_jobs")
        source_matrix = {
            f"{os_name}-{python}"
            for os_name in ("linux", "windows", "macos")
            for python in ("3.12", "3.13")
        }
        native_matrix = {"linux-x86_64", "windows-x86_64", "macos-arm64"}
        if (
            set(results) != {"source_jobs", "native_jobs"}
            or not isinstance(source_jobs, list)
            or not isinstance(native_jobs, list)
            or set(source_jobs) != source_matrix
            or set(native_jobs) != native_matrix
            or len(source_jobs) != 6
            or len(native_jobs) != 3
        ):
            raise ValidationError("portability release report results are invalid")
        return {
            "source_jobs_passed": 6,
            "source_jobs_total": 6,
            "native_platforms_passed": 3,
            "native_platforms_total": 3,
            **report_fact,
        }
    if category == "packaging":
        artifacts = manifest.get("artifacts")
        expected_hashes: dict[str, str] = {}
        if isinstance(artifacts, list):
            expected_hashes = {
                str(item["kind"]): str(item["sha256"])
                for item in artifacts
                if isinstance(item, Mapping)
            }
        attestations, smokes = results.get("native_attestations"), results.get("smokes")
        if (
            set(results) != {"artifacts", "smokes", "native_attestations"}
            or results.get("artifacts") != expected_hashes
            or smokes
            != {
                "isolated_wheel": True,
                "isolated_sdist": True,
                "cli_json": True,
                "schema_2": True,
            }
            or not isinstance(attestations, list)
            or len(attestations) != 3
            or {item.get("kind") for item in attestations if isinstance(item, Mapping)}
            != {"native-linux-x64", "native-windows-x64", "native-macos-arm64"}
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {"kind", "artifact_sha256", "job_id", "toolchain", "source_commit", "status"}
                or item.get("artifact_sha256") != expected_hashes.get(str(item.get("kind")))
                or item.get("toolchain") != f"pyinstaller=={_locked_pyinstaller(root)}"
                or item.get("source_commit") != binding.base_commit
                or item.get("status") != "PASS"
                or not isinstance(item.get("job_id"), str)
                or item.get("job_id") != f"ci-{item.get('kind')}"
                for item in attestations
            )
        ):
            raise ValidationError("packaging release report results are invalid")
        return {
            "artifact_hashes": json.dumps(expected_hashes, sort_keys=True, separators=(",", ":")),
            **smokes,
            **report_fact,
        }
    if category == "selfhost":
        expected_selfhost = {
            "project_model_fingerprint": binding.project_model_fingerprints[0],
            "changeset": "CHG-SELF-RELEASE",
            "adapter_status": "SUCCESS",
            "ledger_entries": len(EVIDENCE_CATEGORIES),
            "checks": {"model": True, "contract": True, "evidence": True, "ledger": True},
        }
        if dict(results) != expected_selfhost:
            raise ValidationError("selfhost release report results are invalid")
        return {
            key: value for key, value in expected_selfhost.items() if key != "checks"
        } | report_fact
    if category == "security":
        attacks, command, secret_scan, waivers = (
            results.get("attacks"),
            results.get("command"),
            results.get("secret_scan"),
            results.get("waivers"),
        )
        expected_attacks = [{"id": item, "status": "PASS"} for item in SECURITY_ATTACK_IDS]
        if (
            set(results) != {"attacks", "command", "secret_scan", "waivers"}
            or attacks != expected_attacks
            or command
            != {"argv": "uv run pytest -m adversarial", "source_commit": binding.base_commit}
            or secret_scan != {"status": "PASS", "secrets_found": 0}
            or waivers != []
        ):
            raise ValidationError("security release report results are invalid")
        return {
            "adversarial_passed": len(SECURITY_ATTACK_IDS),
            "trust_boundaries_passed": True,
            "secret_scan": "PASS",
            "waivers": 0,
            **report_fact,
        }
    raise ValidationError(f"unknown release report category: {category}")


def _validate_category_facts(
    root: Path,
    manifest: Mapping[str, object],
    binding: EvidenceBinding,
    entry: EvidenceEntry,
    category: str,
    blockers: list[str],
) -> None:
    facts = {fact.name: fact.value for fact in entry.facts}
    if category == "understanding":
        expected = {
            "category": category,
            "generated_files": len(REQUIRED_GENERATED),
            "guides": len(REQUIRED_GUIDES),
            "comprehension_score": 1.0,
            "documentation_manifest_sha256": hashlib.sha256(
                (root / DOCUMENTATION_MANIFEST)
                .read_bytes()
                .replace(b"\r\n", b"\n")
                .replace(b"\r", b"\n")
            ).hexdigest(),
        }
    else:
        try:
            expected = {
                "category": category,
                **_report_facts(root, manifest, binding, entry, category),
            }
        except (OSError, ValidationError) as exc:
            blockers.append(f"final evidence release report invalid: {entry.evidence_id}: {exc}")
            return
    if facts != expected:
        blockers.append(f"final evidence facts do not match measured report: {entry.evidence_id}")


def _audit_provenance(
    root: Path,
    entries: Mapping[str, EvidenceEntry],
    binding: EvidenceBinding,
    blockers: list[str],
) -> None:
    try:
        events = AuditLog(root).read_all()
    except (OSError, ArtifactCorruptError) as exc:
        blockers.append(f"independent-validation audit cannot be read: {exc}")
        return
    matching = [
        event for event in events if event.event_type == "RELEASE_CANDIDATE_INDEPENDENT_VALIDATION"
    ]
    if len(matching) != 1:
        blockers.append("independent-validation audit event missing or ambiguous")
        return
    event = matching[0]
    expected_evidence = [
        {
            "evidence_id": entry.evidence_id,
            "entry_hash": entry.entry_hash,
            "validator_id": entry.validator_id,
            "validator_version": entry.validator_version,
            "validator_kind": entry.validator_kind.value,
            "producer_id": entry.producer_id,
        }
        for entry in sorted(entries.values(), key=lambda item: item.evidence_id)
    ]
    if (
        event.commit != binding.base_commit
        or event.actor not in {entry.producer_id for entry in entries.values()}
        or event.payload.get("candidate_commit") != binding.base_commit
        or event.payload.get("contract_hash") != binding.contract_hash
        or event.payload.get("project_model_fingerprint") != binding.project_model_fingerprints[0]
        or event.payload.get("evidence") != expected_evidence
    ):
        blockers.append("independent-validation audit provenance mismatch")


def _status_and_audit_transition(
    root: Path,
    status: Mapping[str, object] | None,
    binding: EvidenceBinding,
    governance_head: str,
    blockers: list[str],
) -> None:
    source_status_blob = _git(root, "show", f"{binding.base_commit}:.artifex/status.yaml")
    source_audit_blob = _git(root, "show", f"{binding.base_commit}:.artifex/audit.jsonl")
    governance_audit_blob = _git(root, "show", f"{governance_head}:.artifex/audit.jsonl")
    if any(
        result.returncode != 0
        for result in (source_status_blob, source_audit_blob, governance_audit_blob)
    ):
        blockers.append("source/governance status or audit history is unavailable")
        return
    try:
        source_status = yaml.load(source_status_blob.stdout, Loader=_UniqueYamlLoader)
        if not isinstance(source_status, Mapping) or status is None:
            raise ValidationError("status history is malformed")
        if set(status) != set(source_status):
            raise ValidationError("status top-level structure changed")
        for key in set(status) - {"derived_at", "implementation", "milestones"}:
            if status[key] != source_status[key]:
                raise ValidationError(f"status authority changed outside release transition: {key}")
        source_milestones = source_status.get("milestones")
        current_milestones = status.get("milestones")
        source_implementation = source_status.get("implementation")
        current_implementation = status.get("implementation")
        if not all(
            isinstance(item, Mapping)
            for item in (
                source_milestones,
                current_milestones,
                source_implementation,
                current_implementation,
            )
        ):
            raise ValidationError("status milestone/implementation structure is malformed")
        assert isinstance(source_milestones, Mapping)
        assert isinstance(current_milestones, Mapping)
        assert isinstance(source_implementation, Mapping)
        assert isinstance(current_implementation, Mapping)
        if set(current_milestones) != set(source_milestones):
            raise ValidationError("status milestone history was added or removed")
        if any(source_milestones.get(f"M{number:02d}") != "ACCEPTED" for number in range(10)):
            raise ValidationError("source status lacks accepted M00-M09 history")
        if "M10" in source_milestones and source_milestones.get("M10") != "ACCEPTED":
            raise ValidationError("optional M10 source history is not accepted")
        if (
            any(
                current_milestones[key] != value
                for key, value in source_milestones.items()
                if key != "M11"
            )
            or current_milestones.get("M11") != "VALIDATING"
        ):
            raise ValidationError("status milestone history/transition mismatch")
        if set(current_implementation) != set(source_implementation):
            raise ValidationError("status implementation structure changed")
        if any(
            current_implementation[key] != value
            for key, value in source_implementation.items()
            if key not in {"current_state", "release"}
        ):
            raise ValidationError("status implementation authority changed")
        if (
            current_implementation.get("current_state") != "VALIDATING"
            or current_implementation.get("release") != "CANDIDATE"
        ):
            raise ValidationError("status release transition mismatch")
        source_audit = source_audit_blob.stdout
        governance_audit = governance_audit_blob.stdout
        if not governance_audit.startswith(source_audit):
            raise ValidationError("audit history is not an append-only extension of S")
        appended = governance_audit[len(source_audit) :]
        if appended and (not source_audit.endswith(b"\n") or not appended.endswith(b"\n")):
            raise ValidationError("audit append does not preserve event boundaries")
        source_event_ids: list[str] = []
        for line in source_audit.splitlines():
            source_value = _json_loads(line)
            if (
                not isinstance(source_value, Mapping)
                or not isinstance(source_value.get("event_id"), str)
                or not source_value["event_id"]
            ):
                raise ValidationError("source audit event identity is malformed")
            source_event_ids.append(source_value["event_id"])
        if len(set(source_event_ids)) != len(source_event_ids):
            raise ValidationError("source audit event IDs are not unique")
        events = []
        appended_event_ids: list[str] = []
        occurred_at: list[datetime] = []
        for line in appended.splitlines():
            value = _json_loads(line)
            if (
                not isinstance(value, Mapping)
                or set(value)
                != {"event_id", "event_type", "occurred_at", "actor", "commit", "payload"}
                or not isinstance(value.get("event_id"), str)
                or not value["event_id"]
                or not isinstance(value.get("event_type"), str)
                or not isinstance(value.get("occurred_at"), str)
                or not isinstance(value.get("actor"), str)
                or not isinstance(value.get("commit"), (str, type(None)))
                or not isinstance(value.get("payload"), Mapping)
            ):
                raise ValidationError("appended audit event is malformed")
            timestamp = datetime.fromisoformat(value["occurred_at"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValidationError("appended audit timestamp is not timezone-aware")
            occurred_at.append(timestamp)
            appended_event_ids.append(value["event_id"])
            events.append(AuditEvent.from_dict(value))
        expected_types = (
            "MILESTONE_STATE_TRANSITION",
            "RELEASE_STATE_TRANSITION",
            "RELEASE_CANDIDATE_INDEPENDENT_VALIDATION",
        )
        if (
            tuple(event.event_type for event in events) != expected_types
            or any(left >= right for left, right in pairwise(occurred_at))
            or len(set(appended_event_ids)) != len(appended_event_ids)
            or not set(appended_event_ids).isdisjoint(source_event_ids)
        ):
            raise ValidationError("appended release audit event set is not exact")
        milestone_event, release_event, _ = events
        if (
            milestone_event.actor != "artifex-core"
            or milestone_event.commit != binding.base_commit
            or milestone_event.payload
            != {
                "milestone": "M11",
                "from": source_milestones.get("M11"),
                "to": "VALIDATING",
                "candidate_commit": binding.base_commit,
            }
            or release_event.actor != "artifex-core"
            or release_event.commit != binding.base_commit
            or release_event.payload
            != {
                "from": source_implementation.get("release"),
                "to": "CANDIDATE",
                "candidate_commit": binding.base_commit,
            }
        ):
            raise ValidationError("audited status transition provenance mismatch")
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
        ValidationError,
    ) as exc:
        blockers.append(f"status/audit transition invalid: {exc}")


def _ledger_evidence(
    root: Path,
    entries: Mapping[str, EvidenceEntry],
    trusted_validators: Mapping[str, TrustedValidatorSpec],
    blockers: list[str],
    checks: list[str],
) -> None:
    try:
        if not entries:
            raise ValidationError("final evidence set is empty")
        _safe_relative_file(root, FINAL_LEDGER, label="schema-2 evidence ledger")
        if _git(root, "diff", "--quiet", "HEAD", "--", FINAL_LEDGER).returncode != 0:
            raise ValidationError("schema-2 ledger must be clean at G")
        current = _git(root, "show", f"HEAD:{FINAL_LEDGER}")
        if current.returncode != 0:
            raise ValidationError("schema-2 ledger committed blob is unavailable")
        current_bytes = current.stdout
        source = _git(
            root, "show", f"{next(iter(entries.values())).binding.base_commit}:{FINAL_LEDGER}"
        )
        if source.returncode == 0:
            source_bytes = source.stdout
            if source_bytes and not source_bytes.endswith(b"\n"):
                raise ValidationError("source schema-2 ledger lacks an event boundary")
            if not current_bytes.startswith(source_bytes):
                raise ValidationError("schema-2 ledger is not an append-only extension of S")
            appended_bytes = current_bytes[len(source_bytes) :]
        else:
            appended_bytes = current_bytes
        raw_events = [
            _json_loads(line)
            for line in appended_bytes.decode("utf-8").splitlines()
            if line.strip()
        ]
        if len(raw_events) != len(EVIDENCE_CATEGORIES) or any(
            not isinstance(event, Mapping)
            or set(event) != {"type", "entry"}
            or event.get("type") != "EVIDENCE"
            for event in raw_events
        ):
            raise ValidationError("schema-2 release ledger event scope is not exact")
        ledger = EvidenceLedger.open_canonical(
            {
                validator_id: specification.version
                for validator_id, specification in trusted_validators.items()
            },
            journal_root=root / ".artifex/validation",
        )
        ledger_entries = {entry.evidence_id: entry for entry in ledger.entries}
        if len(ledger_entries) != len(ledger.entries) or not set(entries) <= set(ledger_entries):
            raise ValidationError("schema-2 release ledger evidence IDs do not match YAML")
        for evidence_id, entry in entries.items():
            if ledger_entries[evidence_id] != entry or not any(
                isinstance(event, Mapping)
                and isinstance(event.get("entry"), Mapping)
                and event["entry"] == evidence_to_payload(entry)
                for event in raw_events
            ):
                raise ValidationError(f"schema-2 release ledger/YAML mismatch: {evidence_id}")
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        blockers.append(f"canonical release evidence ledger invalid: {exc}")
        return
    checks.append("canonical schema-2 ledger matches final YAML evidence")


def _documentation_freshness(
    root: Path,
    binding: EvidenceBinding,
    blockers: list[str],
    checks: list[str],
) -> None:
    try:
        path = _safe_relative_file(root, DOCUMENTATION_MANIFEST, label="documentation manifest")
        value = _json_loads(path.read_text(encoding="utf-8"))
        files = value.get("files") if isinstance(value, Mapping) else None
        expected_paths = {
            *REQUIRED_GUIDES,
            *REQUIRED_GENERATED,
            *REQUIRED_MACHINE,
            *COMPREHENSION_ARTIFACTS,
            *REQUIRED_DASHBOARD,
        }
        if (
            not isinstance(value, Mapping)
            or set(value)
            != {
                "schema_version",
                "candidate_commit",
                "project_model_fingerprint",
                "generator",
                "files",
            }
            or value.get("schema_version") != "1.0"
            or value.get("candidate_commit") != binding.base_commit
            or value.get("project_model_fingerprint") != binding.project_model_fingerprints[0]
            or value.get("generator")
            != {"id": "artifex-compilation", "version": VERSION, "deterministic": True}
            or not isinstance(files, Mapping)
            or set(files) != expected_paths
        ):
            raise ValidationError("documentation manifest identity/scope mismatch")
        for relative, digest in files.items():
            document = _safe_relative_file(root, relative, label="generated documentation")
            if (
                not isinstance(digest, str)
                or _portable_text_digest(document.read_bytes()) != digest
            ):
                raise ValidationError(f"documentation fingerprint mismatch: {relative}")
        for relative in (*REQUIRED_GUIDES, *REQUIRED_GENERATED):
            text = (root / relative).read_text(encoding="utf-8")
            topic = Path(relative).stem.replace("_", " ").casefold()
            terms = DOCUMENT_TOPIC_TERMS[Path(relative).stem]
            words = re.findall(r"[a-z0-9-]+", text.casefold())
            content_lines = [line.strip() for line in text.splitlines() if line.strip()]
            if (
                len(text.strip()) < 350
                or len(set(words)) < 45
                or len(set(content_lines)) != len(content_lines)
                or not text.lstrip().startswith("#")
                or topic not in text.casefold()
                or any(
                    f"## {section}" not in text
                    for section in ("Purpose", "Authority", "Controls", "Verification")
                )
                or f"Candidate: {binding.base_commit}" not in text
                or f"Model: {binding.project_model_fingerprints[0]}" not in text
                or any(term not in text.casefold() for term in terms)
            ):
                raise ValidationError(
                    f"placeholder or topically incomplete documentation: {relative}"
                )
        for relative, human in zip(REQUIRED_MACHINE, REQUIRED_GENERATED, strict=True):
            machine = _json_loads((root / relative).read_text(encoding="utf-8"))
            expected_machine = {
                "schema_version": "1.0",
                "candidate_commit": binding.base_commit,
                "project_model_fingerprint": binding.project_model_fingerprints[0],
                "topic": Path(human).stem,
                "source_human": human,
                "source_sha256": _portable_text_digest((root / human).read_bytes()),
            }
            if machine != expected_machine:
                raise ValidationError(f"machine understanding artifact invalid: {relative}")
        prompt = _json_loads((root / COMPREHENSION_ARTIFACTS[0]).read_text(encoding="utf-8"))
        response = _json_loads((root / COMPREHENSION_ARTIFACTS[1]).read_text(encoding="utf-8"))
        result = _json_loads((root / COMPREHENSION_ARTIFACTS[2]).read_text(encoding="utf-8"))
        questions = [
            {"id": f"Q-{index:02d}", "topic": Path(path).stem}
            for index, path in enumerate(REQUIRED_GENERATED, start=1)
        ]
        expected_prompt = {
            "schema_version": "1.0",
            "candidate_commit": binding.base_commit,
            "project_model_fingerprint": binding.project_model_fingerprints[0],
            "questions": questions,
        }
        if prompt != expected_prompt:
            raise ValidationError("comprehension prompt is invalid")
        answers = response.get("answers") if isinstance(response, Mapping) else None
        if (
            not isinstance(response, Mapping)
            or set(response) != {"schema_version", "validator_id", "answers"}
            or response.get("schema_version") != "1.0"
            or response.get("validator_id") != "independent-reviewer"
            or not isinstance(answers, list)
            or [item.get("id") for item in answers if isinstance(item, Mapping)]
            != [item["id"] for item in questions]
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "id",
                    "topic",
                    "answer",
                    "source_sha256",
                    "candidate_commit",
                    "project_model_fingerprint",
                    "assertions",
                }
                or not isinstance(item.get("answer"), str)
                or len(item["answer"]) < 120
                or item.get("topic") != questions[index]["topic"]
                or str(questions[index]["topic"]).casefold()
                not in item["answer"].casefold()
                or item.get("source_sha256")
                != _portable_text_digest((root / REQUIRED_GENERATED[index]).read_bytes())
                or item.get("candidate_commit") != binding.base_commit
                or item.get("project_model_fingerprint")
                != binding.project_model_fingerprints[0]
                or item.get("assertions")
                != [
                    f"topic:{term}"
                    for term in DOCUMENT_TOPIC_TERMS[Path(REQUIRED_GENERATED[index]).stem]
                ]
                or len(set(re.findall(r"[a-z0-9-]+", item["answer"].casefold()))) < 20
                or any(
                    term not in item["answer"].casefold()
                    for term in DOCUMENT_TOPIC_TERMS[
                        Path(REQUIRED_GENERATED[index]).stem
                    ]
                )
                for index, item in enumerate(answers)
            )
        ):
            raise ValidationError("independent comprehension response is invalid")
        expected_result = {
            "schema_version": "1.0",
            "passed": len(questions),
            "total": len(questions),
            "score": 1.0,
            "prompt_sha256": _portable_text_digest(
                (root / COMPREHENSION_ARTIFACTS[0]).read_bytes()
            ),
            "response_sha256": _portable_text_digest(
                (root / COMPREHENSION_ARTIFACTS[1]).read_bytes()
            ),
            "answer_sha256": [
                hashlib.sha256(
                    json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                for item in answers
            ],
        }
        if result != expected_result:
            raise ValidationError("independent comprehension result is invalid")
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        blockers.append(f"generated documentation freshness invalid: {exc}")
        return
    checks.append("candidate/model-bound generated documentation")


def _validate_dashboard(root: Path, binding: EvidenceBinding) -> None:
    state_path = _safe_relative_file(
        root, REQUIRED_DASHBOARD[1], label="dashboard state"
    )
    index_path = _safe_relative_file(
        root, REQUIRED_DASHBOARD[0], label="dashboard index"
    )
    state_payload = _json_loads(state_path.read_bytes())
    schema_payload = _json_loads(
        (root / "schemas/dashboard-state.schema.json").read_bytes()
    )
    if not isinstance(state_payload, Mapping) or not isinstance(schema_payload, Mapping):
        raise ValidationError("dashboard state/schema is not an object")
    jsonschema.Draft202012Validator(schema_payload).validate(state_payload)
    project = state_payload.get("project")
    git = state_payload.get("git")
    milestones = state_payload.get("milestones")
    gates = state_payload.get("gates")
    evidence = state_payload.get("evidence")
    tests = state_payload.get("tests")
    traceability = state_payload.get("traceability")
    documentation = state_payload.get("documentation")
    integrations = state_payload.get("integrations")
    comprehension = state_payload.get("comprehension")
    status = _yaml(root / ".artifex/status.yaml")
    status_milestones = status.get("milestones") if isinstance(status, Mapping) else None
    expected_milestones = (
        set(status_milestones) if isinstance(status_milestones, Mapping) else set()
    )
    milestone_rows = {
        item.get("id"): item for item in milestones if isinstance(item, Mapping)
    } if isinstance(milestones, list) else {}
    expected_integrations = {"manual", "hermes", "codex", "claude", "deepseek", "pandora"}
    integration_rows = {
        item.get("id"): item for item in integrations if isinstance(item, Mapping)
    } if isinstance(integrations, list) else {}
    expected_docs = set((*REQUIRED_GUIDES, *REQUIRED_GENERATED))
    documentation_rows = {
        item.get("path"): item for item in documentation if isinstance(item, Mapping)
    } if isinstance(documentation, list) else {}
    suites = tests.get("suites") if isinstance(tests, Mapping) else None
    trace_report = validate_traceability(root)
    if (
        not isinstance(project, Mapping)
        or project.get("id") != "ARTIFEX"
        or project.get("current_milestone") != "M11"
        or project.get("accepted_baseline") != binding.base_commit
        or not isinstance(git, Mapping)
        or git.get("commit") != binding.base_commit
        or git.get("dirty") is not False
        or not isinstance(milestones, list)
        or len(milestones) != len(expected_milestones)
        or set(milestone_rows) != expected_milestones
        or any(
            row.get("state")
            != ("VERIFYING" if milestone_id == "M11" else status_milestones[milestone_id])
            or type(row.get("completed_tasks")) is not int
            or row.get("completed_tasks") != row.get("total_tasks")
            or row.get("blockers") != []
            for milestone_id, row in milestone_rows.items()
        )
        or not isinstance(gates, Mapping)
        or gates.get("pass") != len(MANDATORY_GATES)
        or any(gates.get(key) != 0 for key in ("fail", "blocked", "waived", "stale"))
        or not isinstance(evidence, Mapping)
        or evidence.get("current") != len(EVIDENCE_CATEGORIES)
        or evidence.get("stale") != 0
        or not isinstance(suites, list)
        or not suites
        or any(
            not isinstance(suite, Mapping)
            or set(suite) != {"name", "state"}
            or not isinstance(suite.get("name"), str)
            or not suite["name"]
            or suite.get("state") != "PASS"
            for suite in suites
        )
        or len({suite["name"] for suite in suites}) != len(suites)
        or not trace_report.passed
        or traceability
        != {
            "requirements_total": trace_report.requirements_total,
            "requirements_traced": trace_report.requirements_total,
            "orphan_requirements": 0,
        }
        or len(documentation_rows) != len(expected_docs)
        or set(documentation_rows) != expected_docs
        or any(row.get("state") != "CURRENT" for row in documentation_rows.values())
        or len(integration_rows) != len(expected_integrations)
        or set(integration_rows) != expected_integrations
        or any(
            row.get("state") != "PASS" or row.get("version") != VERSION
            for row in integration_rows.values()
        )
        or not isinstance(comprehension, Mapping)
        or comprehension != {"state": "PASS", "score": 1.0}
    ):
        raise ValidationError("dashboard state is not a complete candidate measurement")
    index_text = index_path.read_text(encoding="utf-8")
    match = re.search(
        r'<script id="artifex-dashboard-provenance" type="application/json">(.*?)</script>',
        index_text,
        flags=re.DOTALL,
    )
    provenance = _json_loads(match.group(1)) if match else None
    expected_provenance = {
        "schema_version": "1.0",
        "canonical": False,
        "candidate_commit": binding.base_commit,
        "project_model_fingerprint": binding.project_model_fingerprints[0],
        "state_sha256": _portable_text_digest(state_path.read_bytes()),
    }
    if (
        len(index_text) < 500
        or "<!doctype html>" not in index_text.casefold()
        or "non-canonical" not in index_text.casefold()
        or any(
            f'id="{section}"' not in index_text
            for section in ("milestones", "gates", "evidence")
        )
        or provenance != expected_provenance
    ):
        raise ValidationError("dashboard index is placeholder, stale, or unbound")


def _governance_clean(root: Path, artifact_values: object) -> None:
    artifact_paths: set[str] = set()
    if isinstance(artifact_values, list):
        artifact_paths = {
            str(item["path"])
            for item in artifact_values
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        }
    status = _git(root, "status", "--porcelain", "--untracked-files=all")
    if status.returncode != 0:
        raise ValidationError("cannot inspect governance worktree cleanliness")
    dirty = []
    for line in status.stdout.decode().splitlines():
        path = line[3:].strip().strip('"')
        normalized = path.replace("\\", "/")
        if normalized not in artifact_paths:
            dirty.append(normalized)
    if dirty:
        raise ValidationError(f"governance worktree is dirty: {','.join(sorted(dirty))}")
    required = {
        ".artifex/project-model.json",
        ".artifex/status.yaml",
        ".artifex/audit.jsonl",
        ".artifex/validation/contracts/V1-RELEASE.yaml",
        ".artifex/releases/v1.0.0.yaml",
        ".artifex/implementation/traceability.yaml",
        FINAL_LEDGER,
        *REQUIRED_GUIDES,
        *REQUIRED_GENERATED,
        *REQUIRED_MACHINE,
        *COMPREHENSION_ARTIFACTS,
        *REQUIRED_DASHBOARD,
        DOCUMENTATION_MANIFEST,
        *REQUIRED_KNOWLEDGE,
    }
    required.update(
        str(path.relative_to(root)).replace("\\", "/")
        for directory in (
            root / ".artifex/validation/contracts",
            root / ".artifex/validation/evidence",
            root / ".artifex/validation/gates",
        )
        for path in directory.glob("*")
        if path.is_file()
    )
    untracked = [
        path for path in required if _git(root, "ls-files", "--error-unmatch", path).returncode
    ]
    if untracked:
        raise ValidationError(
            f"release governance input is not tracked at G: {','.join(sorted(untracked))}"
        )


def _git_blob_hash(root: Path, relative: str) -> str:
    try:
        path = _safe_relative_file(root, relative, label="milestone contract")
        result = subprocess.run(
            ("git", "-C", str(root), "show", f"HEAD:{relative}"),
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            raise ValidationError(f"milestone contract is not committed at HEAD: {relative}")
        if (
            subprocess.run(
                ("git", "-C", str(root), "diff", "--quiet", "HEAD", "--", relative),
                check=False,
                timeout=10,
            ).returncode
            != 0
        ):
            raise ValidationError(f"milestone contract differs from HEAD: {relative}")
        if not path.is_file():
            raise ValidationError(f"milestone contract missing: {relative}")
        return hashlib.sha256(result.stdout).hexdigest()
    except OSError as exc:
        raise ValidationError(f"cannot inspect milestone contract: {relative}: {exc}") from exc


def _historical_evidence(root: Path, evidence_id: str, contract_hash: str) -> None:
    candidates = (
        f".artifex/validation/evidence/{evidence_id}.yaml",
        f".artifex/validation/evidence/{evidence_id}.json",
    )
    existing = [relative for relative in candidates if (root / relative).exists()]
    if len(existing) != 1:
        raise ValidationError(f"historical evidence missing or ambiguous: {evidence_id}")
    path = _safe_relative_file(root, existing[0], label="historical evidence")
    try:
        text = path.read_text(encoding="utf-8")
        payload = (
            _json_loads(text)
            if path.suffix == ".json"
            else yaml.load(text, Loader=_UniqueYamlLoader)
        )
    except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise ValidationError(
            f"historical evidence cannot be parsed: {evidence_id}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ValidationError(f"historical evidence is not an object: {evidence_id}")
    classification = classify_evidence_payload(payload)
    if classification is EvidenceClassification.CANONICAL:
        validator_id = payload.get("validator_id")
        validator_version = payload.get("validator_version")
        if not isinstance(validator_id, str) or not isinstance(validator_version, str):
            raise ValidationError(f"canonical historical validator missing: {evidence_id}")
        entry = evidence_from_payload(
            payload,
            trusted_validators={validator_id: validator_version},
            require_independent=True,
        )
        if (
            entry.evidence_id != evidence_id
            or entry.outcome.value != "PASS"
            or entry.binding.contract_hash != contract_hash
        ):
            raise ValidationError(f"canonical historical evidence mismatch: {evidence_id}")
        return
    wrapped = payload.get("evidence")
    if isinstance(wrapped, Mapping):
        source, result = wrapped.get("source"), wrapped.get("result")
        if (
            wrapped.get("id") != evidence_id
            or not isinstance(source, Mapping)
            or source.get("contract_hash") != contract_hash
            or not isinstance(result, Mapping)
            or result.get("status") != "PASS"
        ):
            raise ValidationError(f"wrapped historical evidence mismatch: {evidence_id}")
        return
    validator, binding = payload.get("validator"), payload.get("binding")
    if (
        payload.get("evidence_id") != evidence_id
        or payload.get("outcome") != "PASS"
        or not isinstance(validator, Mapping)
        or not isinstance(binding, Mapping)
        or binding.get("contract_hash") != contract_hash
    ):
        raise ValidationError(f"flat historical evidence mismatch: {evidence_id}")


def _gate_payload(root: Path, gate_id: str) -> Mapping[str, object]:
    relative = f".artifex/validation/gates/{gate_id}.yaml"
    path = _safe_relative_file(root, relative, label="gate")
    payload = _yaml(path)
    gate = payload.get("gate") if payload else None
    if (
        payload is None
        or set(payload) != {"schema_version", "gate"}
        or payload.get("schema_version") != "1.0"
        or not isinstance(gate, Mapping)
        or set(gate)
        != {
            "id",
            "scope",
            "target",
            "state",
            "contract_hash",
            "required_evidence",
            "waiver_allowed",
        }
    ):
        raise ValidationError(f"gate is malformed: {gate_id}")
    return gate


def _historical_gate(root: Path, milestone: str) -> None:
    gate_id = f"G-{milestone}-MILESTONE"
    gate = _gate_payload(root, gate_id)
    required = gate.get("required_evidence")
    if gate.get("id") != gate_id or gate.get("target") != milestone:
        raise ValidationError(f"historical gate identity/target mismatch: {gate_id}")
    if gate.get("state") != "PASS" or gate.get("waiver_allowed") is not False:
        raise ValidationError(f"historical gate is not nonwaivable PASS: {gate_id}")
    if gate.get("scope") != "MILESTONE":
        raise ValidationError(f"historical gate scope mismatch: {gate_id}")
    contract_hash = gate.get("contract_hash")
    if not isinstance(contract_hash, str) or len(contract_hash) != 64:
        raise ValidationError(f"historical gate contract hash invalid: {gate_id}")
    observed = _git_blob_hash(root, f".artifex/validation/contracts/{milestone}.yaml")
    if contract_hash != observed:
        raise ValidationError(f"historical gate contract hash mismatch: {gate_id}")
    if (
        not isinstance(required, list)
        or not required
        or any(not isinstance(item, str) for item in required)
        or len(set(required)) != len(required)
    ):
        raise ValidationError(f"historical gate required evidence invalid: {gate_id}")
    for evidence_id in required:
        _historical_evidence(root, evidence_id, contract_hash)


def _current_gate(
    root: Path,
    gate_id: str,
    expected_target: str,
    expected_scope: str,
    expected_evidence: tuple[str, ...],
    entries: Mapping[str, EvidenceEntry],
    binding: EvidenceBinding,
) -> None:
    gate = _gate_payload(root, gate_id)
    required = gate.get("required_evidence")
    if (
        gate.get("id") != gate_id
        or gate.get("target") != expected_target
        or gate.get("scope") != expected_scope
    ):
        raise ValidationError(f"current gate identity/target mismatch: {gate_id}")
    if gate.get("state") != "PASS" or gate.get("waiver_allowed") is not False:
        raise ValidationError(f"current gate is not nonwaivable PASS: {gate_id}")
    if gate.get("contract_hash") != binding.contract_hash:
        raise ValidationError(f"current gate contract hash mismatch: {gate_id}")
    if not isinstance(required, list) or required != list(expected_evidence):
        raise ValidationError(f"current gate evidence scope mismatch: {gate_id}")
    if any(
        evidence_id not in entries or entries[evidence_id].binding != binding
        for evidence_id in expected_evidence
    ):
        raise ValidationError(f"current gate evidence binding mismatch: {gate_id}")


def _gates(
    root: Path,
    entries: Mapping[str, EvidenceEntry],
    binding: EvidenceBinding,
    blockers: list[str],
    checks: list[str],
) -> None:
    for milestone in (f"M{number:02d}" for number in range(10)):
        try:
            _historical_gate(root, milestone)
        except ValidationError as exc:
            blockers.append(str(exc))
    m11_evidence = tuple(
        item for item in EVIDENCE_CATEGORIES if item.startswith("EVD-M11-")
    )
    for gate_id, target, scope, required in (
        ("G-M11-MILESTONE", "M11", "MILESTONE", m11_evidence),
        ("G-V1-RELEASE", "V1", "RELEASE", ("EVD-V1-RELEASE",)),
    ):
        try:
            _current_gate(root, gate_id, target, scope, required, entries, binding)
        except ValidationError as exc:
            blockers.append(str(exc))
    optional_path = root / ".artifex/validation/gates/G-M10-MILESTONE.yaml"
    if optional_path.exists():
        try:
            _historical_gate(root, "M10")
            checks.append("optional M10 historical gate structurally valid and ignored for Core GA")
        except ValidationError as exc:
            checks.append(f"optional M10 gate invalid and ignored for Core GA: {exc}")


def _artifacts(
    root: Path,
    manifest: Mapping[str, object],
    binding: EvidenceBinding,
    blockers: list[str],
    checks: list[str],
) -> None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        blockers.append("release artifact index missing")
        return
    seen_paths: set[str] = set()
    seen_kinds: set[str] = set()
    seen_digests: set[str] = set()
    observed_files: list[Path] = []
    for item in artifacts:
        if not isinstance(item, Mapping):
            blockers.append("malformed release artifact entry")
            continue
        if set(item) != {"path", "sha256", "kind", "provenance_sha256"}:
            blockers.append("malformed release artifact entry")
            continue
        path_value, digest, kind, provenance_digest = (
            item.get("path"),
            item.get("sha256"),
            item.get("kind"),
            item.get("provenance_sha256"),
        )
        if (
            not isinstance(path_value, str)
            or not isinstance(digest, str)
            or not isinstance(kind, str)
            or not isinstance(provenance_digest, str)
            or len(provenance_digest) != 64
        ):
            blockers.append("malformed release artifact identity")
            continue
        if path_value in seen_paths:
            blockers.append(f"duplicate release artifact path: {path_value}")
            continue
        if kind in seen_kinds:
            blockers.append(f"duplicate release artifact kind: {kind}")
            continue
        seen_paths.add(path_value)
        seen_kinds.add(kind)
        try:
            artifact = _safe_relative_file(root, path_value, label="release artifact")
        except ValidationError as exc:
            blockers.append(str(exc))
            continue
        try:
            if any(os.path.samefile(artifact, observed) for observed in observed_files):
                blockers.append(f"release artifact file reused across kinds: {path_value}")
                continue
        except OSError as exc:
            blockers.append(f"cannot identify release artifact: {path_value}: {exc}")
            continue
        observed_files.append(artifact)
        observed_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if observed_digest != digest:
            blockers.append(f"release artifact hash mismatch: {path_value}")
            continue
        if observed_digest in seen_digests:
            blockers.append(f"release artifact content relabeled across kinds: {path_value}")
            continue
        seen_digests.add(observed_digest)
        try:
            _validate_artifact_identity(root, artifact, kind, binding, provenance_digest)
        except ValidationError as exc:
            blockers.append(str(exc))
    required_kinds = set(REQUIRED_ARTIFACT_KINDS)
    missing_kinds = required_kinds - seen_kinds
    if missing_kinds:
        blockers.append(f"release artifact kinds missing: {','.join(sorted(missing_kinds))}")
    elif not any(blocker.startswith("release artifact") for blocker in blockers):
        checks.append("unique integrity-checked release artifacts")


def _safe_archive_name(name: str) -> None:
    if not name or "\\" in name:
        raise ValidationError(f"release archive contains unsafe path: {name}")
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} or ":" in part for part in name.split("/"))
        or path.as_posix() != name.rstrip("/")
    ):
        raise ValidationError(f"release archive contains unsafe path: {name}")


def _archive_bounds(names_and_sizes: list[tuple[str, int]], *, label: str) -> None:
    names = [name for name, _ in names_and_sizes]
    sizes = [size for _, size in names_and_sizes]
    for name in names:
        _safe_archive_name(name)
    folded = [name.rstrip("/").casefold() for name in names]
    if (
        not names
        or len(names) > 20_000
        or len(set(names)) != len(names)
        or len(set(folded)) != len(folded)
        or any(size < 0 or size > 512 * 1024 * 1024 for size in sizes)
        or sum(sizes) > 1024 * 1024 * 1024
    ):
        raise ValidationError(f"{label} archive inventory exceeds safety bounds")


def _validate_zip_member(info: zipfile.ZipInfo, *, label: str) -> None:
    file_type = (info.external_attr >> 16) & stat.S_IFMT(0o170000)
    allowed = {0, stat.S_IFDIR} if info.is_dir() else {0, stat.S_IFREG}
    if file_type not in allowed:
        raise ValidationError(f"{label} contains a special file")


def _normalized_requirement(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError("candidate dependency metadata is malformed")
    match = re.fullmatch(r"([A-Za-z0-9._-]+)((?:[<>=!~]=?[^,; ]+)(?:,[<>=!~]=?[^,; ]+)*)", value)
    if match is None:
        raise ValidationError("candidate dependency metadata is unsupported")
    name, specifiers = match.groups()
    return name.replace("_", "-").casefold() + ",".join(sorted(specifiers.split(",")))


def _source_package_metadata(root: Path, candidate: str) -> tuple[bytes, bytes, bytes]:
    repository = _candidate_repository_files(root, candidate)
    try:
        pyproject = tomllib.loads(repository["pyproject.toml"].decode("utf-8"))
        project = pyproject["project"]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError("candidate package metadata authority is malformed") from exc
    if not isinstance(project, Mapping):
        raise ValidationError("candidate package metadata authority is malformed")
    name, version = project.get("name"), project.get("version")
    if name != "artifex-dev" or version != VERSION:
        raise ValidationError("candidate package metadata identity mismatch")
    headers = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    scalar_headers = (
        ("description", "Summary"),
        ("requires-python", "Requires-Python"),
    )
    for key, header in scalar_headers:
        value = project.get(key)
        if value is not None:
            if not isinstance(value, str) or "\n" in value or "\r" in value:
                raise ValidationError("candidate package metadata authority is malformed")
            headers.append(f"{header}: {value}")
    authors = project.get("authors")
    if authors is not None:
        if (
            not isinstance(authors, list)
            or not authors
            or any(
                not isinstance(item, Mapping) or not isinstance(item.get("name"), str)
                for item in authors
            )
        ):
            raise ValidationError("candidate package author metadata is malformed")
        headers.append("Author: " + ", ".join(str(item["name"]) for item in authors))
    license_value = project.get("license")
    if license_value is not None:
        if not isinstance(license_value, Mapping) or not isinstance(license_value.get("text"), str):
            raise ValidationError("candidate package license metadata is malformed")
        headers.append(f"License: {license_value['text']}")
    if "LICENSE" in repository:
        headers.append("License-File: LICENSE")
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValidationError("candidate package dependency metadata is malformed")
    headers.extend(f"Requires-Dist: {_normalized_requirement(item)}" for item in dependencies)
    classifiers = project.get("classifiers", [])
    if not isinstance(classifiers, list) or any(not isinstance(item, str) for item in classifiers):
        raise ValidationError("candidate package classifier metadata is malformed")
    headers.extend(f"Classifier: {item}" for item in classifiers)
    body = b""
    readme = project.get("readme")
    if readme is not None:
        if not isinstance(readme, str) or readme not in repository:
            raise ValidationError("candidate package readme metadata is malformed")
        content_type = "text/markdown" if readme.casefold().endswith(".md") else "text/plain"
        headers.append(f"Description-Content-Type: {content_type}")
        body = repository[readme]
    metadata = ("\n".join(headers) + "\n\n").encode() + body
    wheel = (
        b"Wheel-Version: 1.0\n"
        b"Generator: hatchling 1.27.0\n"
        b"Root-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )
    scripts = project.get("scripts")
    if scripts != {"artifex": "artifex.cli:app"}:
        raise ValidationError("candidate console entry point metadata is malformed")
    entry_points = b"[console_scripts]\nartifex = artifex.cli:app\n"
    return metadata, wheel, entry_points


def _validate_package_metadata(
    root: Path,
    candidate: str,
    *,
    metadata: bytes,
    label: str,
    wheel: bytes | None = None,
    entry_points: bytes | None = None,
) -> None:
    expected_metadata, expected_wheel, expected_entry_points = _source_package_metadata(
        root, candidate
    )
    if metadata != expected_metadata:
        raise ValidationError(f"{label} package metadata differs from candidate S")
    if wheel is not None and wheel != expected_wheel:
        raise ValidationError("wheel build metadata differs from pinned candidate tooling")
    if entry_points is not None and entry_points != expected_entry_points:
        raise ValidationError("wheel console entry point differs from candidate S")


def _validate_packaged_schema(content: bytes, *, label: str) -> None:
    try:
        schema = _json_loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} evidence schema is invalid") from exc
    required = schema.get("required") if isinstance(schema, Mapping) else None
    properties = schema.get("properties") if isinstance(schema, Mapping) else None
    schema_version = properties.get("schema_version") if isinstance(properties, Mapping) else None
    if (
        not isinstance(required, list)
        or "independent_of_executor" not in required
        or not isinstance(schema_version, Mapping)
        or schema_version.get("const") != "2.0"
    ):
        raise ValidationError(f"{label} evidence schema identity mismatch")


def _candidate_source_files(root: Path, source_commit: str) -> dict[str, bytes]:
    listing = _git(
        root,
        "ls-tree",
        "-r",
        "--name-only",
        source_commit,
        "--",
        "src/artifex",
        "schemas/acceptance-evidence.schema.json",
        "pyproject.toml",
    )
    if listing.returncode != 0:
        raise ValidationError("candidate package inventory is unavailable")
    paths = tuple(
        relative
        for relative in listing.stdout.decode().splitlines()
        if relative == "pyproject.toml"
        or relative == "schemas/acceptance-evidence.schema.json"
        or relative.startswith("src/artifex/")
    )
    if not paths or "pyproject.toml" not in paths:
        raise ValidationError("candidate package inventory is incomplete")
    values: dict[str, bytes] = {}
    for relative in paths:
        result = _git(root, "show", f"{source_commit}:{relative}")
        if result.returncode != 0:
            raise ValidationError(f"candidate source payload missing: {relative}")
        values[relative] = result.stdout
    return values


def _candidate_repository_files(root: Path, source_commit: str) -> dict[str, bytes]:
    listing = _git(root, "ls-tree", "-r", "--name-only", source_commit)
    if listing.returncode != 0:
        raise ValidationError("candidate repository inventory is unavailable")
    paths = tuple(relative for relative in listing.stdout.decode().splitlines() if relative)
    if not paths:
        raise ValidationError("candidate repository inventory is empty")
    values: dict[str, bytes] = {}
    for relative in paths:
        result = _git(root, "show", f"{source_commit}:{relative}")
        if result.returncode != 0:
            raise ValidationError(f"candidate repository payload missing: {relative}")
        values[relative] = result.stdout
    return values


def _validate_release_provenance(
    root: Path,
    raw: bytes,
    *,
    expected_digest: str,
    kind: str,
    binding: EvidenceBinding,
    packaged_sources: Mapping[str, bytes] | None = None,
) -> None:
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValidationError(f"embedded release provenance hash mismatch for {kind}")
    try:
        value = _json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"embedded release provenance invalid for {kind}") from exc
    source_files = (
        _candidate_repository_files(root, binding.base_commit)
        if kind == "sdist"
        else _candidate_source_files(root, binding.base_commit)
    )
    expected = {
        "schema_version": "1.0",
        "artifact_kind": kind,
        "source_commit": binding.base_commit,
        "project_model_fingerprint": binding.project_model_fingerprints[0],
        "toolchain": (
            "hatchling==1.27.0"
            if kind in {"wheel", "sdist"}
            else f"pyinstaller=={_locked_pyinstaller(root)}"
        ),
        "source_files": {
            path: hashlib.sha256(content).hexdigest() for path, content in source_files.items()
        },
    }
    if value != expected:
        raise ValidationError(f"embedded release provenance/source inventory mismatch for {kind}")
    if packaged_sources is not None:
        expected_packaged = dict(source_files)
        if kind == "wheel":
            expected_packaged.pop("pyproject.toml")
        if dict(packaged_sources) != expected_packaged:
            raise ValidationError(f"packaged source differs from candidate S for {kind}")


def _validate_source_version(content: bytes, *, label: str) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{label} package version source is invalid") from exc
    if re.search(r'^__version__\s*=\s*["\']1\.0\.0["\']', text, re.MULTILINE) is None:
        raise ValidationError(f"{label} package version source mismatch")


def _validate_wheel(
    root: Path, path: Path, binding: EvidenceBinding, provenance_digest: str
) -> None:
    if re.fullmatch(r"artifex_dev-1\.0\.0-py3-none-any\.whl", path.name) is None:
        raise ValidationError("wheel filename identity/tags mismatch")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            _archive_bounds([(info.filename, info.file_size) for info in infos], label="wheel")
            for info in infos:
                _safe_archive_name(info.filename)
                _validate_zip_member(info, label="wheel")
                if info.flag_bits & 0x1:
                    raise ValidationError("wheel contains encrypted content")
            metadata = [info for info in infos if info.filename.endswith(".dist-info/METADATA")]
            wheel = [info for info in infos if info.filename.endswith(".dist-info/WHEEL")]
            entry_points = [
                info for info in infos if info.filename.endswith(".dist-info/entry_points.txt")
            ]
            records = [info for info in infos if info.filename.endswith(".dist-info/RECORD")]
            if len(metadata) != 1 or len(wheel) != 1 or len(entry_points) != 1 or len(records) != 1:
                raise ValidationError("wheel metadata files missing or ambiguous")
            _validate_package_metadata(
                root,
                binding.base_commit,
                metadata=archive.read(metadata[0]),
                wheel=archive.read(wheel[0]),
                entry_points=archive.read(entry_points[0]),
                label="wheel",
            )
            names = {info.filename for info in infos if not info.is_dir()}
            candidate_sources = _candidate_source_files(root, binding.base_commit)
            candidate_repository = _candidate_repository_files(root, binding.base_commit)
            dist_info_name = f"artifex_dev-{VERSION}.dist-info"
            expected_package_names = {
                (
                    "artifex/schemas/acceptance-evidence.schema.json"
                    if source_name == "schemas/acceptance-evidence.schema.json"
                    else source_name.removeprefix("src/")
                )
                for source_name in candidate_sources
                if source_name != "pyproject.toml"
            }
            package_names = {name for name in names if name.startswith("artifex/")}
            if package_names != expected_package_names:
                raise ValidationError("wheel package inventory differs from candidate S")
            _validate_source_version(archive.read("artifex/_version.py"), label="wheel")
            _validate_packaged_schema(
                archive.read("artifex/schemas/acceptance-evidence.schema.json"),
                label="wheel",
            )
            provenance_names = [
                name
                for name in names
                if name.endswith(".dist-info/artifex-release-provenance.json")
            ]
            provenance_name = f"{dist_info_name}/artifex-release-provenance.json"
            expected_names = expected_package_names | {
                f"{dist_info_name}/METADATA",
                f"{dist_info_name}/WHEEL",
                f"{dist_info_name}/entry_points.txt",
                f"{dist_info_name}/RECORD",
                provenance_name,
            }
            license_name = f"{dist_info_name}/licenses/LICENSE"
            if "LICENSE" in candidate_repository:
                expected_names.add(license_name)
            if provenance_names != [provenance_name]:
                raise ValidationError("wheel release provenance missing or ambiguous")
            if names != expected_names:
                raise ValidationError("wheel archive inventory differs from candidate S")
            if (
                "LICENSE" in candidate_repository
                and archive.read(license_name) != candidate_repository["LICENSE"]
            ):
                raise ValidationError("wheel license differs from candidate S")
            _validate_release_provenance(
                root,
                archive.read(provenance_name),
                expected_digest=provenance_digest,
                kind="wheel",
                binding=binding,
                packaged_sources={
                    source_name: archive.read(
                        "artifex/schemas/acceptance-evidence.schema.json"
                        if source_name == "schemas/acceptance-evidence.schema.json"
                        else source_name.removeprefix("src/")
                    )
                    for source_name in candidate_sources
                    if source_name != "pyproject.toml"
                },
            )
            rows = list(csv.reader(io.StringIO(archive.read(records[0]).decode("utf-8"))))
            if any(len(row) != 3 for row in rows):
                raise ValidationError("wheel RECORD is malformed")
            record_values = {row[0]: (row[1], row[2]) for row in rows}
            if len(record_values) != len(rows) or set(record_values) != names:
                raise ValidationError("wheel RECORD inventory mismatch")
            for name in names - {records[0].filename}:
                content = archive.read(name)
                digest, size = record_values[name]
                encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
                if digest != f"sha256={encoded.decode()}" or size != str(len(content)):
                    raise ValidationError("wheel RECORD hash/size mismatch")
            if record_values[records[0].filename] != ("", ""):
                raise ValidationError("wheel RECORD self-entry must be unhashed")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(f"wheel format invalid: {exc}") from exc


def _validate_sdist(
    root: Path, path: Path, binding: EvidenceBinding, provenance_digest: str
) -> None:
    if path.name != "artifex_dev-1.0.0.tar.gz":
        raise ValidationError("sdist filename identity mismatch")
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            _archive_bounds([(member.name, member.size) for member in members], label="sdist")
            for member in members:
                _safe_archive_name(member.name)
                if member.issym() or member.islnk():
                    raise ValidationError("sdist contains a link")
                if not member.isfile() and not member.isdir():
                    raise ValidationError("sdist contains a special file")
            metadata = [
                member
                for member in members
                if member.name == "artifex_dev-1.0.0/PKG-INFO" and member.isfile()
            ]
            if len(metadata) != 1:
                raise ValidationError("sdist PKG-INFO missing or ambiguous")
            stream = archive.extractfile(metadata[0])
            if stream is None:
                raise ValidationError("sdist PKG-INFO cannot be read")
            _validate_package_metadata(
                root,
                binding.base_commit,
                metadata=stream.read(),
                label="sdist",
            )
            names = {member.name for member in members if member.isfile()}
            prefix = "artifex_dev-1.0.0/"
            candidate_repository = _candidate_repository_files(root, binding.base_commit)
            expected_names = {f"{prefix}{source}" for source in candidate_repository} | {
                f"{prefix}PKG-INFO",
                f"{prefix}artifex-release-provenance.json",
            }
            if names != expected_names:
                raise ValidationError("sdist source inventory differs from candidate S")
            version_stream = archive.extractfile(f"{prefix}src/artifex/_version.py")
            schema_stream = archive.extractfile(f"{prefix}schemas/acceptance-evidence.schema.json")
            pyproject_stream = archive.extractfile(f"{prefix}pyproject.toml")
            if version_stream is None or schema_stream is None or pyproject_stream is None:
                raise ValidationError("sdist required source payload cannot be read")
            _validate_source_version(version_stream.read(), label="sdist")
            _validate_packaged_schema(schema_stream.read(), label="sdist")
            project = tomllib.loads(pyproject_stream.read().decode("utf-8"))
            if (
                project.get("project", {}).get("name") != "artifex-dev"
                or project.get("project", {}).get("version") != VERSION
                or project.get("build-system", {}).get("requires") != ["hatchling==1.27.0"]
            ):
                raise ValidationError("sdist pyproject identity/tooling mismatch")
            provenance_stream = archive.extractfile(f"{prefix}artifex-release-provenance.json")
            if provenance_stream is None:
                raise ValidationError("sdist release provenance cannot be read")
            packaged_sources: dict[str, bytes] = {}
            for source_path in candidate_repository:
                source_stream = archive.extractfile(f"{prefix}{source_path}")
                if source_stream is None:
                    raise ValidationError("sdist candidate source cannot be read")
                packaged_sources[source_path] = source_stream.read()
            _validate_release_provenance(
                root,
                provenance_stream.read(),
                expected_digest=provenance_digest,
                kind="sdist",
                binding=binding,
                packaged_sources=packaged_sources,
            )
    except (OSError, UnicodeDecodeError, tarfile.TarError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(f"sdist format invalid: {exc}") from exc


def _native_manifest(path: Path, *, zipped: bool) -> Mapping[str, object]:
    try:
        if zipped:
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                _archive_bounds([(info.filename, info.file_size) for info in infos], label="native")
                for info in infos:
                    _safe_archive_name(info.filename)
                    _validate_zip_member(info, label="native bundle")
                    if info.flag_bits & 0x1:
                        raise ValidationError("native bundle contains encrypted content")
                zip_manifests = [
                    info for info in infos if info.filename == "artifex/artifex-artifact.json"
                ]
                if len(zip_manifests) != 1:
                    raise ValidationError("native provenance manifest missing or ambiguous")
                value = _json_loads(archive.read(zip_manifests[0]))
        else:
            with tarfile.open(path, mode="r:gz") as archive:
                members = archive.getmembers()
                _archive_bounds([(member.name, member.size) for member in members], label="native")
                for member in members:
                    _safe_archive_name(member.name)
                    if member.issym() or member.islnk():
                        raise ValidationError("native bundle contains a link")
                    if not member.isfile() and not member.isdir():
                        raise ValidationError("native bundle contains a special file")
                tar_manifests = [
                    member
                    for member in members
                    if member.name == "artifex/artifex-artifact.json" and member.isfile()
                ]
                if len(tar_manifests) != 1:
                    raise ValidationError("native provenance manifest missing or ambiguous")
                stream = archive.extractfile(tar_manifests[0])
                if stream is None:
                    raise ValidationError("native provenance manifest cannot be read")
                value = _json_loads(stream.read())
    except (OSError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(f"native bundle format invalid: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValidationError("native provenance manifest is not an object")
    return value


def _native_payloads(
    path: Path, *, zipped: bool
) -> tuple[Mapping[str, object], dict[str, bytes], dict[str, int]]:
    provenance = _native_manifest(path, zipped=zipped)
    contents: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    if zipped:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if (
                    not info.is_dir()
                    and PurePosixPath(info.filename).name != "artifex-artifact.json"
                ):
                    try:
                        relative = PurePosixPath(info.filename).relative_to("artifex").as_posix()
                    except ValueError as exc:
                        raise ValidationError("native payload is outside bundle root") from exc
                    contents[relative] = archive.read(info)
                    modes[relative] = (info.external_attr >> 16) & 0o777
    else:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile() and PurePosixPath(member.name).name != "artifex-artifact.json":
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValidationError("native bundle payload cannot be read")
                    try:
                        relative = PurePosixPath(member.name).relative_to("artifex").as_posix()
                    except ValueError as exc:
                        raise ValidationError("native payload is outside bundle root") from exc
                    contents[relative] = stream.read()
                    modes[relative] = member.mode
    return provenance, contents, modes


def _validate_artifact_identity(
    root: Path,
    path: Path,
    kind: str,
    binding: EvidenceBinding,
    provenance_digest: str,
) -> None:
    if kind == "wheel":
        _validate_wheel(root, path, binding, provenance_digest)
        return
    if kind == "sdist":
        _validate_sdist(root, path, binding, provenance_digest)
        return
    native = {
        "native-windows-x64": ("windows", "x86_64", "artifex-1.0.0-windows-x64.zip", True),
        "native-linux-x64": ("linux", "x86_64", "artifex-1.0.0-linux-x64.tar.gz", False),
        "native-macos-arm64": ("macos", "arm64", "artifex-1.0.0-macos-arm64.tar.gz", False),
    }
    identity = native.get(kind)
    if identity is None:
        raise ValidationError(f"unknown release artifact kind: {kind}")
    platform, architecture, filename, zipped = identity
    if path.name != filename:
        raise ValidationError(f"native artifact filename mismatch for {kind}")
    provenance, payloads, modes = _native_payloads(path, zipped=zipped)
    if set(provenance) != {
        "schema_version",
        "product",
        "product_version",
        "build_id",
        "format",
        "platform",
        "architecture",
        "artifact",
        "sha256",
        "files",
        "python_version",
        "pyinstaller_version",
        "source_commit",
        "requires_user_python",
        "requires_user_pip",
        "requires_user_venv",
    }:
        raise ValidationError(f"native artifact manifest fields invalid for {kind}")
    executable = "artifex.exe" if platform == "windows" else "artifex"
    executable_content = payloads.get(executable)
    executable_digest = (
        hashlib.sha256(executable_content).hexdigest() if executable_content is not None else None
    )
    magic = {
        "windows": (b"MZ",),
        "linux": (b"\x7fELF",),
        "macos": (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"),
    }
    if (
        not executable_content
        or not any(executable_content.startswith(prefix) for prefix in magic[platform])
        or (platform != "windows" and modes.get(executable, 0) & 0o111 == 0)
    ):
        raise ValidationError(f"native launch executable invalid for {kind}")
    files = provenance.get("files")
    expected_files = [
        {"path": name, "kind": "file", "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in sorted(payloads.items())
    ]
    expected = {
        "schema_version": "4.0",
        "product": "ARTIFEX",
        "product_version": VERSION,
        "format": "pyinstaller-onedir",
        "platform": platform,
        "architecture": architecture,
        "artifact": executable,
        "sha256": executable_digest,
        "source_commit": binding.base_commit,
        "requires_user_python": False,
        "requires_user_pip": False,
        "requires_user_venv": False,
    }
    expected_build = f"artifex-{VERSION}-{platform}-{architecture}-{str(executable_digest)[:16]}"
    if (
        any(provenance.get(key) != value for key, value in expected.items())
        or provenance.get("build_id") != expected_build
        or not isinstance(provenance.get("python_version"), str)
        or provenance.get("pyinstaller_version") != _locked_pyinstaller(root)
        or files != expected_files
    ):
        raise ValidationError(f"native artifact provenance mismatch for {kind}")
    release_provenance = payloads.get("artifex-release-provenance.json")
    if release_provenance is None:
        raise ValidationError(f"native release provenance missing for {kind}")
    schema_relative = "_internal/artifex/schemas/acceptance-evidence.schema.json"
    schema_result = _git(
        root,
        "show",
        f"{binding.base_commit}:schemas/acceptance-evidence.schema.json",
    )
    if schema_result.returncode != 0 or payloads.get(schema_relative) != schema_result.stdout:
        raise ValidationError(f"native canonical evidence schema missing or stale for {kind}")
    _validate_release_provenance(
        root,
        release_provenance,
        expected_digest=provenance_digest,
        kind=kind,
        binding=binding,
    )


def _source_provenance(root: Path, candidate: str, kind: str) -> bytes:
    model_result = _git(root, "show", f"{candidate}:.artifex/project-model.json")
    if model_result.returncode != 0:
        raise ValidationError("candidate Project Model is unavailable")
    _, model_fingerprint = _canonical_model(_json_loads(model_result.stdout))
    source_files = (
        _candidate_repository_files(root, candidate)
        if kind == "sdist"
        else _candidate_source_files(root, candidate)
    )
    value = {
        "schema_version": "1.0",
        "artifact_kind": kind,
        "source_commit": candidate,
        "project_model_fingerprint": model_fingerprint,
        "toolchain": (
            "hatchling==1.27.0"
            if kind in {"wheel", "sdist"}
            else f"pyinstaller=={_locked_pyinstaller(root)}"
        ),
        "source_files": {
            path: hashlib.sha256(content).hexdigest() for path, content in source_files.items()
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _finalize_wheel(root: Path, path: Path, candidate: str) -> None:
    provenance = _source_provenance(root, candidate, "wheel")
    metadata, wheel_metadata, entry_points = _source_package_metadata(root, candidate)
    candidate_sources = _candidate_source_files(root, candidate)
    candidate_repository = _candidate_repository_files(root, candidate)
    with zipfile.ZipFile(path) as archive:
        files = {
            info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()
        }
    dist_info_name = f"artifex_dev-{VERSION}.dist-info"
    dist_info = {PurePosixPath(name).parts[0] for name in files if ".dist-info/" in name}
    if dist_info != {dist_info_name}:
        raise ValidationError("wheel dist-info identity is ambiguous")
    packaged_sources = {
        source_name: files.get(
            "artifex/schemas/acceptance-evidence.schema.json"
            if source_name == "schemas/acceptance-evidence.schema.json"
            else source_name.removeprefix("src/")
        )
        for source_name in candidate_sources
        if source_name != "pyproject.toml"
    }
    packaged_names = {
        source_name: (
            "artifex/schemas/acceptance-evidence.schema.json"
            if source_name == "schemas/acceptance-evidence.schema.json"
            else source_name.removeprefix("src/")
        )
        for source_name in candidate_sources
        if source_name != "pyproject.toml"
    }
    package_names = {name for name in files if name.startswith("artifex/")}
    record = f"{dist_info_name}/RECORD"
    provenance_name = f"{dist_info_name}/artifex-release-provenance.json"
    metadata_names = {
        f"{dist_info_name}/METADATA",
        f"{dist_info_name}/WHEEL",
        f"{dist_info_name}/entry_points.txt",
        record,
    }
    license_name = f"{dist_info_name}/licenses/LICENSE"
    if "LICENSE" in candidate_repository:
        metadata_names.add(license_name)
    expected_names = set(packaged_names.values()) | metadata_names
    if (
        any(content is None for content in packaged_sources.values())
        or package_names != set(packaged_names.values())
        or frozenset(files)
        not in {frozenset(expected_names), frozenset(expected_names | {provenance_name})}
    ):
        raise ValidationError("built wheel inventory differs from candidate S")
    for source_name, packaged_name in packaged_names.items():
        files[packaged_name] = candidate_sources[source_name]
    if "LICENSE" in candidate_repository:
        files[license_name] = candidate_repository["LICENSE"]
    files[f"{dist_info_name}/METADATA"] = metadata
    files[f"{dist_info_name}/WHEEL"] = wheel_metadata
    files[f"{dist_info_name}/entry_points.txt"] = entry_points
    files[provenance_name] = provenance
    files.pop(record)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode()}", len(content)))
    writer.writerow((record, "", ""))
    files[record] = stream.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    path.write_bytes(output.getvalue())


def _finalize_sdist(root: Path, path: Path, candidate: str) -> None:
    provenance = _source_provenance(root, candidate, "sdist")
    metadata_payload, _, _ = _source_package_metadata(root, candidate)
    candidate_sources = _candidate_source_files(root, candidate)
    candidate_repository = _candidate_repository_files(root, candidate)
    with tarfile.open(path, mode="r:gz") as archive:
        members: dict[str, tuple[bytes, int]] = {}
        for member in archive.getmembers():
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is not None:
                    members[member.name] = (stream.read(), member.mode)
    roots = {PurePosixPath(name).parts[0] for name in members}
    if roots != {f"artifex_dev-{VERSION}"}:
        raise ValidationError("sdist root identity is ambiguous")
    archive_root = next(iter(roots))
    packaged_sources = {
        source_name: members.get(f"{archive_root}/{source_name}", (None, 0))[0]
        for source_name in candidate_sources
    }
    if any(content is None for content in packaged_sources.values()):
        raise ValidationError("built sdist inventory differs from candidate S")
    metadata_name = f"{archive_root}/PKG-INFO"
    if metadata_name not in members:
        raise ValidationError("built sdist PKG-INFO missing")
    members = {
        f"{archive_root}/{source_name}": (content, 0o644)
        for source_name, content in candidate_repository.items()
    }
    members[metadata_name] = (metadata_payload, 0o644)
    members[f"{archive_root}/artifex-release-provenance.json"] = (provenance, 0o644)
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w") as archive:
        for name, (content, mode) in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    path.write_bytes(gzip.compress(raw_tar.getvalue(), mtime=0))


def finalize_source_artifacts(root: Path, output: Path, candidate: str) -> dict[str, str]:
    if importlib.metadata.version("hatchling") != "1.27.0":
        raise ValidationError("active Hatchling backend differs from pinned 1.27.0")
    wheel = output / f"artifex_dev-{VERSION}-py3-none-any.whl"
    sdist = output / f"artifex_dev-{VERSION}.tar.gz"
    if not wheel.is_file() or not sdist.is_file():
        raise ValidationError("source build outputs are missing")
    _finalize_wheel(root, wheel, candidate)
    _finalize_sdist(root, sdist, candidate)
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (wheel, sdist)}


def smoke_source_artifacts(output: Path) -> None:
    artifacts = (
        output.resolve() / f"artifex_dev-{VERSION}-py3-none-any.whl",
        output.resolve() / f"artifex_dev-{VERSION}.tar.gz",
    )
    script = (
        "import artifex,importlib.resources,json;"
        "assert artifex.__version__=='1.0.0';"
        "p=json.loads(importlib.resources.files('artifex').joinpath("
        "'schemas/acceptance-evidence.schema.json').read_text());"
        "assert p['properties']['schema_version']['const']=='2.0';"
        "assert 'independent_of_executor' in p['required']"
    )
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("COV_CORE_") or name == "COVERAGE_PROCESS_START":
            environment.pop(name)
    with tempfile.TemporaryDirectory(prefix="artifex-source-smoke-") as directory:
        for artifact in artifacts:
            if not artifact.is_file():
                raise ValidationError(f"source smoke artifact missing: {artifact.name}")
            base = ("uv", "run", "--isolated", "--no-project", "--with", str(artifact))
            measured = subprocess.run(
                (*base, "python", "-c", script),
                cwd=directory,
                capture_output=True,
                check=False,
                env=environment,
            )
            if measured.returncode != 0:
                raise ValidationError(f"isolated source artifact smoke failed: {artifact.name}")
            cli = subprocess.run(
                (*base, "artifex", "system", "version"),
                cwd=directory,
                capture_output=True,
                check=False,
                env=environment,
            )
            try:
                identity = _json_loads(cli.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"source artifact CLI JSON invalid: {artifact.name}") from exc
            if (
                cli.returncode != 0
                or not isinstance(identity, Mapping)
                or identity.get("ok") is not True
                or not isinstance(identity.get("value"), Mapping)
                or identity["value"].get("version") != VERSION
            ):
                raise ValidationError(f"source artifact CLI identity failed: {artifact.name}")


def finalize_native_artifact(
    root: Path, source_dir: Path, output: Path, candidate: str, kind: str
) -> Path:
    identities = {
        "native-windows-x64": ("windows", "x86_64", "artifex.exe", True, "x64"),
        "native-linux-x64": ("linux", "x86_64", "artifex", False, "x64"),
        "native-macos-arm64": ("macos", "arm64", "artifex", False, "arm64"),
    }
    if kind not in identities:
        raise ValidationError("unknown native finalization kind")
    if importlib.metadata.version("pyinstaller") != _locked_pyinstaller(root):
        raise ValidationError("active PyInstaller differs from uv.lock")
    platform, architecture, executable, zipped, label = identities[kind]
    source_dir = source_dir.resolve()
    provenance = _source_provenance(root, candidate, kind)
    (source_dir / "artifex-release-provenance.json").write_bytes(provenance)
    schema = _git(root, "show", f"{candidate}:schemas/acceptance-evidence.schema.json")
    if schema.returncode != 0:
        raise ValidationError("candidate canonical evidence schema is unavailable")
    runtime_schema = source_dir / "_internal/artifex/schemas/acceptance-evidence.schema.json"
    runtime_schema.parent.mkdir(parents=True, exist_ok=True)
    runtime_schema.write_bytes(schema.stdout)
    payloads = {
        path.relative_to(source_dir).as_posix(): path.read_bytes()
        for path in source_dir.rglob("*")
        if path.is_file() and path.name != "artifex-artifact.json"
    }
    executable_content = payloads.get(executable)
    if executable_content is None:
        raise ValidationError("native executable is missing")
    executable_digest = hashlib.sha256(executable_content).hexdigest()
    manifest = {
        "schema_version": "4.0",
        "product": "ARTIFEX",
        "product_version": VERSION,
        "build_id": f"artifex-{VERSION}-{platform}-{architecture}-{executable_digest[:16]}",
        "format": "pyinstaller-onedir",
        "platform": platform,
        "architecture": architecture,
        "artifact": executable,
        "sha256": executable_digest,
        "files": [
            {"path": name, "kind": "file", "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(payloads.items())
        ],
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        ),
        "pyinstaller_version": _locked_pyinstaller(root),
        "source_commit": candidate,
        "requires_user_python": False,
        "requires_user_pip": False,
        "requires_user_venv": False,
    }
    (source_dir / "artifex-artifact.json").write_text(
        json.dumps(manifest, sort_keys=True, allow_nan=False), encoding="utf-8"
    )
    output.mkdir(parents=True, exist_ok=True)
    suffix = "zip" if zipped else "tar.gz"
    destination = output / f"artifex-{VERSION}-{platform}-{label}.{suffix}"
    files = {
        f"artifex/{path.relative_to(source_dir).as_posix()}": path.read_bytes()
        for path in source_dir.rglob("*")
        if path.is_file()
    }
    if zipped:
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, content in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100755 << 16
                bundle.writestr(info, content)
        destination.write_bytes(archive.getvalue())
    else:
        raw_tar = io.BytesIO()
        with tarfile.open(fileobj=raw_tar, mode="w") as bundle:
            for name, content in sorted(files.items()):
                tar_info = tarfile.TarInfo(name)
                tar_info.size = len(content)
                tar_info.mode = 0o755 if PurePosixPath(name).name == executable else 0o644
                tar_info.mtime = 0
                bundle.addfile(tar_info, io.BytesIO(content))
        destination.write_bytes(gzip.compress(raw_tar.getvalue(), mtime=0))
    return destination


def verify_release(root: Path = ROOT) -> ReleaseReport:
    """Measure a pre-promotion candidate; Core acceptance occurs only after this passes."""

    root = root.resolve()
    checks: list[str] = []
    blockers: list[str] = []
    _version_checks(root, blockers, checks)
    status = _yaml(root / ".artifex/status.yaml")
    milestones = status.get("milestones") if status else None
    implementation = status.get("implementation") if status else None
    if not isinstance(milestones, Mapping) or milestones.get("M11") != "VALIDATING":
        blockers.append("M11 candidate state must be VALIDATING")
    if not isinstance(implementation, Mapping) or implementation.get("release") != "CANDIDATE":
        blockers.append("release state must be CANDIDATE")

    traceability = validate_traceability(root)
    if traceability.passed:
        checks.append("full traceability")
    else:
        blockers.extend(f"traceability: {error}" for error in traceability.errors)
    for relative in (
        *REQUIRED_GUIDES,
        *REQUIRED_GENERATED,
        *REQUIRED_DASHBOARD,
        DOCUMENTATION_MANIFEST,
        *REQUIRED_KNOWLEDGE,
    ):
        if not (root / relative).is_file():
            blockers.append(f"missing required documentation: {relative}")

    manifest = _yaml(root / ".artifex/releases/v1.0.0.yaml")
    if manifest is None:
        blockers.append("missing canonical release record: .artifex/releases/v1.0.0.yaml")
        return ReleaseReport(tuple(checks), tuple(blockers))
    if set(manifest) != {"schema_version", "version", "status", "binding", "evidence", "artifacts"}:
        blockers.append("release record contains unknown or missing fields")
    manifest_binding = manifest.get("binding")
    if (
        not isinstance(manifest_binding, Mapping)
        or set(manifest_binding) != {"base_commit", "contract_hash", "project_model_fingerprints"}
        or not isinstance(manifest.get("evidence"), list)
        or not isinstance(manifest.get("artifacts"), list)
    ):
        blockers.append("release record binding/evidence/artifact schema invalid")
    if manifest.get("schema_version") != "1.0" or manifest.get("version") != VERSION:
        blockers.append("release record schema/version mismatch")
    if manifest.get("status") != "CANDIDATE":
        blockers.append("release record status must be CANDIDATE")
    lessons: tuple[KnowledgeItem, ...] = ()
    proposals: tuple[ImprovementProposal, ...] = ()
    try:
        binding, trusted_validators, governance_head = _derived_authority(root)
        checks.append("repository-derived release authority")
    except ValidationError as exc:
        blockers.append(str(exc))
        return ReleaseReport(tuple(checks), tuple(blockers))
    _status_and_audit_transition(root, status, binding, governance_head, blockers)
    _documentation_freshness(root, binding, blockers, checks)
    try:
        _validate_dashboard(root, binding)
    except (OSError, json.JSONDecodeError, jsonschema.ValidationError, ValidationError) as exc:
        blockers.append(
            "dashboard is not deterministic noncanonical candidate-bound output: " + str(exc)
        )
    try:
        lesson_values = _json_loads((root / REQUIRED_KNOWLEDGE[0]).read_text(encoding="utf-8"))
        proposal_values = _json_loads((root / REQUIRED_KNOWLEDGE[1]).read_text(encoding="utf-8"))
        if not isinstance(lesson_values, list) or not lesson_values:
            raise ValueError("project lessons must be a nonempty array")
        if not isinstance(proposal_values, list) or not proposal_values:
            raise ValueError("improvement proposals must be a nonempty array")
        lessons = tuple(KnowledgeItem.from_dict(item) for item in lesson_values)
        proposals = tuple(ImprovementProposal.from_dict(item) for item in proposal_values)
        lesson_ids = {str(item.id) for item in lessons}
        if any(
            lesson.scope is not KnowledgeScope.PROJECT
            or lesson.project_id != "ARTIFEX"
            or lesson.kind is not KnowledgeKind.LESSON
            for lesson in lessons
        ):
            raise ValueError("lessons must be PROJECT/ARTIFEX/LESSON records")
        if any(
            {str(lesson_id) for lesson_id in proposal.lesson_ids} - lesson_ids
            or not proposal.evidence
            or proposal.requested_privileges
            for proposal in proposals
        ):
            raise ValueError("proposal lessons/evidence/privileges are invalid")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        blockers.append(f"persisted M11 knowledge is invalid: {exc}")
    entries = _evidence(root, manifest, binding, trusted_validators, blockers, checks)
    expected_evidence_references = {
        f"{evidence_id}:{entry.entry_hash}" for evidence_id, entry in entries.items()
    } | {
        f"candidate:{binding.base_commit}",
        f"contract:{binding.contract_hash}",
    }
    if (
        lessons
        and proposals
        and (
            any(
                any(
                    provenance.commit != binding.base_commit
                    or not provenance.evidence_ids
                    or set(provenance.evidence_ids) - set(entries)
                    for provenance in lesson.provenance
                )
                for lesson in lessons
            )
            or any(
                set(proposal.evidence) != expected_evidence_references for proposal in proposals
            )
        )
    ):
        blockers.append("persisted M11 knowledge evidence does not resolve to S/final hashes")
    _ledger_evidence(root, entries, trusted_validators, blockers, checks)
    _audit_provenance(root, entries, binding, blockers)
    _gates(root, entries, binding, blockers, checks)
    _artifacts(root, manifest, binding, blockers, checks)
    try:
        _governance_clean(root, manifest.get("artifacts"))
        checks.append(f"clean committed governance authority at {governance_head}")
    except ValidationError as exc:
        blockers.append(str(exc))
    return ReleaseReport(tuple(checks), tuple(blockers))


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in {
        "finalize-source",
        "finalize-native",
        "smoke-source",
    }:
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "command", choices=("finalize-source", "finalize-native", "smoke-source")
        )
        parser.add_argument("--candidate")
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--input", type=Path)
        parser.add_argument("--kind")
        arguments = parser.parse_args()
        try:
            if arguments.command == "finalize-source":
                if arguments.candidate is None:
                    parser.error("finalize-source requires --candidate")
                result: object = finalize_source_artifacts(
                    ROOT, arguments.output, arguments.candidate
                )
            elif arguments.command == "smoke-source":
                smoke_source_artifacts(arguments.output)
                result = {"smoke": "PASS"}
            else:
                if arguments.candidate is None or arguments.input is None or arguments.kind is None:
                    parser.error("finalize-native requires --input and --kind")
                result = {
                    "artifact": str(
                        finalize_native_artifact(
                            ROOT,
                            arguments.input,
                            arguments.output,
                            arguments.candidate,
                            arguments.kind,
                        )
                    )
                }
        except (OSError, ValidationError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
            return 1
        print(json.dumps({"ok": True, "value": result}, sort_keys=True))
        return 0
    report = verify_release(ROOT)
    for check in report.checks:
        print(f"PASS {check}")
    for blocker in report.blockers:
        print(f"BLOCKER {blocker}")
    print("release=PASS" if report.passed else "release=BLOCKED")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())

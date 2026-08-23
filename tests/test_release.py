from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from artifex.integrations import ManualIntegration
from artifex.integrations.claude import ClaudeIntegration
from artifex.integrations.codex import CodexIntegration
from artifex.integrations.deepseek import DeepSeekHarnessAdapter
from artifex.integrations.hermes import HermesIntegration
from artifex.integrations.pandora import FilesystemResearchTransport, PandoraResearchAdapter
from artifex.project import AuditEvent, AuditLog
from artifex.validation import (
    EvidenceBinding,
    EvidenceEntry,
    MeasuredFact,
    StructuredInspectionValidator,
    ValidationContext,
    ValidationError,
    dump_evidence,
    evidence_to_payload,
)

SCRIPT_DIR = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from validate_release import (  # noqa: E402
    CATEGORY_REPORTS,
    COMPREHENSION_ARTIFACTS,
    CONTRACT_GOVERNANCE_ALLOWLIST,
    DOCUMENT_TOPIC_TERMS,
    DOCUMENTATION_MANIFEST,
    EVIDENCE_CATEGORIES,
    FINAL_LEDGER,
    MANDATORY_GATES,
    REQUIRED_ARTIFACT_KINDS,
    REQUIRED_GENERATED,
    REQUIRED_GUIDES,
    REQUIRED_MACHINE,
    SECURITY_ATTACK_IDS,
    VERSION,
    _historical_evidence,
    _portable_text_digest,
    _validate_sdist,
    _validate_wheel,
    finalize_native_artifact,
    finalize_source_artifacts,
    smoke_source_artifacts,
    verify_release,
)
from validate_traceability import validate_traceability  # noqa: E402


def _write(path: Path, text: str = "ok\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _yaml_write(path: Path, payload: object) -> None:
    _write(path, yaml.safe_dump(payload, sort_keys=True))


def _project_model_digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _traceability(root: Path, *, unknown: bool = False) -> None:
    owner = "UNKNOWN" if unknown else "M11"
    evidence_ids = sorted(
        path.stem
        for path in (root / ".artifex/validation/evidence").glob("EVD-*.yaml")
        if path.stem != "EVD-M10" and not path.stem.startswith("EVD-M10-")
    )
    gate_ids = sorted(
        path.stem
        for path in (root / ".artifex/validation/gates").glob("G-*.yaml")
        if path.stem != "G-M10-MILESTONE"
    )
    final_evidence = [item for item in EVIDENCE_CATEGORIES if item.startswith("EVD-M11-")]
    maps = {
        "architecture": {"REQ-F-001": ["Core"], "REQ-F-002": ["Worker"]},
        "ownership": {"REQ-F-001": [owner], "REQ-F-002": ["M09"]},
        "tasks": {"REQ-F-001": ["M11-T12"], "REQ-F-002": ["M09-T01"]},
        "evidence": {"REQ-F-001": final_evidence, "REQ-F-002": ["EVD-M09-001"]},
        "gates": {"REQ-F-001": ["G-M11-MILESTONE"], "REQ-F-002": ["G-M09-MILESTONE"]},
    }
    payload = {
        "schema_version": "2.0",
        "source": {
            "project_model_sha256": _project_model_digest(
                json.loads((root / ".artifex/project-model.json").read_text())
            ),
            "requirements_baseline_sha256": hashlib.sha256(
                subprocess.run(
                    (
                        "git",
                        "-C",
                        str(root),
                        "show",
                        "HEAD:docs/requirements/REQUIREMENTS_BASELINE.md",
                    ),
                    capture_output=True,
                    check=True,
                ).stdout
            ).hexdigest(),
        },
        "policy": {
            "mapping": "accepted-project-model-traceability-manifest",
            "catalogs_exact": True,
        },
        "definitions": {
            "architecture": ["Core", "Worker"],
            "milestones": ["M09", "M11"],
            "tasks": ["M09-T01", "M11-T12"],
            "evidence": evidence_ids,
            "gates": gate_ids,
        },
        "maps": maps,
        "metrics": {
            "requirements_total": 2,
            "architecture_traced": 2,
            "ownership_traced": 2,
            "tasks_traced": 2,
            "evidence_traced": 2,
            "gates_traced": 2,
        },
    }
    _yaml_write(root / ".artifex/implementation/traceability.yaml", payload)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _git_blob_sha(root: Path, relative: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), "show", f"HEAD:{relative}"),
        capture_output=True,
        check=True,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def _binding(root: Path, candidate_commit: str | None = None) -> EvidenceBinding:
    model = json.loads((root / ".artifex/project-model.json").read_text(encoding="utf-8"))
    model_bytes = json.dumps(
        model, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    contract = root / ".artifex/validation/contracts/V1-RELEASE.yaml"
    committed = subprocess.run(
        ("git", "-C", str(root), "show", "HEAD:.artifex/validation/contracts/V1-RELEASE.yaml"),
        capture_output=True,
        check=False,
    )
    if committed.returncode != 0:
        committed = subprocess.run(
            ("git", "-C", str(root), "show", ":.artifex/validation/contracts/V1-RELEASE.yaml"),
            capture_output=True,
            check=True,
        )
    return EvidenceBinding(
        candidate_commit or _git(root, "rev-parse", "HEAD"),
        hashlib.sha256(committed.stdout if committed.stdout else contract.read_bytes()).hexdigest(),
        (hashlib.sha256(model_bytes).hexdigest(),),
    )


def _evidence(
    root: Path,
    binding: EvidenceBinding,
    artifacts: list[dict[str, str]] | None = None,
    validator_id: str = "VAL-RELEASE",
) -> list[str]:
    validator = StructuredInspectionValidator(validator_id, "1")
    evidence_paths: list[str] = []
    category_entries: list[EvidenceEntry] = []
    for evidence_id, category in EVIDENCE_CATEGORIES.items():
        if evidence_id == "EVD-V1-RELEASE":
            continue
        report_path = CATEGORY_REPORTS.get(category)
        report_digest = (
            hashlib.sha256(
                subprocess.run(
                    ("git", "-C", str(root), "show", f":{report_path}"),
                    capture_output=True,
                    check=True,
                ).stdout
            ).hexdigest()
            if report_path is not None
            else ""
        )
        category_facts: dict[str, tuple[MeasuredFact, ...]] = {
            "build": (
                MeasuredFact("source_commit", binding.base_commit),
                MeasuredFact("ci_run", 42),
                MeasuredFact("ci_jobs_passed", 10),
                MeasuredFact("ci_jobs_total", 10),
                MeasuredFact("build_report_sha256", report_digest),
            ),
            "validation": (
                MeasuredFact("ruff", "PASS"),
                MeasuredFact("mypy", "PASS"),
                MeasuredFact("tests_passed", 325),
                MeasuredFact("coverage_percent", 85.8),
                MeasuredFact("validation_report_sha256", report_digest),
            ),
            "understanding": (
                MeasuredFact("generated_files", len(REQUIRED_GENERATED)),
                MeasuredFact("guides", len(REQUIRED_GUIDES)),
                MeasuredFact("comprehension_score", 1.0),
                MeasuredFact(
                    "documentation_manifest_sha256",
                    _portable_text_digest((root / DOCUMENTATION_MANIFEST).read_bytes()),
                ),
            ),
            "continuity": (
                MeasuredFact("integrations_passed", 6),
                MeasuredFact("integrations_total", 6),
                MeasuredFact("continuity_report_sha256", report_digest),
            ),
            "portability": (
                MeasuredFact("source_jobs_passed", 6),
                MeasuredFact("source_jobs_total", 6),
                MeasuredFact("native_platforms_passed", 3),
                MeasuredFact("native_platforms_total", 3),
                MeasuredFact("portability_report_sha256", report_digest),
            ),
            "packaging": (
                MeasuredFact(
                    "artifact_hashes",
                    json.dumps(
                        {item["kind"]: item["sha256"] for item in artifacts or []},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
                MeasuredFact("isolated_wheel", True),
                MeasuredFact("isolated_sdist", True),
                MeasuredFact("cli_json", True),
                MeasuredFact("schema_2", True),
                MeasuredFact("packaging_report_sha256", report_digest),
            ),
            "selfhost": (
                MeasuredFact("project_model_fingerprint", binding.project_model_fingerprints[0]),
                MeasuredFact("changeset", "CHG-SELF-RELEASE"),
                MeasuredFact("adapter_status", "SUCCESS"),
                MeasuredFact("ledger_entries", len(EVIDENCE_CATEGORIES)),
                MeasuredFact("selfhost_report_sha256", report_digest),
            ),
            "security": (
                MeasuredFact("adversarial_passed", len(SECURITY_ATTACK_IDS)),
                MeasuredFact("trust_boundaries_passed", True),
                MeasuredFact("secret_scan", "PASS"),
                MeasuredFact("waivers", 0),
                MeasuredFact("security_report_sha256", report_digest),
            ),
        }
        result = validator.validate(
            ValidationContext(f"{category} release evidence", "worker", binding),
            inspector_id="independent-reviewer",
            passed=True,
            facts=(MeasuredFact("category", category), *category_facts[category]),
        )
        entry = EvidenceEntry.create(
            evidence_id, result, binding, recorded_at=datetime(2026, 8, 22, tzinfo=UTC)
        )
        relative = f".artifex/validation/evidence/{evidence_id}.yaml"
        dump_evidence(entry, root / relative)
        evidence_paths.append(relative)
        category_entries.append(entry)
    aggregate_result = validator.validate(
        ValidationContext("release aggregate evidence", "worker", binding),
        inspector_id="independent-reviewer",
        passed=True,
        facts=(
            MeasuredFact("category", "release"),
            *(
                MeasuredFact(f"aggregate:{entry.evidence_id}", entry.entry_hash)
                for entry in category_entries
            ),
        ),
    )
    aggregate = EvidenceEntry.create(
        "EVD-V1-RELEASE",
        aggregate_result,
        binding,
        recorded_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    aggregate_relative = ".artifex/validation/evidence/EVD-V1-RELEASE.yaml"
    dump_evidence(aggregate, root / aggregate_relative)
    evidence_paths.append(aggregate_relative)
    return evidence_paths


def _release_reports(root: Path, binding: EvidenceBinding, artifacts: list[dict[str, str]]) -> None:
    common = {
        "schema_version": "1.0",
        "binding": {
            "candidate_commit": binding.base_commit,
            "contract_hash": binding.contract_hash,
            "project_model_fingerprint": binding.project_model_fingerprints[0],
        },
        "attestation": {
            "validator_id": "VAL-RELEASE",
            "validator_version": "1",
            "validator_kind": "STRUCTURED_INSPECTION",
            "producer_id": "independent-reviewer",
        },
    }
    build_jobs = [
        {
            "id": f"test-{os_name}-{python}",
            "status": "PASS",
            "source_commit": binding.base_commit,
        }
        for os_name in ("linux", "windows", "macos")
        for python in ("3.12", "3.13")
    ] + [
        {"id": job, "status": "PASS", "source_commit": binding.base_commit}
        for job in (
            "native-linux",
            "native-windows",
            "native-macos",
            "source-package-linux",
        )
    ]
    artifact_hashes = {item["kind"]: item["sha256"] for item in artifacts}
    reports: dict[str, object] = {
        "build": {"run_id": 42, "jobs": build_jobs},
        "validation": {
            "commands": [
                {"name": "ruff", "exit_code": 0},
                {"name": "mypy", "exit_code": 0},
                {"name": "pytest-full", "exit_code": 0},
            ],
            "summary": {"tests_passed": 325, "coverage_percent": 85.8},
        },
        "continuity": {
            "integrations": [
                {"id": integration, "version": "1.0.0", "status": "PASS"}
                for integration in ("manual", "hermes", "codex", "claude", "deepseek", "pandora")
            ]
        },
        "portability": {
            "source_jobs": [
                f"{os_name}-{python}"
                for os_name in ("linux", "windows", "macos")
                for python in ("3.12", "3.13")
            ],
            "native_jobs": ["linux-x86_64", "windows-x86_64", "macos-arm64"],
        },
        "packaging": {
            "artifacts": artifact_hashes,
            "smokes": {
                "isolated_wheel": True,
                "isolated_sdist": True,
                "cli_json": True,
                "schema_2": True,
            },
            "native_attestations": [
                {
                    "kind": kind,
                    "artifact_sha256": artifact_hashes[kind],
                    "job_id": f"ci-{kind}",
                    "toolchain": "pyinstaller==6.22.2",
                    "source_commit": binding.base_commit,
                    "status": "PASS",
                }
                for kind in ("native-linux-x64", "native-windows-x64", "native-macos-arm64")
            ],
        },
        "selfhost": {
            "project_model_fingerprint": binding.project_model_fingerprints[0],
            "changeset": "CHG-SELF-RELEASE",
            "adapter_status": "SUCCESS",
            "ledger_entries": len(EVIDENCE_CATEGORIES),
            "checks": {"model": True, "contract": True, "evidence": True, "ledger": True},
        },
        "security": {
            "attacks": [
                {"id": attack_id, "status": "PASS"}
                for attack_id in SECURITY_ATTACK_IDS
            ],
            "command": {
                "argv": "uv run pytest -m adversarial",
                "source_commit": binding.base_commit,
            },
            "secret_scan": {"status": "PASS", "secrets_found": 0},
            "waivers": [],
        },
    }
    for category, results in reports.items():
        payload = {**common, "category": category, "results": results}
        _write(root / CATEGORY_REPORTS[category], json.dumps(payload, sort_keys=True) + "\n")


def _understanding_artifacts(root: Path, binding: EvidenceBinding) -> None:
    for relative in (*REQUIRED_GUIDES, *REQUIRED_GENERATED):
        topic = Path(relative).stem.replace("_", " ").casefold()
        terms = DOCUMENT_TOPIC_TERMS[Path(relative).stem]
        _write(
            root / relative,
            f"# {topic.title()}\n\nCandidate: {binding.base_commit}\n"
            f"Model: {binding.project_model_fingerprints[0]}\n\n"
            f"## Purpose\nThe {topic} establishes {terms[0]} behavior for deterministic "
            "ARTIFEX release governance and evidence-bound operation.\n\n"
            f"## Authority\nGit and the typed Project Model define {terms[1]} authority; "
            "narrative output is non-canonical and cannot promote a release.\n\n"
            f"## Controls\nThe {terms[2]} controls fail closed on stale bindings, unknown "
            "identities, waivers, or incomplete measurements.\n\n"
            "## Verification\nIndependent validation re-measures the candidate, checks hashes, "
            "and records audit evidence before any promotion decision. Rollback remains "
            "explicit.\n",
        )
    for relative, human in zip(REQUIRED_MACHINE, REQUIRED_GENERATED, strict=True):
        payload = {
            "schema_version": "1.0",
            "candidate_commit": binding.base_commit,
            "project_model_fingerprint": binding.project_model_fingerprints[0],
            "topic": Path(human).stem,
            "source_human": human,
            "source_sha256": _portable_text_digest((root / human).read_bytes()),
        }
        _write(root / relative, json.dumps(payload, sort_keys=True) + "\n")
    questions = [
        {"id": f"Q-{index:02d}", "topic": Path(path).stem}
        for index, path in enumerate(REQUIRED_GENERATED, start=1)
    ]
    prompt = {
        "schema_version": "1.0",
        "candidate_commit": binding.base_commit,
        "project_model_fingerprint": binding.project_model_fingerprints[0],
        "questions": questions,
    }
    _write(root / COMPREHENSION_ARTIFACTS[0], json.dumps(prompt, sort_keys=True) + "\n")
    answers = [
        {
            "id": question["id"],
            "topic": question["topic"],
            "answer": (
                f"Independent explanation of {question['topic']} confirms candidate-bound "
                "authority, deterministic evidence hashes, fail-closed validation, and explicit "
                "release controls without treating generated narrative as canonical promotion. "
                "It cross-checks "
                + ", ".join(
                    DOCUMENT_TOPIC_TERMS[Path(REQUIRED_GENERATED[index]).stem]
                )
                + " against the typed source and independent audit result."
            ),
            "source_sha256": _portable_text_digest(
                (root / REQUIRED_GENERATED[index]).read_bytes()
            ),
            "candidate_commit": binding.base_commit,
            "project_model_fingerprint": binding.project_model_fingerprints[0],
            "assertions": [
                f"topic:{term}"
                for term in DOCUMENT_TOPIC_TERMS[Path(REQUIRED_GENERATED[index]).stem]
            ],
        }
        for index, question in enumerate(questions)
    ]
    response = {
        "schema_version": "1.0",
        "validator_id": "independent-reviewer",
        "answers": answers,
    }
    _write(root / COMPREHENSION_ARTIFACTS[1], json.dumps(response, sort_keys=True) + "\n")
    result = {
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
    _write(root / COMPREHENSION_ARTIFACTS[2], json.dumps(result, sort_keys=True) + "\n")


def _dashboard_artifacts(root: Path, binding: EvidenceBinding) -> None:
    status = yaml.safe_load((root / ".artifex/status.yaml").read_text(encoding="utf-8"))
    milestone_numbers = range(11) if "M10" in status["milestones"] else range(10)
    state = {
        "schema_version": "1.0",
        "project": {
            "id": "ARTIFEX",
            "name": "ARTIFEX",
            "architecture_version": "1.0",
            "implementation_plan_version": "1.0",
            "current_stage": "SELF_HOST",
            "current_milestone": "M11",
            "accepted_baseline": binding.base_commit,
        },
        "milestones": [
            {
                "id": f"M{number:02d}",
                "state": "ACCEPTED",
                "completed_tasks": 1,
                "total_tasks": 1,
                "blockers": [],
            }
            for number in milestone_numbers
        ]
        + [
            {
                "id": "M11",
                "state": "VERIFYING",
                "completed_tasks": 13,
                "total_tasks": 13,
                "blockers": [],
            }
        ],
        "gates": {"pass": 12, "fail": 0, "blocked": 0, "waived": 0, "stale": 0},
        "evidence": {"current": 9, "stale": 0},
        "tests": {"suites": [{"name": "full", "state": "PASS"}]},
        "traceability": {
            "requirements_total": 2,
            "requirements_traced": 2,
            "orphan_requirements": 0,
        },
        "documentation": [
            {"path": relative, "state": "CURRENT"}
            for relative in (*REQUIRED_GUIDES, *REQUIRED_GENERATED)
        ],
        "integrations": [
            {"id": integration, "state": "PASS", "version": VERSION}
            for integration in ("manual", "hermes", "codex", "claude", "deepseek", "pandora")
        ],
        "comprehension": {"state": "PASS", "score": 1.0},
        "git": {"commit": binding.base_commit, "tag": None, "dirty": False},
    }
    state_path = root / "docs/implementation/dashboard/state.json"
    _write(state_path, json.dumps(state, sort_keys=True) + "\n")
    provenance = {
        "schema_version": "1.0",
        "canonical": False,
        "candidate_commit": binding.base_commit,
        "project_model_fingerprint": binding.project_model_fingerprints[0],
        "state_sha256": _portable_text_digest(state_path.read_bytes()),
    }
    narrative = (
        "This deterministic implementation dashboard reports the M11 candidate baseline, "
        "final gate measurements, canonical evidence inventory, and independent comprehension "
        "without claiming canonical authority. "
    ) * 3
    index = (
        "<!doctype html><html><head><title>ARTIFEX M11 non-canonical dashboard</title></head>"
        "<body><main><h1>ARTIFEX release candidate dashboard</h1>"
        f'<section id="milestones"><h2>Milestones</h2><p>{narrative}</p></section>'
        f'<section id="gates"><h2>Gates</h2><p>{narrative}</p></section>'
        f'<section id="evidence"><h2>Evidence</h2><p>{narrative}</p></section>'
        '<script id="artifex-dashboard-provenance" type="application/json">'
        + json.dumps(provenance, sort_keys=True, separators=(",", ":"))
        + "</script></main></body></html>\n"
    )
    _write(root / "docs/implementation/dashboard/index.html", index)


def _rewrite_aggregate(root: Path, mutation: str) -> None:
    contract = yaml.safe_load(
        (root / ".artifex/validation/contracts/V1-RELEASE.yaml").read_text(encoding="utf-8")
    )
    binding = _binding(root, contract["contract"]["candidate_commit"])
    category_hashes = {}
    for evidence_id in EVIDENCE_CATEGORIES:
        if not evidence_id.startswith("EVD-M11-"):
            continue
        payload = yaml.safe_load(
            (root / f".artifex/validation/evidence/{evidence_id}.yaml").read_text(encoding="utf-8")
        )
        category_hashes[evidence_id] = payload["entry_hash"]
    if mutation == "missing":
        category_hashes.pop("EVD-M11-BUILD")
    elif mutation == "extra":
        category_hashes["EVD-M11-BOGUS"] = "0" * 64
    else:
        category_hashes["EVD-M11-BUILD"] = "0" * 64
    validator = StructuredInspectionValidator("VAL-RELEASE", "1")
    result = validator.validate(
        ValidationContext("release aggregate evidence", "worker", binding),
        inspector_id="independent-reviewer",
        passed=True,
        facts=(
            MeasuredFact("category", "release"),
            MeasuredFact("passed", True),
            *(
                MeasuredFact(f"aggregate:{evidence_id}", entry_hash)
                for evidence_id, entry_hash in sorted(category_hashes.items())
            ),
        ),
    )
    entry = EvidenceEntry.create(
        "EVD-V1-RELEASE",
        result,
        binding,
        recorded_at=datetime(2026, 8, 22, tzinfo=UTC),
    )
    dump_evidence(entry, root / ".artifex/validation/evidence/EVD-V1-RELEASE.yaml")


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return stream.getvalue()


def _rewrite_zip_members(path: Path, updates: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path) as archive:
        files = {
            info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()
        }
    files.update(updates)
    path.write_bytes(_zip_bytes(files))


def _rewrite_wheel_with_record(path: Path, updates: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path) as archive:
        files = {
            info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()
        }
    files.update(updates)
    record_name = next(name for name in files if name.endswith(".dist-info/RECORD"))
    files.pop(record_name)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode()}", len(content)))
    writer.writerow((record_name, "", ""))
    files[record_name] = stream.getvalue().encode()
    path.write_bytes(_zip_bytes(files))


def _rewrite_zip_special(path: Path, name: str, file_type: int) -> None:
    with zipfile.ZipFile(path) as archive:
        files = {
            info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()
        }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, content in files.items():
            archive.writestr(relative, content)
        info = zipfile.ZipInfo(name)
        info.external_attr = (file_type | 0o644) << 16
        archive.writestr(info, b"special")
    path.write_bytes(stream.getvalue())


def _rewrite_tar_members(path: Path, updates: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        files: dict[str, tuple[bytes, int]] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                files[member.name] = (extracted.read(), member.mode)
    for name, content in updates.items():
        _, mode = files.get(name, (b"", 0o644))
        files[name] = (content, mode)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, (content, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    path.write_bytes(gzip.compress(stream.getvalue(), mtime=0))


def _tar_bytes(files: dict[str, bytes], *, executable_names: frozenset[str] = frozenset()) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, value in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            info.mtime = 0
            info.mode = 0o755 if name in executable_names else 0o644
            archive.addfile(info, io.BytesIO(value))
    return stream.getvalue()


def _fixture_candidate_files(root: Path, candidate: str) -> dict[str, bytes]:
    listing = subprocess.run(
        (
            "git",
            "-C",
            str(root),
            "ls-tree",
            "-r",
            "--name-only",
            candidate,
            "--",
            "src/artifex",
            "schemas/acceptance-evidence.schema.json",
            "pyproject.toml",
        ),
        capture_output=True,
        check=True,
        text=True,
    ).stdout.splitlines()
    return {
        relative: subprocess.run(
            ("git", "-C", str(root), "show", f"{candidate}:{relative}"),
            capture_output=True,
            check=True,
        ).stdout
        for relative in listing
    }


def _fixture_repository_files(root: Path, candidate: str) -> dict[str, bytes]:
    listing = subprocess.run(
        ("git", "-C", str(root), "ls-tree", "-r", "--name-only", candidate),
        capture_output=True,
        check=True,
        text=True,
    ).stdout.splitlines()
    return {
        relative: subprocess.run(
            ("git", "-C", str(root), "show", f"{candidate}:{relative}"),
            capture_output=True,
            check=True,
        ).stdout
        for relative in listing
    }


def _wheel_bytes(sources: dict[str, bytes], provenance: bytes) -> bytes:
    metadata = b"Metadata-Version: 2.4\nName: artifex-dev\nVersion: 1.0.0\n\n"
    files = {
        (
            "artifex/schemas/acceptance-evidence.schema.json"
            if source_name == "schemas/acceptance-evidence.schema.json"
            else source_name.removeprefix("src/")
        ): content
        for source_name, content in sources.items()
        if source_name != "pyproject.toml"
    } | {
        "artifex_dev-1.0.0.dist-info/METADATA": metadata,
        "artifex_dev-1.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: hatchling 1.27.0\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "artifex_dev-1.0.0.dist-info/entry_points.txt": (
            b"[console_scripts]\nartifex = artifex.cli:app\n"
        ),
        "artifex_dev-1.0.0.dist-info/artifex-release-provenance.json": provenance,
    }
    record_name = "artifex_dev-1.0.0.dist-info/RECORD"
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode()}", len(content)))
    writer.writerow((record_name, "", ""))
    files[record_name] = stream.getvalue().encode()
    return _zip_bytes(files)


def _artifact_index(root: Path, source_commit: str) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    metadata = b"Metadata-Version: 2.4\nName: artifex-dev\nVersion: 1.0.0\n\n"
    sources = _fixture_candidate_files(root, source_commit)
    repository_sources = _fixture_repository_files(root, source_commit)
    binding = _binding(root, source_commit)
    wheel_provenance = _release_provenance(root, "wheel", binding)
    sdist_provenance = _release_provenance(root, "sdist", binding)
    sdist_files = {
        "artifex_dev-1.0.0/PKG-INFO": metadata,
        "artifex_dev-1.0.0/artifex-release-provenance.json": sdist_provenance,
    } | {
        f"artifex_dev-1.0.0/{name}": content for name, content in repository_sources.items()
    }
    values: tuple[tuple[str, str, bytes], ...] = (
        (
            "wheel",
            "artifex_dev-1.0.0-py3-none-any.whl",
            _wheel_bytes(sources, wheel_provenance),
        ),
        (
            "sdist",
            "artifex_dev-1.0.0.tar.gz",
            _tar_bytes(sdist_files),
        ),
        *tuple(
            (
                kind,
                f"artifex-1.0.0-{platform}-{label}.{extension}",
                _native_archive(
                    root=root,
                    binding=binding,
                    kind=kind,
                    platform=platform,
                    architecture=architecture,
                    source_commit=source_commit,
                    zipped=extension == "zip",
                ),
            )
            for kind, platform, architecture, label, extension in (
                ("native-windows-x64", "windows", "x86_64", "x64", "zip"),
                ("native-linux-x64", "linux", "x86_64", "x64", "tar.gz"),
                ("native-macos-arm64", "macos", "arm64", "arm64", "tar.gz"),
            )
        ),
    )
    provenance_by_kind = {
        "wheel": wheel_provenance,
        "sdist": sdist_provenance,
        **{
            kind: _release_provenance(root, kind, binding)
            for kind in (
                "native-windows-x64",
                "native-linux-x64",
                "native-macos-arm64",
            )
        },
    }
    for kind, name, content in values:
        relative = f"dist/release/{name}"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        artifacts.append(
            {
                "kind": kind,
                "path": relative,
                "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
                "provenance_sha256": hashlib.sha256(provenance_by_kind[kind]).hexdigest(),
            }
        )
    return artifacts


def _native_archive(
    *,
    root: Path,
    binding: EvidenceBinding,
    kind: str,
    platform: str,
    architecture: str,
    source_commit: str,
    zipped: bool,
) -> bytes:
    executable = "artifex.exe" if platform == "windows" else "artifex"
    magic = {
        "windows": b"MZ",
        "linux": b"\x7fELF",
        "macos": b"\xcf\xfa\xed\xfe",
    }[platform]
    payload = magic + b"ARTIFEX-FIXTURE-PAYLOAD"
    digest = hashlib.sha256(payload).hexdigest()
    release_provenance = _release_provenance(root, kind, binding)
    release_provenance_digest = hashlib.sha256(release_provenance).hexdigest()
    schema = subprocess.run(
        (
            "git",
            "-C",
            str(root),
            "show",
            f"{source_commit}:schemas/acceptance-evidence.schema.json",
        ),
        capture_output=True,
        check=True,
    ).stdout
    schema_digest = hashlib.sha256(schema).hexdigest()
    manifest = {
        "schema_version": "4.0",
        "product": "ARTIFEX",
        "product_version": "1.0.0",
        "build_id": f"artifex-1.0.0-{platform}-{architecture}-{digest[:16]}",
        "format": "pyinstaller-onedir",
        "platform": platform,
        "architecture": architecture,
        "artifact": executable,
        "sha256": digest,
        "files": sorted(
            (
                {"path": executable, "kind": "file", "sha256": digest},
                {
                    "path": "artifex-release-provenance.json",
                    "kind": "file",
                    "sha256": release_provenance_digest,
                },
                {
                    "path": "_internal/artifex/schemas/acceptance-evidence.schema.json",
                    "kind": "file",
                    "sha256": schema_digest,
                },
            ),
            key=lambda item: item["path"],
        ),
        "python_version": "3.12.0",
        "pyinstaller_version": "6.22.2",
        "source_commit": source_commit,
        "requires_user_python": False,
        "requires_user_pip": False,
        "requires_user_venv": False,
    }
    files = {
        f"artifex/{executable}": payload,
        "artifex/artifex-release-provenance.json": release_provenance,
        "artifex/_internal/artifex/schemas/acceptance-evidence.schema.json": schema,
        "artifex/artifex-artifact.json": json.dumps(manifest, sort_keys=True).encode(),
    }
    if zipped:
        return _zip_bytes(files)
    return _tar_bytes(files, executable_names=frozenset({f"artifex/{executable}"}))


def _release_provenance(root: Path, kind: str, binding: EvidenceBinding) -> bytes:
    inventory = (
        _fixture_repository_files(root, binding.base_commit)
        if kind == "sdist"
        else _fixture_candidate_files(root, binding.base_commit)
    )
    source_files = {
        relative: hashlib.sha256(content).hexdigest()
        for relative, content in inventory.items()
    }
    value = {
        "schema_version": "1.0",
        "artifact_kind": kind,
        "source_commit": binding.base_commit,
        "project_model_fingerprint": binding.project_model_fingerprints[0],
        "toolchain": ("hatchling==1.27.0" if kind in {"wheel", "sdist"} else "pyinstaller==6.22.2"),
        "source_files": source_files,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _complete_release_fixture_v2_unused(root: Path) -> dict[str, Any]:
    _write(root / "pyproject.toml", '[project]\nname="artifex-dev"\nversion="1.0.0"\n')
    _write(root / "src/artifex/_version.py", '__version__ = "1.0.0"\n')
    _write(root / "src/artifex/__init__.py", "from ._version import __version__\n")
    _write(root / "src/artifex/cli.py", "app = object()\n")
    _write(root / "docs/requirements/REQUIREMENTS_BASELINE.md", "REQ-F-001\n")
    _write(root / "docs/architecture/ARCHITECTURE.md", "# Architecture\n\n## Core\n")
    _write(root / "docs/implementation/milestones/M11.md", "# M11\n\nM11-T12\n")
    _traceability(root)
    for relative in (*REQUIRED_GUIDES, *REQUIRED_GENERATED):
        _write(root / relative)
    _write(root / ".artifex/project-model.json", '{"project":{"id":"fixture"}}\n')
    _yaml_write(
        root / ".artifex/validation/contracts/V1-RELEASE.yaml",
        {"schema_version": "1.0", "contract": {"trusted_validators": {"VAL-RELEASE": "1"}}},
    )
    for number in range(10):
        milestone = f"M{number:02d}"
        _yaml_write(
            root / f".artifex/validation/contracts/{milestone}.yaml",
            {
                "schema_version": "1.0",
                "contract": {"id": f"VAL-{milestone}", "milestone": milestone},
            },
        )
    _git(root, "init")
    _git(root, "config", "user.email", "fixture@artifex.test")
    _git(root, "config", "user.name", "ARTIFEX Fixture")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "candidate authority")
    binding = _binding(root)
    evidence_paths = _evidence(root, binding)
    for number in range(10):
        milestone = f"M{number:02d}"
        gate_id = f"G-{milestone}-MILESTONE"
        historical_id = f"EVD-{milestone}-001"
        contract_hash = _git_blob_sha(root, f".artifex/validation/contracts/{milestone}.yaml")
        if number < 9:
            historical_payload: dict[str, Any] = {
                "schema_version": "1.0",
                "evidence": {
                    "id": historical_id,
                    "gate": gate_id,
                    "claim": f"{milestone} historical acceptance",
                    "validator": {
                        "id": "legacy-independent",
                        "version": "1",
                        "type": "independent_agent",
                    },
                    "source": {
                        "commit": "historical",
                        "contract_hash": contract_hash,
                        "project_model_fingerprint": "historical",
                    },
                    "result": {"status": "PASS", "measured": {"tests": 1}},
                    "created_at": "2026-08-21T00:00:00+00:00",
                },
            }
        else:
            historical_payload = {
                "evidence_id": historical_id,
                "validator": {
                    "id": "legacy-independent",
                    "version": "1",
                    "kind": "INDEPENDENT_AGENT",
                },
                "claim": f"{milestone} historical acceptance",
                "outcome": "PASS",
                "facts": [{"name": "tests", "value": 1}],
                "binding": {
                    "base_commit": "historical",
                    "contract_hash": contract_hash,
                    "project_model_fingerprints": ["historical"],
                },
                "output": "historical",
                "recorded_at": "2026-08-21T00:00:00+00:00",
                "producer_id": "legacy-reviewer",
                "entry_hash": "0" * 64,
            }
        _yaml_write(
            root / f".artifex/validation/evidence/{historical_id}.yaml",
            historical_payload,
        )
        _yaml_write(
            root / f".artifex/validation/gates/{gate_id}.yaml",
            {
                "schema_version": "1.0",
                "gate": {
                    "id": gate_id,
                    "target": milestone,
                    "state": "PASS",
                    "contract_hash": contract_hash,
                    "required_evidence": [historical_id],
                    "waiver_allowed": False,
                },
            },
        )
    for gate_id, target, required in (
        (
            "G-M11-MILESTONE",
            "M11",
            [item for item in EVIDENCE_CATEGORIES if item.startswith("EVD-M11-")],
        ),
        ("G-V1-RELEASE", "V1", ["EVD-V1-RELEASE"]),
    ):
        _yaml_write(
            root / f".artifex/validation/gates/{gate_id}.yaml",
            {
                "schema_version": "1.0",
                "gate": {
                    "id": gate_id,
                    "target": target,
                    "state": "PASS",
                    "contract_hash": binding.contract_hash,
                    "required_evidence": required,
                    "waiver_allowed": False,
                },
            },
        )
    _yaml_write(
        root / ".artifex/status.yaml",
        {"milestones": {"M11": "VALIDATING"}, "implementation": {"release": "CANDIDATE"}},
    )
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "version": "1.0.0",
        "status": "CANDIDATE",
        "binding": {
            "base_commit": binding.base_commit,
            "contract_hash": binding.contract_hash,
            "project_model_fingerprints": list(binding.project_model_fingerprints),
        },
        "evidence": evidence_paths,
        "artifacts": _artifact_index(root, binding.base_commit),
    }
    _yaml_write(root / ".artifex/releases/v1.0.0.yaml", manifest)
    return manifest


def _fixture_model() -> dict[str, Any]:
    expected_traceability = {
        "schema_version": "1.0",
        "requirements": {
            "REQ-F-001": {
                "architecture": ["Core"],
                "ownership": ["M11"],
                "tasks": ["M11-T12"],
                "evidence": [
                    item for item in EVIDENCE_CATEGORIES if item.startswith("EVD-M11-")
                ],
                "gates": ["G-M11-MILESTONE"],
            },
            "REQ-F-002": {
                "architecture": ["Worker"],
                "ownership": ["M09"],
                "tasks": ["M09-T01"],
                "evidence": ["EVD-M09-001"],
                "gates": ["G-M09-MILESTONE"],
            },
        },
    }
    return {
        "schema_version": "1.0",
        "project": {
            "id": "fixture",
            "name": "Fixture",
            "description": "release fixture",
            "lifecycle": "brownfield",
            "workflow_depth": "DEEP",
        },
        "git": {
            "initialized": True,
            "branch": "main",
            "baseline_commit": None,
            "current_commit": None,
            "dirty": False,
            "remote_status": "NONE",
            "remotes": [],
        },
        "artifacts": [
            {
                "id": "ART-SELF-REQUIREMENTS",
                "type": "requirements",
                "path": "docs/requirements/REQUIREMENTS_BASELINE.md",
                "status": "ACCEPTED",
                "fingerprint": "0" * 64,
                "depends_on": [],
                "provenance": None,
                "metadata": {"traceability_expected": expected_traceability},
            },
            {
                "id": "ART-SELF-CHARTER",
                "type": "architecture",
                "path": "docs/architecture/ARCHITECTURE.md",
                "status": "ACCEPTED",
                "fingerprint": "1" * 64,
                "depends_on": [],
                "provenance": None,
                "metadata": {"understanding": {"core_components": ["Core", "Worker"]}},
            },
            {
                "id": "ART-SELF-IMPLEMENTATION",
                "type": "implementation-plan",
                "path": "docs/implementation/STATUS.md",
                "status": "ACCEPTED",
                "fingerprint": "2" * 64,
                "depends_on": [],
                "provenance": None,
                "metadata": {},
            },
            {
                "id": "ART-SELF-M11",
                "type": "milestone-plan",
                "path": "docs/implementation/milestones/M11.md",
                "status": "ACCEPTED",
                "fingerprint": "3" * 64,
                "depends_on": ["ART-SELF-IMPLEMENTATION"],
                "provenance": None,
                "metadata": {},
            },
        ],
        "entities": [
            {
                "id": "REQ-F-001",
                "kind": "requirement",
                "title": "Release",
                "statement": "Release is controlled",
                "artifact_id": "ART-SELF-REQUIREMENTS",
                "depends_on": [],
            },
            {
                "id": "M11",
                "kind": "milestone",
                "title": "M11",
                "statement": "Release milestone",
                "artifact_id": "ART-SELF-IMPLEMENTATION",
                "depends_on": [],
            },
            {
                "id": "M11-T12",
                "kind": "task",
                "title": "Release",
                "statement": "Build candidate",
                "artifact_id": "ART-SELF-M11",
                "depends_on": ["M11"],
            },
            {
                "id": "REQ-F-002",
                "kind": "requirement",
                "title": "Worker",
                "statement": "Worker continuity is controlled",
                "artifact_id": "ART-SELF-REQUIREMENTS",
                "depends_on": [],
            },
            {
                "id": "M09",
                "kind": "milestone",
                "title": "M09",
                "statement": "Worker milestone",
                "artifact_id": "ART-SELF-IMPLEMENTATION",
                "depends_on": [],
            },
            {
                "id": "M09-T01",
                "kind": "task",
                "title": "Worker validation",
                "statement": "Validate worker",
                "artifact_id": "ART-SELF-M11",
                "depends_on": ["M09"],
            },
        ],
    }


def _complete_release_fixture(
    root: Path,
    *,
    source_schema2_ledger: bool = False,
    optional_m10: str | None = None,
    core_autocrlf: bool = False,
) -> dict[str, Any]:
    if optional_m10 not in {None, "valid", "invalid"}:
        raise ValueError("optional_m10 must be valid, invalid, or None")
    milestone_numbers = range(11) if optional_m10 is not None else range(10)
    _write(root / ".gitignore", "dist/\n")
    _write(root / "uv.lock", 'version = 1\n[[package]]\nname = "pyinstaller"\nversion = "6.22.2"\n')
    _write(
        root / "pyproject.toml",
        '[build-system]\nrequires=["hatchling==1.27.0"]\n'
        'build-backend="hatchling.build"\n[project]\nname="artifex-dev"\nversion="1.0.0"\n'
        '[project.scripts]\nartifex="artifex.cli:app"\n',
    )
    _write(root / "src/artifex/_version.py", '__version__ = "1.0.0"\n')
    _write(root / "src/artifex/__init__.py", "from ._version import __version__\n")
    _write(root / "src/artifex/cli.py", "app = object()\n")
    _write(root / "src/artifex/validation/core.py", "VALUE = 'candidate-core'\n")
    _write(root / "src/artifex/integrations/manual.py", "VALUE = 'candidate-integration'\n")
    _write(root / "src/artifex/dependencies.py", "PINNED = True\n")
    _write(root / "docs/requirements/REQUIREMENTS_BASELINE.md", "REQ-F-001\nREQ-F-002\n")
    _write(root / "docs/architecture/ARCHITECTURE.md", "# Architecture\n\n## Core\n")
    _write(root / "docs/architecture/SECOND.md", "# Worker Architecture\n")
    _write(root / "docs/implementation/milestones/M11.md", "# M11\n\nM11-T12\n")
    _write(
        root / "schemas/project-model.schema.json",
        (Path(__file__).parents[1] / "schemas/project-model.schema.json").read_text(
            encoding="utf-8"
        ),
    )
    _write(
        root / "schemas/dashboard-state.schema.json",
        (Path(__file__).parents[1] / "schemas/dashboard-state.schema.json").read_text(
            encoding="utf-8"
        ),
    )
    _write(
        root / "schemas/acceptance-evidence.schema.json",
        (Path(__file__).parents[1] / "schemas/acceptance-evidence.schema.json").read_text(
            encoding="utf-8"
        ),
    )
    _write(root / ".artifex/project-model.json", json.dumps(_fixture_model(), indent=2) + "\n")
    source_status = {
        "schema_version": "1.0",
        "derived_at": "2026-08-21T00:00:00Z",
        "project": "ARTIFEX",
        "implementation": {
            "current_milestone": "M11",
            "current_state": "ACTIVE",
            "release": "PLANNED",
        },
        "milestones": {
            **{f"M{number:02d}": "ACCEPTED" for number in milestone_numbers},
            "M11": "ACTIVE",
        },
        "publication": {"remote": "NONE", "url": None},
    }
    _yaml_write(root / ".artifex/status.yaml", source_status)
    AuditLog(root).append(
        AuditEvent(
            event_id="00000000-0000-0000-0000-000000000000",
            event_type="PROJECT_INITIALIZED",
            occurred_at="2026-08-21T00:00:00Z",
            actor="artifex",
            commit=None,
            payload={"project_id": "ARTIFEX"},
        )
    )
    for number in milestone_numbers:
        milestone = f"M{number:02d}"
        _yaml_write(
            root / f".artifex/validation/contracts/{milestone}.yaml",
            {
                "schema_version": "1.0",
                "contract": {"id": f"VAL-{milestone}", "milestone": milestone},
            },
        )
    if source_schema2_ledger:
        validator = StructuredInspectionValidator("VAL-RELEASE", "1")
        previous = EvidenceEntry.create(
            "EVD-PREVIOUS",
            validator.validate(
                ValidationContext(
                    "previous schema-2 evidence",
                    "worker",
                    EvidenceBinding("1" * 40, "2" * 64, ("3" * 64,)),
                ),
                inspector_id="independent-reviewer",
                passed=True,
                facts=(MeasuredFact("history", True),),
            ),
            EvidenceBinding("1" * 40, "2" * 64, ("3" * 64,)),
            recorded_at=datetime(2026, 8, 20, tzinfo=UTC),
        )
        _write(
            root / FINAL_LEDGER,
            json.dumps(
                {"type": "EVIDENCE", "entry": evidence_to_payload(previous)},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )
    _git(root, "init")
    _git(root, "config", "user.email", "fixture@artifex.test")
    _git(root, "config", "user.name", "ARTIFEX Fixture")
    _git(root, "config", "core.autocrlf", "true" if core_autocrlf else "false")
    _git(root, "add", ".")
    for number in milestone_numbers:
        milestone = f"M{number:02d}"
        gate_id, evidence_id = f"G-{milestone}-MILESTONE", f"EVD-{milestone}-001"
        contract_relative = f".artifex/validation/contracts/{milestone}.yaml"
        contract_bytes = subprocess.run(
            ("git", "-C", str(root), "show", f":{contract_relative}"),
            capture_output=True,
            check=True,
        ).stdout
        contract_hash = hashlib.sha256(contract_bytes).hexdigest()
        legacy = {
            "schema_version": "1.0",
            "evidence": {
                "id": evidence_id,
                "gate": gate_id,
                "claim": f"{milestone} historical acceptance",
                "validator": {"id": "legacy", "version": "1", "type": "independent_agent"},
                "source": {
                    "commit": "0" * 40,
                    "contract_hash": contract_hash,
                    "project_model_fingerprint": "1" * 64,
                },
                "result": {"status": "PASS", "measured": {"tests": 1}},
                "evidence_excerpt": f"Independent historical validation for {milestone}",
                "scrubbed": True,
                "created_at": "2026-08-21T00:00:00+00:00",
            },
        }
        _yaml_write(root / f".artifex/validation/evidence/{evidence_id}.yaml", legacy)
        _yaml_write(
            root / f".artifex/validation/gates/{gate_id}.yaml",
            {
                "schema_version": "1.0",
                "gate": {
                    "id": gate_id,
                    "scope": "MILESTONE",
                    "target": milestone,
                    "state": (
                        "FAIL" if milestone == "M10" and optional_m10 == "invalid" else "PASS"
                    ),
                    "contract_hash": contract_hash,
                    "required_evidence": [evidence_id],
                    "waiver_allowed": False,
                },
            },
        )
    if optional_m10 == "invalid":
        _write(root / ".artifex/validation/evidence/EVD-M10-001.yaml", "not: [valid\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "integrated source candidate")
    candidate_commit = _git(root, "rev-parse", "HEAD")
    model_bytes = json.dumps(
        _fixture_model(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    model_fingerprint = hashlib.sha256(model_bytes).hexdigest()
    _yaml_write(
        root / ".artifex/validation/contracts/V1-RELEASE.yaml",
        {
            "schema_version": "1.0",
            "contract": {
                "id": "VAL-V1-RELEASE",
                "version": 1,
                "state": "FROZEN",
                "candidate_commit": candidate_commit,
                "project_model_fingerprint": model_fingerprint,
                "product_version": "1.0.0",
                "evidence_categories": EVIDENCE_CATEGORIES,
                "artifact_kinds": list(REQUIRED_ARTIFACT_KINDS),
                "governance_allowlist": list(CONTRACT_GOVERNANCE_ALLOWLIST),
                "trusted_validators": [
                    {
                        "id": "VAL-RELEASE",
                        "version": "1",
                        "kind": "STRUCTURED_INSPECTION",
                        "producers": ["independent-reviewer"],
                    }
                ],
            },
        },
    )
    _git(root, "add", ".artifex/validation/contracts/V1-RELEASE.yaml")
    binding = _binding(root, candidate_commit)
    _understanding_artifacts(root, binding)
    _dashboard_artifacts(root, binding)
    documentation_manifest = {
        "schema_version": "1.0",
        "candidate_commit": candidate_commit,
        "project_model_fingerprint": model_fingerprint,
        "generator": {"id": "artifex-compilation", "version": "1.0.0", "deterministic": True},
        "files": {
            relative: _portable_text_digest((root / relative).read_bytes())
            for relative in (
                *REQUIRED_GUIDES,
                *REQUIRED_GENERATED,
                *REQUIRED_MACHINE,
                *COMPREHENSION_ARTIFACTS,
                "docs/implementation/dashboard/index.html",
                "docs/implementation/dashboard/state.json",
            )
        },
    }
    _write(
        root / DOCUMENTATION_MANIFEST,
        json.dumps(documentation_manifest, sort_keys=True) + "\n",
    )
    artifact_values = _artifact_index(root, candidate_commit)
    _release_reports(root, binding, artifact_values)
    _git(root, "add", *CATEGORY_REPORTS.values())
    evidence_paths = _evidence(root, binding, artifact_values)
    ledger_events = []
    for relative in evidence_paths:
        payload = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        ledger_events.append(
            json.dumps(
                {"type": "EVIDENCE", "entry": payload},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    ledger_prefix = (
        (root / FINAL_LEDGER).read_text(encoding="utf-8") if source_schema2_ledger else ""
    )
    _write(root / FINAL_LEDGER, ledger_prefix + "\n".join(ledger_events) + "\n")
    for gate_id, target, required in (
        (
            "G-M11-MILESTONE",
            "M11",
            [item for item in EVIDENCE_CATEGORIES if item.startswith("EVD-M11-")],
        ),
        ("G-V1-RELEASE", "V1", ["EVD-V1-RELEASE"]),
    ):
        _yaml_write(
            root / f".artifex/validation/gates/{gate_id}.yaml",
            {
                "schema_version": "1.0",
                "gate": {
                    "id": gate_id,
                    "scope": "MILESTONE" if target == "M11" else "RELEASE",
                    "target": target,
                    "state": "PASS",
                    "contract_hash": binding.contract_hash,
                    "required_evidence": required,
                    "waiver_allowed": False,
                },
            },
        )
    _traceability(root)
    lesson = {
        "id": "LES-ONE",
        "scope": "PROJECT",
        "kind": "LESSON",
        "statement": "Release authority remains separate from source authority.",
        "provenance": [
            {
                "source": "independent release validation",
                "observed_at": "2026-08-22T00:00:00Z",
                "artifact": None,
                "commit": candidate_commit,
                "integration": None,
                "evidence_ids": ["EVD-V1-RELEASE"],
            }
        ],
        "confidence": 1.0,
        "sensitivity": "INTERNAL",
        "promotion_policy": {
            "allowed_targets": ["PROJECT"],
            "minimum_confidence": 0.7,
            "minimum_evidence": 1,
            "maximum_sensitivity": "SENSITIVE",
            "require_validation": True,
        },
        "verified_against": [],
        "revisit_triggers": [],
        "state": "CURRENT",
        "project_id": "ARTIFEX",
        "run_id": None,
        "promoted_from": None,
    }
    _write(
        root / ".artifex/knowledge/project/lessons.json",
        json.dumps([lesson], sort_keys=True) + "\n",
    )
    proposal = {
        "id": "IMP-ONE",
        "title": "Keep release verification two-phase",
        "lesson_ids": ["LES-ONE"],
        "target": "release verifier",
        "reason": "Avoid self-referential evidence binding",
        "expected_benefit": "Deterministic source and governance authority",
        "evidence": [
            f"candidate:{candidate_commit}",
            f"contract:{binding.contract_hash}",
            *[
                f"{payload['evidence_id']}:{payload['entry_hash']}"
                for payload in (
                    yaml.safe_load((root / relative).read_text(encoding="utf-8"))
                    for relative in evidence_paths
                )
            ],
        ],
        "requested_privileges": [],
    }
    _write(
        root / ".artifex/knowledge/instances/artifex-self/improvement-proposals.json",
        json.dumps([proposal], sort_keys=True) + "\n",
    )
    release_status = json.loads(json.dumps(source_status))
    release_status["derived_at"] = "2026-08-22T00:00:00Z"
    release_status["milestones"]["M11"] = "VALIDATING"
    release_status["implementation"]["current_state"] = "VALIDATING"
    release_status["implementation"]["release"] = "CANDIDATE"
    _yaml_write(root / ".artifex/status.yaml", release_status)
    entries = []
    for relative in evidence_paths:
        payload = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        entries.append(
            {
                "evidence_id": payload["evidence_id"],
                "entry_hash": payload["entry_hash"],
                "validator_id": payload["validator_id"],
                "validator_version": payload["validator_version"],
                "validator_kind": payload["validator_kind"],
                "producer_id": payload["producer_id"],
            }
        )
    release_audit_events = (
        AuditEvent(
            event_id="00000000-0000-0000-0000-000000000010",
            event_type="MILESTONE_STATE_TRANSITION",
            occurred_at="2026-08-22T00:00:00Z",
            actor="artifex-core",
            commit=candidate_commit,
            payload={
                "milestone": "M11",
                "from": "ACTIVE",
                "to": "VALIDATING",
                "candidate_commit": candidate_commit,
            },
        ),
        AuditEvent(
            event_id="00000000-0000-0000-0000-000000000011",
            event_type="RELEASE_STATE_TRANSITION",
            occurred_at="2026-08-22T00:00:01Z",
            actor="artifex-core",
            commit=candidate_commit,
            payload={
                "from": "PLANNED",
                "to": "CANDIDATE",
                "candidate_commit": candidate_commit,
            },
        ),
        AuditEvent(
            event_id="00000000-0000-0000-0000-000000000001",
            event_type="RELEASE_CANDIDATE_INDEPENDENT_VALIDATION",
            occurred_at="2026-08-22T00:00:02Z",
            actor="independent-reviewer",
            commit=candidate_commit,
            payload={
                "candidate_commit": candidate_commit,
                "contract_hash": binding.contract_hash,
                "project_model_fingerprint": model_fingerprint,
                "evidence": sorted(entries, key=lambda item: item["evidence_id"]),
            },
        ),
    )
    for event in release_audit_events:
        AuditLog(root).append(event)
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "version": "1.0.0",
        "status": "CANDIDATE",
        "binding": {
            "base_commit": candidate_commit,
            "contract_hash": binding.contract_hash,
            "project_model_fingerprints": [model_fingerprint],
        },
        "evidence": evidence_paths,
        "artifacts": artifact_values,
    }
    _yaml_write(root / ".artifex/releases/v1.0.0.yaml", manifest)
    _git(root, "add", ".")
    _git(root, "commit", "-m", "release governance authority")
    return manifest


@pytest.mark.unit
def test_traceability_uses_repository_authority_and_rejects_unknown(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    assert validate_traceability(tmp_path).passed
    _traceability(tmp_path, unknown=True)
    assert any("unknown references" in error for error in validate_traceability(tmp_path).errors)


@pytest.mark.adversarial
@pytest.mark.parametrize("authority", ["empty-evidence", "mismatched-evidence", "empty-gate"])
def test_traceability_rejects_filename_only_authority(tmp_path: Path, authority: str) -> None:
    _complete_release_fixture(tmp_path)
    if authority == "empty-evidence":
        _write(tmp_path / ".artifex/validation/evidence/EVD-BOGUS.yaml", "")
    elif authority == "mismatched-evidence":
        source = tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml"
        _write(
            tmp_path / ".artifex/validation/evidence/EVD-BOGUS.yaml",
            source.read_text(encoding="utf-8"),
        )
    else:
        _write(tmp_path / ".artifex/validation/gates/G-BOGUS.yaml", "")
    report = validate_traceability(tmp_path)
    assert not report.passed
    assert any(
        "invalid evidence authority" in item or "invalid gate authority" in item
        for item in report.errors
    )


@pytest.mark.unit
def test_all_v1_integrations_accept_one_and_reject_two(tmp_path: Path) -> None:
    integrations = (
        ManualIntegration(),
        HermesIntegration.simulated(),
        CodexIntegration(),
        ClaudeIntegration(),
        DeepSeekHarnessAdapter(),
        PandoraResearchAdapter(FilesystemResearchTransport(tmp_path / "pandora")),
    )
    for integration in integrations:
        assert integration.metadata.compatibility.supports("1.0.0")
        assert not integration.metadata.compatibility.supports("2.0.0")


@pytest.mark.unit
def test_candidate_passes_without_optional_m10_gate(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    assert not (tmp_path / ".artifex/validation/gates/G-M10-MILESTONE.yaml").exists()
    legacy = tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml"
    before = legacy.read_bytes()
    assert verify_release(tmp_path).passed
    traceability = yaml.safe_load(
        (tmp_path / ".artifex/implementation/traceability.yaml").read_text(encoding="utf-8")
    )
    assert "G-V1-RELEASE" in traceability["definitions"]["gates"]
    assert all(
        "G-V1-RELEASE" not in gates for gates in traceability["maps"]["gates"].values()
    )
    assert validate_traceability(tmp_path).passed
    assert legacy.read_bytes() == before


@pytest.mark.parametrize("optional_m10", ["valid", "invalid"])
@pytest.mark.adversarial
def test_optional_m10_never_changes_core_release_authority(
    tmp_path: Path, optional_m10: str
) -> None:
    _complete_release_fixture(tmp_path, optional_m10=optional_m10)
    report = verify_release(tmp_path)
    assert report.passed
    assert any(
        "optional M10" in check and "ignored for Core GA" in check for check in report.checks
    )

    traceability = yaml.safe_load(
        (tmp_path / ".artifex/implementation/traceability.yaml").read_text(encoding="utf-8")
    )
    assert all(
        not identifier.startswith(("EVD-M10", "G-M10"))
        for catalog in traceability["definitions"].values()
        for identifier in catalog
    )
    assert validate_traceability(tmp_path).passed

    dashboard = tmp_path / "docs/implementation/dashboard/state.json"
    dashboard_state = json.loads(dashboard.read_text(encoding="utf-8"))
    assert dashboard_state["gates"]["pass"] == len(MANDATORY_GATES)
    dashboard_state["gates"]["pass"] += 1
    _write(dashboard, json.dumps(dashboard_state, sort_keys=True) + "\n")
    assert any(
        "dashboard is not deterministic noncanonical candidate-bound output" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_release_report_hash_uses_clean_committed_blob_across_crlf_checkout(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path, core_autocrlf=True)
    relative = CATEGORY_REPORTS["build"]
    path = tmp_path / relative
    path.unlink()
    _git(tmp_path, "checkout", "--", relative)
    assert b"\r\n" in path.read_bytes()
    assert (
        subprocess.run(
            ("git", "-C", str(tmp_path), "diff", "--quiet", "HEAD", "--", relative),
            check=False,
        ).returncode
        == 0
    )
    assert verify_release(tmp_path).passed


@pytest.mark.adversarial
def test_historical_gate_contract_hash_is_bound_to_committed_contract(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    gate_path = tmp_path / ".artifex/validation/gates/G-M00-MILESTONE.yaml"
    payload = yaml.safe_load(gate_path.read_text(encoding="utf-8"))
    payload["gate"]["contract_hash"] = "f" * 64
    _yaml_write(gate_path, payload)
    assert any("contract hash mismatch" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_symlink_historical_gate_is_rejected(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    gate = tmp_path / ".artifex/validation/gates/G-M00-MILESTONE.yaml"
    target = gate.with_name("actual-G-M00.yaml")
    gate.replace(target)
    try:
        gate.symlink_to(target)
    except OSError:
        target.replace(gate)
        pytest.skip("symlink creation is unavailable")
    assert any("symlink" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_missing_historical_evidence_is_rejected(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    (tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml").unlink()
    assert any("historical evidence missing" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_manifest_cannot_spoof_binding_or_validator_registry(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    forged = EvidenceBinding("f" * 40, "e" * 64, ("d" * 64,))
    manifest["binding"] = {
        "base_commit": forged.base_commit,
        "contract_hash": forged.contract_hash,
        "project_model_fingerprints": list(forged.project_model_fingerprints),
    }
    manifest["trusted_validators"] = {"VAL-FORGED": "1"}
    manifest["evidence"] = _evidence(tmp_path, forged, validator_id="VAL-FORGED")
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    report = verify_release(tmp_path)
    assert not report.passed
    assert any("derived repository authority" in item for item in report.blockers)
    assert any("spoofed" in item for item in report.blockers)


@pytest.mark.adversarial
def test_absolute_evidence_path_is_rejected(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    manifest["evidence"][0] = str((tmp_path / manifest["evidence"][0]).resolve())
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    assert any("relative" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_symlink_evidence_path_is_rejected(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    target = tmp_path / manifest["evidence"][0]
    link = target.with_name("EVD-SYMLINK.yaml")
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    manifest["evidence"][0] = str(link.relative_to(tmp_path)).replace("\\", "/")
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    assert any("symlink" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_released_states_are_circular_and_rejected(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    _yaml_write(
        tmp_path / ".artifex/status.yaml",
        {"milestones": {"M11": "ACCEPTED"}, "implementation": {"release": "RELEASED"}},
    )
    manifest["status"] = "RELEASED"
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    report = verify_release(tmp_path)
    assert {"M11 candidate state must be VALIDATING", "release state must be CANDIDATE"} <= set(
        report.blockers
    )
    assert "release record status must be CANDIDATE" in report.blockers


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "gate_payload",
    [
        None,
        {"gate": {"state": "FAIL"}},
        {"gate": {"state": "STALE"}},
        {
            "gate": {
                "id": "G-SPOOFED",
                "target": "M00",
                "state": "PASS",
                "required_evidence": ["EVD-M11-VALIDATION"],
                "waiver_allowed": False,
            }
        },
    ],
)
def test_empty_or_failed_mandatory_gate_is_rejected(
    tmp_path: Path, gate_payload: dict[str, object] | None
) -> None:
    _complete_release_fixture(tmp_path)
    gate = tmp_path / ".artifex/validation/gates/G-M00-MILESTONE.yaml"
    _write(gate, "" if gate_payload is None else yaml.safe_dump(gate_payload))
    report = verify_release(tmp_path)
    assert not report.passed
    assert any("G-M00-MILESTONE" in item for item in report.blockers)


@pytest.mark.adversarial
@pytest.mark.parametrize("duplicate", ["path", "kind"])
def test_duplicate_artifact_path_or_kind_is_rejected(tmp_path: Path, duplicate: str) -> None:
    manifest = _complete_release_fixture(tmp_path)
    copied = dict(manifest["artifacts"][0])
    if duplicate == "path":
        copied["kind"] = "extra-kind"
    else:
        relative = "dist/release/other.whl"
        _write(tmp_path / relative, "other")
        copied["path"] = relative
        copied["sha256"] = hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest()
    manifest["artifacts"].append(copied)
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    assert any(
        f"duplicate release artifact {duplicate}" in item
        for item in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_hardlinked_artifact_cannot_satisfy_two_kinds(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    first = tmp_path / manifest["artifacts"][0]["path"]
    linked = tmp_path / "dist/release/relabelled.whl"
    try:
        os.link(first, linked)
    except OSError:
        pytest.skip("hardlink creation is unavailable")
    manifest["artifacts"].append(
        {
            "kind": "relabelled-kind",
            "path": str(linked.relative_to(tmp_path)).replace("\\", "/"),
            "sha256": hashlib.sha256(linked.read_bytes()).hexdigest(),
            "provenance_sha256": manifest["artifacts"][0]["provenance_sha256"],
        }
    )
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    assert any("reused across kinds" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
@pytest.mark.parametrize("mutation", ["missing", "extra", "mismatch"])
def test_release_aggregate_exactly_binds_category_hashes(tmp_path: Path, mutation: str) -> None:
    _complete_release_fixture(tmp_path)
    _rewrite_aggregate(tmp_path, mutation)
    assert (
        "V1 aggregate evidence hashes do not exactly bind all M11 evidence"
        in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
@pytest.mark.parametrize(
    "mutation",
    ["copied", "kind", "filename", "metadata", "record", "sdist-source", "empty", "provenance"],
)
def test_release_artifacts_are_kind_specific_and_source_bound(
    tmp_path: Path, mutation: str
) -> None:
    manifest = _complete_release_fixture(tmp_path)
    by_kind = {item["kind"]: item for item in manifest["artifacts"]}
    if mutation == "copied":
        source = tmp_path / by_kind["wheel"]["path"]
        target = tmp_path / by_kind["sdist"]["path"]
        target.write_bytes(source.read_bytes())
        by_kind["sdist"]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        expected = "content relabeled across kinds"
    elif mutation == "kind":
        by_kind["wheel"]["kind"] = "wheel-relabelled"
        expected = "unknown release artifact kind"
    elif mutation == "filename":
        source = tmp_path / by_kind["wheel"]["path"]
        target = source.with_name("renamed.whl")
        source.replace(target)
        by_kind["wheel"]["path"] = str(target.relative_to(tmp_path)).replace("\\", "/")
        expected = "wheel filename identity/tags mismatch"
    elif mutation == "metadata":
        target = tmp_path / by_kind["wheel"]["path"]
        _rewrite_zip_members(
            target,
            {
                "artifex_dev-1.0.0.dist-info/METADATA": (
                    b"Metadata-Version: 2.3\nName: artifex-dev\nVersion: 9.9.9\n"
                )
            },
        )
        by_kind["wheel"]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        expected = "wheel package metadata differs from candidate S"
    elif mutation == "record":
        target = tmp_path / by_kind["wheel"]["path"]
        _rewrite_zip_members(target, {"artifex_dev-1.0.0.dist-info/RECORD": b"tampered\n"})
        by_kind["wheel"]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        expected = "wheel RECORD"
    elif mutation == "sdist-source":
        target = tmp_path / by_kind["sdist"]["path"]
        with tarfile.open(target, mode="r:gz") as archive:
            files: dict[str, bytes] = {}
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is not None:
                    files[member.name] = extracted.read()
        files["artifex_dev-1.0.0/src/artifex/cli.py"] = b"malicious = True\n"
        target.write_bytes(_tar_bytes(files))
        by_kind["sdist"]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        expected = "packaged source differs from candidate S"
    elif mutation == "empty":
        target = tmp_path / by_kind["native-windows-x64"]["path"]
        with zipfile.ZipFile(target) as archive:
            core_manifest = json.loads(archive.read("artifex/artifex-artifact.json"))
        empty_digest = hashlib.sha256(b"").hexdigest()
        core_manifest["sha256"] = empty_digest
        core_manifest["build_id"] = f"artifex-1.0.0-windows-x86_64-{empty_digest[:16]}"
        for item in core_manifest["files"]:
            if item["path"] == "artifex.exe":
                item["sha256"] = empty_digest
        _rewrite_zip_members(
            target,
            {
                "artifex/artifex.exe": b"",
                "artifex/artifex-artifact.json": json.dumps(core_manifest, sort_keys=True).encode(),
            },
        )
        by_kind["native-windows-x64"]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        expected = "native launch executable invalid"
    else:
        target = tmp_path / by_kind["native-windows-x64"]["path"]
        with zipfile.ZipFile(target) as archive:
            provenance = json.loads(archive.read("artifex/artifex-artifact.json"))
        provenance["source_commit"] = "f" * 40
        _rewrite_zip_members(
            target,
            {"artifex/artifex-artifact.json": json.dumps(provenance, sort_keys=True).encode()},
        )
        by_kind["native-windows-x64"]["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        expected = "native artifact provenance mismatch"
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    assert any(expected in blocker for blocker in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_dirty_or_untracked_governance_authority_is_rejected(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    _write(tmp_path / ".artifex/validation/evidence/EVD-UNTRACKED.yaml", "invented\n")
    assert any("governance worktree is dirty" in item for item in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_source_to_governance_delta_cannot_include_source_changes(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    _write(tmp_path / "src/forbidden.py", "value = 1\n")
    _git(tmp_path, "add", "src/forbidden.py")
    _git(tmp_path, "commit", "-m", "forbidden governance source mutation")
    assert any(
        "source-to-governance delta escapes allowlist" in item
        for item in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_dashboard_and_knowledge_must_be_typed_and_candidate_bound(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    state_path = tmp_path / "docs/implementation/dashboard/state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["git"]["commit"] = "f" * 40
    _write(state_path, json.dumps(state) + "\n")
    _write(tmp_path / "docs/implementation/dashboard/index.html", "<p>non-canonical</p>\n")
    _write(tmp_path / ".artifex/knowledge/project/lessons.json", '[{"id":"LES-ONE"}]\n')
    _write(
        tmp_path / ".artifex/audit.jsonl",
        '{"event":"RELEASE_CANDIDATE_INDEPENDENT_VALIDATION"}\n',
    )
    report = verify_release(tmp_path)
    assert any(
        "dashboard is not deterministic noncanonical candidate-bound output" in item
        for item in report.blockers
    )
    assert any("persisted M11 knowledge is invalid" in item for item in report.blockers)
    assert any("independent-validation audit cannot be read" in item for item in report.blockers)


@pytest.mark.adversarial
def test_traceability_ignores_entities_owned_by_draft_artifacts(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    model_path = tmp_path / ".artifex/project-model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["artifacts"][0]["status"] = "DRAFT"
    _write(model_path, json.dumps(model) + "\n")
    traceability_path = tmp_path / ".artifex/implementation/traceability.yaml"
    traceability = yaml.safe_load(traceability_path.read_text(encoding="utf-8"))
    traceability["source"]["project_model_sha256"] = _project_model_digest(model)
    _yaml_write(traceability_path, traceability)
    report = validate_traceability(tmp_path)
    assert not report.passed
    assert any("differs from typed Project Model" in item for item in report.errors)


@pytest.mark.unit
def test_build_backend_is_exactly_pinned_locked_and_nonisolated() -> None:
    root = Path(__file__).parents[1]
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    lock = (root / "uv.lock").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert 'requires = ["hatchling==1.27.0"]' in project
    assert 'name = "hatchling"' in lock
    assert "uv build --no-build-isolation --wheel --sdist" in workflow


@pytest.mark.adversarial
@pytest.mark.parametrize("mutation", ["missing", "mismatch", "duplicate", "extra", "invalidation"])
def test_release_requires_exact_yaml_ledger_parity(tmp_path: Path, mutation: str) -> None:
    _complete_release_fixture(tmp_path)
    ledger = tmp_path / FINAL_LEDGER
    lines = ledger.read_text(encoding="utf-8").splitlines()
    if mutation == "missing":
        ledger.unlink()
    elif mutation == "mismatch":
        event = json.loads(lines[0])
        event["entry"]["entry_hash"] = "0" * 64
        lines[0] = json.dumps(event)
        _write(ledger, "\n".join(lines) + "\n")
    elif mutation == "duplicate":
        _write(ledger, "\n".join((*lines, lines[0])) + "\n")
    elif mutation == "extra":
        event = json.loads(lines[0])
        event["entry"]["evidence_id"] = "EVD-EXTRA"
        _write(ledger, "\n".join((*lines, json.dumps(event))) + "\n")
    else:
        invalidation = {
            "type": "INVALIDATION",
            "evidence_id": "EVD-M11-BUILD",
            "reason": "stale",
        }
        _write(ledger, "\n".join((*lines, json.dumps(invalidation))) + "\n")
    assert any(
        "canonical release evidence ledger invalid" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
@pytest.mark.parametrize("mutation", ["validator", "facts", "timestamp", "gate"])
def test_governance_cannot_rewrite_historical_authority(tmp_path: Path, mutation: str) -> None:
    _complete_release_fixture(tmp_path)
    if mutation == "gate":
        path = tmp_path / ".artifex/validation/gates/G-M00-MILESTONE.yaml"
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        value["gate"]["state"] = "PASS"
        value["gate"]["scope"] = "MILESTONE"
    else:
        path = tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml"
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if mutation == "validator":
            value["evidence"]["validator"]["id"] = "other-independent-validator"
        elif mutation == "facts":
            value["evidence"]["result"]["measured"]["tests"] = 2
        else:
            value["evidence"]["created_at"] = "2026-08-21T00:00:01+00:00"
    if mutation == "gate":
        _write(path, "# semantically equivalent rewrite\n" + yaml.safe_dump(value, sort_keys=True))
    else:
        _yaml_write(path, value)
    _git(tmp_path, "add", str(path.relative_to(tmp_path)))
    _git(tmp_path, "commit", "-m", f"rewrite historical {mutation}")
    assert any(
        "historical evidence/gate authority changed after S" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
@pytest.mark.parametrize("mutation", ["fail-gate", "stale-gate", "binding", "legacy"])
def test_traceability_rejects_nonpassing_or_unbound_authority(
    tmp_path: Path, mutation: str
) -> None:
    _complete_release_fixture(tmp_path)
    if mutation in {"fail-gate", "stale-gate", "binding"}:
        path = tmp_path / ".artifex/validation/gates/G-M00-MILESTONE.yaml"
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if mutation == "binding":
            value["gate"]["contract_hash"] = "f" * 64
        else:
            value["gate"]["state"] = "FAIL" if mutation == "fail-gate" else "STALE"
    else:
        path = tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml"
        value = {"schema_version": "1.0", "evidence": {"id": "EVD-M00-001"}}
    _yaml_write(path, value)
    report = validate_traceability(tmp_path)
    assert not report.passed
    assert any(
        "invalid gate authority" in item or "invalid evidence authority" in item
        for item in report.errors
    )


@pytest.mark.adversarial
def test_traceability_rejects_symlink_authority(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml"
    target = path.with_name("actual-EVD-M00.yaml")
    path.replace(target)
    try:
        path.symlink_to(target)
    except OSError:
        target.replace(path)
        pytest.skip("symlink creation is unavailable")
    assert any("symlink" in item for item in validate_traceability(tmp_path).errors)


@pytest.mark.adversarial
def test_contract_hash_uses_canonical_git_blob_under_crlf_checkout(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    contract = tmp_path / ".artifex/validation/contracts/V1-RELEASE.yaml"
    contract.write_bytes(contract.read_bytes().replace(b"\n", b"\r\n"))
    if _git(tmp_path, "diff", "--name-only", "--", str(contract.relative_to(tmp_path))):
        pytest.skip("Git checkout does not normalize CRLF in this environment")
    assert verify_release(tmp_path).passed


@pytest.mark.adversarial
def test_status_and_audit_history_cannot_be_minimized_or_replaced(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    _yaml_write(
        tmp_path / ".artifex/status.yaml",
        {"milestones": {"M11": "VALIDATING"}, "implementation": {"release": "CANDIDATE"}},
    )
    _write(tmp_path / ".artifex/audit.jsonl", "")
    report = verify_release(tmp_path)
    assert any("status/audit transition invalid" in blocker for blocker in report.blockers)


@pytest.mark.adversarial
def test_documentation_manifest_and_evidence_fact_schema_fail_closed(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    _write(tmp_path / REQUIRED_GUIDES[0], "stale documentation\n")
    evidence = tmp_path / ".artifex/validation/evidence/EVD-M11-BUILD.yaml"
    value = yaml.safe_load(evidence.read_text(encoding="utf-8"))
    value["facts"] = [{"name": "category", "value": "build"}]
    _yaml_write(evidence, value)
    report = verify_release(tmp_path)
    assert any("documentation fingerprint mismatch" in blocker for blocker in report.blockers)
    assert any(
        "final evidence fact schema mismatch" in blocker or "release evidence invalid" in blocker
        for blocker in report.blockers
    )


@pytest.mark.adversarial
@pytest.mark.parametrize("authority", ["contract", "manifest"])
def test_release_authority_rejects_unknown_fields(tmp_path: Path, authority: str) -> None:
    manifest = _complete_release_fixture(tmp_path)
    if authority == "contract":
        path = tmp_path / ".artifex/validation/contracts/V1-RELEASE.yaml"
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        value["contract"]["self_asserted_override"] = True
        _yaml_write(path, value)
        _git(tmp_path, "add", str(path.relative_to(tmp_path)))
        _git(tmp_path, "commit", "-m", "malformed release contract")
        expected = "release contract identity/scope is invalid"
    else:
        manifest["self_asserted_override"] = True
        _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
        expected = "release record contains unknown or missing fields"
    assert any(expected in blocker for blocker in verify_release(tmp_path).blockers)


@pytest.mark.adversarial
def test_knowledge_proposal_must_resolve_final_evidence_hash(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/knowledge/instances/artifex-self/improvement-proposals.json"
    proposals = json.loads(path.read_text(encoding="utf-8"))
    proposals[0]["evidence"] = ["EVD-V1-RELEASE:" + "0" * 64]
    _write(path, json.dumps(proposals, sort_keys=True) + "\n")
    assert any(
        "persisted M11 knowledge evidence does not resolve to S/final hashes" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_sdist_rejects_special_archive_member(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    artifact = next(item for item in manifest["artifacts"] if item["kind"] == "sdist")
    path = tmp_path / artifact["path"]
    with tarfile.open(path, mode="r:gz") as archive:
        members: list[tuple[tarfile.TarInfo, bytes]] = []
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is not None:
                members.append((member, stream.read()))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for original, content in members:
            info = tarfile.TarInfo(original.name)
            info.size = len(content)
            info.mode = original.mode
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
        special = tarfile.TarInfo("artifex_dev-1.0.0/forged-pipe")
        special.type = tarfile.FIFOTYPE
        special.mtime = 0
        archive.addfile(special)
    path.write_bytes(output.getvalue())
    artifact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _yaml_write(tmp_path / ".artifex/releases/v1.0.0.yaml", manifest)
    assert any(
        "sdist contains a special file" in blocker for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.integration
def test_real_uv_source_build_is_finalized_with_exact_candidate_inventory(tmp_path: Path) -> None:
    source = Path(__file__).parents[1]
    root = tmp_path / "source"
    isolated_environment = os.environ.copy()
    for name in tuple(isolated_environment):
        if name.startswith("COV_CORE_") or name == "COVERAGE_PROCESS_START":
            isolated_environment.pop(name)
    subprocess.run(
        (
            "git",
            "-c",
            "core.autocrlf=false",
            "clone",
            "--quiet",
            "--no-hardlinks",
            str(source),
            str(root),
        ),
        check=True,
        env=isolated_environment,
    )
    current_patch = subprocess.run(
        ("git", "-C", str(source), "diff", "--binary", "HEAD"),
        capture_output=True,
        check=True,
    ).stdout
    if current_patch:
        subprocess.run(
            ("git", "-C", str(root), "apply", "--whitespace=nowarn", "-"),
            input=current_patch,
            check=True,
        )
        _git(root, "config", "user.email", "fixture@artifex.test")
        _git(root, "config", "user.name", "ARTIFEX Fixture")
        _git(root, "add", ".")
        _git(root, "commit", "-m", "current release finalizer candidate")
    candidate = _git(root, "rev-parse", "HEAD")
    output = tmp_path / "output"
    subprocess.run(
        (
            "uv",
            "build",
            "--no-build-isolation",
            "--wheel",
            "--sdist",
            "--out-dir",
            str(output),
        ),
        cwd=root,
        capture_output=True,
        check=True,
        env=isolated_environment,
    )
    crlf_version = (root / "src/artifex/_version.py").read_bytes().replace(b"\n", b"\r\n")
    _rewrite_zip_members(
        output / "artifex_dev-1.0.0-py3-none-any.whl",
        {"artifex/_version.py": crlf_version},
    )
    _rewrite_tar_members(
        output / "artifex_dev-1.0.0.tar.gz",
        {"artifex_dev-1.0.0/src/artifex/_version.py": crlf_version},
    )
    digests = finalize_source_artifacts(root, output, candidate)
    smoke_source_artifacts(output)
    assert set(digests) == {
        "artifex_dev-1.0.0-py3-none-any.whl",
        "artifex_dev-1.0.0.tar.gz",
    }
    with zipfile.ZipFile(output / "artifex_dev-1.0.0-py3-none-any.whl") as archive:
        assert any(
            name.endswith(".dist-info/artifex-release-provenance.json")
            for name in archive.namelist()
        )
        assert "artifex/validation/core.py" in archive.namelist()
        assert "artifex/integrations/manual.py" in archive.namelist()
        assert archive.read("artifex/_version.py") == subprocess.run(
            ("git", "-C", str(root), "show", f"{candidate}:src/artifex/_version.py"),
            capture_output=True,
            check=True,
        ).stdout
    with tarfile.open(output / "artifex_dev-1.0.0.tar.gz", mode="r:gz") as archive:
        names = archive.getnames()
        assert "artifex_dev-1.0.0/artifex-release-provenance.json" in names
        assert "artifex_dev-1.0.0/src/artifex/validation/core.py" in names
        assert "artifex_dev-1.0.0/pyproject.toml" in names
        version_stream = archive.extractfile(
            "artifex_dev-1.0.0/src/artifex/_version.py"
        )
        assert version_stream is not None
        assert version_stream.read() == subprocess.run(
            ("git", "-C", str(root), "show", f"{candidate}:src/artifex/_version.py"),
            capture_output=True,
            check=True,
        ).stdout

    native_output = root / "dist/native"
    native_work = root / "build/native"
    subprocess.run(
        (
            "uv",
            "run",
            "python",
            "packaging/build.py",
            "--output",
            str(native_output),
            "--work",
            str(native_work),
            "--clean",
        ),
        cwd=root,
        capture_output=True,
        check=True,
        env=isolated_environment,
    )
    machine = platform.machine().casefold()
    kind = (
        "native-windows-x64"
        if sys.platform == "win32"
        else "native-macos-arm64"
        if sys.platform == "darwin" and machine in {"arm64", "aarch64"}
        else "native-linux-x64"
    )
    native_archive = finalize_native_artifact(
        root, native_output / "artifex", tmp_path / "release", candidate, kind
    )
    assert native_archive.is_file()
    if native_archive.suffix == ".zip":
        with zipfile.ZipFile(native_archive) as archive:
            native_manifest = json.loads(archive.read("artifex/artifex-artifact.json"))
            native_provenance = json.loads(
                archive.read("artifex/artifex-release-provenance.json")
            )
            native_schema = archive.read(
                "artifex/_internal/artifex/schemas/acceptance-evidence.schema.json"
            )
    else:
        with tarfile.open(native_archive, mode="r:gz") as archive:
            manifest_stream = archive.extractfile("artifex/artifex-artifact.json")
            provenance_stream = archive.extractfile("artifex/artifex-release-provenance.json")
            assert manifest_stream is not None and provenance_stream is not None
            native_manifest = json.loads(manifest_stream.read())
            native_provenance = json.loads(provenance_stream.read())
            schema_stream = archive.extractfile(
                "artifex/_internal/artifex/schemas/acceptance-evidence.schema.json"
            )
            assert schema_stream is not None
            native_schema = schema_stream.read()
    assert native_manifest["source_commit"] == candidate
    assert native_manifest["pyinstaller_version"] == "6.22.2"
    assert native_provenance["source_commit"] == candidate
    assert native_provenance["toolchain"] == "pyinstaller==6.22.2"
    assert native_schema == subprocess.run(
        (
            "git",
            "-C",
            str(root),
            "show",
            f"{candidate}:schemas/acceptance-evidence.schema.json",
        ),
        capture_output=True,
        check=True,
    ).stdout


@pytest.mark.adversarial
def test_category_reports_fail_closed_on_missing_tamper_stale_and_nominal_claims(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / CATEGORY_REPORTS["build"]
    original = path.read_bytes()
    mutations: list[object] = [
        None,
        {"results": {"passed": True}},
        {"binding": {"candidate_commit": "f" * 40}},
        {"attestation": {"producer_id": "self-asserted-worker"}},
        {"results": {"run_id": 42, "jobs": []}},
    ]
    for mutation in mutations:
        if mutation is None:
            path.unlink()
        else:
            value = json.loads(original)
            assert isinstance(mutation, dict)
            for key, replacement in mutation.items():
                if isinstance(replacement, dict) and isinstance(value.get(key), dict):
                    value[key].update(replacement)
                else:
                    value[key] = replacement
            _write(path, json.dumps(value, sort_keys=True) + "\n")
        assert any(
            "final evidence release report invalid: EVD-M11-BUILD" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        path.write_bytes(original)


@pytest.mark.adversarial
def test_release_reports_reject_bool_counts_duplicate_rows_and_nominal_security(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path)
    mutations: tuple[tuple[str, object], ...] = (
        ("build", {"run_id": True}),
        ("validation", {"summary": {"tests_passed": True, "coverage_percent": 85.8}}),
        (
            "portability",
            {
                "native_jobs": [
                    "linux-x86_64",
                    "windows-x86_64",
                    "windows-x86_64",
                ]
            },
        ),
        ("packaging", {"duplicate_native_attestation": True}),
        ("security", {"attacks": [{"id": "nominal", "status": "PASS"}]}),
    )
    for category, mutation in mutations:
        path = tmp_path / CATEGORY_REPORTS[category]
        original = path.read_bytes()
        report = json.loads(original)
        results = report["results"]
        assert isinstance(mutation, dict)
        if mutation.get("duplicate_native_attestation"):
            results["native_attestations"] = [
                results["native_attestations"][0],
                results["native_attestations"][0],
                results["native_attestations"][1],
            ]
        else:
            results.update(mutation)
        _write(path, json.dumps(report, sort_keys=True) + "\n")
        assert any(
            f"final evidence release report invalid: EVD-M11-{category.upper()}" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        path.write_bytes(original)


@pytest.mark.adversarial
def test_traceability_rejects_one_valid_chain_laundered_across_requirements(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/implementation/traceability.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    for map_name in ("architecture", "ownership", "tasks", "evidence", "gates"):
        value["maps"][map_name]["REQ-F-002"] = list(value["maps"][map_name]["REQ-F-001"])
    _yaml_write(path, value)
    report = validate_traceability(tmp_path)
    assert not report.passed
    assert any("semantic mapping mismatch: REQ-F-002" in error for error in report.errors)


@pytest.mark.adversarial
def test_traceability_rejects_overlap_duplicate_owners_and_catalogs(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/implementation/traceability.yaml"
    baseline = yaml.safe_load(path.read_text(encoding="utf-8"))

    overlap = json.loads(json.dumps(baseline))
    overlap["maps"]["ownership"]["REQ-F-001..002"] = ["M11"]
    _yaml_write(path, overlap)
    assert any(
        "ownership overlapping requirement keys" in error
        for error in validate_traceability(tmp_path).errors
    )

    duplicate_owner = json.loads(json.dumps(baseline))
    duplicate_owner["maps"]["tasks"]["REQ-F-001"].append("M11-T12")
    _yaml_write(path, duplicate_owner)
    assert any(
        "traceability entry has no valid owner" in error
        for error in validate_traceability(tmp_path).errors
    )

    duplicate_catalog = json.loads(json.dumps(baseline))
    duplicate_catalog["definitions"]["evidence"].append(
        duplicate_catalog["definitions"]["evidence"][0]
    )
    _yaml_write(path, duplicate_catalog)
    assert any(
        "missing definition catalog: evidence" in error
        for error in validate_traceability(tmp_path).errors
    )


@pytest.mark.adversarial
def test_current_gates_reject_duplicate_required_evidence(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/validation/gates/G-M11-MILESTONE.yaml"
    gate = yaml.safe_load(path.read_text(encoding="utf-8"))
    gate["gate"]["required_evidence"].append(gate["gate"]["required_evidence"][0])
    _yaml_write(path, gate)
    assert any(
        "current gate evidence scope mismatch: G-M11-MILESTONE" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_release_audit_append_requires_order_exact_types_and_aware_time(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    prefix, appended = lines[:-3], [json.loads(line) for line in lines[-3:]]
    mutations = (
        [appended[2], appended[1], appended[0]],
        [{**appended[0], "actor": 7}, appended[1], appended[2]],
        [{**appended[0], "occurred_at": "2026-08-22T00:00:00"}, appended[1], appended[2]],
        [{**appended[0], "unexpected": True}, appended[1], appended[2]],
    )
    for mutation in mutations:
        _write(
            path,
            "\n".join((*prefix, *(json.dumps(item, sort_keys=True) for item in mutation)))
            + "\n",
        )
        _git(tmp_path, "add", ".artifex/audit.jsonl")
        _git(tmp_path, "commit", "-m", "audit adversarial mutation")
        assert any(
            "status/audit transition invalid" in blocker
            for blocker in verify_release(tmp_path).blockers
        )


@pytest.mark.parametrize("mutation", ["missing", "invented"])
@pytest.mark.adversarial
def test_cross_artifact_traceability_manifest_is_exact_authority(
    tmp_path: Path, mutation: str
) -> None:
    _complete_release_fixture(tmp_path)
    model_path = tmp_path / ".artifex/project-model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    requirement_artifact = next(
        artifact for artifact in model["artifacts"] if artifact["id"] == "ART-SELF-REQUIREMENTS"
    )
    expected = requirement_artifact["metadata"]["traceability_expected"]["requirements"]
    if mutation == "missing":
        expected.pop("REQ-F-002")
        message = "requirement catalog mismatch"
    else:
        expected["REQ-F-002"]["architecture"].append("Invented component")
        message = "references unknown architecture"
    _write(model_path, json.dumps(model, indent=2) + "\n")
    traceability_path = tmp_path / ".artifex/implementation/traceability.yaml"
    traceability = yaml.safe_load(traceability_path.read_text(encoding="utf-8"))
    traceability["source"]["project_model_sha256"] = _project_model_digest(model)
    _yaml_write(traceability_path, traceability)
    report = validate_traceability(tmp_path)
    assert not report.passed
    assert any(message in error for error in report.errors)


@pytest.mark.adversarial
def test_complete_package_inventory_and_native_attestation_reject_rebuilt_payloads(
    tmp_path: Path,
) -> None:
    manifest = _complete_release_fixture(tmp_path)
    release_path = tmp_path / ".artifex/releases/v1.0.0.yaml"
    wheel = next(item for item in manifest["artifacts"] if item["kind"] == "wheel")
    wheel_path = tmp_path / wheel["path"]
    original_wheel = wheel_path.read_bytes()
    original_digest = wheel["sha256"]
    for name in (
        "artifex/validation/core.py",
        "artifex/integrations/manual.py",
        "artifex/dependencies.py",
    ):
        _rewrite_zip_members(wheel_path, {name: b"attacker_rebuild = True\n"})
        wheel["sha256"] = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
        _yaml_write(release_path, manifest)
        assert any(
            "packaged source differs from candidate S for wheel" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        wheel_path.write_bytes(original_wheel)
        wheel["sha256"] = original_digest
    _rewrite_zip_members(wheel_path, {"artifex/extra_module.py": b"ESCAPE = True\n"})
    wheel["sha256"] = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    _yaml_write(release_path, manifest)
    assert any(
        "wheel package inventory differs from candidate S" in blocker
        for blocker in verify_release(tmp_path).blockers
    )
    wheel_path.write_bytes(original_wheel)
    wheel["sha256"] = original_digest

    for name in (
        "attacker.pth",
        "evil/__init__.py",
        "evil-1.0.dist-info/METADATA",
    ):
        _rewrite_zip_members(wheel_path, {name: b"attacker payload\n"})
        wheel["sha256"] = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
        _yaml_write(release_path, manifest)
        expected = (
            "wheel metadata files missing or ambiguous"
            if ".dist-info/" in name
            else "wheel archive inventory differs from candidate S"
        )
        assert any(
            expected in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        wheel_path.write_bytes(original_wheel)
        wheel["sha256"] = original_digest

    sdist = next(item for item in manifest["artifacts"] if item["kind"] == "sdist")
    sdist_path = tmp_path / sdist["path"]
    original_sdist = sdist_path.read_bytes()
    original_sdist_digest = sdist["sha256"]
    for name in ("setup.py", "extra-payload.bin"):
        _rewrite_tar_members(
            sdist_path,
            {f"artifex_dev-1.0.0/{name}": b"attacker payload\n"},
        )
        sdist["sha256"] = hashlib.sha256(sdist_path.read_bytes()).hexdigest()
        _yaml_write(release_path, manifest)
        assert any(
            "sdist source inventory differs from candidate S" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        sdist_path.write_bytes(original_sdist)
        sdist["sha256"] = original_sdist_digest

    native = next(item for item in manifest["artifacts"] if item["kind"] == "native-windows-x64")
    native_path = tmp_path / native["path"]
    with zipfile.ZipFile(native_path) as archive:
        core_manifest = json.loads(archive.read("artifex/artifex-artifact.json"))
    payload = b"MZself-authored-native-rebuild"
    digest = hashlib.sha256(payload).hexdigest()
    core_manifest["sha256"] = digest
    core_manifest["build_id"] = f"artifex-1.0.0-windows-x86_64-{digest[:16]}"
    for item in core_manifest["files"]:
        if item["path"] == "artifex.exe":
            item["sha256"] = digest
    _rewrite_zip_members(
        native_path,
        {
            "artifex/artifex.exe": payload,
            "artifex/artifex-artifact.json": json.dumps(core_manifest, sort_keys=True).encode(),
        },
    )
    native["sha256"] = hashlib.sha256(native_path.read_bytes()).hexdigest()
    _yaml_write(release_path, manifest)
    assert any(
        "packaging release report results are invalid" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_wheel_rejects_alias_collisions_special_files_and_duplicate_identity(
    tmp_path: Path,
) -> None:
    manifest = _complete_release_fixture(tmp_path)
    release_path = tmp_path / ".artifex/releases/v1.0.0.yaml"
    wheel = next(item for item in manifest["artifacts"] if item["kind"] == "wheel")
    path = tmp_path / wheel["path"]
    original = path.read_bytes()

    for name, expected in (
        ("ARTIFEX/_version.py", "archive inventory exceeds safety bounds"),
        ("artifex/./escape.py", "unsafe path"),
    ):
        _rewrite_zip_members(path, {name: b"attacker\n"})
        wheel["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        _yaml_write(release_path, manifest)
        assert any(expected in blocker for blocker in verify_release(tmp_path).blockers)
        path.write_bytes(original)

    for file_type in (stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK):
        _rewrite_zip_special(path, "artifex/special", file_type)
        wheel["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        _yaml_write(release_path, manifest)
        assert any(
            "wheel contains a special file" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        path.write_bytes(original)

    with zipfile.ZipFile(path) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name)
    _rewrite_wheel_with_record(path, {metadata_name: metadata + b"Name: attacker\n"})
    wheel["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _yaml_write(release_path, manifest)
    assert any(
        "wheel package metadata differs from candidate S" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_understanding_pack_rejects_placeholder_missing_machine_and_forged_result(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path)
    mutations = (
        (tmp_path / REQUIRED_GUIDES[0], b"ok\n"),
        (tmp_path / REQUIRED_MACHINE[0], None),
        (
            tmp_path / COMPREHENSION_ARTIFACTS[2],
            json.dumps(
                {
                    "schema_version": "1.0",
                    "passed": 9,
                    "total": 9,
                    "score": 1.0,
                    "response_sha256": "0" * 64,
                }
            ).encode(),
        ),
    )
    for path, replacement in mutations:
        original = path.read_bytes()
        if replacement is None:
            path.unlink()
        else:
            path.write_bytes(replacement)
        assert any(
            "generated documentation freshness invalid" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
        path.write_bytes(original)


@pytest.mark.adversarial
def test_schema2_ledger_preserves_source_prefix_and_rejects_rewrite(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path, source_schema2_ledger=True)
    assert verify_release(tmp_path).passed
    ledger = tmp_path / FINAL_LEDGER
    lines = ledger.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["entry"]["evidence_id"] == "EVD-PREVIOUS"
    _write(ledger, "\n".join(lines[1:]) + "\n")
    _git(tmp_path, "add", FINAL_LEDGER)
    _git(tmp_path, "commit", "-m", "rewrite schema2 history")
    assert any(
        "schema-2 ledger is not an append-only extension of S" in blocker
        for blocker in verify_release(tmp_path).blockers
    )


@pytest.mark.adversarial
def test_contract_authority_rejects_duplicate_keys_nonhex_and_unresolved_candidate(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/validation/contracts/V1-RELEASE.yaml"
    original = path.read_text(encoding="utf-8")
    duplicate = original.replace(
        "  candidate_commit:", "  candidate_commit: 'f'\n  candidate_commit:", 1
    )
    mutations = (
        (duplicate, "duplicate YAML key"),
        (
            original.replace(
                _git(tmp_path, "rev-parse", "HEAD~1"), "candidate-" + "x" * 30, 1
            ),
            "candidate commit missing",
        ),
        (
            original.replace(_git(tmp_path, "rev-parse", "HEAD~1"), "0" * 40, 1),
            "candidate commit",
        ),
    )
    for index, (text, message) in enumerate(mutations):
        _write(path, text)
        _git(tmp_path, "add", str(path.relative_to(tmp_path)))
        _git(tmp_path, "commit", "-m", f"contract authority attack {index}")
        assert any(message in blocker for blocker in verify_release(tmp_path).blockers)
        _write(path, original)
        _git(tmp_path, "add", str(path.relative_to(tmp_path)))
        _git(tmp_path, "commit", "-m", f"restore contract authority {index}")


@pytest.mark.adversarial
def test_project_model_and_schema_authority_reject_duplicate_json_keys(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    for relative, marker in (
        (".artifex/project-model.json", '  "schema_version":'),
        ("schemas/project-model.schema.json", '  "$schema":'),
    ):
        path = tmp_path / relative
        original = path.read_text(encoding="utf-8")
        first_line = next(line for line in original.splitlines() if marker in line)
        _write(path, original.replace(first_line, first_line + "\n" + first_line, 1))
        report = validate_traceability(tmp_path)
        assert not report.passed
        assert any("duplicate JSON key" in error for error in report.errors)
        path.write_text(original, encoding="utf-8")


@pytest.mark.adversarial
def test_historical_yaml_and_json_reject_duplicate_authority_keys(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    yaml_path = tmp_path / ".artifex/validation/evidence/EVD-M00-001.yaml"
    original = yaml_path.read_text(encoding="utf-8")
    gate = yaml.safe_load(
        (tmp_path / ".artifex/validation/gates/G-M00-MILESTONE.yaml").read_text()
    )
    contract_hash = gate["gate"]["contract_hash"]
    _write(yaml_path, original.replace("  id: EVD-M00-001", "  id: EVD-OTHER\n  id: EVD-M00-001"))
    with pytest.raises(ValidationError, match="duplicate YAML key"):
        _historical_evidence(tmp_path, "EVD-M00-001", contract_hash)
    payload = yaml.safe_load(original)
    yaml_path.unlink()
    json_path = yaml_path.with_suffix(".json")
    encoded = json.dumps(payload)
    _write(
        json_path,
        encoded.replace(
            '"schema_version": "1.0"',
            '"schema_version": "0", "schema_version": "1.0"',
            1,
        ),
    )
    with pytest.raises(ValidationError, match="duplicate JSON key"):
        _historical_evidence(tmp_path, "EVD-M00-001", contract_hash)


@pytest.mark.adversarial
def test_traceability_rejects_normalization_collisions_and_is_checkout_stable(
    tmp_path: Path,
) -> None:
    _complete_release_fixture(tmp_path)
    assert validate_traceability(tmp_path).passed
    requirements = tmp_path / "docs/requirements/REQUIREMENTS_BASELINE.md"
    requirements.write_bytes(requirements.read_bytes().replace(b"\n", b"\r\n"))
    model_path = tmp_path / ".artifex/project-model.json"
    model_path.write_bytes(model_path.read_bytes().replace(b"\n", b"\r\n"))
    assert validate_traceability(tmp_path).passed
    model = json.loads(model_path.read_text(encoding="utf-8"))
    architecture = next(
        artifact for artifact in model["artifacts"] if artifact["id"] == "ART-SELF-CHARTER"
    )
    architecture["metadata"]["understanding"]["core_components"] += [
        "A & B",
        "a and b",
    ]
    _write(model_path, json.dumps(model, indent=2) + "\n")
    traceability_path = tmp_path / ".artifex/implementation/traceability.yaml"
    traceability = yaml.safe_load(traceability_path.read_text(encoding="utf-8"))
    traceability["source"]["project_model_sha256"] = hashlib.sha256(
        json.dumps(
            model,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    _yaml_write(traceability_path, traceability)
    report = validate_traceability(tmp_path)
    assert any("normalization is not injective" in error for error in report.errors)


@pytest.mark.adversarial
def test_dashboard_requires_complete_measured_candidate_state(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / "docs/implementation/dashboard/state.json"
    original = path.read_text(encoding="utf-8")
    mutations = (
        ("gates", lambda value: value["gates"].update({"pass": 0})),
        ("tests", lambda value: value["tests"].update({"suites": []})),
        ("trace", lambda value: value["traceability"].update({"requirements_total": 0})),
        ("docs", lambda value: value.update({"documentation": []})),
        ("integrations", lambda value: value.update({"integrations": []})),
        ("milestones", lambda value: value.update({"milestones": value["milestones"][-1:]})),
    )
    for _, mutate in mutations:
        value = json.loads(original)
        mutate(value)
        _write(path, json.dumps(value, sort_keys=True) + "\n")
        assert any(
            "dashboard is not deterministic noncanonical candidate-bound output" in blocker
            for blocker in verify_release(tmp_path).blockers
        )
    _write(path, original)


@pytest.mark.adversarial
def test_release_audit_ids_are_global_and_timestamps_strictly_increasing(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    path = tmp_path / ".artifex/audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    prefix, appended = lines[:-3], [json.loads(line) for line in lines[-3:]]
    source_id = json.loads(prefix[0])["event_id"]
    mutations = (
        [{**appended[0], "event_id": appended[1]["event_id"]}, appended[1], appended[2]],
        [{**appended[0], "event_id": source_id}, appended[1], appended[2]],
        [appended[0], {**appended[1], "occurred_at": appended[0]["occurred_at"]}, appended[2]],
    )
    for index, mutation in enumerate(mutations):
        _write(
            path,
            "\n".join((*prefix, *(json.dumps(item, sort_keys=True) for item in mutation)))
            + "\n",
        )
        _git(tmp_path, "add", str(path.relative_to(tmp_path)))
        _git(tmp_path, "commit", "-m", f"audit identity attack {index}")
        assert any(
            "appended release audit event set is not exact" in blocker
            for blocker in verify_release(tmp_path).blockers
        )


@pytest.mark.adversarial
def test_package_metadata_is_exactly_derived_from_candidate_pyproject(tmp_path: Path) -> None:
    manifest = _complete_release_fixture(tmp_path)
    contract = yaml.safe_load(
        (tmp_path / ".artifex/validation/contracts/V1-RELEASE.yaml").read_text()
    )
    binding = _binding(tmp_path, contract["contract"]["candidate_commit"])
    by_kind = {item["kind"]: item for item in manifest["artifacts"]}
    wheel_item = by_kind["wheel"]
    wheel_path = tmp_path / wheel_item["path"]
    original_wheel = wheel_path.read_bytes()
    with zipfile.ZipFile(wheel_path) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("/METADATA"))
        wheel_name = next(name for name in archive.namelist() if name.endswith("/WHEEL"))
        entry_name = next(name for name in archive.namelist() if name.endswith("/entry_points.txt"))
        metadata = archive.read(metadata_name)
        wheel_metadata = archive.read(wheel_name)
        entry_points = archive.read(entry_name)
    wheel_attacks = (
        {metadata_name: metadata.replace(b"\n\n", b"\nRequires-Dist: attacker>=1\n\n", 1)},
        {metadata_name: metadata.replace(b"\n\n", b"\nRequires-Python: >=99\n\n", 1)},
        {metadata_name: metadata.replace(b"\n\n", b"\nClassifier: Private :: Attack\n\n", 1)},
        {wheel_name: wheel_metadata.replace(b"hatchling 1.27.0", b"attacker 9")},
        {wheel_name: wheel_metadata.replace(b"Root-Is-Purelib: true", b"Root-Is-Purelib: false")},
        {entry_name: entry_points.replace(b"artifex.cli:app", b"attacker:app")},
    )
    for updates in wheel_attacks:
        _rewrite_wheel_with_record(wheel_path, updates)
        with pytest.raises(ValidationError, match=r"metadata|tooling|entry point"):
            _validate_wheel(
                tmp_path,
                wheel_path,
                binding,
                wheel_item["provenance_sha256"],
            )
        wheel_path.write_bytes(original_wheel)
    sdist_item = by_kind["sdist"]
    sdist_path = tmp_path / sdist_item["path"]
    original_sdist = sdist_path.read_bytes()
    with tarfile.open(sdist_path, mode="r:gz") as archive:
        metadata_member = next(member for member in archive if member.name.endswith("/PKG-INFO"))
        stream = archive.extractfile(metadata_member)
        assert stream is not None
        sdist_metadata = stream.read()
    for injected in (
        b"Requires-Dist: attacker>=1",
        b"Requires-Python: >=99",
        b"Classifier: Attack",
    ):
        _rewrite_tar_members(
            sdist_path,
            {metadata_member.name: sdist_metadata.replace(b"\n\n", b"\n" + injected + b"\n\n", 1)},
        )
        with pytest.raises(ValidationError, match="package metadata"):
            _validate_sdist(
                tmp_path,
                sdist_path,
                binding,
                sdist_item["provenance_sha256"],
            )
        sdist_path.write_bytes(original_sdist)


@pytest.mark.adversarial
def test_understanding_rejects_long_filler_and_nominal_assertions(tmp_path: Path) -> None:
    _complete_release_fixture(tmp_path)
    document = tmp_path / REQUIRED_GENERATED[0]
    filler = (
        "# Readme\n\n"
        + f"Candidate: {_git(tmp_path, 'rev-parse', 'HEAD~1')}\nModel: "
        + _binding(tmp_path, _git(tmp_path, "rev-parse", "HEAD~1")).project_model_fingerprints[0]
        + "\n\n## Purpose\n## Authority\n## Controls\n## Verification\n"
        + "artifex governance evidence filler " * 100
    )
    document.write_text(filler, encoding="utf-8")
    assert any(
        "generated documentation freshness invalid" in blocker
        for blocker in verify_release(tmp_path).blockers
    )

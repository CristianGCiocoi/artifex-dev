"""Optional Pandora research provider using an authority-preserving file boundary."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import yaml  # type: ignore[import-untyped]

from artifex.integrations.contracts import (
    CompatibilityRange,
    ConfigurationProvenance,
    HealthReport,
    HealthStatus,
    IntegrationError,
    IntegrationMetadata,
    IntegrationRole,
)
from artifex.integrations.research import ResearchBundle, ResearchRequest
from artifex.project.model import WorkflowDepth

_MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_PROVIDER_MANIFEST = "pandora-provider.json"


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class PandoraProviderManifest:
    """Provider-written identity for the filesystem exchange contract.

    A valid manifest proves contract identity only.  It is deliberately not live
    role certification.
    """

    instance_id: str
    version: str
    contract: str
    issued_at: str
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise IntegrationError("unsupported Pandora provider manifest schema")
        if not all(
            item.strip() for item in (self.instance_id, self.version, self.contract, self.issued_at)
        ):
            raise IntegrationError("Pandora provider manifest identity is incomplete")
        if self.contract != "filesystem-contract-v1":
            raise IntegrationError("Pandora provider manifest contract is unsupported")
        try:
            parsed = datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise IntegrationError("Pandora provider manifest timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise IntegrationError("Pandora provider manifest timestamp must be timezone-aware")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "provider_id": "pandora",
            "role": "RESEARCH",
            "instance_id": self.instance_id,
            "version": self.version,
            "contract": self.contract,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PandoraProviderManifest:
        if value.get("provider_id") != "pandora" or value.get("role") != "RESEARCH":
            raise IntegrationError("Pandora manifest may declare only the RESEARCH role")
        return cls(
            instance_id=str(value.get("instance_id", "")),
            version=str(value.get("version", "")),
            contract=str(value.get("contract", "")),
            issued_at=str(value.get("issued_at", "")),
            schema_version=str(value.get("schema_version", "")),
        )


@dataclass(frozen=True, slots=True)
class PandoraReadiness:
    state: str
    checks: Mapping[str, bool]
    manifest: PandoraProviderManifest | None
    detail: str

    @property
    def available_for_research(self) -> bool:
        return self.state == "AVAILABLE" and all(self.checks.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": "pandora",
            "role": "RESEARCH",
            "state": self.state,
            "checks": dict(sorted(self.checks.items())),
            "globally_available": self.available_for_research,
            "available_for": "RESEARCH" if self.available_for_research else None,
            "manifest": self.manifest.to_dict() if self.manifest else None,
            "certification": None,
            "certification_authority": "UNAVAILABLE",
            "detail": self.detail,
        }


class ResearchTransport(Protocol):
    """Semantic transport seam shared by filesystem and future CLI/API transports."""

    def export_request(self, request: ResearchRequest) -> Path: ...

    def import_bundle(self, request: ResearchRequest) -> ImportedResearch: ...


@dataclass(frozen=True, slots=True)
class ImportedResearch:
    """Validated evidence only; never a Project Model state transition."""

    bundle: ResearchBundle
    report: str
    bundle_path: str
    report_path: str
    bundle_sha256: str
    report_sha256: str
    canonical: bool = False
    authority: str = "research-evidence-only"

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": self.bundle.to_dict(),
            "report": self.report,
            "bundle_path": self.bundle_path,
            "report_path": self.report_path,
            "bundle_sha256": self.bundle_sha256,
            "report_sha256": self.report_sha256,
            "canonical": self.canonical,
            "authority": self.authority,
        }


class FilesystemResearchTransport:
    """Atomic, path-safe V1 request/bundle exchange.

    Each portable request ID receives its own directory to prevent collisions:
    ``<root>/<request-id>/research-request.yaml`` and Pandora returns
    ``research-bundle.json`` plus ``research-report.md`` in that directory.
    """

    def __init__(self, exchange_root: str | Path) -> None:
        supplied = Path(exchange_root)
        if supplied.exists() and supplied.is_symlink():
            raise IntegrationError("Pandora exchange root may not be a symlink")
        self._root = supplied.resolve()

    @property
    def exchange_root(self) -> Path:
        return self._root

    def request_directory(self, request_id: str) -> Path:
        _validate_identifier(request_id)
        directory = (self._root / request_id).resolve()
        if self._root != directory.parent:
            raise IntegrationError("Pandora request directory escapes exchange root")
        return directory

    def export_request(self, request: ResearchRequest) -> Path:
        directory = self.request_directory(request.request_id)
        _ensure_safe_directory(self._root)
        _ensure_safe_directory(directory)
        output = directory / "research-request.yaml"
        payload = yaml.safe_dump(
            request.to_dict(),
            sort_keys=True,
            allow_unicode=True,
            default_flow_style=False,
        ).encode("utf-8")
        _atomic_write(output, payload)
        return output

    def import_bundle(self, request: ResearchRequest) -> ImportedResearch:
        directory = self.request_directory(request.request_id)
        _require_safe_existing_directory(self._root)
        _require_safe_existing_directory(directory)
        bundle_path = directory / "research-bundle.json"
        report_path = directory / "research-report.md"
        bundle_bytes = _read_regular_file(bundle_path, maximum=_MAX_BUNDLE_BYTES)
        report_bytes = _read_regular_file(report_path, maximum=_MAX_REPORT_BYTES)
        try:
            value = json.loads(bundle_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrationError("Pandora research bundle must be valid UTF-8 JSON") from exc
        if not isinstance(value, Mapping):
            raise IntegrationError("Pandora research bundle must be a JSON object")
        bundle = ResearchBundle.from_dict(value)
        if bundle.request_id != request.request_id:
            raise IntegrationError("Pandora bundle request_id does not match exported request")
        try:
            report = report_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IntegrationError("Pandora research report must be UTF-8") from exc
        if not report.strip():
            raise IntegrationError("Pandora research report must not be empty")
        return ImportedResearch(
            bundle,
            report,
            str(bundle_path),
            str(report_path),
            hashlib.sha256(bundle_bytes).hexdigest(),
            hashlib.sha256(report_bytes).hexdigest(),
        )


class ResearchRoute(StrEnum):
    NATIVE = "NATIVE"
    PANDORA_PREFERRED = "PANDORA_PREFERRED"
    PANDORA_ESCALATION = "PANDORA_ESCALATION"


@dataclass(frozen=True, slots=True)
class ResearchPolicyDecision:
    route: ResearchRoute
    reason: str


def select_research_route(
    depth: WorkflowDepth,
    *,
    pandora_available: bool,
    evidence_needs_escalation: bool = False,
) -> ResearchPolicyDecision:
    """Apply the frozen QUICK/STANDARD/DEEP research policy deterministically."""

    if depth is WorkflowDepth.DEEP and pandora_available:
        return ResearchPolicyDecision(
            ResearchRoute.PANDORA_PREFERRED,
            "DEEP prefers an available Pandora provider for external research",
        )
    if (
        depth is WorkflowDepth.STANDARD
        and evidence_needs_escalation
        and pandora_available
    ):
        return ResearchPolicyDecision(
            ResearchRoute.PANDORA_ESCALATION,
            "STANDARD escalates because explicit evidence needs justify it",
        )
    reason = "native research remains available"
    if depth is WorkflowDepth.DEEP and not pandora_available:
        reason = "Pandora is unavailable; DEEP falls back to native research"
    return ResearchPolicyDecision(ResearchRoute.NATIVE, reason)


class PandoraResearchAdapter:
    """Evidence exchange only. ARTIFEX Core remains the sole model authority."""

    def __init__(self, transport: ResearchTransport) -> None:
        self.transport = transport

    @property
    def metadata(self) -> IntegrationMetadata:
        return IntegrationMetadata(
            integration_id="pandora",
            name="Pandora Research",
            version="1.0.0",
            compatibility=CompatibilityRange("0.1.0", "2.0.0"),
            tested_external_versions=("filesystem-contract-v1",),
            roles=frozenset({IntegrationRole.RESEARCH_PROVIDER}),
            capabilities=frozenset({"filesystem_exchange", "source_backed_research"}),
            configuration=ConfigurationProvenance("explicit research transport"),
        )

    def health(self) -> HealthReport:
        if isinstance(self.transport, FilesystemResearchTransport):
            root = self.transport.exchange_root
            if root.exists() and not root.is_dir():
                return HealthReport(
                    HealthStatus.FAIL,
                    "Pandora exchange root is not a directory",
                    {"transport": HealthStatus.FAIL},
                )
            return HealthReport(
                HealthStatus.PASS,
                "Pandora filesystem research contract is available",
                {"transport": HealthStatus.PASS},
            )
        return HealthReport(
            HealthStatus.PASS,
            "Pandora semantic research transport is configured",
            {"transport": HealthStatus.PASS},
        )

    def export_request(self, request: ResearchRequest) -> Path:
        return self.transport.export_request(request)

    def import_bundle(self, request: ResearchRequest) -> ImportedResearch:
        imported = self.transport.import_bundle(request)
        return _validate_imported_research(imported, request)

    def route(
        self,
        depth: WorkflowDepth,
        *,
        evidence_needs_escalation: bool = False,
    ) -> ResearchPolicyDecision:
        return select_research_route(
            depth,
            pandora_available=self.health().status is HealthStatus.PASS,
            evidence_needs_escalation=evidence_needs_escalation,
        )

    @staticmethod
    def transition_project_model(*_args: object, **_kwargs: object) -> None:
        """Make the authority denial explicit for callers and adversarial tests."""

        raise IntegrationError(
            "Pandora is evidence-only and cannot transition the ARTIFEX Project Model"
        )


class PandoraResearchService:
    """M8B product surface over the V1 evidence transport.

    Request export and evidence import never mutate a Project.  Adoption creates a
    semantic proposal and deliberately leaves acceptance to Project Authority.
    """

    def __init__(
        self,
        exchange_root: str | Path,
    ) -> None:
        self.transport = FilesystemResearchTransport(exchange_root)
        self.adapter = PandoraResearchAdapter(self.transport)

    def readiness(self) -> PandoraReadiness:
        root = self.transport.exchange_root
        checks = {
            "exchange_root_safe": root.is_dir() and not root.is_symlink(),
            "provider_manifest_valid": False,
            "independent_certification_authority_configured": False,
            "live_role_certified": False,
        }
        manifest: PandoraProviderManifest | None = None
        if checks["exchange_root_safe"]:
            try:
                manifest = _read_provider_manifest(root)
                checks["provider_manifest_valid"] = True
            except IntegrationError:
                manifest = None
        state = "CONFIGURED" if checks["exchange_root_safe"] else "NOT_DETECTED"
        detail = (
            "Pandora filesystem contract is configured, but no independently anchored "
            "certification authority is available; caller-supplied receipts are forbidden"
            if state == "CONFIGURED"
            else "Pandora exchange root is unavailable"
        )
        return PandoraReadiness(state, checks, manifest, detail)

    def export_request(self, request: ResearchRequest) -> dict[str, Any]:
        manifest = _read_provider_manifest(self.transport.exchange_root)
        path = self.adapter.export_request(request)
        request_sha256 = _canonical_sha256(request.to_dict())
        return {
            "request": request.to_dict(),
            "request_path": str(path),
            "request_sha256": request_sha256,
            "provider_manifest": manifest.to_dict(),
            "canonical": False,
            "authority": "research-request-only",
        }

    def import_evidence(self, request: ResearchRequest) -> dict[str, Any]:
        manifest = _read_provider_manifest(self.transport.exchange_root)
        imported = self.adapter.import_bundle(request)
        _validate_provider_generation(imported.bundle, manifest)
        return {
            "imported": imported.to_dict(),
            "request_sha256": _canonical_sha256(request.to_dict()),
            "source_manifest_sha256": _canonical_sha256(
                [source.to_dict() for source in imported.bundle.source_manifest]
            ),
            "provider_manifest": manifest.to_dict(),
            "canonical": False,
            "authority": "research-evidence-only",
        }

    def propose_adoption(
        self,
        *,
        project_root: str | Path,
        request: ResearchRequest,
        expected_revision: int,
        actor: str,
        proposed_at: str | None = None,
    ) -> dict[str, Any]:
        readiness = self.readiness()
        if not readiness.available_for_research:
            raise IntegrationError(
                "Pandora lacks independently anchored LIVE_ROLE_CERTIFIED authority and "
                "cannot supply an adoption proposal"
            )
        assert readiness.manifest is not None
        raise AssertionError("unreachable until an independent certification authority exists")


def _read_provider_manifest(root: Path) -> PandoraProviderManifest:
    path = root / _PROVIDER_MANIFEST
    raw = _read_regular_file(path, maximum=64 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrationError("Pandora provider manifest must be UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise IntegrationError("Pandora provider manifest must be an object")
    return PandoraProviderManifest.from_dict(value)


def _validate_provider_generation(
    bundle: ResearchBundle, manifest: PandoraProviderManifest
) -> None:
    metadata = bundle.generation_metadata
    expected = {
        "provider_id": "pandora",
        "provider_instance_id": manifest.instance_id,
        "provider_version": manifest.version,
        "provider_role": "RESEARCH",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise IntegrationError(f"Pandora bundle generation metadata mismatches {key}")


def _validate_identifier(value: str) -> None:
    # ResearchRequest already enforces this, but the transport seam is callable directly.
    portable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if not value or any(character not in portable for character in value):
        raise IntegrationError("Pandora request ID must be a portable path segment")
    if value in {".", ".."}:
        raise IntegrationError("Pandora request ID must be a portable path segment")


def _validate_imported_research(
    imported: object, request: ResearchRequest
) -> ImportedResearch:
    """Re-establish the evidence-only boundary after every transport call."""

    if not isinstance(imported, ImportedResearch):
        raise IntegrationError("Pandora transport must return ImportedResearch")
    if imported.canonical is not False:
        raise IntegrationError("Pandora transport attempted to claim canonical authority")
    if imported.authority != "research-evidence-only":
        raise IntegrationError("Pandora transport attempted to widen research authority")
    if type(imported.bundle) is not ResearchBundle:
        raise IntegrationError("Pandora transport supplied an invalid research bundle")
    if not isinstance(imported.report, str):
        raise IntegrationError("Pandora transport supplied an invalid research report")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (imported.bundle_path, imported.report_path)
    ):
        raise IntegrationError("Pandora transport supplied invalid artifact references")
    # Round-trip through the frozen contract so a future transport cannot bypass
    # ResearchBundle validation by returning a forged or partially constructed object.
    try:
        bundle = ResearchBundle.from_dict(imported.bundle.to_dict())
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise IntegrationError("Pandora transport supplied an invalid research bundle") from exc
    if bundle.request_id != request.request_id:
        raise IntegrationError("Pandora bundle request_id does not match requested research")
    if not imported.report.strip():
        raise IntegrationError("Pandora research report must not be empty")
    for name, digest in (
        ("bundle_sha256", imported.bundle_sha256),
        ("report_sha256", imported.report_sha256),
    ):
        valid = isinstance(digest, str) and len(digest) == 64 and all(
            character in "0123456789abcdef" for character in digest
        )
        if not valid:
            raise IntegrationError(f"Pandora transport supplied an invalid {name}")
    return ImportedResearch(
        bundle,
        imported.report,
        imported.bundle_path,
        imported.report_path,
        imported.bundle_sha256,
        imported.report_sha256,
    )


def _ensure_safe_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise IntegrationError("Pandora exchange directories may not be symlinks")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise IntegrationError("Pandora exchange path is not a safe directory")


def _require_safe_existing_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise IntegrationError("Pandora exchange directory is missing or unsafe")


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise IntegrationError("Pandora request destination is not a regular file")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise IntegrationError(f"Pandora artifact is missing or unsafe: {path.name}")
    size = path.stat().st_size
    if size > maximum:
        raise IntegrationError(f"Pandora artifact exceeds size limit: {path.name}")
    return path.read_bytes()


__all__ = [
    "FilesystemResearchTransport",
    "ImportedResearch",
    "PandoraProviderManifest",
    "PandoraReadiness",
    "PandoraResearchAdapter",
    "PandoraResearchService",
    "ResearchPolicyDecision",
    "ResearchRoute",
    "ResearchTransport",
    "select_research_route",
]

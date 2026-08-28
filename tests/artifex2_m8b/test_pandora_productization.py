from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifex.application import Application, OperationContext, OperationRequest
from artifex.integrations.contracts import IntegrationError
from artifex.integrations.pandora import (
    PandoraProviderManifest,
    PandoraResearchService,
)
from artifex.integrations.research import (
    ResearchBundle,
    ResearchClaim,
    ResearchRequest,
    ResearchSource,
)
from artifex.project import ProjectAuthority, ProjectRepository


def _request(identifier: str = "RSR-J13-001") -> ResearchRequest:
    return ResearchRequest(
        identifier,
        "evaluate a durable research integration",
        "RESEARCH",
        ("Which option preserves Project Authority?",),
        ("Pandora supplies evidence only",),
        "2026-08-28",
        "primary sources",
        {"network": "pandora-owned", "max_sources": 5},
    )


def _manifest(root: Path) -> PandoraProviderManifest:
    root.mkdir(parents=True)
    manifest = PandoraProviderManifest(
        "pandora-fixture",
        "0.1.0.dev0",
        "filesystem-contract-v1",
        "2026-08-28T08:00:00+00:00",
    )
    (root / "pandora-provider.json").write_text(
        json.dumps(manifest.to_dict(), sort_keys=True), encoding="utf-8"
    )
    return manifest


def _bundle(request_id: str, manifest: PandoraProviderManifest) -> ResearchBundle:
    source = ResearchSource(
        "SRC-PRIMARY",
        "https://example.invalid/primary",
        "Primary specification",
        "2026-08-28T08:01:00+00:00",
        "primary",
    )
    return ResearchBundle(
        "RSB-J13-001",
        request_id,
        ("Use explicit proposal and Project Authority acceptance.",),
        ({"name": "explicit-adoption", "risk": "operator action required"},),
        (ResearchClaim("Project Authority remains singular", (source.source_id,), 0.97),),
        (),
        (source,),
        {
            "provider_id": "pandora",
            "provider_instance_id": manifest.instance_id,
            "provider_version": manifest.version,
            "provider_role": "RESEARCH",
        },
    )


def _provider_output(
    root: Path, request: ResearchRequest, manifest: PandoraProviderManifest
) -> None:
    directory = root / request.request_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "research-bundle.json").write_text(
        json.dumps(_bundle(request.request_id, manifest).to_dict(), sort_keys=True),
        encoding="utf-8",
    )
    (directory / "research-report.md").write_text(
        "# Pandora research\n\nEvidence only; Project Authority decides.\n",
        encoding="utf-8",
    )


def _project(root: Path) -> ProjectAuthority:
    repository = ProjectRepository.initialize(root, project_id="project-j13", name="J13")
    return ProjectAuthority.bootstrap(
        repository, actor="bootstrap", accepted_at="2026-08-28T08:00:00+00:00"
    )


@pytest.mark.integration
def test_public_request_and_import_are_evidence_only_and_project_unchanged(
    tmp_path: Path,
) -> None:
    exchange = tmp_path / "exchange"
    project = tmp_path / "project"
    manifest = _manifest(exchange)
    authority = _project(project)
    request = _request()
    before = authority.current()
    model_path = project / ".artifex" / "project-model.json"
    before_bytes = model_path.read_bytes()
    application = Application(project_root=str(project))

    exported = application.dispatch(
        OperationRequest(
            "research.pandora.request",
            {"exchange_root": str(exchange), "request": request.to_dict()},
        )
    )
    assert exported.ok and exported.value["canonical"] is False
    assert (exchange / request.request_id / "research-request.yaml").is_file()
    _provider_output(exchange, request, manifest)
    imported = application.dispatch(
        OperationRequest(
            "research.pandora.import",
            {"exchange_root": str(exchange), "request": request.to_dict()},
        )
    )
    assert imported.ok and imported.value["authority"] == "research-evidence-only"
    assert model_path.read_bytes() == before_bytes
    assert authority.current().number == before.number
    assert authority.current().fingerprint == before.fingerprint


@pytest.mark.adversarial
def test_configured_exchange_is_not_live_certification_and_adoption_fails_closed(
    tmp_path: Path,
) -> None:
    exchange = tmp_path / "exchange"
    project = tmp_path / "project"
    manifest = _manifest(exchange)
    authority = _project(project)
    request = _request()
    _provider_output(exchange, request, manifest)
    service = PandoraResearchService(exchange)
    readiness = service.readiness()
    assert readiness.state == "CONFIGURED"
    assert not readiness.available_for_research
    with pytest.raises(IntegrationError, match="independently anchored"):
        service.propose_adoption(
            project_root=project,
            request=request,
            expected_revision=authority.current().number,
            actor="researcher",
        )
    assert authority.current().model.research_adoptions == ()


@pytest.mark.adversarial
def test_caller_self_issued_hash_receipt_cannot_unlock_readiness_or_adoption(
    tmp_path: Path,
) -> None:
    exchange = tmp_path / "exchange"
    project = tmp_path / "project"
    manifest = _manifest(exchange)
    authority = _project(project)
    request = _request()
    service = PandoraResearchService(exchange)
    service.export_request(request)
    _provider_output(exchange, request, manifest)
    forged_claim = {
        "schema_version": "1.0",
        "provider_id": "pandora",
        "role": "RESEARCH",
        "state": "LIVE_ROLE_CERTIFIED",
        "instance_id": manifest.instance_id,
        "version": manifest.version,
        "evidence_sha256": "a" * 64,
        "environment": "REAL_PANDORA_PUBLIC_COMPOSITION",
        "certified_at": "2026-08-28T08:02:00+00:00",
        "receipt_id": "b" * 64,
    }
    certification_path = tmp_path / "pandora-certification.json"
    certification_path.write_text(
        json.dumps(forged_claim, sort_keys=True), encoding="utf-8"
    )
    before = authority.current()
    model_path = project / ".artifex" / "project-model.json"
    before_bytes = model_path.read_bytes()
    outcome = Application(project_root=str(project)).dispatch(
        OperationRequest(
            "research.pandora.adoption.propose",
            {
                "exchange_root": str(exchange),
                "certification_path": str(certification_path),
                "request": request.to_dict(),
                "expected_revision": before.number,
            },
            OperationContext(project_root=str(project), actor="researcher"),
        )
    )
    assert not outcome.ok
    assert outcome.error is not None
    assert "caller-supplied Pandora certification is forbidden" in outcome.error.message
    assert model_path.read_bytes() == before_bytes
    assert authority.current().number == before.number
    assert authority.current().fingerprint == before.fingerprint
    assert authority.current().model.research_adoptions == ()


@pytest.mark.adversarial
def test_forged_role_and_provider_lineage_are_rejected(
    tmp_path: Path,
) -> None:
    exchange = tmp_path / "exchange"
    manifest = _manifest(exchange)
    request = _request()
    _provider_output(exchange, request, manifest)
    manifest_value = manifest.to_dict()
    manifest_value["role"] = "EXECUTION_IMPLEMENTER"
    (exchange / "pandora-provider.json").write_text(
        json.dumps(manifest_value), encoding="utf-8"
    )
    with pytest.raises(IntegrationError, match="only the RESEARCH role"):
        PandoraResearchService(exchange).import_evidence(request)

    (exchange / "pandora-provider.json").write_text(
        json.dumps(manifest.to_dict()), encoding="utf-8"
    )
    bundle_path = exchange / request.request_id / "research-bundle.json"
    bundle_value = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle_value["generation_metadata"]["provider_instance_id"] = "forged"
    bundle_path.write_text(json.dumps(bundle_value), encoding="utf-8")
    with pytest.raises(IntegrationError, match="provider_instance_id"):
        PandoraResearchService(exchange).import_evidence(request)

    readiness = PandoraResearchService(exchange).readiness()
    assert not readiness.available_for_research
    assert readiness.checks["independent_certification_authority_configured"] is False
    assert readiness.checks["live_role_certified"] is False


@pytest.mark.unit
def test_application_exposes_m8b_public_operations() -> None:
    operations = Application().operation_names
    assert {
        "research.pandora.readiness",
        "research.pandora.request",
        "research.pandora.import",
        "research.pandora.adoption.propose",
    } <= set(operations)
    result = Application().dispatch(
        OperationRequest(
            "research.pandora.adoption.propose",
            {
                "exchange_root": "missing",
                "request": _request().to_dict(),
                "expected_revision": 1,
            },
            OperationContext(project_root="missing", actor="provider"),
        )
    )
    assert not result.ok
    assert result.error is not None
    assert "independently anchored" in result.error.message

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from artifex.integrations.conformance import ConformanceSuite
from artifex.integrations.contracts import (
    Capability,
    ExecutionPacket,
    HealthStatus,
    IntegrationError,
    IntegrationRole,
)
from artifex.integrations.deepseek import (
    DeepSeekCompatibility,
    DeepSeekDetection,
    DeepSeekHarnessAdapter,
    detect_deepseek,
    normalize_deepseek_result,
)
from artifex.integrations.pandora import (
    FilesystemResearchTransport,
    ImportedResearch,
    PandoraResearchAdapter,
    ResearchRoute,
    select_research_route,
)
from artifex.integrations.research import (
    ResearchBundle,
    ResearchClaim,
    ResearchRequest,
    ResearchSource,
)
from artifex.project.model import WorkflowDepth
from artifex.workflow import ExecutionBaseline, ExecutionStatus


def _stable_detection(*, interface: bool = False) -> DeepSeekDetection:
    capabilities = {
        Capability.HEADLESS.value,
        Capability.STRUCTURED_OUTPUT.value,
        Capability.REPOSITORY_READ.value,
    }
    if interface:
        capabilities.add(Capability.INTERACTIVE.value)
    return DeepSeekDetection(
        True,
        "deepseek-fixture",
        "1.2.3",
        frozenset(capabilities),
        DeepSeekCompatibility.STABLE,
        "deterministic fixture",
    )


def _packet(adapter: DeepSeekHarnessAdapter) -> ExecutionPacket:
    return adapter.prepare_execution(
        task_contract={"id": "M10-T02", "stage": "implementation"},
        context={"relevant": ["INV-002"]},
        base_commit="a" * 40,
        project_model_fingerprint="b" * 64,
        acceptance_criteria=("normalized result",),
        ownership={"paths": ["owned.txt"]},
        expected_result={"status": [status.value for status in ExecutionStatus]},
        interfaces=("Integration Contract v1",),
        invariants=("INV-002",),
    )


def _request(request_id: str = "RSR-M10-001") -> ResearchRequest:
    return ResearchRequest(
        request_id=request_id,
        purpose="choose an evidence-backed architecture",
        stage="research",
        questions=("Which alternative best preserves the authority boundary?",),
        project_constraints=("Pandora is evidence-only",),
        required_freshness="current major versions",
        required_source_quality="primary sources",
        resource_envelope={"max_sources": 8, "network": "Pandora-owned"},
        desired_alternatives=2,
    )


def _bundle(request_id: str = "RSR-M10-001") -> ResearchBundle:
    source = ResearchSource(
        "SRC-1",
        "https://example.invalid/spec",
        "Primary specification",
        "2026-08-21T12:00:00+00:00",
        "primary",
    )
    return ResearchBundle(
        "RSB-M10-001",
        request_id,
        ("The filesystem contract is inspectable.",),
        ({"name": "CLI", "risk": "product coupling"},),
        (ResearchClaim("The contract is inspectable", ("SRC-1",), 0.96),),
        ("Future transport authentication remains open.",),
        (source,),
        {"provider": "pandora", "transport": "filesystem-v1"},
    )


@pytest.mark.unit
def test_deepseek_detection_is_read_only_capability_based_and_fail_graceful(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import artifex.integrations.deepseek as module

    monkeypatch.setattr(module.shutil, "which", lambda _name: "/fixture/deepseek")
    observed: list[tuple[str, ...]] = []

    def probe(command: tuple[str, ...], _timeout: float) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "DeepSeek 1.4.0", "")
        return subprocess.CompletedProcess(
            command,
            0,
            "run --interactive --headless --format json --input; edit test",
            "",
        )

    monkeypatch.setattr(module, "_probe", probe)
    detection = detect_deepseek(timeout=0.1)
    assert detection.installed and detection.stable_headless and detection.stable_interface
    assert detection.compatibility is DeepSeekCompatibility.STABLE
    assert Capability.REPOSITORY_WRITE.value in detection.capabilities
    assert Capability.TEST_EXECUTION.value in detection.capabilities
    assert detection.to_dict()["version"] == "1.4.0"
    assert observed == [
        ("/fixture/deepseek", "--version"),
        ("/fixture/deepseek", "run", "--help"),
    ]

    monkeypatch.setattr(module.shutil, "which", lambda _name: None)
    assert not detect_deepseek().installed
    monkeypatch.setattr(module.shutil, "which", lambda _name: "/fixture/deepseek")
    monkeypatch.setattr(module, "_probe", lambda _command, _timeout: "timeout")
    assert not detect_deepseek().installed


@pytest.mark.adversarial
def test_deepseek_unknown_preview_and_incompatible_boundaries_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import artifex.integrations.deepseek as module

    monkeypatch.setattr(module.shutil, "which", lambda _name: "/fixture/deepseek")

    def detection_for(version: str, help_text: str = "--headless --json") -> DeepSeekDetection:
        calls = iter(
            (
                subprocess.CompletedProcess((), 0, version, ""),
                subprocess.CompletedProcess((), 0, help_text, ""),
            )
        )
        monkeypatch.setattr(module, "_probe", lambda _command, _timeout: next(calls))
        return detect_deepseek()

    assert detection_for("DeepSeek 1.1.0-beta.2").compatibility is DeepSeekCompatibility.PREVIEW
    assert detection_for("DeepSeek 2.0.0").compatibility is DeepSeekCompatibility.INCOMPATIBLE
    unknown = detection_for("unknown", "headless mode unavailable")
    assert unknown.compatibility is DeepSeekCompatibility.UNKNOWN
    adapter = DeepSeekHarnessAdapter(unknown)
    assert adapter.health().status is HealthStatus.FAIL
    with pytest.raises(IntegrationError, match="stable headless"):
        _packet(adapter)

    unavailable = DeepSeekHarnessAdapter(DeepSeekDetection(False))
    assert unavailable.health().status is HealthStatus.DEGRADED
    with pytest.raises(IntegrationError, match="fails closed"):
        unavailable.plan_execution(
            ExecutionPacket(
                {"id": "x"},
                {},
                "a" * 40,
                "b" * 64,
                ("criterion",),
                {},
                {"status": "SUCCESS"},
            ),
            worktree_root=tmp_path,
        )


@pytest.mark.conformance
def test_deepseek_stable_adapter_conforms_and_interface_role_is_conditional() -> None:
    harness = DeepSeekHarnessAdapter(_stable_detection())
    report = ConformanceSuite().run(harness)
    assert report.status is HealthStatus.PASS
    assert IntegrationRole.INTERFACE not in harness.metadata.roles
    interface = DeepSeekHarnessAdapter(_stable_detection(interface=True))
    assert IntegrationRole.INTERFACE in interface.metadata.roles
    assert interface.health().status is HealthStatus.PASS


@pytest.mark.integration
def test_deepseek_headless_plan_and_result_normalization(tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def runner(command: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.update({"command": command, **kwargs})
        packet_value = json.loads(kwargs["input"])
        output = {
            "status": "completed",
            "base_commit": packet_value["base_commit"],
            "execution_contract_fingerprint": packet_value[
                "execution_contract_fingerprint"
            ],
            "project_model_fingerprint": packet_value["project_model_fingerprint"],
            "artifacts": [{"path": "owned.txt"}],
            "validation": {"tests": "PASS"},
            "message": "done",
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    adapter = DeepSeekHarnessAdapter(_stable_detection(), runner=runner)
    packet = _packet(adapter)
    plan = adapter.plan_execution(packet, worktree_root=tmp_path)
    assert plan.to_dict()["mutating"] is False
    result = adapter.execute(plan, timeout=1)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.artifacts == ({"path": "owned.txt"},)
    assert captured["cwd"] == str(tmp_path)
    assert captured["shell"] is False
    assert adapter.submit_validation({"tests": "PASS"})["canonical"] is False
    assert adapter.cancel(packet).status is ExecutionStatus.CANCELLED
    stale = ExecutionBaseline("c" * 40, packet.contract_fingerprint, "b" * 64)
    assert (
        adapter.submit_result(packet, result, current_baseline=stale).status
        is ExecutionStatus.REBASE_REQUIRED
    )


@pytest.mark.adversarial
@pytest.mark.parametrize(
    ("runner", "message"),
    [
        (
            lambda command, **_kwargs: subprocess.CompletedProcess(command, 7, "", "boom"),
            "boom",
        ),
        (
            lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "not-json", ""),
            "invalid JSON",
        ),
        (
            lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "[]", ""),
            "JSON object",
        ),
        (
            lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, '{"status":"mystery"}', ""
            ),
            "result rejected",
        ),
    ],
)
def test_deepseek_failure_mapping(
    tmp_path: Path, runner: Any, message: str
) -> None:
    adapter = DeepSeekHarnessAdapter(_stable_detection(), runner=runner)
    result = adapter.execute(adapter.plan_execution(_packet(adapter), worktree_root=tmp_path))
    assert result.status is ExecutionStatus.FAIL
    assert message in result.message


@pytest.mark.adversarial
def test_deepseek_timeout_launch_failure_and_baseline_tamper(tmp_path: Path) -> None:
    def timeout_runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("fixture", 1)

    adapter = DeepSeekHarnessAdapter(_stable_detection(), runner=timeout_runner)
    packet = _packet(adapter)
    result = adapter.execute(adapter.plan_execution(packet, worktree_root=tmp_path))
    assert result.status is ExecutionStatus.CANCELLED

    def os_error(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("unavailable")

    adapter = DeepSeekHarnessAdapter(_stable_detection(), runner=os_error)
    result = adapter.execute(adapter.plan_execution(_packet(adapter), worktree_root=tmp_path))
    assert result.status is ExecutionStatus.FAIL
    with pytest.raises(IntegrationError, match="base_commit"):
        normalize_deepseek_result({"status": "success", "base_commit": "c" * 40}, packet)
    with pytest.raises(IntegrationError, match="artifacts"):
        normalize_deepseek_result({"status": "success", "artifacts": "bad"}, packet)
    with pytest.raises(IntegrationError, match="artifact entries"):
        normalize_deepseek_result({"status": "success", "artifacts": ["bad"]}, packet)
    with pytest.raises(IntegrationError, match="validation"):
        normalize_deepseek_result({"status": "success", "validation": []}, packet)
    with pytest.raises(IntegrationError, match="existing directory"):
        adapter.plan_execution(_packet(adapter), worktree_root=tmp_path / "missing")


@pytest.mark.integration
def test_pandora_filesystem_request_export_bundle_import_and_atomicity(tmp_path: Path) -> None:
    transport = FilesystemResearchTransport(tmp_path / "exchange")
    adapter = PandoraResearchAdapter(transport)
    request = _request()
    request_path = adapter.export_request(request)
    assert request_path.name == "research-request.yaml"
    assert yaml.safe_load(request_path.read_text(encoding="utf-8")) == request.to_dict()
    assert not list(request_path.parent.glob("*.tmp"))

    bundle_path = request_path.parent / "research-bundle.json"
    report_path = request_path.parent / "research-report.md"
    bundle_path.write_text(json.dumps(_bundle().to_dict()), encoding="utf-8")
    report_path.write_text(
        "# Research report\n\nEvidence remains non-canonical.\n", encoding="utf-8"
    )
    imported = adapter.import_bundle(request)
    assert imported.bundle.request_id == request.request_id
    assert imported.canonical is False and imported.authority == "research-evidence-only"
    assert len(imported.bundle_sha256) == len(imported.report_sha256) == 64
    assert imported.to_dict()["report"].startswith("# Research")
    assert adapter.metadata.roles == frozenset({IntegrationRole.RESEARCH_PROVIDER})
    assert adapter.health().status is HealthStatus.PASS


@pytest.mark.adversarial
def test_pandora_import_validation_and_path_safety(tmp_path: Path) -> None:
    transport = FilesystemResearchTransport(tmp_path / "exchange")
    request = _request()
    request_path = transport.export_request(request)
    bundle_path = request_path.parent / "research-bundle.json"
    report_path = request_path.parent / "research-report.md"
    with pytest.raises(IntegrationError, match="missing or unsafe"):
        transport.import_bundle(request)
    bundle_path.write_text("not-json", encoding="utf-8")
    report_path.write_text("report", encoding="utf-8")
    with pytest.raises(IntegrationError, match="UTF-8 JSON"):
        transport.import_bundle(request)
    bundle_path.write_text("[]", encoding="utf-8")
    with pytest.raises(IntegrationError, match="JSON object"):
        transport.import_bundle(request)
    bundle_path.write_text(json.dumps(_bundle("different").to_dict()), encoding="utf-8")
    with pytest.raises(IntegrationError, match="request_id"):
        transport.import_bundle(request)
    bundle_path.write_text(json.dumps(_bundle().to_dict()), encoding="utf-8")
    report_path.write_text("", encoding="utf-8")
    with pytest.raises(IntegrationError, match="must not be empty"):
        transport.import_bundle(request)
    with pytest.raises(IntegrationError, match="portable path"):
        transport.request_directory("../escape")

    unsafe_root = tmp_path / "unsafe"
    unsafe_root.write_text("not a directory", encoding="utf-8")
    unsafe = PandoraResearchAdapter(FilesystemResearchTransport(unsafe_root))
    assert unsafe.health().status is HealthStatus.FAIL


@pytest.mark.architecture
def test_pandora_deep_policy_authority_and_future_transport_seam() -> None:
    class MemoryTransport:
        def __init__(self) -> None:
            self.request: ResearchRequest | None = None

        def export_request(self, request: ResearchRequest) -> Path:
            self.request = request
            return Path("future://request")

        def import_bundle(self, request: ResearchRequest) -> ImportedResearch:
            assert self.request == request
            return ImportedResearch(_bundle(), "report", "bundle", "report", "a" * 64, "b" * 64)

    transport = MemoryTransport()
    adapter = PandoraResearchAdapter(transport)
    request = _request()
    assert adapter.export_request(request) == Path("future:/request")
    assert adapter.import_bundle(request).canonical is False
    assert adapter.health().status is HealthStatus.PASS
    assert adapter.route(WorkflowDepth.DEEP).route is ResearchRoute.PANDORA_PREFERRED
    assert select_research_route(
        WorkflowDepth.STANDARD,
        pandora_available=True,
        evidence_needs_escalation=True,
    ).route is ResearchRoute.PANDORA_ESCALATION
    assert select_research_route(
        WorkflowDepth.QUICK, pandora_available=True
    ).route is ResearchRoute.NATIVE
    assert select_research_route(
        WorkflowDepth.DEEP, pandora_available=False
    ).route is ResearchRoute.NATIVE

    canonical_model = {"milestone": "ACTIVE", "revision": 7}
    before = dict(canonical_model)
    with pytest.raises(IntegrationError, match="cannot transition"):
        adapter.transition_project_model(canonical_model, {"milestone": "ACCEPTED"})
    assert canonical_model == before


@pytest.mark.architecture
def test_deepseek_pack_is_explicitly_optional_and_fail_closed() -> None:
    root = Path(__file__).parents[1] / "interface_packs" / "deepseek"
    manifest = yaml.safe_load((root / "manifest.yaml").read_text(encoding="utf-8"))
    assert manifest["core_ga_blocking"] is False
    assert manifest["enable_when"]["compatibility"] == "STABLE"
    assert manifest["authority"]["project_model_transition"] == "forbidden"
    assert set(manifest["roles"]) == {"harness", "implementer"}

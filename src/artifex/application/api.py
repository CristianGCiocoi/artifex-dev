"""Transport-independent operation registry and dispatch."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from time import time
from typing import Any

from artifex import __version__
from artifex.capabilities import (
    CLAUDE_DISPATCH_AUTHORIZED_ROLES,
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    ActorContext,
    CapabilityGraph,
    CapabilityRequest,
    CapabilityResolver,
    DataClassification,
    ProviderCompositionLoader,
    ProviderInteractionService,
    ProviderRole,
    claude_certification_projection,
    codex_certification_projection,
    record_execution_implementer_evidence,
)
from artifex.distribution import (
    ExperienceMode,
    apply_integration_setup,
    discover_environment,
    install,
    install_plan,
    plan_integration_setup,
    presentation_policy,
    run_distribution_doctor,
    start_beginner_journey,
    uninstall,
    uninstall_plan,
    upgrade,
    upgrade_plan,
)
from artifex.distribution.artifact import runtime_release_identity
from artifex.integrations import (
    ExecutionPacket,
    ExecutionResult,
    IntegrationConformanceSuite,
    IntegrationRegistry,
    IntegrationRole,
    ManualIntegration,
    ResearchBundle,
    ResearchRequest,
    SelectionPolicy,
    SelectionRequest,
    run_doctor,
    select_integration,
)
from artifex.integrations.claude import (
    ClaudeDetection,
    ClaudeIntegration,
    ClaudeProcessRunner,
)
from artifex.integrations.codex import CodexIntegration, CodexProcessRunner
from artifex.project import (
    ProjectAuthority,
    ProjectControlService,
    ProjectModel,
    default_catalog_path,
)
from artifex.runtime import (
    ActorPrincipal,
    ActorType,
    DelegationGrant,
    EvidenceRecord,
    ExecutionEnvelope,
    ManagedRuntimeService,
    Materiality,
    ReconciliationOutcome,
    SupervisionLevel,
)
from artifex.runtime import (
    CredentialReference as RuntimeCredentialReference,
)
from artifex.workflow import ExecutionBaseline, ExecutionStatus

CodexRunnerFactory = Callable[[tuple[str, ...]], CodexProcessRunner]
ClaudeRunnerFactory = Callable[[tuple[str, ...]], ClaudeProcessRunner]


@dataclass(frozen=True, slots=True)
class OperationContext:
    project_root: str | None = None
    actor: str = "anonymous"
    correlation_id: str | None = None


@dataclass(frozen=True, slots=True)
class OperationRequest:
    operation: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    context: OperationContext = field(default_factory=OperationContext)


@dataclass(frozen=True, slots=True)
class OperationError:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OperationResult:
    ok: bool
    value: Mapping[str, Any] = field(default_factory=dict)
    error: OperationError | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"ok": self.ok, "value": dict(self.value)}
        if self.error is not None:
            value["error"] = {
                "code": self.error.code,
                "message": self.error.message,
                "details": dict(self.error.details),
            }
        return value


Operation = Callable[[OperationRequest], OperationResult]


class Application:
    """The single semantic API used by CLI, MCP, and interface packs."""

    def __init__(
        self,
        registry: IntegrationRegistry | None = None,
        *,
        project_root: str | None = None,
        provider_loader: ProviderCompositionLoader | None = None,
        provider_interaction: ProviderInteractionService | None = None,
        codex_runner_factory: CodexRunnerFactory | None = None,
        claude_runner_factory: ClaudeRunnerFactory | None = None,
    ) -> None:
        self._operations: dict[str, Operation] = {}
        self._project_root = project_root
        self._provider_loader = provider_loader or ProviderCompositionLoader(
            certified_roles={
                "codex": CODEX_DISPATCH_AUTHORIZED_ROLES,
                "claude": CLAUDE_DISPATCH_AUTHORIZED_ROLES,
            }
        )
        self._provider_interaction = provider_interaction or ProviderInteractionService()
        self._codex_runner_factory = codex_runner_factory or _codex_process_runner
        self._claude_runner_factory = claude_runner_factory or _claude_process_runner
        self.registry = (
            IntegrationRegistry((ManualIntegration(),)) if registry is None else registry
        )
        self.register("system.version", self._version)
        self.register("system.health", self._health)
        self.register("system.operations", self._operation_list)
        self.register("system.doctor", self._doctor)
        self.register("integrations.list", self._integrations_list)
        self.register("integrations.health", self._integration_health)
        self.register("integrations.select", self._integration_select)
        self.register("integrations.conformance", self._integration_conformance)
        self.register("providers.graph", self._providers_graph)
        self.register("providers.readiness", self._providers_readiness)
        self.register("providers.resolve", self._providers_resolve)
        self.register("providers.interact", self._providers_interact)
        self.register("providers.certifications", self._providers_certifications)
        self.register("project.status", self._project_status)
        self.register("project.create", self._project_create)
        self.register("project.adopt", self._project_adopt)
        self.register("project.continue", self._project_continue)
        self.register("project.propose", self._project_propose)
        self.register("project.accept", self._project_accept)
        self.register("project.observe", self._project_observe)
        self.register("reality.state", self._reality_state)
        self.register("documentation.status", self._documentation_status)
        self.register("documentation.regenerate", self._documentation_regenerate)
        self.register("dashboard.project", self._project_dashboard)
        self.register("dashboard.platform", self._platform_dashboard)
        self.register("runtime.bootstrap", self._runtime_bootstrap)
        self.register("runtime.status", self._runtime_status)
        self.register("runtime.attempt.finish", self._runtime_attempt_finish)
        self.register("runtime.attempt.cancel", self._runtime_attempt_cancel)
        self.register("runtime.attempt.unknown", self._runtime_attempt_unknown)
        self.register("runtime.attempt.reconcile", self._runtime_attempt_reconcile)
        self.register("runtime.attempt.retry", self._runtime_attempt_retry)
        self.register("runtime.accept", self._runtime_accept)
        self.register("runtime.workspace.create", self._runtime_workspace_create)
        self.register("runtime.workspace.promote", self._runtime_workspace_promote)
        self.register("runtime.provider.execute", self._runtime_provider_execute)
        self.register("manual.packet.create", self._manual_packet_create)
        self.register("manual.result.submit", self._manual_result_submit)
        self.register("research.request.validate", self._research_request_validate)
        self.register("research.bundle.validate", self._research_bundle_validate)
        self.register("distribution.discover", self._distribution_discover)
        self.register("distribution.presentation", self._distribution_presentation)
        self.register("distribution.setup.plan", self._distribution_setup_plan)
        self.register("distribution.setup.apply", self._distribution_setup_apply)
        self.register("distribution.doctor", self._distribution_doctor)
        self.register("distribution.install.plan", self._distribution_install_plan)
        self.register("distribution.install", self._distribution_install)
        self.register("distribution.upgrade", self._distribution_upgrade)
        self.register("distribution.upgrade.plan", self._distribution_upgrade_plan)
        self.register("distribution.uninstall.plan", self._distribution_uninstall_plan)
        self.register("distribution.uninstall", self._distribution_uninstall)
        self.register("beginner.start", self._beginner_start)

    def register(self, name: str, operation: Operation) -> None:
        if not name or name in self._operations:
            raise ValueError(f"operation is empty or already registered: {name!r}")
        self._operations[name] = operation

    def dispatch(self, request: OperationRequest) -> OperationResult:
        operation = self._operations.get(request.operation)
        if operation is None:
            return OperationResult(
                ok=False,
                error=OperationError(
                    "OPERATION_NOT_FOUND", f"unknown operation {request.operation!r}"
                ),
            )
        try:
            return operation(request)
        except Exception as exc:  # semantic boundary: normalize transport errors
            return OperationResult(
                ok=False,
                error=OperationError("OPERATION_FAILED", str(exc), {"type": type(exc).__name__}),
            )

    @property
    def operation_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._operations))

    @staticmethod
    def _version(_: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value=runtime_release_identity())

    @staticmethod
    def _health(_: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value={"status": "PASS", "core": "available"})

    def _operation_list(self, _: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value={"operations": list(self.operation_names)})

    def _doctor(self, request: OperationRequest) -> OperationResult:
        root = request.arguments.get("project_root", request.context.project_root)
        if root is not None and not isinstance(root, str):
            raise TypeError("project_root must be a string")
        return OperationResult(
            ok=True,
            value=run_doctor(self.registry, project_root=root).to_dict(),
        )

    def _integrations_list(self, _: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value={"integrations": self.registry.report()})

    def _integration_health(self, request: OperationRequest) -> OperationResult:
        identifier = _required_string(request.arguments, "integration_id")
        integration = self.registry.get(identifier)
        return OperationResult(
            ok=True,
            value={
                "integration_id": identifier,
                "health": integration.health().to_dict(),
                "compatibility": integration.metadata.to_dict(core_version=__version__)[
                    "core_compatible"
                ],
            },
        )

    def _integration_select(self, request: OperationRequest) -> OperationResult:
        role = IntegrationRole(_required_string(request.arguments, "role"))
        capabilities = frozenset(_string_sequence(request.arguments, "capabilities"))
        requested = request.arguments.get("integration_id")
        if requested is not None and not isinstance(requested, str):
            raise TypeError("integration_id must be a string")
        preferred = tuple(_string_sequence(request.arguments, "preferred_integrations"))
        allowed = frozenset(_string_sequence(request.arguments, "allowed_integrations"))
        policy = SelectionPolicy(
            allowed_integrations=allowed,
            preferred_integrations=preferred or ("manual",),
            allow_fallback=_optional_bool(request.arguments, "allow_fallback", True),
        )
        decision = select_integration(
            self.registry,
            SelectionRequest(role, capabilities, requested),
            policy,
        )
        return OperationResult(ok=True, value=decision.to_dict())

    def _integration_conformance(self, request: OperationRequest) -> OperationResult:
        identifier = str(request.arguments.get("integration_id", "manual"))
        integration = self.registry.get(identifier)
        # Runtime protocol behavior is intentionally exercised by the suite.
        report = IntegrationConformanceSuite().run(
            integration  # type: ignore[arg-type]
        )
        return OperationResult(ok=report.status.value == "PASS", value=report.to_dict())

    def _providers_graph(self, request: OperationRequest) -> OperationResult:
        graph = self._load_provider_graph(request)
        return OperationResult(ok=True, value={"graph": graph.to_dict()})

    def _providers_readiness(self, request: OperationRequest) -> OperationResult:
        provider_id = _required_string(request.arguments, "provider_id")
        provider = self._load_provider_graph(request).provider(provider_id)
        if provider is None:
            raise ValueError(f"provider is not registered: {provider_id}")
        return OperationResult(ok=True, value={"readiness": provider.readiness.to_dict()})

    def _providers_resolve(self, request: OperationRequest) -> OperationResult:
        role = ProviderRole(_required_string(request.arguments, "role"))
        request_value = self._provider_capability_request(request, role)
        decision = CapabilityResolver().resolve(self._load_provider_graph(request), request_value)
        return OperationResult(ok=True, value={"decision": decision.to_dict()})

    def _providers_interact(self, request: OperationRequest) -> OperationResult:
        request_value = self._provider_interaction_request(request)
        graph = self._load_provider_graph(request)
        decision = CapabilityResolver().resolve(graph, request_value)
        if not decision.eligible or decision.provider_id is None:
            raise ValueError(
                "provider is not contextually eligible for INTERACTION: "
                + ", ".join(decision.reasons)
            )
        provider = graph.provider(decision.provider_id)
        if provider is None:
            raise ValueError("resolved provider disappeared from the Capability Graph")
        root = request.arguments.get("project_root", request.context.project_root)
        if root is None:
            root = self._project_root
        if not isinstance(root, str) or not root:
            raise ValueError("project_root is required for provider interaction")
        value = self._provider_interaction.interact(
            provider=provider,
            project_root=root,
            project_id=request_value.project_id,
            project_job_id=request_value.project_job_id,
            prompt=_required_string(request.arguments, "prompt"),
        )
        return OperationResult(ok=True, value={"interaction": value})

    def _providers_certifications(self, request: OperationRequest) -> OperationResult:
        project_id = _optional_string(request.arguments, "project_id")
        provider_id = _optional_string(request.arguments, "provider_id") or "codex"
        if provider_id == "codex":
            authorized_roles = CODEX_DISPATCH_AUTHORIZED_ROLES
            projection_factory = codex_certification_projection
        elif provider_id == "claude":
            authorized_roles = CLAUDE_DISPATCH_AUTHORIZED_ROLES
            projection_factory = claude_certification_projection
        else:
            raise ValueError(f"provider certification is unsupported: {provider_id}")
        receipts = self._provider_interaction.store.valid_receipts(
            provider_id=provider_id, project_id=project_id
        )
        evidence: dict[ProviderRole, tuple[str, ...]] = {}
        for role in authorized_roles:
            role_receipts = tuple(
                f"capability-receipt:{item.receipt_id}" for item in receipts if item.role is role
            )
            if role_receipts:
                evidence[role] = role_receipts
        projection = projection_factory(evidence)
        return OperationResult(
            ok=True,
            value={
                "certifications": projection,
                "authority": "LOCAL_CAPABILITY_EVIDENCE_STORE",
                "project_id": project_id,
            },
        )

    @staticmethod
    def _provider_capability_request(
        request: OperationRequest, role: ProviderRole
    ) -> CapabilityRequest:
        envelope = _required_mapping(request.arguments, "envelope")
        actor_value = _required_mapping(request.arguments, "actor")
        project_policy = _optional_mapping(request.arguments, "project_policy")
        return CapabilityRequest(
            project_id=_required_string(request.arguments, "project_id"),
            project_job_id=_required_string(request.arguments, "project_job_id"),
            role=role,
            capabilities=frozenset(_string_sequence(request.arguments, "capabilities")),
            allowed_providers=frozenset(_string_sequence(envelope, "allowed_providers")),
            envelope_capabilities=frozenset(_string_sequence(envelope, "allowed_capabilities")),
            actor=ActorContext(
                actor_id=_required_string(actor_value, "actor_id"),
                actor_type=_required_string(actor_value, "actor_type"),
                delegated_roles=frozenset(
                    ProviderRole(item) for item in _string_sequence(actor_value, "delegated_roles")
                ),
            ),
            data_classification=DataClassification(
                _required_string(request.arguments, "data_classification")
            ),
            preferred_provider=_optional_string(request.arguments, "provider_id"),
            project_allowed_providers=frozenset(
                _string_sequence(project_policy, "allowed_providers")
            ),
            project_allowed_roles=frozenset(
                ProviderRole(item) for item in _string_sequence(project_policy, "allowed_roles")
            ),
        )

    @staticmethod
    def _provider_interaction_request(request: OperationRequest) -> CapabilityRequest:
        project_id = _required_string(request.arguments, "project_id")
        provider_id = _optional_string(request.arguments, "provider_id")
        capabilities = frozenset(_string_sequence(request.arguments, "capabilities"))
        if not capabilities:
            capabilities = frozenset({"repository_read"})
        envelope = _optional_mapping(request.arguments, "envelope")
        allowed_providers = frozenset(_string_sequence(envelope, "allowed_providers"))
        if not allowed_providers and provider_id is not None:
            allowed_providers = frozenset({provider_id})
        allowed_capabilities = frozenset(_string_sequence(envelope, "allowed_capabilities"))
        if not allowed_capabilities:
            allowed_capabilities = capabilities
        actor_value = _optional_mapping(request.arguments, "actor")
        actor_id = _optional_string(actor_value, "actor_id") or request.context.actor
        actor_type = _optional_string(actor_value, "actor_type") or "CLIENT"
        delegated = frozenset(
            ProviderRole(item) for item in _string_sequence(actor_value, "delegated_roles")
        )
        if not delegated:
            delegated = frozenset({ProviderRole.INTERACTION})
        project_policy = _optional_mapping(request.arguments, "project_policy")
        return CapabilityRequest(
            project_id=project_id,
            project_job_id=(
                _optional_string(request.arguments, "project_job_id") or f"{project_id}:interaction"
            ),
            role=ProviderRole.INTERACTION,
            capabilities=capabilities,
            allowed_providers=allowed_providers,
            envelope_capabilities=allowed_capabilities,
            actor=ActorContext(actor_id, actor_type, delegated),
            data_classification=DataClassification(
                str(request.arguments.get("data_classification", "INTERNAL"))
            ),
            preferred_provider=provider_id,
            project_allowed_providers=frozenset(
                _string_sequence(project_policy, "allowed_providers")
            ),
            project_allowed_roles=frozenset(
                ProviderRole(item) for item in _string_sequence(project_policy, "allowed_roles")
            ),
        )

    def _load_provider_graph(self, request: OperationRequest) -> CapabilityGraph:
        root = request.arguments.get("project_root", request.context.project_root)
        if root is None:
            root = self._project_root
        if not isinstance(root, str) or not root:
            raise ValueError("project_root is required for provider composition")
        return self._provider_loader.load(root)

    def _project_status(self, request: OperationRequest) -> OperationResult:
        root = request.arguments.get("project_root", request.context.project_root)
        if not isinstance(root, str) or not root:
            raise ValueError("project_root is required")
        identifier = str(request.arguments.get("integration_id", "manual"))
        integration = self.registry.get(identifier)
        reader = getattr(integration, "read_project_status", None)
        if not callable(reader):
            raise ValueError(f"integration does not support project status read: {identifier}")
        return OperationResult(ok=True, value=dict(reader(root)))

    @staticmethod
    def _project_create(request: OperationRequest) -> OperationResult:
        result = _project_service(request).create(
            _project_root(request),
            name=_required_string(request.arguments, "name"),
            description=str(request.arguments.get("description", "")),
            project_id=_optional_string(request.arguments, "project_id"),
            actor=request.context.actor,
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _project_adopt(request: OperationRequest) -> OperationResult:
        result = _project_service(request).adopt(
            _project_root(request),
            name=_optional_string(request.arguments, "name"),
            description=str(request.arguments.get("description", "")),
            project_id=_optional_string(request.arguments, "project_id"),
            actor=request.context.actor,
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _project_continue(request: OperationRequest) -> OperationResult:
        result = _project_service(request).continue_by_name(
            _required_string(request.arguments, "name")
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _project_propose(request: OperationRequest) -> OperationResult:
        proposal = _project_service(request).propose(
            _required_string(request.arguments, "name"),
            _required_mapping(request.arguments, "model"),
            expected_revision=_required_int(request.arguments, "expected_revision"),
            actor=request.context.actor,
            source=str(request.arguments.get("source", "CLIENT")),
        )
        return OperationResult(ok=True, value={"proposal": proposal.to_dict()})

    @staticmethod
    def _project_accept(request: OperationRequest) -> OperationResult:
        result = _project_service(request).accept(
            _required_string(request.arguments, "name"),
            _required_string(request.arguments, "proposal_id"),
            expected_revision=_required_int(request.arguments, "expected_revision"),
            actor=request.context.actor,
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _project_observe(request: OperationRequest) -> OperationResult:
        result = _project_service(request).observe_external(
            _required_string(request.arguments, "name"), actor=request.context.actor
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _reality_state(request: OperationRequest) -> OperationResult:
        result = _project_service(request).reality_state(
            _required_string(request.arguments, "name")
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _documentation_status(request: OperationRequest) -> OperationResult:
        result = _project_service(request).documentation_status(
            _required_string(request.arguments, "name")
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _documentation_regenerate(request: OperationRequest) -> OperationResult:
        result = _project_service(request).regenerate_documentation(
            _required_string(request.arguments, "name"),
            _string_sequence(request.arguments, "documents"),
        )
        return OperationResult(ok=True, value=result)

    @staticmethod
    def _project_dashboard(request: OperationRequest) -> OperationResult:
        return OperationResult(
            ok=True,
            value=_project_service(request).project_dashboard(
                _required_string(request.arguments, "name")
            ),
        )

    @staticmethod
    def _platform_dashboard(request: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value=_project_service(request).platform_dashboard())

    @staticmethod
    def _runtime_bootstrap(request: OperationRequest) -> OperationResult:
        envelope_value = _required_mapping(request.arguments, "envelope")
        envelope = _execution_envelope(envelope_value)
        automated = bool(envelope.allowed_providers)
        actor = _required_actor(request.arguments, "actor") if automated else request.context.actor
        approval_actor = _required_actor(request.arguments, "approval_actor") if automated else None
        value = _runtime_service(request).bootstrap_run(
            envelope,
            workstream_id=_required_string(request.arguments, "workstream_id"),
            run_id=_required_string(request.arguments, "run_id"),
            project_job_id=_required_string(request.arguments, "project_job_id"),
            attempt_id=_required_string(request.arguments, "attempt_id"),
            purpose=_required_string(request.arguments, "purpose"),
            actor_id=actor,
            approval_actor=approval_actor,
            correlation_id=request.context.correlation_id,
        )
        return OperationResult(ok=True, value=value)

    @staticmethod
    def _runtime_status(request: OperationRequest) -> OperationResult:
        return OperationResult(
            ok=True,
            value=_runtime_service(request).status(_required_string(request.arguments, "run_id")),
        )

    @staticmethod
    def _runtime_attempt_finish(request: OperationRequest) -> OperationResult:
        _runtime_service(request).finish(
            _required_string(request.arguments, "attempt_id"),
            _required_string(request.arguments, "result_claim"),
            actor_id=request.context.actor,
        )
        return OperationResult(ok=True, value={"attempt_state": "FINISHED", "accepted": False})

    @staticmethod
    def _runtime_attempt_cancel(request: OperationRequest) -> OperationResult:
        _runtime_service(request).cancel(
            _required_string(request.arguments, "attempt_id"), actor_id=request.context.actor
        )
        return OperationResult(ok=True, value={"attempt_state": "CANCELLED", "accepted": False})

    @staticmethod
    def _runtime_attempt_unknown(request: OperationRequest) -> OperationResult:
        _runtime_service(request).mark_unknown(
            _required_string(request.arguments, "attempt_id"), actor_id=request.context.actor
        )
        return OperationResult(
            ok=True,
            value={"attempt_state": "UNKNOWN", "blind_retry": False, "accepted": False},
        )

    @staticmethod
    def _runtime_attempt_reconcile(request: OperationRequest) -> OperationResult:
        service = _runtime_service(request)
        attempt_id = _required_string(request.arguments, "attempt_id")
        if _optional_bool(request.arguments, "begin", True):
            service.begin_reconciliation(attempt_id, actor_id=request.context.actor)
        outcome = ReconciliationOutcome(_required_string(request.arguments, "outcome"))
        service.reconcile(
            attempt_id,
            outcome,
            actor_id=request.context.actor,
            recovered_claim=_optional_string(request.arguments, "recovered_claim"),
        )
        return OperationResult(ok=True, value={"outcome": outcome.value, "accepted": False})

    @staticmethod
    def _runtime_attempt_retry(request: OperationRequest) -> OperationResult:
        service = _runtime_service(request)
        service.coordinator.retry_attempt(
            _required_string(request.arguments, "previous_attempt_id"),
            _required_string(request.arguments, "new_attempt_id"),
            actor_id=request.context.actor,
        )
        return OperationResult(ok=True, value={"created": True, "provider_dispatch": False})

    @staticmethod
    def _runtime_accept(request: OperationRequest) -> OperationResult:
        service = _runtime_service(request)
        project_job_id = _required_string(request.arguments, "project_job_id")
        actor = _runtime_actor(
            service,
            request,
            entity="project_job",
            entity_id=project_job_id,
            action="acceptance",
        )
        decision = service.accept(
            project_job_id,
            evidence_valid=_optional_bool(request.arguments, "evidence_valid", False),
            evidence_ids=_string_sequence(request.arguments, "evidence_ids"),
            actor_id=actor,
            reason=_required_string(request.arguments, "reason"),
            correlation_id=request.context.correlation_id,
        )
        return OperationResult(ok=True, value={"decision": decision.to_dict()})

    @staticmethod
    def _runtime_workspace_create(request: OperationRequest) -> OperationResult:
        service = _runtime_service(request)
        attempt_id = _required_string(request.arguments, "attempt_id")
        actor = _runtime_actor(
            service,
            request,
            entity="attempt",
            entity_id=attempt_id,
            action="workspace creation",
        )
        path = service.create_workspace(
            _required_string(request.arguments, "workspace_id"),
            attempt_id,
            _required_string(request.arguments, "project_root"),
            _required_int(request.arguments, "baseline_revision"),
            actor_id=actor,
        )
        return OperationResult(ok=True, value={"workspace_root": str(path), "isolated": True})

    @staticmethod
    def _runtime_workspace_promote(request: OperationRequest) -> OperationResult:
        service = _runtime_service(request)
        project_job_id = _required_string(request.arguments, "project_job_id")
        workspace_id = _required_string(request.arguments, "workspace_id")
        actor = _runtime_actor(
            service,
            request,
            entity="project_job",
            entity_id=project_job_id,
            action="workspace promotion",
        )
        revision = service.promote_accepted_workspace(
            workspace_id,
            ProjectModel.from_dict(_required_mapping(request.arguments, "model")),
            project_job_id,
            actor_id=actor,
        )
        receipt = _record_promoted_provider_certification(
            service,
            workspace_id=workspace_id,
            project_job_id=project_job_id,
            revision=revision,
        )
        value: dict[str, Any] = {"semantic_revision": revision}
        if receipt is not None:
            value["provider_certification_receipt"] = receipt
        return OperationResult(ok=True, value=value)

    def _runtime_provider_execute(self, request: OperationRequest) -> OperationResult:
        service = _runtime_service(request)
        attempt_id = _required_string(request.arguments, "attempt_id")
        project_job_id = _required_string(request.arguments, "project_job_id")
        run_id = _required_string(request.arguments, "run_id")
        workspace_id = _required_string(request.arguments, "workspace_id")
        provider_id = _required_string(request.arguments, "provider_id")
        role = ProviderRole(_required_string(request.arguments, "role"))
        if role is not ProviderRole.EXECUTION_IMPLEMENTER:
            raise ValueError("runtime.provider.execute requires EXECUTION_IMPLEMENTER role")

        _, _, _, workspace, envelope = _bound_runtime_execution(
            service,
            attempt_id=attempt_id,
            project_job_id=project_job_id,
            run_id=run_id,
            workspace_id=workspace_id,
        )
        dispatch_actor = _required_actor(request.arguments, "actor")
        provider_actor = _required_actor(request.arguments, "provider_actor")
        evidence_actor = _required_actor(request.arguments, "evidence_actor")
        _validate_execution_actors(dispatch_actor, provider_actor, evidence_actor)

        capabilities = _string_sequence(request.arguments, "capabilities")
        if not capabilities:
            capabilities = tuple(
                capability
                for capability in envelope.allowed_capabilities
                if capability in {"repository_read", "repository_write", "test_execution"}
            )
        if not capabilities:
            raise ValueError("provider execution requires explicit provider capabilities")
        project_policy = _optional_mapping(request.arguments, "project_policy")
        graph = self._load_provider_graph(request)
        decision = CapabilityResolver().resolve(
            graph,
            CapabilityRequest(
                project_id=envelope.project_id,
                project_job_id=project_job_id,
                role=role,
                capabilities=frozenset(capabilities),
                allowed_providers=frozenset(envelope.allowed_providers),
                envelope_capabilities=frozenset(envelope.allowed_capabilities),
                actor=ActorContext(
                    actor_id=dispatch_actor.actor_id,
                    actor_type=dispatch_actor.actor_type.value,
                    delegated_roles=frozenset({role}),
                ),
                data_classification=DataClassification(envelope.data_classification),
                preferred_provider=provider_id,
                project_allowed_providers=frozenset(
                    _string_sequence(project_policy, "allowed_providers")
                ),
                project_allowed_roles=frozenset(
                    ProviderRole(item) for item in _string_sequence(project_policy, "allowed_roles")
                ),
            ),
        )
        if not decision.eligible or decision.provider_id != provider_id:
            raise ValueError("provider is not contextually eligible: " + ",".join(decision.reasons))
        provider = graph.provider(provider_id)
        if provider is None:
            raise ValueError(f"provider is not registered: {provider_id}")

        owned_paths = _string_sequence(request.arguments, "owned_paths")
        if not owned_paths:
            raise ValueError("owned_paths must contain at least one path")
        for path in owned_paths:
            service.workspaces.assert_allowed_path(
                workspace_id, path, permission="WRITE", actor_id=dispatch_actor
            )
        credential_ids = _string_sequence(request.arguments, "credential_reference_ids")
        singular_credential = _optional_string(request.arguments, "credential_reference_id")
        if singular_credential is not None:
            if credential_ids:
                raise ValueError(
                    "credential_reference_id and credential_reference_ids are mutually exclusive"
                )
            credential_ids = (singular_credential,)
        packet = ManualIntegration().prepare_execution(
            task_contract={
                "id": project_job_id,
                "objective": _required_string(request.arguments, "objective"),
                "run_id": run_id,
                "attempt_id": attempt_id,
            },
            context={
                "execution_envelope_id": envelope.envelope_id,
                "execution_envelope_version": envelope.version,
                "execution_envelope_fingerprint": envelope.fingerprint,
                "workspace_id": workspace_id,
            },
            base_commit=_required_envelope_commit(envelope),
            project_model_fingerprint=_required_envelope_fingerprint(envelope),
            acceptance_criteria=(
                tuple(_required_sequence(request.arguments, "acceptance_criteria"))
                if "acceptance_criteria" in request.arguments
                else _provider_execution_criteria(envelope)
            ),
            ownership={"paths": list(owned_paths)},
            expected_result={
                "status": "SUCCESS",
                "artifacts": [{"path": path} for path in owned_paths],
                "canonical_acceptance": False,
            },
            interfaces=_string_sequence(request.arguments, "interfaces"),
            invariants=_string_sequence(request.arguments, "invariants"),
        )
        workspace_root = Path(str(workspace["workspace_root"])).resolve()
        execute_provider: Callable[[], ExecutionResult]
        if provider_id == "codex":
            codex_integration = CodexIntegration()
            codex_plan = codex_integration.prepare_stage(
                packet,
                workspace_root,
                require_clean=True,
                command_prefix=provider.configuration.command,
            )
            codex_runner = self._codex_runner_factory(provider.configuration.command)

            def run_codex_provider() -> ExecutionResult:
                return codex_integration.execute_stage(codex_plan, codex_runner)

            execute_provider = run_codex_provider
        elif provider_id == "claude":
            claude_integration = ClaudeIntegration(
                ClaudeDetection(
                    True,
                    provider.readiness.executable or provider.configuration.command[0],
                    provider.readiness.version,
                    provider.readiness.detail,
                )
            )
            claude_plan = claude_integration.plan_stage_execution(
                packet,
                project_root=workspace_root,
                worktree_root=workspace_root,
                require_clean=True,
                command_prefix=provider.configuration.command,
            )
            claude_runner = self._claude_runner_factory(provider.configuration.command)

            def run_claude_provider() -> ExecutionResult:
                return claude_integration.execute_stage(claude_plan, claude_runner)

            execute_provider = run_claude_provider
        else:
            raise ValueError(f"provider execution is unsupported: {provider_id}")
        authorization = service.authorize_dispatch(
            attempt_id,
            provider_id=provider_id,
            provider_role=role.value,
            requested_capabilities=capabilities,
            filesystem_permissions=_string_sequence_or_default(
                request.arguments,
                "filesystem_permissions",
                envelope.filesystem_permissions,
            ),
            network_permissions=_string_sequence_or_default(
                request.arguments, "network_permissions", envelope.network_permissions
            ),
            tool_permissions=_string_sequence_or_default(
                request.arguments, "tool_permissions", envelope.tool_permissions
            ),
            credential_reference_ids=credential_ids,
            actor=dispatch_actor,
            correlation_id=request.context.correlation_id,
        )
        try:
            with service.coordinator_heartbeat():
                result = execute_provider()
            manifest, manifest_digest = _validate_owned_artifacts(
                service,
                workspace_id=workspace_id,
                workspace_root=workspace_root,
                owned_paths=owned_paths,
                result=result,
                actor=evidence_actor,
                require_complete=result.status is ExecutionStatus.SUCCESS,
            )
            passed = result.status is ExecutionStatus.SUCCESS
            evidence = _record_required_evidence(
                service,
                envelope=envelope,
                project_job_id=project_job_id,
                attempt_id=attempt_id,
                workspace_id=workspace_id,
                manifest_digest=manifest_digest,
                passed=passed,
                actor=evidence_actor,
                correlation_id=request.context.correlation_id,
            )
            if result.status is ExecutionStatus.CANCELLED:
                service.cancel(attempt_id, actor_id=provider_actor)
            else:
                service.finish(
                    attempt_id,
                    f"provider={provider_id}; status={result.status.value}; "
                    f"owned_artifacts_sha256={manifest_digest}",
                    actor_id=provider_actor,
                    correlation_id=request.context.correlation_id,
                )
        except Exception:
            with suppress(Exception):
                service.mark_unknown(attempt_id, actor_id=provider_actor)
            raise

        return OperationResult(
            ok=True,
            value={
                "execution": {
                    "provider_id": provider_id,
                    "provider_role": role.value,
                    "live": True,
                    "status": result.status.value,
                    "result": result.to_dict(),
                    "packet_fingerprint": packet.contract_fingerprint,
                    "dispatch_authorization": authorization.to_dict(),
                    "owned_artifacts": manifest,
                    "owned_artifacts_sha256": manifest_digest,
                    "evidence": [record.to_dict() for record in evidence],
                    "accepted": False,
                    "promoted": False,
                }
            },
        )

    def _manual_packet_create(self, request: OperationRequest) -> OperationResult:
        manual = self.registry.get("manual")
        if not isinstance(manual, ManualIntegration):
            raise TypeError("registered manual integration has an invalid adapter type")
        packet = manual.prepare_execution(
            task_contract=_required_mapping(request.arguments, "task_contract"),
            context=_optional_mapping(request.arguments, "context"),
            base_commit=_required_string(request.arguments, "base_commit"),
            project_model_fingerprint=_required_string(
                request.arguments, "project_model_fingerprint"
            ),
            acceptance_criteria=_required_sequence(request.arguments, "acceptance_criteria"),
            ownership=_optional_mapping(request.arguments, "ownership"),
            expected_result=_required_mapping(request.arguments, "expected_result"),
            interfaces=_string_sequence(request.arguments, "interfaces"),
            invariants=_string_sequence(request.arguments, "invariants"),
        )
        return OperationResult(ok=True, value={"packet": packet.to_dict()})

    def _manual_result_submit(self, request: OperationRequest) -> OperationResult:
        manual = self.registry.get("manual")
        if not isinstance(manual, ManualIntegration):
            raise TypeError("registered manual integration has an invalid adapter type")
        packet = ExecutionPacket.from_dict(_required_mapping(request.arguments, "packet"))
        result = ExecutionResult.from_dict(_required_mapping(request.arguments, "result"))
        current_value = request.arguments.get("current_baseline")
        current = None
        if current_value is not None:
            baseline = _mapping(current_value, "current_baseline")
            current = ExecutionBaseline(
                _required_string(baseline, "base_commit"),
                _required_string(baseline, "execution_contract_fingerprint"),
                _required_string(baseline, "project_model_fingerprint"),
            )
        classified = manual.submit_result(packet, result, current_baseline=current)
        return OperationResult(
            ok=True,
            value={"result": classified.to_dict(), "canonical_acceptance": False},
        )

    @staticmethod
    def _research_request_validate(request: OperationRequest) -> OperationResult:
        value = ResearchRequest.from_dict(_required_mapping(request.arguments, "request"))
        return OperationResult(ok=True, value={"request": value.to_dict(), "valid": True})

    @staticmethod
    def _research_bundle_validate(request: OperationRequest) -> OperationResult:
        value = ResearchBundle.from_dict(_required_mapping(request.arguments, "bundle"))
        return OperationResult(
            ok=True,
            value={
                "bundle": value.to_dict(),
                "valid": True,
                "canonical_decision": False,
            },
        )

    @staticmethod
    def _distribution_discover(request: OperationRequest) -> OperationResult:
        path = request.arguments.get("resource_path", request.context.project_root or ".")
        if not isinstance(path, str):
            raise TypeError("resource_path must be a string")
        return OperationResult(ok=True, value=discover_environment(resource_path=path).to_dict())

    @staticmethod
    def _distribution_presentation(request: OperationRequest) -> OperationResult:
        mode = ExperienceMode(str(request.arguments.get("mode", "BEGINNER")))
        return OperationResult(ok=True, value=presentation_policy(mode))

    @staticmethod
    def _distribution_setup_plan(request: OperationRequest) -> OperationResult:
        root = _project_root(request)
        identifiers = _string_sequence(request.arguments, "integration_ids")
        provider_specs = _mapping_sequence(request.arguments, "provider_specs")
        plan = (
            plan_integration_setup(root, identifiers, provider_specs=provider_specs)
            if provider_specs
            else plan_integration_setup(root, identifiers)
        )
        return OperationResult(ok=True, value=plan.to_dict())

    @staticmethod
    def _distribution_setup_apply(request: OperationRequest) -> OperationResult:
        root = _project_root(request)
        identifiers = _string_sequence(request.arguments, "integration_ids")
        token = request.arguments.get("confirmation_token")
        if token is not None and not isinstance(token, str):
            raise TypeError("confirmation_token must be a string")
        provider_specs = _mapping_sequence(request.arguments, "provider_specs")
        plan = (
            plan_integration_setup(
                root,
                identifiers,
                provider_specs=provider_specs,
                issue_token=False,
            )
            if provider_specs
            else plan_integration_setup(root, identifiers, issue_token=False)
        )
        return OperationResult(
            ok=True,
            value=apply_integration_setup(plan, confirmation_token=token).to_dict(),
        )

    @staticmethod
    def _distribution_doctor(request: OperationRequest) -> OperationResult:
        root = request.arguments.get("project_root", request.context.project_root)
        if root is not None and not isinstance(root, str):
            raise TypeError("project_root must be a string")
        report = run_distribution_doctor(
            root,
            fix=_optional_bool(request.arguments, "fix", False),
            apply=_optional_bool(request.arguments, "apply", False),
        )
        return OperationResult(ok=True, value=report.to_dict())

    @staticmethod
    def _distribution_install_plan(request: OperationRequest) -> OperationResult:
        decision = install_plan(
            _required_string(request.arguments, "source_executable"),
            _required_string(request.arguments, "install_root"),
        )
        return OperationResult(ok=True, value=decision.to_dict())

    @staticmethod
    def _distribution_install(request: OperationRequest) -> OperationResult:
        result = install(
            _required_string(request.arguments, "source_executable"),
            _required_string(request.arguments, "install_root"),
            confirmation_token=_optional_string(request.arguments, "confirmation_token"),
        )
        return OperationResult(ok=True, value=result.to_dict())

    @staticmethod
    def _distribution_upgrade(request: OperationRequest) -> OperationResult:
        result = upgrade(
            _required_string(request.arguments, "source_executable"),
            _required_string(request.arguments, "install_root"),
            confirmation_token=_optional_string(request.arguments, "confirmation_token"),
        )
        return OperationResult(ok=True, value=result.to_dict())

    @staticmethod
    def _distribution_upgrade_plan(request: OperationRequest) -> OperationResult:
        decision = upgrade_plan(
            _required_string(request.arguments, "source_executable"),
            _required_string(request.arguments, "install_root"),
        )
        return OperationResult(ok=True, value=decision.to_dict())

    @staticmethod
    def _distribution_uninstall_plan(request: OperationRequest) -> OperationResult:
        decision = uninstall_plan(_required_string(request.arguments, "install_root"))
        return OperationResult(ok=True, value=decision.to_dict())

    @staticmethod
    def _distribution_uninstall(request: OperationRequest) -> OperationResult:
        value = uninstall(
            _required_string(request.arguments, "install_root"),
            confirmation_token=_optional_string(request.arguments, "confirmation_token"),
        )
        return OperationResult(ok=True, value=value)

    @staticmethod
    def _beginner_start(request: OperationRequest) -> OperationResult:
        root = _project_root(request)
        result = start_beginner_journey(
            root,
            _required_string(request.arguments, "intent"),
            project_name=_optional_string(request.arguments, "project_name"),
        )
        return OperationResult(ok=True, value=result.to_dict())


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    return value


def _required_mapping(arguments: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = _mapping(arguments.get(name), name)
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _optional_mapping(arguments: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return _mapping(arguments.get(name, {}), name)


def _required_string(arguments: Mapping[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required and must be a string")
    return value


def _required_sequence(arguments: Mapping[str, Any], name: str) -> Sequence[Any]:
    value = arguments.get(name)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)) or not value:
        raise ValueError(f"{name} is required and must be a non-empty array")
    return value


def _string_sequence(arguments: Mapping[str, Any], name: str) -> tuple[str, ...]:
    value = arguments.get(name, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{name} must be an array")
    if not all(isinstance(item, str) and item for item in value):
        raise TypeError(f"{name} must contain strings")
    return tuple(value)


def _mapping_sequence(arguments: Mapping[str, Any], name: str) -> tuple[Mapping[str, Any], ...]:
    value = arguments.get(name, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{name} must be an array")
    if any(not isinstance(item, Mapping) for item in value):
        raise TypeError(f"{name} entries must be objects")
    return tuple(item for item in value if isinstance(item, Mapping))


def _optional_bool(arguments: Mapping[str, Any], name: str, default: bool) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _optional_string(arguments: Mapping[str, Any], name: str) -> str | None:
    value = arguments.get(name)
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _optional_int(arguments: Mapping[str, Any], name: str) -> int | None:
    value = arguments.get(name)
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise TypeError(f"{name} must be an integer")
    return value


def _required_int(arguments: Mapping[str, Any], name: str) -> int:
    value = arguments.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    return value


def _project_root(request: OperationRequest) -> str:
    root = request.arguments.get("project_root", request.context.project_root)
    if not isinstance(root, str) or not root:
        raise ValueError("project_root is required")
    return root


def _project_service(request: OperationRequest) -> ProjectControlService:
    catalog = request.arguments.get("catalog_path")
    if catalog is None:
        catalog = str(default_catalog_path())
    if not isinstance(catalog, str) or not catalog:
        raise TypeError("catalog_path must be a string")
    return ProjectControlService(catalog)


def _runtime_service(request: OperationRequest) -> ManagedRuntimeService:
    store_path = _required_string(request.arguments, "store_path")
    service_id = str(request.arguments.get("service_id", "artifex-managed-service"))
    workspace_root = _optional_string(request.arguments, "workspace_root")
    return ManagedRuntimeService(store_path, service_id=service_id, workspace_root=workspace_root)


def _codex_process_runner(command: tuple[str, ...]) -> CodexProcessRunner:
    return CodexProcessRunner(command=command)


def _claude_process_runner(command: tuple[str, ...]) -> ClaudeProcessRunner:
    return ClaudeProcessRunner(command=command)


def _execution_envelope(value: Mapping[str, Any]) -> ExecutionEnvelope:
    budget = _optional_mapping(value, "resource_budget")
    resource_budget: list[tuple[str, int]] = []
    for key, item in sorted(budget.items()):
        if not isinstance(key, str) or not key.strip():
            raise TypeError("resource_budget keys must be non-empty strings")
        if not isinstance(item, int) or isinstance(item, bool):
            raise TypeError("resource_budget values must be integers")
        resource_budget.append((key, item))
    credentials = tuple(
        RuntimeCredentialReference(
            reference_id=_required_string(item, "reference_id"),
            provider_id=_required_string(item, "provider_id"),
            role=_required_string(item, "role"),
            project_id=_required_string(item, "project_id"),
            expires_at=_optional_int(item, "expires_at"),
            revoked=_optional_bool(item, "revoked", False),
        )
        for item in _mapping_sequence(value, "credential_references")
    )
    return ExecutionEnvelope(
        envelope_id=_required_string(value, "envelope_id"),
        version=_required_int(value, "version"),
        project_id=_required_string(value, "project_id"),
        objective=_required_string(value, "objective"),
        baseline_revision=_required_int(value, "baseline_revision"),
        actor_id=_required_string(value, "actor_id"),
        allowed_paths=_string_sequence(value, "allowed_paths"),
        allowed_capabilities=_string_sequence(value, "allowed_capabilities"),
        required_gates=_string_sequence(value, "required_gates"),
        max_attempts=_required_int(value, "max_attempts"),
        recovery_policy=_required_string(value, "recovery_policy"),
        stop_on_unknown=_optional_bool(value, "stop_on_unknown", True),
        approved=_optional_bool(value, "approved", True),
        supervision_level=SupervisionLevel(
            str(value.get("supervision_level", SupervisionLevel.L2.value))
        ),
        materiality=Materiality(str(value.get("materiality", Materiality.TACTICAL.value))),
        allowed_workstreams=_string_sequence(value, "allowed_workstreams"),
        allowed_providers=_string_sequence(value, "allowed_providers"),
        allowed_provider_roles=_string_sequence(value, "allowed_provider_roles"),
        filesystem_permissions=_string_sequence_or_default(
            value, "filesystem_permissions", ("READ", "WRITE")
        ),
        network_permissions=_string_sequence(value, "network_permissions"),
        tool_permissions=_string_sequence(value, "tool_permissions"),
        data_classification=_string_or_default(value, "data_classification", "INTERNAL"),
        credential_references=credentials,
        resource_budget=tuple(resource_budget),
        deadline_at=_optional_int(value, "deadline_at"),
        stop_conditions=_string_sequence_or_default(
            value, "stop_conditions", ("MAX_ATTEMPTS", "UNKNOWN_OUTCOME")
        ),
        require_durable_evidence=_optional_bool(value, "require_durable_evidence", False),
        baseline_fingerprint=_optional_string(value, "baseline_fingerprint"),
        baseline_commit=_optional_string(value, "baseline_commit"),
    )


def _required_actor(arguments: Mapping[str, Any], name: str) -> ActorPrincipal:
    value = _required_mapping(arguments, name)
    delegation_value = value.get("delegation")
    delegation = None
    if delegation_value is not None:
        grant = _mapping(delegation_value, f"{name}.delegation")
        delegation = DelegationGrant(
            grant_id=_required_string(grant, "grant_id"),
            delegator_id=_required_string(grant, "delegator_id"),
            delegate_id=_required_string(grant, "delegate_id"),
            project_id=_required_string(grant, "project_id"),
            allowed_actions=_string_sequence(grant, "allowed_actions"),
            issued_at=_required_int(grant, "issued_at"),
            expires_at=_optional_int(grant, "expires_at"),
        )
    return ActorPrincipal(
        actor_id=_required_string(value, "actor_id"),
        actor_type=ActorType(_required_string(value, "actor_type")),
        authenticated=_optional_bool(value, "authenticated", False),
        authentication_method=_required_string(value, "authentication_method"),
        direct_permissions=_string_sequence(value, "direct_permissions"),
        delegation=delegation,
    )


def _string_sequence_or_default(
    arguments: Mapping[str, Any], name: str, default: tuple[str, ...]
) -> tuple[str, ...]:
    if name not in arguments:
        return default
    return _string_sequence(arguments, name)


def _string_or_default(arguments: Mapping[str, Any], name: str, default: str) -> str:
    if name not in arguments:
        return default
    return _required_string(arguments, name)


def _run_for_job(service: ManagedRuntimeService, project_job_id: str) -> dict[str, Any]:
    job = service.store.get("project_jobs", "project_job_id", project_job_id)
    if job is None:
        raise ValueError(f"unknown ProjectJob: {project_job_id}")
    run = service.store.get("runs", "run_id", str(job["run_id"]))
    if run is None:
        raise ValueError(f"ProjectJob Run is missing: {project_job_id}")
    return run


def _run_for_attempt(service: ManagedRuntimeService, attempt_id: str) -> dict[str, Any]:
    attempt = service.store.get("attempts", "attempt_id", attempt_id)
    if attempt is None:
        raise ValueError(f"unknown Attempt: {attempt_id}")
    return _run_for_job(service, str(attempt["project_job_id"]))


def _envelope_for_run(service: ManagedRuntimeService, run: Mapping[str, Any]) -> ExecutionEnvelope:
    value = service.store.envelope(str(run["envelope_id"]), int(run["envelope_version"]))
    if value is None:
        raise ValueError(f"Run Execution Envelope is missing: {run['run_id']}")
    return _execution_envelope(value)


def _runtime_actor(
    service: ManagedRuntimeService,
    request: OperationRequest,
    *,
    entity: str,
    entity_id: str,
    action: str,
) -> str | ActorPrincipal:
    run = (
        _run_for_attempt(service, entity_id)
        if entity == "attempt"
        else _run_for_job(service, entity_id)
    )
    envelope = _envelope_for_run(service, run)
    if not envelope.allowed_providers:
        return request.context.actor
    if "actor" not in request.arguments:
        raise ValueError(f"automated provider {action} requires an explicit actor object")
    return _required_actor(request.arguments, "actor")


def _bound_runtime_execution(
    service: ManagedRuntimeService,
    *,
    attempt_id: str,
    project_job_id: str,
    run_id: str,
    workspace_id: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    ExecutionEnvelope,
]:
    attempt = service.store.get("attempts", "attempt_id", attempt_id)
    job = service.store.get("project_jobs", "project_job_id", project_job_id)
    run = service.store.get("runs", "run_id", run_id)
    workspace = service.store.get("workspaces", "workspace_id", workspace_id)
    if any(value is None for value in (attempt, job, run, workspace)):
        raise ValueError(
            "provider execution requires an existing Run, ProjectJob, Attempt, and workspace"
        )
    assert attempt is not None and job is not None and run is not None and workspace is not None
    if str(attempt["project_job_id"]) != project_job_id:
        raise ValueError("Attempt is not bound to the requested ProjectJob")
    if str(job["run_id"]) != run_id:
        raise ValueError("ProjectJob is not bound to the requested Run")
    if str(workspace["attempt_id"]) != attempt_id:
        raise ValueError("Execution Workspace is not bound to the requested Attempt")
    if str(attempt["state"]) != "PENDING" or str(workspace["state"]) != "ACTIVE":
        raise ValueError("provider execution requires a PENDING Attempt and ACTIVE workspace")
    envelope = _envelope_for_run(service, run)
    if not envelope.allowed_providers:
        raise ValueError("Run Execution Envelope does not authorize automated providers")
    if int(workspace["baseline_revision"]) != envelope.baseline_revision:
        raise ValueError("Execution Workspace baseline is not bound to the Envelope")
    return attempt, job, run, workspace, envelope


def _validate_execution_actors(
    dispatch_actor: ActorPrincipal,
    provider_actor: ActorPrincipal,
    evidence_actor: ActorPrincipal,
) -> None:
    if provider_actor.actor_type is not ActorType.PROVIDER:
        raise ValueError("provider_actor must have PROVIDER actor type")
    if evidence_actor.actor_type is not ActorType.ARTIFEX_SERVICE:
        raise ValueError("evidence_actor must have ARTIFEX_SERVICE actor type")
    if len({dispatch_actor.actor_id, provider_actor.actor_id, evidence_actor.actor_id}) != 3:
        raise ValueError("dispatch, provider-result, and evidence actors must be distinct")


def _required_envelope_commit(envelope: ExecutionEnvelope) -> str:
    if envelope.baseline_commit is None:
        raise ValueError("provider Execution Envelope is missing baseline_commit")
    return envelope.baseline_commit


def _required_envelope_fingerprint(envelope: ExecutionEnvelope) -> str:
    if envelope.baseline_fingerprint is None:
        raise ValueError("provider Execution Envelope is missing baseline_fingerprint")
    return envelope.baseline_fingerprint


def _validate_owned_artifacts(
    service: ManagedRuntimeService,
    *,
    workspace_id: str,
    workspace_root: Path,
    owned_paths: tuple[str, ...],
    result: ExecutionResult,
    actor: ActorPrincipal,
    require_complete: bool = True,
) -> tuple[list[dict[str, str]], str]:
    manifest: dict[str, str] = {}
    for owned_path in owned_paths:
        target = service.workspaces.assert_allowed_path(
            workspace_id, owned_path, permission="READ", actor_id=actor
        )
        candidates = [target] if target.is_file() else sorted(target.rglob("*"))
        owned_files = 0
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            resolved = candidate.resolve()
            try:
                relative = resolved.relative_to(workspace_root).as_posix()
            except ValueError as exc:
                raise ValueError("owned artifact escapes the Execution Workspace") from exc
            manifest[relative] = hashlib.sha256(resolved.read_bytes()).hexdigest()
            owned_files += 1
        if owned_files == 0 and require_complete:
            raise ValueError(f"owned artifact was not produced: {owned_path}")
    claimed = {
        _required_string(artifact, "path").replace("\\", "/").removeprefix("./")
        for artifact in result.artifacts
    }
    if result.status is ExecutionStatus.SUCCESS and not claimed.issubset(manifest):
        raise ValueError("provider claimed an artifact outside the independently hashed manifest")
    values = [{"path": path, "sha256": manifest[path]} for path in sorted(manifest)]
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return values, hashlib.sha256(encoded).hexdigest()


def _record_required_evidence(
    service: ManagedRuntimeService,
    *,
    envelope: ExecutionEnvelope,
    project_job_id: str,
    attempt_id: str,
    workspace_id: str,
    manifest_digest: str,
    passed: bool,
    actor: ActorPrincipal,
    correlation_id: str | None,
) -> tuple[EvidenceRecord, ...]:
    authority_gates = {"acceptance", "acceptance-authority", "project-authority"}
    recorded_at = int(time())
    records: list[EvidenceRecord] = []
    for gate in envelope.required_gates:
        if gate.casefold() in authority_gates:
            continue
        identity = hashlib.sha256(f"{attempt_id}\0{gate}\0{manifest_digest}".encode()).hexdigest()[
            :24
        ]
        record = EvidenceRecord(
            evidence_id=f"evidence-{identity}",
            project_job_id=project_job_id,
            attempt_id=attempt_id,
            gate=gate,
            passed=passed,
            envelope_fingerprint=envelope.fingerprint,
            baseline_revision=envelope.baseline_revision,
            artifact_ref=f"workspace://{workspace_id}/owned-artifacts",
            artifact_digest=manifest_digest,
            actor_id=actor.actor_id,
            recorded_at=recorded_at,
        )
        service.record_evidence(record, actor=actor, correlation_id=correlation_id)
        records.append(record)
    return tuple(records)


def _provider_execution_criteria(envelope: ExecutionEnvelope) -> tuple[str, ...]:
    """Keep Acceptance Authority gates out of an implementer's task contract."""

    authority_gates = {"acceptance", "acceptance-authority", "project-authority"}
    criteria = tuple(
        f"gate:{gate}" for gate in envelope.required_gates if gate.casefold() not in authority_gates
    )
    return criteria or ("executor-result-bound-to-envelope",)


def _record_promoted_provider_certification(
    service: ManagedRuntimeService,
    *,
    workspace_id: str,
    project_job_id: str,
    revision: int,
) -> dict[str, object] | None:
    """Certify supported provider execution only after acceptance and promotion."""

    workspace = service.store.get("workspaces", "workspace_id", workspace_id)
    if workspace is None:
        raise ValueError("promoted Execution Workspace is missing")
    attempt_id = str(workspace["attempt_id"])
    dispatch = service.store.dispatch_authorization(attempt_id)
    provider_id = "" if dispatch is None else str(dispatch["provider_id"])
    if dispatch is None or (
        provider_id not in {"codex", "claude"}
        or str(dispatch["provider_role"]) != ProviderRole.EXECUTION_IMPLEMENTER.value
    ):
        return None
    decision = service.store.acceptance(project_job_id)
    if decision is None:
        raise ValueError("promoted provider ProjectJob has no persisted acceptance")
    raw_evidence_ids = decision.get("evidence_ids", "[]")
    if isinstance(raw_evidence_ids, str):
        parsed_evidence_ids = json.loads(raw_evidence_ids)
    else:
        parsed_evidence_ids = raw_evidence_ids
    if not isinstance(parsed_evidence_ids, list) or not parsed_evidence_ids:
        raise ValueError("promoted provider ProjectJob has no bound evidence")
    evidence_ids = tuple(str(item) for item in parsed_evidence_ids)
    records = service.store.evidence(evidence_ids)
    if len(records) != len(evidence_ids) or not all(bool(item["passed"]) for item in records):
        raise ValueError("promoted provider ProjectJob evidence is incomplete")
    accepted_result_sha256 = hashlib.sha256(
        json.dumps(
            [
                {
                    "evidence_id": item["evidence_id"],
                    "artifact_digest": item["artifact_digest"],
                    "gate": item["gate"],
                }
                for item in records
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    promoted = ProjectAuthority(str(workspace["project_root"])).current()
    if promoted.number != revision:
        raise ValueError("provider certification revision does not match Project Authority")
    receipt = record_execution_implementer_evidence(
        project_id=promoted.project_id,
        project_job_id=project_job_id,
        accepted_result_sha256=accepted_result_sha256,
        promoted_baseline_sha256=promoted.fingerprint,
        acceptance_decision_id=str(decision["decision_id"]),
        promotion_revision=revision,
        provider_id=provider_id,
    )
    return receipt.to_dict()

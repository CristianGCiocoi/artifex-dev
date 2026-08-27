"""Transport-independent operation registry and dispatch."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from artifex import __version__
from artifex.capabilities import (
    CODEX_DISPATCH_AUTHORIZED_ROLES,
    ActorContext,
    CapabilityGraph,
    CapabilityRequest,
    CapabilityResolver,
    DataClassification,
    ProviderCompositionLoader,
    ProviderRole,
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
from artifex.project import ProjectControlService, ProjectModel, default_catalog_path
from artifex.runtime import ExecutionEnvelope, ManagedRuntimeService, ReconciliationOutcome
from artifex.workflow import ExecutionBaseline


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
    ) -> None:
        self._operations: dict[str, Operation] = {}
        self._project_root = project_root
        self._provider_loader = provider_loader or ProviderCompositionLoader(
            certified_roles={"codex": CODEX_DISPATCH_AUTHORIZED_ROLES}
        )
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
        self.register("project.status", self._project_status)
        self.register("project.create", self._project_create)
        self.register("project.adopt", self._project_adopt)
        self.register("project.continue", self._project_continue)
        self.register("project.propose", self._project_propose)
        self.register("project.accept", self._project_accept)
        self.register("project.observe", self._project_observe)
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
        envelope = _required_mapping(request.arguments, "envelope")
        actor_value = _required_mapping(request.arguments, "actor")
        project_policy = _optional_mapping(request.arguments, "project_policy")
        role = ProviderRole(_required_string(request.arguments, "role"))
        request_value = CapabilityRequest(
            project_id=_required_string(request.arguments, "project_id"),
            project_job_id=_required_string(request.arguments, "project_job_id"),
            role=role,
            capabilities=frozenset(_string_sequence(request.arguments, "capabilities")),
            allowed_providers=frozenset(_string_sequence(envelope, "allowed_providers")),
            envelope_capabilities=frozenset(
                _string_sequence(envelope, "allowed_capabilities")
            ),
            actor=ActorContext(
                actor_id=_required_string(actor_value, "actor_id"),
                actor_type=_required_string(actor_value, "actor_type"),
                delegated_roles=frozenset(
                    ProviderRole(item)
                    for item in _string_sequence(actor_value, "delegated_roles")
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
                ProviderRole(item)
                for item in _string_sequence(project_policy, "allowed_roles")
            ),
        )
        decision = CapabilityResolver().resolve(self._load_provider_graph(request), request_value)
        return OperationResult(ok=True, value={"decision": decision.to_dict()})

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
    def _platform_dashboard(request: OperationRequest) -> OperationResult:
        return OperationResult(ok=True, value=_project_service(request).platform_dashboard())

    @staticmethod
    def _runtime_bootstrap(request: OperationRequest) -> OperationResult:
        envelope_value = _required_mapping(request.arguments, "envelope")
        envelope = ExecutionEnvelope(
            envelope_id=_required_string(envelope_value, "envelope_id"),
            version=_required_int(envelope_value, "version"),
            project_id=_required_string(envelope_value, "project_id"),
            objective=_required_string(envelope_value, "objective"),
            baseline_revision=_required_int(envelope_value, "baseline_revision"),
            actor_id=_required_string(envelope_value, "actor_id"),
            allowed_paths=_string_sequence(envelope_value, "allowed_paths"),
            allowed_capabilities=_string_sequence(envelope_value, "allowed_capabilities"),
            required_gates=_string_sequence(envelope_value, "required_gates"),
            max_attempts=_required_int(envelope_value, "max_attempts"),
            recovery_policy=_required_string(envelope_value, "recovery_policy"),
            stop_on_unknown=_optional_bool(envelope_value, "stop_on_unknown", True),
            approved=_optional_bool(envelope_value, "approved", True),
        )
        value = _runtime_service(request).bootstrap_run(
            envelope,
            workstream_id=_required_string(request.arguments, "workstream_id"),
            run_id=_required_string(request.arguments, "run_id"),
            project_job_id=_required_string(request.arguments, "project_job_id"),
            attempt_id=_required_string(request.arguments, "attempt_id"),
            purpose=_required_string(request.arguments, "purpose"),
            actor_id=request.context.actor,
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
        decision = _runtime_service(request).accept(
            _required_string(request.arguments, "project_job_id"),
            evidence_valid=_optional_bool(request.arguments, "evidence_valid", False),
            actor_id=request.context.actor,
            reason=_required_string(request.arguments, "reason"),
        )
        return OperationResult(ok=True, value={"decision": decision.to_dict()})

    @staticmethod
    def _runtime_workspace_create(request: OperationRequest) -> OperationResult:
        path = _runtime_service(request).create_workspace(
            _required_string(request.arguments, "workspace_id"),
            _required_string(request.arguments, "attempt_id"),
            _required_string(request.arguments, "project_root"),
            _required_int(request.arguments, "baseline_revision"),
            actor_id=request.context.actor,
        )
        return OperationResult(ok=True, value={"workspace_root": str(path), "isolated": True})

    @staticmethod
    def _runtime_workspace_promote(request: OperationRequest) -> OperationResult:
        revision = _runtime_service(request).promote_accepted_workspace(
            _required_string(request.arguments, "workspace_id"),
            ProjectModel.from_dict(_required_mapping(request.arguments, "model")),
            _required_string(request.arguments, "project_job_id"),
            actor_id=request.context.actor,
        )
        return OperationResult(ok=True, value={"semantic_revision": revision})

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


def _mapping_sequence(
    arguments: Mapping[str, Any], name: str
) -> tuple[Mapping[str, Any], ...]:
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

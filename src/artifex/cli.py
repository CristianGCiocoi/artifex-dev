"""Semantic command-line transport over the ARTIFEX Application API."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

import typer

from artifex.application import Application, OperationContext, OperationRequest
from artifex.distribution import complete_deferred_uninstall
from artifex.policy import scrub_secrets

app = typer.Typer(help="ARTIFEX development continuity and validation control plane.")
system_app = typer.Typer(help="Inspect the ARTIFEX installation.")
integration_app = typer.Typer(help="Inspect and select replaceable integrations.")
client_app = typer.Typer(help="Configure public Codex and Claude clients with approval.")
mcp_app = typer.Typer(help="Run and inspect the installed ARTIFEX MCP bridge.")
manual_app = typer.Typer(help="Exchange portable manual execution packets and results.")
project_app = typer.Typer(help="Read semantic project state.")
research_app = typer.Typer(help="Validate provider-neutral research contracts.")
pandora_app = typer.Typer(help="Use the optional Pandora RESEARCH provider boundary.")
documentation_app = typer.Typer(help="Inspect and selectively regenerate Project documentation.")
dashboard_app = typer.Typer(
    help="Open the ARTIFEX Platform Dashboard or inspect its operational views.",
    invoke_without_command=True,
)
reality_app = typer.Typer(help="Inspect sourced Observed Reality and divergences.")
service_app = typer.Typer(help="Use the frontend-independent ARTIFEX managed service.")
migration_app = typer.Typer(help="Inspect and migrate a real ARTIFEX V1 Project.")
app.add_typer(system_app, name="system")
app.add_typer(integration_app, name="integration")
app.add_typer(client_app, name="client")
app.add_typer(mcp_app, name="mcp")
app.add_typer(manual_app, name="manual")
app.add_typer(project_app, name="project")
app.add_typer(research_app, name="research")
research_app.add_typer(pandora_app, name="pandora")
app.add_typer(documentation_app, name="documentation")
app.add_typer(dashboard_app, name="dashboard")
app.add_typer(reality_app, name="reality")
app.add_typer(service_app, name="service")
app.add_typer(migration_app, name="migration")


@dashboard_app.callback()
def dashboard_entrypoint(
    ctx: typer.Context,
    catalog_path: str | None = typer.Option(None, "--catalog"),
    state_root: str | None = typer.Option(None, "--state-root"),
    port: int = typer.Option(0, "--port", min=0, max=65535),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser"),
) -> None:
    """Launch the dashboard when no read-only projection subcommand is selected."""

    if ctx.invoked_subcommand is not None:
        return
    from artifex.platform_dashboard import launch_dashboard

    launch_dashboard(
        catalog_path=catalog_path,
        state_root=state_root,
        port=port,
        open_browser=open_browser,
    )


def _emit(
    operation: str,
    arguments: dict[str, Any] | None = None,
    *,
    project_root: str | None = None,
) -> None:
    result = Application().dispatch(
        OperationRequest(
            operation,
            arguments or {},
            OperationContext(project_root=project_root, actor="cli"),
        )
    )
    typer.echo(json.dumps(result.to_dict(), sort_keys=True, ensure_ascii=False))
    if not result.ok:
        raise typer.Exit(1)


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(f"cannot read JSON object: {exc}") from exc
    if not isinstance(value, dict):
        raise typer.BadParameter("JSON input must be an object")
    return value


def _emit_service_result(value: Mapping[str, object]) -> None:
    rendered = dict(value)
    typer.echo(json.dumps(rendered, sort_keys=True, ensure_ascii=False))
    if rendered.get("ok") is False:
        raise typer.Exit(1)


@service_app.command("serve")
def service_serve(
    state_root: str | None = typer.Option(None, "--state-root"),
    service_id: str = typer.Option("artifex-managed-service", "--service-id"),
    port: int = typer.Option(0, "--port"),
) -> None:
    """Run the managed service in the current service-manager process."""

    from artifex.managed_service import ManagedServiceHost

    ManagedServiceHost(state_root, service_id=service_id, port=port).serve_forever()


@service_app.command("status")
def service_status(
    state_root: str | None = typer.Option(None, "--state-root"),
) -> None:
    """Read service status through the authenticated local transport."""

    from artifex.managed_service import LocalServiceClient

    _emit_service_result(LocalServiceClient(state_root).status())


@service_app.command("stop")
def service_stop(
    state_root: str | None = typer.Option(None, "--state-root"),
) -> None:
    """Request a controlled managed-service shutdown."""

    from artifex.managed_service import LocalServiceClient

    _emit_service_result(LocalServiceClient(state_root).shutdown())


@service_app.command("call")
def service_call(
    operation: str,
    arguments: str = typer.Option("{}", "--arguments"),
    state_root: str | None = typer.Option(None, "--state-root"),
    project_root: str | None = typer.Option(None, "--project-root"),
    timeout_seconds: float = typer.Option(
        30.0,
        "--timeout-seconds",
        min=0.1,
        max=3600.0,
        help="Bounded wait for the managed-service response.",
    ),
) -> None:
    """Call an Application operation through the persistent managed service."""

    from artifex.managed_service import LocalServiceClient

    try:
        value = json.loads(arguments)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"arguments are not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise typer.BadParameter("arguments must be a JSON object")
    _emit_service_result(
        LocalServiceClient(state_root, timeout_seconds=timeout_seconds).call(
            operation,
            value,
            project_root=project_root,
        )
    )


@system_app.command("health")
def system_health() -> None:
    """Report normalized Core health."""

    _emit("system.health")


@system_app.command("version")
def system_version() -> None:
    """Report the installed Core version."""

    _emit("system.version")


@system_app.command("operations")
def system_operations() -> None:
    """List semantic operations shared by CLI, API, and MCP."""

    _emit("system.operations")


@mcp_app.command("serve")
def mcp_serve() -> None:
    """Serve the local MCP protocol over stdio without opening a network port."""

    from artifex.mcp import serve_stdio

    serve_stdio()


@mcp_app.command("health")
def mcp_health() -> None:
    """Report the installed MCP bridge identity and self-test result."""

    from artifex.mcp import bridge_self_test

    result = bridge_self_test()
    typer.echo(json.dumps(result, sort_keys=True, ensure_ascii=False))
    if result["status"] != "PASS":
        raise typer.Exit(1)


@mcp_app.command("version")
def mcp_version() -> None:
    """Report bridge and protocol versions."""

    from artifex.mcp import bridge_identity

    typer.echo(json.dumps(bridge_identity(), sort_keys=True, ensure_ascii=False))


@mcp_app.command("test")
def mcp_test() -> None:
    """Run a bounded local bridge test suitable for installers and doctors."""

    from artifex.mcp import bridge_self_test

    result = bridge_self_test()
    typer.echo(json.dumps(result, sort_keys=True, ensure_ascii=False))
    if result["status"] != "PASS":
        raise typer.Exit(1)


@system_app.command("installation-doctor")
def installation_doctor(
    record_path: str | None = typer.Option(None, "--record-path"),
) -> None:
    """Verify the installed launcher, canonical state and managed-service readiness."""

    _emit("distribution.installation.doctor", {"record_path": record_path})


@app.command("doctor")
def doctor(
    project_root: str | None = typer.Option(None, "--project-root"),
    runstore_path: str | None = typer.Option(None, "--runstore-path"),
    service_state_path: str | None = typer.Option(None, "--service-state-path"),
    fix: bool = typer.Option(False, "--fix"),
    apply: bool = typer.Option(False, "--apply"),
) -> None:
    """Diagnose distribution health; fixes are allowlisted and dry-run unless applied."""

    _emit(
        "distribution.doctor",
        {
            "fix": fix,
            "apply": apply,
            "runstore_path": runstore_path,
            "service_state_path": service_state_path,
        },
        project_root=project_root,
    )


@app.command("bootstrap")
def bootstrap(project_root: str = typer.Option(..., "--project-root")) -> None:
    """Consume persisted setup in this process and show the public provider path."""

    _emit("distribution.bootstrap", project_root=project_root)


def _migration_arguments(
    project_root: str,
    catalog_path: str,
    runstore_path: str,
    state_root: str,
) -> dict[str, Any]:
    return {
        "project_root": project_root,
        "catalog_path": catalog_path,
        "runstore_path": runstore_path,
        "state_root": state_root,
    }


@migration_app.command("inspect")
def migration_inspect(
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str = typer.Option(..., "--catalog"),
    runstore_path: str = typer.Option(..., "--runstore"),
    state_root: str = typer.Option(..., "--state-root"),
) -> None:
    """Read and classify a V1 Project without mutation."""

    _emit(
        "migration.inspect",
        _migration_arguments(project_root, catalog_path, runstore_path, state_root),
        project_root=project_root,
    )


@migration_app.command("plan")
def migration_plan(
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str = typer.Option(..., "--catalog"),
    runstore_path: str = typer.Option(..., "--runstore"),
    state_root: str = typer.Option(..., "--state-root"),
) -> None:
    """Dry-run the exact reversible migration and issue a bounded approval token."""

    _emit(
        "migration.plan",
        _migration_arguments(project_root, catalog_path, runstore_path, state_root),
        project_root=project_root,
    )


@migration_app.command("apply")
def migration_apply(
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str = typer.Option(..., "--catalog"),
    runstore_path: str = typer.Option(..., "--runstore"),
    state_root: str = typer.Option(..., "--state-root"),
    confirm: str | None = typer.Option(None, "--confirm"),
) -> None:
    """Apply the approved backup-bound migration."""

    arguments = _migration_arguments(project_root, catalog_path, runstore_path, state_root)
    arguments["confirmation_token"] = confirm
    _emit("migration.apply", arguments, project_root=project_root)


@migration_app.command("validate")
def migration_validate(
    record_path: str = typer.Option(..., "--record"),
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str = typer.Option(..., "--catalog"),
    runstore_path: str = typer.Option(..., "--runstore"),
    state_root: str = typer.Option(..., "--state-root"),
) -> None:
    """Validate semantic preservation, bootstrap state and the first new Run."""

    arguments = _migration_arguments(project_root, catalog_path, runstore_path, state_root)
    arguments["record_path"] = record_path
    _emit("migration.validate", arguments, project_root=project_root)


@migration_app.command("rollback-plan")
def migration_rollback_plan(
    record_path: str = typer.Option(..., "--record"),
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str = typer.Option(..., "--catalog"),
    runstore_path: str = typer.Option(..., "--runstore"),
    state_root: str = typer.Option(..., "--state-root"),
) -> None:
    """Dry-run rollback to the exact pre-migration snapshot."""

    arguments = _migration_arguments(project_root, catalog_path, runstore_path, state_root)
    arguments["record_path"] = record_path
    _emit("migration.rollback.plan", arguments, project_root=project_root)


@migration_app.command("rollback")
def migration_rollback(
    record_path: str = typer.Option(..., "--record"),
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str = typer.Option(..., "--catalog"),
    runstore_path: str = typer.Option(..., "--runstore"),
    state_root: str = typer.Option(..., "--state-root"),
    confirm: str | None = typer.Option(None, "--confirm"),
) -> None:
    """Restore the exact approved V1 snapshot if no post-migration drift exists."""

    arguments = _migration_arguments(project_root, catalog_path, runstore_path, state_root)
    arguments.update({"record_path": record_path, "confirmation_token": confirm})
    _emit("migration.rollback", arguments, project_root=project_root)


@app.command("discover")
def discover(resource_path: str = typer.Option(".", "--resource-path")) -> None:
    """Discover supported tools and resources using bounded read-only probes."""

    _emit("distribution.discover", {"resource_path": resource_path})


@app.command("mode")
def mode(mode_name: str = typer.Argument("BEGINNER")) -> None:
    """Show the BEGINNER, GUIDED, or EXPERT presentation policy."""

    _emit("distribution.presentation", {"mode": mode_name.upper()})


@app.command("setup")
def setup_integrations(
    project_root: str = typer.Option(..., "--project-root"),
    integration: Annotated[list[str] | None, typer.Option("--integration")] = None,
    apply: bool = typer.Option(False, "--apply"),
    confirm: str | None = typer.Option(None, "--confirm"),
) -> None:
    """Plan or explicitly apply project-owned integration configuration."""

    operation = "distribution.setup.apply" if apply else "distribution.setup.plan"
    _emit(
        operation,
        {"integration_ids": integration or ("manual",), "confirmation_token": confirm},
        project_root=project_root,
    )


@app.command("start")
def beginner_start(
    intent: str,
    project_root: str = typer.Option(..., "--project-root"),
    project_name: str | None = typer.Option(None, "--project-name"),
) -> None:
    """Start from a plain-language goal without YAML, PATH, or MCP configuration."""

    _emit(
        "beginner.start",
        {"intent": intent, "project_name": project_name},
        project_root=project_root,
    )


@app.command("install")
def install_command(
    install_root: str = typer.Option(..., "--install-root"),
    source_executable: str = typer.Option(sys.executable, "--source-executable"),
    apply: bool = typer.Option(False, "--apply"),
    confirm: str | None = typer.Option(None, "--confirm"),
    managed_service: bool = typer.Option(False, "--managed-service/--no-managed-service"),
    service_state_root: str | None = typer.Option(None, "--service-state-root"),
    service_id: str = typer.Option("artifex-managed-service", "--service-id"),
    service_readiness_timeout_seconds: int = typer.Option(
        30, "--service-readiness-timeout-seconds", min=1, max=300
    ),
) -> None:
    """Plan or install the current frozen executable with a managed manifest."""

    operation = "distribution.install" if apply else "distribution.install.plan"
    _emit(
        operation,
        {
            "source_executable": source_executable,
            "install_root": install_root,
            "confirmation_token": confirm,
            "managed_service": managed_service,
            "service_state_root": service_state_root,
            "service_id": service_id,
            "service_readiness_timeout_seconds": service_readiness_timeout_seconds,
        },
    )


@app.command("upgrade")
def upgrade_command(
    install_root: str = typer.Option(..., "--install-root"),
    source_executable: str = typer.Option(sys.executable, "--source-executable"),
    apply: bool = typer.Option(False, "--apply"),
    confirm: str | None = typer.Option(None, "--confirm"),
    managed_service: bool = typer.Option(False, "--managed-service/--no-managed-service"),
    service_state_root: str | None = typer.Option(None, "--service-state-root"),
    service_id: str = typer.Option("artifex-managed-service", "--service-id"),
    service_readiness_timeout_seconds: int = typer.Option(
        30, "--service-readiness-timeout-seconds", min=1, max=300
    ),
) -> None:
    """Plan or perform a backed-up, rollback-capable executable upgrade."""

    operation = "distribution.upgrade" if apply else "distribution.upgrade.plan"
    arguments: dict[str, Any] = {
        "install_root": install_root,
        "source_executable": source_executable,
        "managed_service": managed_service,
        "service_state_root": service_state_root,
        "service_id": service_id,
        "service_readiness_timeout_seconds": service_readiness_timeout_seconds,
    }
    if apply:
        arguments["confirmation_token"] = confirm
    _emit(operation, arguments)


@app.command("uninstall")
def uninstall_command(
    install_root: str = typer.Option(..., "--install-root"),
    apply: bool = typer.Option(False, "--apply"),
    confirm: str | None = typer.Option(None, "--confirm"),
    managed_service: bool = typer.Option(False, "--managed-service/--no-managed-service"),
    service_id: str = typer.Option("artifex-managed-service", "--service-id"),
    service_readiness_timeout_seconds: int = typer.Option(
        30, "--service-readiness-timeout-seconds", min=1, max=300
    ),
) -> None:
    """Plan or remove only checksum-verified, manifest-owned files."""

    operation = "distribution.uninstall" if apply else "distribution.uninstall.plan"
    _emit(
        operation,
        {
            "install_root": install_root,
            "confirmation_token": confirm,
            "managed_service": managed_service,
            "service_id": service_id,
            "service_readiness_timeout_seconds": service_readiness_timeout_seconds,
        },
    )


@app.command("_installer-lifecycle", hidden=True)
def installer_lifecycle_command(
    action: str = typer.Argument(...),
    install_root: str = typer.Option(..., "--install-root"),
    source_executable: str | None = typer.Option(None, "--source-executable"),
    service_state_root: str | None = typer.Option(None, "--service-state-root"),
    consent: bool = typer.Option(False, "--consent"),
) -> None:
    """Apply the authenticated lifecycle after explicit enclosing installer consent."""

    if not consent:
        raise typer.BadParameter("explicit enclosing installer consent is required")
    from artifex.distribution.windows_installer import apply_installer, remove_installer

    if action == "install":
        if source_executable is None or service_state_root is None:
            raise typer.BadParameter(
                "install requires source executable and service state root"
            )
        result = apply_installer(source_executable, install_root, service_state_root)
    elif action == "uninstall":
        result = remove_installer(install_root)
    else:
        raise typer.BadParameter("installer lifecycle action must be install or uninstall")
    typer.echo(json.dumps({"ok": True, "value": result}, sort_keys=True))


@app.command("_complete-lifecycle", hidden=True)
def complete_uninstall_command(
    request_file: str = typer.Option(..., "--request-file"),
    parent_pid: int = typer.Option(..., "--parent-pid"),
) -> None:
    """Complete an authenticated lifecycle operation after its parent exits."""

    # The signed request is authoritative; the duplicated PID option prevents
    # accidental invocation with a different process identity.
    value = json.loads(Path(request_file).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("parent_pid") != parent_pid:
        raise typer.BadParameter("parent PID does not match signed request")
    try:
        result = complete_deferred_uninstall(request_file)
    except Exception as exc:
        failure_path = Path(request_file).with_suffix(".failure.json")
        failure_path.write_text(
            json.dumps(
                {
                    "schema_version": "artifex.deferred-lifecycle-failure/v1",
                    "exception_type": type(exc).__name__,
                    "detail": scrub_secrets(str(exc))[:500],
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        raise
    typer.echo(json.dumps(result, sort_keys=True, ensure_ascii=False))


@app.command("call")
def call_operation(
    operation: str,
    arguments: str = typer.Option("{}", "--arguments"),
    project_root: str | None = typer.Option(None, "--project-root"),
) -> None:
    """Call any semantic Application operation using a JSON argument object."""

    try:
        value = json.loads(arguments)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"arguments are not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise typer.BadParameter("arguments must be a JSON object")
    _emit(operation, value, project_root=project_root)


@integration_app.command("list")
def integration_list() -> None:
    """List metadata, compatibility, capabilities, and health."""

    _emit("integrations.list")


@integration_app.command("health")
def integration_health(integration_id: str) -> None:
    """Report one integration's normalized health."""

    _emit("integrations.health", {"integration_id": integration_id})


@integration_app.command("select")
def integration_select(
    role: str,
    capability: Annotated[list[str] | None, typer.Option("--capability")] = None,
    integration_id: str | None = typer.Option(None, "--integration-id"),
    preferred: Annotated[list[str] | None, typer.Option("--preferred")] = None,
    allowed: Annotated[list[str] | None, typer.Option("--allowed")] = None,
    allow_fallback: bool = typer.Option(True, "--allow-fallback/--no-fallback"),
) -> None:
    """Apply explicit capability-based selection policy."""

    arguments: dict[str, Any] = {
        "role": role,
        "capabilities": capability or [],
        "preferred_integrations": preferred or [],
        "allowed_integrations": allowed or [],
        "allow_fallback": allow_fallback,
    }
    if integration_id is not None:
        arguments["integration_id"] = integration_id
    _emit("integrations.select", arguments)


@integration_app.command("conformance")
def integration_conformance(integration_id: str = typer.Argument("manual")) -> None:
    """Run the integration conformance harness."""

    _emit("integrations.conformance", {"integration_id": integration_id})


@client_app.command("plan")
def client_plan(
    client: str,
    project_root: str = typer.Option(..., "--project-root"),
    bridge_executable: str = typer.Option(..., "--bridge-executable"),
    config_root: str | None = typer.Option(None, "--config-root"),
) -> None:
    """Show exact Codex or Claude changes and issue a bounded approval token."""

    arguments: dict[str, Any] = {
        "client": client,
        "bridge_command": [bridge_executable],
    }
    if config_root is not None:
        arguments["config_root"] = config_root
    _emit("clients.enable.plan", arguments, project_root=project_root)


@client_app.command("apply")
def client_apply(
    plan_path: Annotated[Path, typer.Option("--plan")],
    confirm: str = typer.Option(..., "--confirm"),
    receipt_root: str | None = typer.Option(None, "--receipt-root"),
) -> None:
    """Apply an unchanged approved plan and persist a rollback receipt."""

    arguments: dict[str, Any] = {
        "plan": _load_object(plan_path),
        "confirmation_token": confirm,
    }
    if receipt_root is not None:
        arguments["receipt_root"] = receipt_root
    _emit("clients.enable.apply", arguments)


@client_app.command("doctor")
def client_doctor(
    client: str,
    project_root: str = typer.Option(..., "--project-root"),
    bridge_executable: str = typer.Option(..., "--bridge-executable"),
    config_root: str | None = typer.Option(None, "--config-root"),
) -> None:
    """Check client detection, MCP registration, bridge health, and configured files."""

    arguments: dict[str, Any] = {
        "client": client,
        "bridge_command": [bridge_executable],
    }
    if config_root is not None:
        arguments["config_root"] = config_root
    _emit("clients.verify", arguments, project_root=project_root)


@client_app.command("rollback-plan")
def client_rollback_plan(receipt: str = typer.Option(..., "--receipt")) -> None:
    """Show rollback changes and issue a separate bounded approval token."""

    _emit("clients.rollback.plan", {"receipt_path": receipt})


@client_app.command("rollback")
def client_rollback(
    plan_path: Annotated[Path, typer.Option("--plan")],
    confirm: str = typer.Option(..., "--confirm"),
) -> None:
    """Remove only unchanged ARTIFEX-managed client configuration."""

    _emit(
        "clients.rollback.apply",
        {"plan": _load_object(plan_path), "confirmation_token": confirm},
    )


@project_app.command("status")
def project_status(
    project_root: str = typer.Option(..., "--project-root"),
    integration_id: str = typer.Option("manual", "--integration-id"),
) -> None:
    """Read inspectable project status through an integration."""

    _emit(
        "project.status",
        {"integration_id": integration_id},
        project_root=project_root,
    )


@project_app.command("create")
def project_create(
    name: str,
    project_root: str = typer.Option(..., "--project-root"),
    catalog_path: str | None = typer.Option(None, "--catalog"),
    project_id: str | None = typer.Option(None, "--project-id"),
    description: str = typer.Option("", "--description"),
) -> None:
    """Create and catalog a Project with its first accepted semantic revision."""

    arguments: dict[str, Any] = {
        "name": name,
        "project_id": project_id,
        "description": description,
    }
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("project.create", arguments, project_root=project_root)


@project_app.command("adopt")
def project_adopt(
    project_root: str = typer.Option(..., "--project-root"),
    name: str | None = typer.Option(None, "--name"),
    catalog_path: str | None = typer.Option(None, "--catalog"),
    project_id: str | None = typer.Option(None, "--project-id"),
) -> None:
    """Non-destructively adopt a V1 or brownfield Project into the Catalog."""

    arguments: dict[str, Any] = {"name": name, "project_id": project_id}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("project.adopt", arguments, project_root=project_root)


@project_app.command("continue")
def project_continue(
    name: str,
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Continue a cataloged Project by name without supplying its path."""

    arguments = {"name": name}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("project.continue", arguments)


@project_app.command("propose")
def project_propose(
    name: str,
    model_file: Path,
    expected_revision: int = typer.Option(..., "--expected-revision"),
    catalog_path: str | None = typer.Option(None, "--catalog"),
    source: str = typer.Option("CLIENT", "--source"),
) -> None:
    """Create a semantic proposal without accepting it."""

    arguments: dict[str, Any] = {
        "name": name,
        "model": _load_object(model_file),
        "expected_revision": expected_revision,
        "source": source,
    }
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("project.propose", arguments)


@project_app.command("accept")
def project_accept(
    name: str,
    proposal_id: str,
    expected_revision: int = typer.Option(..., "--expected-revision"),
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Accept a proposal through Project Authority with optimistic revision checking."""

    arguments: dict[str, Any] = {
        "name": name,
        "proposal_id": proposal_id,
        "expected_revision": expected_revision,
    }
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("project.accept", arguments)


@project_app.command("observe")
def project_observe(
    name: str,
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Record external repository mutation as a proposal, never acceptance."""

    arguments = {"name": name}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("project.observe", arguments)


@reality_app.command("state")
def reality_state(
    name: str,
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Read sourced observations and unresolved divergences."""

    arguments = {"name": name}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("reality.state", arguments)


@documentation_app.command("status")
def documentation_status(
    name: str,
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Classify generated Project documentation as CURRENT, STALE, or MISSING."""

    arguments = {"name": name}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("documentation.status", arguments)


@documentation_app.command("regenerate")
def documentation_regenerate(
    name: str,
    document: Annotated[list[str] | None, typer.Option("--document")] = None,
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Regenerate only the requested or currently affected documents."""

    arguments: dict[str, Any] = {"name": name, "documents": document or []}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("documentation.regenerate", arguments)


@dashboard_app.command("project")
def dashboard_project(
    name: str,
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Rebuild and read one Project operational dashboard."""

    arguments = {"name": name}
    if catalog_path is not None:
        arguments["catalog_path"] = catalog_path
    _emit("dashboard.project", arguments)


@dashboard_app.command("platform")
def dashboard_platform(
    catalog_path: str | None = typer.Option(None, "--catalog"),
) -> None:
    """Read the catalog-backed Platform operational dashboard."""

    arguments = {} if catalog_path is None else {"catalog_path": catalog_path}
    _emit("dashboard.platform", arguments)


@dashboard_app.command("launch")
def dashboard_launch(
    catalog_path: str | None = typer.Option(None, "--catalog"),
    state_root: str | None = typer.Option(None, "--state-root"),
    port: int = typer.Option(0, "--port", min=0, max=65535),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser"),
) -> None:
    """Launch the authenticated, loopback-only ARTIFEX Platform Dashboard."""

    from artifex.platform_dashboard import launch_dashboard

    launch_dashboard(
        catalog_path=catalog_path,
        state_root=state_root,
        port=port,
        open_browser=open_browser,
    )


@manual_app.command("packet-create")
def manual_packet_create(arguments_file: Path) -> None:
    """Create a portable execution packet from a JSON argument object."""

    _emit("manual.packet.create", _load_object(arguments_file))


@manual_app.command("result-submit")
def manual_result_submit(arguments_file: Path) -> None:
    """Classify a manual result without granting canonical acceptance."""

    _emit("manual.result.submit", _load_object(arguments_file))


@research_app.command("request-validate")
def research_request_validate(request_file: Path) -> None:
    """Validate and normalize a ResearchRequest JSON document."""

    _emit("research.request.validate", {"request": _load_object(request_file)})


@research_app.command("bundle-validate")
def research_bundle_validate(bundle_file: Path) -> None:
    """Validate a ResearchBundle without treating it as a Core decision."""

    _emit("research.bundle.validate", {"bundle": _load_object(bundle_file)})


@pandora_app.command("readiness")
def pandora_readiness(
    exchange_root: str = typer.Option(..., "--exchange-root"),
) -> None:
    """Report contract identity separately from live RESEARCH certification."""

    _emit("research.pandora.readiness", {"exchange_root": exchange_root})


@pandora_app.command("request")
def pandora_request(
    request_file: Path,
    exchange_root: str = typer.Option(..., "--exchange-root"),
) -> None:
    """Atomically export one provider-neutral request to Pandora."""

    _emit(
        "research.pandora.request",
        {"exchange_root": exchange_root, "request": _load_object(request_file)},
    )


@pandora_app.command("import")
def pandora_import(
    request_file: Path,
    exchange_root: str = typer.Option(..., "--exchange-root"),
) -> None:
    """Import validated evidence without mutating Project truth."""

    _emit(
        "research.pandora.import",
        {"exchange_root": exchange_root, "request": _load_object(request_file)},
    )


@pandora_app.command("propose-adoption")
def pandora_propose_adoption(
    request_file: Path,
    project_root: str = typer.Option(..., "--project-root"),
    exchange_root: str = typer.Option(..., "--exchange-root"),
    expected_revision: int = typer.Option(..., "--expected-revision"),
) -> None:
    """Create a Project Authority proposal; acceptance remains a separate command."""

    _emit(
        "research.pandora.adoption.propose",
        {
            "exchange_root": exchange_root,
            "request": _load_object(request_file),
            "expected_revision": expected_revision,
        },
        project_root=project_root,
    )


if __name__ == "__main__":
    app()

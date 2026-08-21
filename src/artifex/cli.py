"""Semantic command-line transport over the ARTIFEX Application API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from artifex.application import Application, OperationContext, OperationRequest

app = typer.Typer(help="ARTIFEX development continuity and validation control plane.")
system_app = typer.Typer(help="Inspect the ARTIFEX installation.")
integration_app = typer.Typer(help="Inspect and select replaceable integrations.")
manual_app = typer.Typer(help="Exchange portable manual execution packets and results.")
project_app = typer.Typer(help="Read semantic project state.")
research_app = typer.Typer(help="Validate provider-neutral research contracts.")
app.add_typer(system_app, name="system")
app.add_typer(integration_app, name="integration")
app.add_typer(manual_app, name="manual")
app.add_typer(project_app, name="project")
app.add_typer(research_app, name="research")


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


@app.command("doctor")
def doctor(project_root: str | None = typer.Option(None, "--project-root")) -> None:
    """Run non-mutating environment and integration diagnostics."""

    _emit("system.doctor", project_root=project_root)


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


if __name__ == "__main__":
    app()

"""Command-line transport over the ARTIFEX Application API."""

from __future__ import annotations

import json

import typer

from artifex.application import Application, OperationRequest

app = typer.Typer(help="ARTIFEX development continuity and validation control plane.")
system_app = typer.Typer(help="Inspect the ARTIFEX installation.")
app.add_typer(system_app, name="system")


def _emit(operation: str) -> None:
    result = Application().dispatch(OperationRequest(operation))
    payload = {"ok": result.ok, "value": dict(result.value)}
    if result.error is not None:
        payload["error"] = {
            "code": result.error.code,
            "message": result.error.message,
            "details": dict(result.error.details),
        }
    typer.echo(json.dumps(payload, sort_keys=True))
    if not result.ok:
        raise typer.Exit(1)


@system_app.command("health")
def system_health() -> None:
    """Report normalized Core health."""

    _emit("system.health")


@system_app.command("version")
def system_version() -> None:
    """Report the installed Core version."""

    _emit("system.version")


if __name__ == "__main__":
    app()

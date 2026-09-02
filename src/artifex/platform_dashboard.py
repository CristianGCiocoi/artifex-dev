"""Loopback-only user interface over ARTIFEX's semantic Application API.

The Platform Dashboard is deliberately a client and projection.  Project creation,
adoption, provider opt-in and projection refreshes are dispatched through the same
Application boundary as the CLI and MCP transports; this module is never a semantic
authority.
"""

# HTML and CSS are intentionally kept as self-contained shipping assets.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import base64
import html
import json
import secrets
import sqlite3
import sys
import webbrowser
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from artifex.application import Application, OperationContext, OperationRequest, OperationResult
from artifex.distribution.client_setup import (
    ClientConfigurationError,
    discover_bridge_command,
)
from artifex.managed_service import LocalServiceClient, ServicePaths
from artifex.project import default_catalog_path

_MAX_REQUEST_BYTES = 64 * 1024
_ACTIVE_RUN_STATES = frozenset({"ACTIVE", "RUNNING", "WAITING_RECONCILIATION"})


@dataclass(frozen=True, slots=True)
class DashboardConfig:
    """Resolved inputs for one local dashboard process."""

    catalog_path: Path
    state_root: Path
    host: str = "127.0.0.1"
    port: int = 0

    @classmethod
    def resolve(
        cls,
        *,
        catalog_path: str | Path | None = None,
        state_root: str | Path | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> DashboardConfig:
        if host != "127.0.0.1":
            raise ValueError("Platform Dashboard must bind to IPv4 loopback")
        if not 0 <= port <= 65535:
            raise ValueError("dashboard port must be between 0 and 65535")
        service_paths = ServicePaths.resolve(state_root)
        selected_catalog = (
            Path(catalog_path).expanduser().resolve()
            if catalog_path is not None
            else default_catalog_path().resolve()
        )
        return cls(selected_catalog, service_paths.state_root, host, port)


class PlatformDashboard:
    """Friendly rendering and action composition over existing authorities."""

    def __init__(
        self,
        config: DashboardConfig,
        *,
        application: Application | None = None,
        bridge_executable: str | Path | None = None,
    ) -> None:
        self.config = config
        self.application = application or Application()
        self.bridge_executable = bridge_executable

    def snapshot(self) -> dict[str, Any]:
        version = self._dispatch("system.version")
        platform = self._dispatch(
            "dashboard.platform", {"catalog_path": str(self.config.catalog_path)}
        )
        projects = list(platform.get("projects", []))
        service = self._service_status()
        providers = self._provider_status(projects)
        runs = self._runtime_activity()
        issues = self._issues(service, providers, projects)
        installation = self._installation_status()
        return {
            "version": version,
            "service": service,
            "state_root": str(self.config.state_root),
            "catalog_path": str(self.config.catalog_path),
            "projects": projects,
            "providers": providers,
            "activity": runs,
            "issues": issues,
            "installation": installation,
        }

    def create_project(self, form: Mapping[str, str]) -> str:
        root = _project_root_form(form)
        name = _required_form(form, "name")
        self._dispatch(
            "project.create",
            {
                "name": name,
                "description": form.get("description", ""),
                "catalog_path": str(self.config.catalog_path),
            },
            project_root=root,
        )
        return name

    def import_project(self, form: Mapping[str, str]) -> str:
        root = _project_root_form(form)
        name = form.get("name", "").strip() or None
        value = self._dispatch(
            "project.adopt",
            {
                "name": name,
                "catalog_path": str(self.config.catalog_path),
            },
            project_root=root,
        )
        project = value.get("project", {})
        return str(project.get("name", name or Path(root).name))

    def project_dashboard(self, name: str) -> str:
        self._dispatch(
            "dashboard.project",
            {"name": name, "catalog_path": str(self.config.catalog_path)},
        )
        platform = self._dispatch(
            "dashboard.platform", {"catalog_path": str(self.config.catalog_path)}
        )
        for project in platform.get("projects", []):
            if str(project.get("primary_name")) != name:
                continue
            locations = project.get("locations", [])
            if locations:
                path = Path(str(locations[0])) / ".artifex" / "dashboard" / "index.html"
                try:
                    return path.read_text(encoding="utf-8")
                except OSError as exc:
                    raise DashboardActionError(
                        "Project Dashboard could not be opened",
                        f"The projection was refreshed, but {path} is not readable.",
                        "Check that the Project location is available, then try again.",
                    ) from exc
        raise DashboardActionError(
            "Project is not available",
            f"ARTIFEX could not find {name!r} in the current Project Catalog.",
            "Return to the Platform Dashboard and import the Project again.",
        )

    def plan_provider(self, form: Mapping[str, str]) -> dict[str, Any]:
        provider = _required_form(form, "provider")
        if provider not in {"codex", "claude"}:
            raise DashboardActionError(
                "Unsupported Core provider",
                f"{provider!r} is not a Core provider onboarding target.",
                "Choose Codex or Claude.",
            )
        project_root = _required_form(form, "project_root")
        value = self._dispatch(
            "distribution.setup.plan",
            {"integration_ids": [provider]},
            project_root=project_root,
        )
        client_plan = self._dispatch(
            "clients.enable.plan",
            {
                "client": provider,
                "bridge_command": list(self._bridge_command()),
            },
            project_root=project_root,
        )
        return {
            "provider": provider,
            "project_root": project_root,
            "distribution_plan": value,
            "client_plan": client_plan,
        }

    def apply_provider(self, form: Mapping[str, str]) -> str:
        provider = _required_form(form, "provider")
        project_root = _required_form(form, "project_root")
        distribution_token = _required_form(form, "distribution_token")
        client_token = _required_form(form, "client_token")
        client_plan = _decode_plan(_required_form(form, "client_plan"))
        if client_plan.get("client") != provider or client_plan.get("project_root") != project_root:
            raise DashboardActionError(
                "Provider approval no longer matches",
                "The submitted configuration plan does not match this Project and provider.",
                "Return to the Platform Dashboard and review a new plan.",
            )
        self._dispatch(
            "distribution.setup.apply",
            {
                "integration_ids": [provider],
                "confirmation_token": distribution_token,
            },
            project_root=project_root,
        )
        receipt = self._dispatch(
            "clients.enable.apply",
            {"plan": client_plan, "confirmation_token": client_token},
            project_root=project_root,
        )
        verification = receipt.get("verification", {})
        if not isinstance(verification, Mapping) or verification.get("status") != "READY":
            detail = "; ".join(str(item) for item in verification.get("diagnostics", []))
            raise DashboardActionError(
                f"{provider.title()} needs attention",
                detail or "ARTIFEX applied the approved files but the live client verification did not pass.",
                "Open diagnostics, correct the discovered client state, then review and apply a fresh plan.",
            )
        return provider

    def _bridge_command(self) -> tuple[str, ...]:
        candidate = self.bridge_executable
        if candidate is None and Path(sys.executable).name.casefold() in {
            "artifex",
            "artifex.exe",
        }:
            candidate = sys.executable
        try:
            return discover_bridge_command(candidate)
        except ClientConfigurationError as exc:
            raise DashboardActionError(
                "Installed ARTIFEX bridge was not found",
                str(exc),
                "Repair the ARTIFEX installation, then reopen the Platform Dashboard.",
            ) from exc

    def render_home(self, *, notice: str | None = None) -> str:
        snapshot = self.snapshot()
        projects = snapshot["projects"]
        project_rows = "".join(self._project_card(item) for item in projects)
        if not project_rows:
            project_rows = (
                '<div class="empty"><strong>No Projects yet.</strong>'
                " Add a new Project or import an existing repository below.</div>"
            )
        provider_rows = "".join(self._provider_card(item, projects) for item in snapshot["providers"])
        activity = snapshot["activity"]
        activity_rows = "".join(
            "<tr>"
            f"<td>{_h(item['kind'])}</td><td>{_h(item['id'])}</td>"
            f"<td><span class=\"pill neutral\">{_h(item['state'])}</span></td>"
            f"<td>{_h(item.get('project_id', ''))}</td>"
            "</tr>"
            for item in activity
        ) or '<tr><td colspan="4" class="muted">No recent runtime activity.</td></tr>'
        issues = snapshot["issues"]
        issue_rows = "".join(
            f'<li class="issue {"good" if item["level"] == "READY" else "warn"}">'
            f'<strong>{_h(item["title"])}</strong><span>{_h(item["detail"])}</span></li>'
            for item in issues
        )
        service = snapshot["service"]
        service_ready = service["status"] == "READY"
        notice_html = f'<div class="notice">{_h(notice)}</div>' if notice else ""
        body = f"""
<header><div><p class="eyebrow">ARTIFEX PLATFORM</p><h1>Your work, in one place.</h1>
<p class="lede">Projects, providers, Runs and readiness — projected from ARTIFEX authorities.</p><p><a class="text-link" href="/help">Quick Start and provider help</a></p></div>
<div class="version">ARTIFEX <strong>{_h(_version_label(snapshot['version']))}</strong></div></header>
{notice_html}
<section class="status-grid">
  <article><span>Managed service</span><strong class="{'ready' if service_ready else 'attention'}">{_h(service['status'])}</strong><small>{_h(service['detail'])}</small></article>
  <article><span>Canonical state</span><strong>DISCOVERED</strong><small title="{_h(snapshot['state_root'])}">{_h(snapshot['state_root'])}</small></article>
  <article><span>Projects</span><strong>{len(projects)}</strong><small>{sum(bool(p.get('reachable')) for p in projects)} reachable</small></article>
  <article><span>Readiness</span><strong class="{'ready' if not any(i['level'] == 'ACTION' for i in issues) else 'attention'}">{'READY' if not any(i['level'] == 'ACTION' for i in issues) else 'ACTION NEEDED'}</strong><small>See diagnostics below</small></article>
</section>
<main>
<section><div class="section-head"><div><p class="eyebrow">PROJECT CATALOG</p><h2>Projects</h2></div><a class="text-link" href="#add-project">Add or import</a></div><div class="cards">{project_rows}</div></section>
<section><div class="section-head"><div><p class="eyebrow">CORE PROVIDERS</p><h2>Codex and Claude</h2></div></div><div class="cards providers">{provider_rows}</div></section>
<section><div class="section-head"><div><p class="eyebrow">EXECUTION</p><h2>Active and recent work</h2></div></div>
<div class="table-wrap"><table><thead><tr><th>Type</th><th>Identifier</th><th>State</th><th>Project</th></tr></thead><tbody>{activity_rows}</tbody></table></div></section>
<section class="split" id="add-project"><div><p class="eyebrow">START SOMETHING</p><h2>Add Project</h2><p>Create an ARTIFEX Project at an empty location.</p>
<form method="post" action="/actions/projects/create">{_csrf_input()}<label>Name<input name="name" required maxlength="160" placeholder="My Project"></label><label>Location<input name="project_root" required placeholder="C:\\Projects\\my-project"></label><label>Description<input name="description" maxlength="500" placeholder="What this Project is for"></label><button type="submit">Add Project</button></form></div>
<div><p class="eyebrow">BRING EXISTING WORK</p><h2>Import Project</h2><p>Adopt a repository non-destructively through Project Authority.</p>
<form method="post" action="/actions/projects/import">{_csrf_input()}<label>Location<input name="project_root" required placeholder="C:\\Projects\\existing-repo"></label><label>Name <span class="muted">(if not already known)</span><input name="name" maxlength="160"></label><button type="submit">Import Project</button></form></div></section>
<section id="diagnostics"><div class="section-head"><div><p class="eyebrow">READINESS</p><h2>Diagnostics</h2></div><a class="text-link" href="/diagnostics">Open detailed diagnostics</a></div><ul class="issues">{issue_rows}</ul></section>
</main>
"""
        return _page("ARTIFEX Platform", body)

    def render_provider_plan(self, value: Mapping[str, Any]) -> str:
        distribution_plan = value["distribution_plan"]
        client_plan = value["client_plan"]
        distribution_decision = (
            distribution_plan.get("decision", {})
            if isinstance(distribution_plan, Mapping)
            else {}
        )
        client_decision = (
            client_plan.get("decision", {}) if isinstance(client_plan, Mapping) else {}
        )
        distribution_effects = distribution_decision.get("effects", [])
        mutations = client_plan.get("mutations", []) if isinstance(client_plan, Mapping) else []
        rows = "".join(f"<li>{_h(item)}</li>" for item in distribution_effects)
        rows += "".join(
            f"<li><strong>{_h(item.get('action', 'CHANGE'))}</strong> "
            f"{_h(item.get('path', ''))} — {_h(item.get('effect', ''))}</li>"
            for item in mutations
            if isinstance(item, Mapping)
        )
        distribution_token = str(distribution_decision.get("confirmation_token", ""))
        client_token = str(client_decision.get("confirmation_token", ""))
        expiry = str(client_decision.get("expires_at", ""))
        encoded_plan = _encode_plan(client_plan)
        body = f"""
<main class="narrow"><a class="back" href="/">← Platform Dashboard</a><p class="eyebrow">REVIEW CHANGES</p>
<h1>Enable {_h(str(value['provider']).title())}</h1><p class="lede">Nothing has been changed yet.</p>
<div class="review"><h2>ARTIFEX plans to</h2><ul>{rows}</ul><p><strong>Rollback:</strong> {_h(client_decision.get('rollback', 'Restore the previous configuration.'))}</p><p class="muted">Approval expires {_h(expiry)}.</p></div>
<form method="post" action="/actions/providers/apply">{_csrf_input()}<input type="hidden" name="provider" value="{_h(value['provider'])}"><input type="hidden" name="project_root" value="{_h(value['project_root'])}"><input type="hidden" name="distribution_token" value="{_h(distribution_token)}"><input type="hidden" name="client_token" value="{_h(client_token)}"><input type="hidden" name="client_plan" value="{_h(encoded_plan)}"><button type="submit">Approve, apply and verify</button> <a class="button secondary" href="/">Cancel</a></form></main>"""
        return _page("Review provider changes", body)

    def render_diagnostics(self) -> str:
        snapshot = self.snapshot()
        installation = snapshot["installation"]
        installation_checks = "".join(
            f'<li class="issue {"good" if item.get("status") == "PASS" else "warn"}"><strong>{_h(item.get("id", "installation"))}: {_h(item.get("status", "UNKNOWN"))}</strong><span>{_h(item.get("detail", ""))}</span></li>'
            for item in installation.get("checks", [])
            if isinstance(item, Mapping)
        ) or '<li class="issue warn"><strong>Installation record unavailable</strong><span>No installation checks were returned.</span></li>'
        client_checks = "".join(
            f'<li class="issue {"good" if item.get("state") == "READY" else "warn"}"><strong>{_h(str(item.get("id", "client")).title())}: {_h(item.get("state", "UNKNOWN"))}</strong><span>{_h(item.get("detail", ""))}</span></li>'
            for item in snapshot["providers"]
        )
        body = f"""<main class="narrow"><a class="back" href="/">← Platform Dashboard</a><p class="eyebrow">INSTALLATION READINESS</p><h1>Diagnostics</h1>
<div class="review"><h2>Discovered state</h2><dl><dt>Version</dt><dd>{_h(_version_label(snapshot['version']))}</dd><dt>State root</dt><dd>{_h(snapshot['state_root'])}</dd><dt>Project Catalog</dt><dd>{_h(snapshot['catalog_path'])}</dd><dt>Managed service</dt><dd>{_h(snapshot['service']['status'])} — {_h(snapshot['service']['detail'])}</dd><dt>Dashboard</dt><dd>READY — authenticated loopback surface</dd></dl></div>
<h2>Installation doctor — {_h(installation.get('status', 'UNKNOWN'))}</h2><ul class="issues">{installation_checks}</ul>
<h2>Client doctors</h2><ul class="issues">{client_checks}</ul>
<h2>Recommended actions</h2><ul class="issues">{''.join(f'<li class="issue"><strong>{_h(i["title"])}</strong><span>{_h(i["detail"])}</span></li>' for i in snapshot['issues'])}</ul>
<p><a class="button secondary" href="/diagnostics.json">Export diagnostic report</a></p></main>"""
        return _page("ARTIFEX diagnostics", body)

    def render_help(self) -> str:
        body = """<main class="narrow"><a class="back" href="/">← Platform Dashboard</a><p class="eyebrow">QUICK START</p><h1>Get ready without a terminal</h1>
<div class="review"><ol><li>Confirm the managed service is READY.</li><li>Add a new Project or import an existing repository.</li><li>Open its Project Dashboard from the Project card.</li><li>Choose Codex or Claude, review every planned change and rollback action, then approve.</li><li>Open Diagnostics and verify the client, installed MCP bridge and persistent receipt.</li></ol></div>
<h2 id="codex">Codex</h2><p>Codex Desktop and Codex CLI are separate client forms. Follow the detected-client guidance; never repair detection by weakening PowerShell policy or manually editing PATH.</p>
<h2 id="claude">Claude</h2><p>Claude uses its public MCP configuration and the installed standalone ARTIFEX bridge. Authenticate in Claude itself; ARTIFEX does not collect provider credentials.</p>
<h2>Troubleshooting</h2><p>Availability, configuration, authentication, live verification and role certification are separate states. Open Diagnostics for the discovered state and proposed repair. Cancel a setup plan to leave vendor configuration unchanged.</p>
<p class="muted">The Platform Dashboard is the installed product UI. The implementation dashboard is release-engineering evidence, not a Project control surface.</p></main>"""
        return _page("ARTIFEX Quick Start", body)

    def render_error(self, error: DashboardActionError) -> str:
        body = f"""<main class="narrow"><a class="back" href="/">← Platform Dashboard</a><p class="eyebrow">ACTION COULD NOT COMPLETE</p><h1>{_h(error.title)}</h1><div class="review error"><h2>What ARTIFEX found</h2><p>{_h(error.discovered)}</p><h2>Suggested repair</h2><p>{_h(error.repair)}</p></div><a class="button" href="/diagnostics">Open diagnostics</a></main>"""
        return _page(error.title, body)

    def _dispatch(
        self,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        project_root: str | None = None,
    ) -> dict[str, Any]:
        result = self.application.dispatch(
            OperationRequest(
                operation,
                dict(arguments or {}),
                OperationContext(project_root=project_root, actor="platform-dashboard"),
            )
        )
        if not result.ok:
            raise _friendly_operation_error(operation, result)
        return dict(result.value)

    def _service_status(self) -> dict[str, str]:
        try:
            result = LocalServiceClient(self.config.state_root, timeout_seconds=1.0).status()
            value = result.get("value")
            if result.get("ok") is not True or not isinstance(value, Mapping):
                raise ValueError("service status operation did not return a value")
            lifecycle = str(value.get("lifecycle_state", value.get("status", "RUNNING")))
            ready = value.get("ready", True) is not False and lifecycle in {"RUNNING", "PASS"}
            return {
                "status": "READY" if ready else "ACTION NEEDED",
                "detail": f"Service reports {lifecycle}.",
            }
        except Exception as exc:
            return {
                "status": "NOT READY",
                "detail": f"Managed service is unavailable ({type(exc).__name__}).",
            }

    def _installation_status(self) -> dict[str, Any]:
        try:
            return self._dispatch("distribution.installation.doctor")
        except DashboardActionError as exc:
            return {
                "status": "FAIL",
                "checks": [
                    {
                        "id": "installation-doctor",
                        "status": "FAIL",
                        "detail": exc.discovered,
                        "repair": exc.repair,
                    }
                ],
            }

    def _provider_status(self, projects: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        statuses: dict[str, dict[str, Any]] = {
            provider: {
                "id": provider,
                "state": "NOT CONFIGURED",
                "detail": "Choose a Project to review and enable this provider.",
                "project_root": None,
            }
            for provider in ("codex", "claude")
        }
        for project in projects:
            locations = project.get("locations", [])
            if not locations:
                continue
            root = str(locations[0])
            try:
                graph = self._dispatch("providers.graph", project_root=root).get("graph", {})
            except DashboardActionError:
                continue
            for provider in graph.get("providers", []):
                identifier = str(provider.get("provider_id", ""))
                if identifier not in statuses:
                    continue
                readiness = provider.get("readiness", {})
                graph_state = str(readiness.get("state", "CONFIGURED"))
                try:
                    verification = self._dispatch(
                        "clients.verify",
                        {
                            "client": identifier,
                            "bridge_command": list(self._bridge_command()),
                        },
                        project_root=root,
                    )
                except DashboardActionError as exc:
                    verification = {
                        "status": "NEEDS_ATTENTION",
                        "diagnostics": [exc.discovered],
                    }
                verification_state = str(verification.get("status", "NEEDS_ATTENTION"))
                diagnostics = verification.get("diagnostics", [])
                diagnostic_text = "; ".join(str(item) for item in diagnostics)
                state = "READY" if graph_state == "AVAILABLE" and verification_state == "READY" else "NEEDS ATTENTION"
                statuses[identifier] = {
                    "id": identifier,
                    "state": state,
                    "detail": (
                        f"Ready for {project.get('primary_name', 'Project')}."
                        if state == "READY"
                        else diagnostic_text
                        or f"Provider state is {graph_state}; client verification is {verification_state}."
                    ),
                    "project_root": root,
                    "graph_state": graph_state,
                    "verification": verification,
                }
        return list(statuses.values())

    def _runtime_activity(self) -> list[dict[str, str]]:
        path = self.config.state_root / "runstore.sqlite3"
        if not path.is_file():
            return []
        try:
            with closing(
                sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            ) as connection:
                connection.row_factory = sqlite3.Row
                rows: list[dict[str, str]] = []
                for query, kind in (
                    (
                        "SELECT run_id AS id, state, project_id, updated_at "
                        "FROM runs ORDER BY updated_at DESC LIMIT 8",
                        "Run",
                    ),
                    (
                        "SELECT j.project_job_id AS id, j.state, r.project_id, j.updated_at "
                        "FROM project_jobs j JOIN runs r ON r.run_id = j.run_id "
                        "ORDER BY j.updated_at DESC LIMIT 8",
                        "ProjectJob",
                    ),
                    (
                        "SELECT a.attempt_id AS id, a.state, r.project_id, a.updated_at "
                        "FROM attempts a JOIN project_jobs j "
                        "ON j.project_job_id = a.project_job_id "
                        "JOIN runs r ON r.run_id = j.run_id "
                        "ORDER BY a.updated_at DESC LIMIT 8",
                        "Attempt",
                    ),
                ):
                    for row in connection.execute(query):
                        rows.append(
                            {
                                "kind": kind,
                                "id": str(row["id"]),
                                "state": str(row["state"]),
                                "project_id": str(row["project_id"]),
                            }
                        )
            return sorted(
                rows,
                key=lambda item: item["state"] not in _ACTIVE_RUN_STATES,
            )[:12]
        except (OSError, sqlite3.DatabaseError):
            return []

    @staticmethod
    def _issues(
        service: Mapping[str, str],
        providers: Sequence[Mapping[str, Any]],
        projects: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, str]]:
        issues = []
        issues.append(
            {
                "level": "READY" if service["status"] == "READY" else "ACTION",
                "title": "Managed service",
                "detail": service["detail"],
            }
        )
        if not projects:
            issues.append(
                {
                    "level": "ACTION",
                    "title": "No Project is discoverable",
                    "detail": "Add or import a Project to continue onboarding.",
                }
            )
        for provider in providers:
            issues.append(
                {
                    "level": "READY" if provider["state"] == "READY" else "INFO",
                    "title": str(provider["id"]).title(),
                    "detail": str(provider["detail"]),
                }
            )
        return issues

    @staticmethod
    def _project_card(project: Mapping[str, Any]) -> str:
        name = str(project.get("primary_name", "Unnamed Project"))
        reachable = bool(project.get("reachable"))
        return f"""<article class="project-card"><div><span class="pill {'ready' if reachable else 'warn'}">{'REACHABLE' if reachable else 'UNREACHABLE'}</span><h3>{_h(name)}</h3><p>{_h(project.get('lifecycle', 'UNKNOWN'))} · revision {_h(project.get('semantic_revision', project.get('last_semantic_revision', '—')))}</p></div><a class="button" href="/projects/{quote(name, safe='')}/dashboard">Open Project Dashboard</a></article>"""

    @staticmethod
    def _provider_card(
        provider: Mapping[str, Any], projects: Sequence[Mapping[str, Any]]
    ) -> str:
        identifier = str(provider["id"])
        choices = "".join(
            f'<option value="{_h(str(item.get("locations", [""])[0]))}">{_h(item.get("primary_name", "Project"))}</option>'
            for item in projects
            if item.get("locations")
        )
        form = (
            f'<form method="post" action="/actions/providers/plan">{_csrf_input()}'
            f'<input type="hidden" name="provider" value="{_h(identifier)}">'
            f'<label>Project<select name="project_root" required>{choices}</select></label>'
            '<button type="submit">Review configuration</button></form>'
            if choices
            else '<p class="muted">Add a Project before configuring providers.</p>'
        )
        return f"""<article class="provider-card"><span class="pill neutral">{_h(provider['state'])}</span><h3>{_h(identifier.title())}</h3><p>{_h(provider['detail'])}</p><p><a class="text-link" href="/help#{_h(identifier)}">Setup and troubleshooting</a></p>{form}</article>"""


class DashboardActionError(RuntimeError):
    def __init__(self, title: str, discovered: str, repair: str) -> None:
        super().__init__(discovered)
        self.title = title
        self.discovered = discovered
        self.repair = repair


class DashboardHTTPServer(ThreadingHTTPServer):
    dashboard: PlatformDashboard
    authorization_token: str
    session_token: str
    csrf_token: str
    allowed_hosts: frozenset[str]


def create_dashboard_server(
    config: DashboardConfig,
    *,
    application: Application | None = None,
) -> DashboardHTTPServer:
    server = DashboardHTTPServer((config.host, config.port), _DashboardHandler)
    server.dashboard = PlatformDashboard(config, application=application)
    server.authorization_token = secrets.token_urlsafe(32)
    server.session_token = secrets.token_urlsafe(32)
    server.csrf_token = secrets.token_urlsafe(32)
    host, port = server.server_address[:2]
    host_text = host.decode() if isinstance(host, bytes) else str(host)
    server.allowed_hosts = frozenset(
        {
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
            f"{host_text}:{port}",
        }
    )
    return server


def launch_dashboard(
    *,
    catalog_path: str | Path | None = None,
    state_root: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
) -> None:
    """Run the authenticated local dashboard until interrupted."""

    config = DashboardConfig.resolve(
        catalog_path=catalog_path, state_root=state_root, host=host, port=port
    )
    server = create_dashboard_server(config)
    actual_host, actual_port = server.server_address[:2]
    browser_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else str(actual_host)
    url = f"http://{browser_host}:{actual_port}/?token={quote(server.authorization_token)}"
    if open_browser:
        webbrowser.open(url, new=1)
    print(f"ARTIFEX Platform Dashboard is available at http://{browser_host}:{actual_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Launch the ARTIFEX Platform Dashboard")
    parser.add_argument("--catalog")
    parser.add_argument("--state-root")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-browser", action="store_true")
    arguments = parser.parse_args(argv)
    launch_dashboard(
        catalog_path=arguments.catalog,
        state_root=arguments.state_root,
        port=arguments.port,
        open_browser=not arguments.no_browser,
    )


class _DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardHTTPServer

    def do_GET(self) -> None:
        if not self._valid_host():
            self._send_text(HTTPStatus.BAD_REQUEST, "Invalid Host header")
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/" and parse_qs(parsed.query).get("token") == [
            self.server.authorization_token
        ]:
            self.send_response(HTTPStatus.SEE_OTHER)
            self._security_headers()
            self.send_header(
                "Set-Cookie",
                f"artifex_dashboard={self.server.session_token}; HttpOnly; SameSite=Strict; Path=/",
            )
            self.send_header("Location", "/")
            self.end_headers()
            return
        if not self._authorized():
            self._send_text(HTTPStatus.UNAUTHORIZED, "ARTIFEX Dashboard authorization required")
            return
        try:
            if parsed.path == "/":
                notices = parse_qs(parsed.query).get("notice", [])
                notice = notices[-1][:240] if notices else None
                self._send_html(
                    HTTPStatus.OK, self.server.dashboard.render_home(notice=notice)
                )
            elif parsed.path == "/diagnostics":
                self._send_html(HTTPStatus.OK, self.server.dashboard.render_diagnostics())
            elif parsed.path == "/diagnostics.json":
                self._send_json(HTTPStatus.OK, self.server.dashboard.snapshot())
            elif parsed.path == "/help":
                self._send_html(HTTPStatus.OK, self.server.dashboard.render_help())
            elif parsed.path.startswith("/projects/") and parsed.path.endswith("/dashboard"):
                encoded = parsed.path[len("/projects/") : -len("/dashboard")].strip("/")
                self._send_html(
                    HTTPStatus.OK, self.server.dashboard.project_dashboard(unquote(encoded))
                )
            else:
                self._send_text(HTTPStatus.NOT_FOUND, "Not found")
        except DashboardActionError as exc:
            self._send_html(HTTPStatus.BAD_REQUEST, self.server.dashboard.render_error(exc))
        except Exception as exc:
            error = DashboardActionError(
                "Dashboard view is unavailable",
                f"ARTIFEX discovered {type(exc).__name__} while building this view.",
                "Open diagnostics and verify the managed service, state root and Project Catalog.",
            )
            self._send_html(HTTPStatus.INTERNAL_SERVER_ERROR, self.server.dashboard.render_error(error))

    def do_POST(self) -> None:
        if not self._valid_host() or not self._authorized():
            self._send_text(HTTPStatus.UNAUTHORIZED, "ARTIFEX Dashboard authorization required")
            return
        try:
            form = self._read_form()
            if form.pop("csrf_token", "") != self.server.csrf_token:
                self._send_text(HTTPStatus.FORBIDDEN, "Invalid dashboard request token")
                return
            if self.path == "/actions/projects/create":
                name = self.server.dashboard.create_project(form)
                self._redirect(f"/?notice={quote('Project added: ' + name)}")
            elif self.path == "/actions/projects/import":
                name = self.server.dashboard.import_project(form)
                self._redirect(f"/?notice={quote('Project imported: ' + name)}")
            elif self.path == "/actions/providers/plan":
                plan = self.server.dashboard.plan_provider(form)
                self._send_html(HTTPStatus.OK, self.server.dashboard.render_provider_plan(plan))
            elif self.path == "/actions/providers/apply":
                provider = self.server.dashboard.apply_provider(form)
                self._redirect(f"/?notice={quote(provider.title() + ' enabled for this Project')}")
            else:
                self._send_text(HTTPStatus.NOT_FOUND, "Not found")
        except DashboardActionError as exc:
            self._send_html(HTTPStatus.BAD_REQUEST, self.server.dashboard.render_error(exc))
        except Exception as exc:
            error = DashboardActionError(
                "ARTIFEX could not complete the action",
                f"The requested operation returned {type(exc).__name__}.",
                "Review the entered path and current readiness, then retry from the dashboard.",
            )
            self._send_html(HTTPStatus.BAD_REQUEST, self.server.dashboard.render_error(error))

    def log_message(self, format: str, *args: object) -> None:
        return

    def _read_form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise DashboardActionError(
                "Invalid request", "The request size was invalid.", "Return and retry the action."
            ) from exc
        if not 0 <= length <= _MAX_REQUEST_BYTES:
            raise DashboardActionError(
                "Request is too large",
                "The submitted form exceeded the local dashboard limit.",
                "Shorten the entered values and retry.",
            )
        raw = self.rfile.read(length).decode("utf-8", errors="strict")
        values = parse_qs(raw, keep_blank_values=True, max_num_fields=24)
        return {key: items[-1] for key, items in values.items() if items}

    def _valid_host(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _authorized(self) -> bool:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        value = cookie.get("artifex_dashboard")
        return value is not None and secrets.compare_digest(value.value, self.server.session_token)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self._security_headers()
        self.send_header("Location", location)
        self.end_headers()

    def _send_html(self, status: HTTPStatus, content: str) -> None:
        encoded = _inject_csrf(content, self.server.csrf_token).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_text(self, status: HTTPStatus, content: str) -> None:
        encoded = content.encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, status: HTTPStatus, content: Mapping[str, Any]) -> None:
        encoded = (json.dumps(content, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="artifex-diagnostics.json"')
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")


def _friendly_operation_error(operation: str, result: OperationResult) -> DashboardActionError:
    error = result.error
    message = error.message if error is not None else "The operation did not complete."
    error_type = str(error.details.get("type", "ARTIFEX error")) if error is not None else "ARTIFEX error"
    repairs = {
        "project.create": "Choose an empty writable location and a unique Project name.",
        "project.adopt": "Choose an accessible repository and provide a name when it has no ARTIFEX model.",
        "dashboard.project": "Verify that the Project remains reachable from its cataloged location.",
        "distribution.setup.plan": "Verify the Project is reachable, then review provider setup again.",
        "distribution.setup.apply": "Return to Review configuration and approve the newly issued exact plan.",
        "clients.enable.plan": "Verify the installed ARTIFEX bridge and client configuration locations, then review provider setup again.",
        "clients.enable.apply": "Return to Review configuration and approve a fresh exact client plan.",
    }
    return DashboardActionError(
        "ARTIFEX could not complete the action",
        f"{error_type}: {message}",
        repairs.get(operation, "Open diagnostics, correct the reported state, and retry."),
    )


def _required_form(form: Mapping[str, str], name: str) -> str:
    value = form.get(name, "").strip()
    if not value:
        raise DashboardActionError(
            "Required information is missing",
            f"The {name.replace('_', ' ')} field was empty.",
            "Complete the field and retry.",
        )
    return value


def _project_root_form(form: Mapping[str, str]) -> str:
    value = _required_form(form, "project_root")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise DashboardActionError(
            "Project location must be absolute",
            f"ARTIFEX received a relative location: {value}",
            "Choose a complete location such as C:\\Projects\\my-project.",
        )
    return str(path.resolve())


def _version_label(value: Mapping[str, Any]) -> str:
    return str(value.get("version", value.get("release", "unknown")))


def _encode_plan(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_plan(value: str) -> dict[str, Any]:
    try:
        payload = base64.urlsafe_b64decode(value.encode("ascii"))
        decoded = json.loads(payload)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise DashboardActionError(
            "Provider approval is invalid",
            "The submitted configuration plan could not be read.",
            "Return to the Platform Dashboard and review a fresh plan.",
        ) from exc
    if not isinstance(decoded, dict):
        raise DashboardActionError(
            "Provider approval is invalid",
            "The submitted configuration plan is not an ARTIFEX plan object.",
            "Return to the Platform Dashboard and review a fresh plan.",
        )
    return decoded


def _h(value: object) -> str:
    return html.escape(str(value), quote=True)


def _csrf_input() -> str:
    # The per-process value is replaced immediately before an HTTP response is sent.
    # Keeping a marker in renderers also makes the HTML independently testable.
    return '<input type="hidden" name="csrf_token" value="__ARTIFEX_CSRF__">'


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_h(title)}</title><style>
:root{{--ink:#171a21;--muted:#68707d;--paper:#f5f4ef;--panel:#fff;--line:#deddd6;--accent:#3c55d9;--green:#197049;--amber:#a45a11}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 Inter,Segoe UI,system-ui,sans-serif}}header,main{{max-width:1180px;margin:auto;padding:36px 28px}}header{{display:flex;justify-content:space-between;gap:30px;align-items:start;padding-top:58px}}h1{{font-size:clamp(34px,6vw,68px);line-height:1.02;letter-spacing:-.045em;margin:5px 0 14px}}h2{{font-size:28px;letter-spacing:-.025em;margin:4px 0 18px}}h3{{font-size:20px;margin:12px 0 4px}}p{{margin:5px 0 14px}}.eyebrow{{font-size:12px;font-weight:800;letter-spacing:.16em;color:var(--accent)}}.lede{{color:var(--muted);font-size:18px;max-width:700px}}.version{{background:var(--ink);color:#fff;border-radius:99px;padding:10px 17px;white-space:nowrap}}.status-grid{{max-width:1180px;margin:0 auto 12px;padding:0 28px;display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.status-grid article,.project-card,.provider-card,.review,.split>div{{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px}}.status-grid span,.status-grid small{{display:block;color:var(--muted)}}.status-grid strong{{display:block;font-size:20px;margin:6px 0}}.status-grid small{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}section{{margin:32px 0 52px}}.section-head{{display:flex;justify-content:space-between;align-items:end}}.cards{{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}}.project-card{{display:flex;justify-content:space-between;gap:18px;align-items:center}}.providers{{grid-template-columns:repeat(2,1fr)}}.pill{{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.08em;padding:5px 9px;border-radius:99px;background:#e6f5ed;color:var(--green)}}.pill.warn{{background:#fff0dd;color:var(--amber)}}.pill.neutral{{background:#e9ebf5;color:#4e5877}}.ready{{color:var(--green)}}.attention{{color:var(--amber)}}.button,button{{display:inline-block;border:0;border-radius:9px;background:var(--accent);color:white;padding:10px 14px;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}}.secondary{{background:#e9e9e5;color:var(--ink)}}.text-link,.back{{color:var(--accent);font-weight:700;text-decoration:none}}form{{display:grid;gap:12px;margin-top:18px}}label{{display:grid;gap:5px;font-weight:700}}input,select{{width:100%;border:1px solid #c9c9c2;border-radius:9px;padding:10px 11px;background:#fff;font:inherit}}.split{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}.table-wrap{{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:18px}}table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:13px 16px;border-bottom:1px solid var(--line)}}th{{font-size:12px;letter-spacing:.08em}}.issues{{list-style:none;padding:0;display:grid;gap:9px}}.issue{{background:#fff;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 15px;display:grid}}.issue.good{{border-left-color:var(--green)}}.issue.warn{{border-left-color:var(--amber)}}.issue span,.muted{{color:var(--muted)}}.empty,.notice{{background:#fff;border:1px dashed #b9b8b1;padding:28px;border-radius:18px}}.notice{{max-width:1124px;margin:0 auto 20px;border-style:solid;border-color:#9bcfb2;background:#edf9f2}}.narrow{{max-width:780px;padding-top:60px}}.narrow h1{{font-size:48px}}.review{{margin:24px 0}}.review.error{{border-left:5px solid var(--amber)}}dl{{display:grid;grid-template-columns:150px 1fr;gap:10px}}dt{{font-weight:800}}dd{{margin:0;overflow-wrap:anywhere}}@media(max-width:800px){{header{{display:block}}.version{{display:inline-block;margin-top:14px}}.status-grid{{grid-template-columns:1fr 1fr}}.cards,.providers,.split{{grid-template-columns:1fr}}.project-card{{align-items:start;flex-direction:column}}}}@media(max-width:480px){{.status-grid{{grid-template-columns:1fr}}header,main{{padding-left:18px;padding-right:18px}}}}
</style></head><body>{body}</body></html>"""


def _inject_csrf(content: str, token: str) -> str:
    return content.replace("__ARTIFEX_CSRF__", _h(token))


if __name__ == "__main__":
    main()

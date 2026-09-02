from __future__ import annotations

import http.client
import sqlite3
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest
from typer.testing import CliRunner

from artifex.application import Application, OperationContext, OperationRequest
from artifex.cli import app
from artifex.platform_dashboard import (
    DashboardActionError,
    DashboardConfig,
    PlatformDashboard,
    create_dashboard_server,
)


def _request(
    server: object,
    method: str,
    path: str,
    *,
    cookie: str | None = None,
    body: str | None = None,
) -> tuple[int, dict[str, str], str]:
    host, port = server.server_address[:2]  # type: ignore[attr-defined]
    connection = http.client.HTTPConnection(host, port, timeout=30)
    headers = {"Host": f"127.0.0.1:{port}"}
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read().decode("utf-8")
    result = response.status, {key.lower(): value for key, value in response.getheaders()}, payload
    connection.close()
    return result


@pytest.fixture
def dashboard_server(tmp_path: Path):
    config = DashboardConfig.resolve(
        catalog_path=tmp_path / "catalog.sqlite3",
        state_root=tmp_path / "state",
    )
    server = create_dashboard_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.unit
def test_dashboard_rejects_non_loopback_bindings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="loopback"):
        DashboardConfig.resolve(
            catalog_path=tmp_path / "catalog.sqlite3",
            state_root=tmp_path / "state",
            host="0.0.0.0",
        )


@pytest.mark.unit
def test_windows_installer_entrypoint_launches_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def launch_dashboard(**kwargs: object) -> None:
        observed.update(kwargs)

    monkeypatch.setattr("artifex.platform_dashboard.launch_dashboard", launch_dashboard)
    result = CliRunner().invoke(app, ["dashboard", "--no-browser"])
    assert result.exit_code == 0, result.stdout
    assert observed["open_browser"] is False


@pytest.mark.integration
def test_dashboard_requires_bootstrap_token_and_authenticated_cookie(dashboard_server) -> None:
    status, _, _ = _request(dashboard_server, "GET", "/")
    assert status == 401

    status, headers, _ = _request(
        dashboard_server,
        "GET",
        f"/?token={dashboard_server.authorization_token}",
    )
    assert status == 303
    assert headers["location"] == "/"
    assert "HttpOnly" in headers["set-cookie"]
    assert "SameSite=Strict" in headers["set-cookie"]

    cookie = headers["set-cookie"].split(";", 1)[0]
    status, headers, body = _request(dashboard_server, "GET", "/", cookie=cookie)
    assert status == 200
    assert "ARTIFEX PLATFORM" in body
    assert "Add Project" in body
    assert "Import Project" in body
    assert "Content-Security-Policy".lower() in headers
    assert dashboard_server.csrf_token in body


@pytest.mark.integration
def test_non_cli_create_and_open_project_dashboard_flow(dashboard_server, tmp_path: Path) -> None:
    _, headers, _ = _request(
        dashboard_server,
        "GET",
        f"/?token={dashboard_server.authorization_token}",
    )
    cookie = headers["set-cookie"].split(";", 1)[0]
    project_root = tmp_path / "new-project"
    body = urlencode(
        {
            "csrf_token": dashboard_server.csrf_token,
            "name": "Dashboard Project",
            "project_root": str(project_root),
            "description": "Created without a terminal",
        }
    )
    status, headers, _ = _request(
        dashboard_server,
        "POST",
        "/actions/projects/create",
        cookie=cookie,
        body=body,
    )
    assert status == 303
    assert headers["location"].startswith("/?notice=")
    assert (project_root / ".artifex" / "dashboard" / "index.html").is_file()

    status, _, rendered = _request(
        dashboard_server,
        "GET",
        "/projects/Dashboard%20Project/dashboard",
        cookie=cookie,
    )
    assert status == 200
    assert "Dashboard Project" in rendered


@pytest.mark.integration
def test_provider_configuration_is_planned_and_approval_gated(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    root = tmp_path / "project"
    application = Application()
    created = application.dispatch(
        OperationRequest(
            "project.create",
            {"name": "Provider Project", "catalog_path": str(catalog)},
            OperationContext(project_root=str(root), actor="test"),
        )
    )
    assert created.ok
    dashboard = PlatformDashboard(
        DashboardConfig.resolve(catalog_path=catalog, state_root=tmp_path / "state"),
        application=application,
    )
    planned = dashboard.plan_provider({"provider": "codex", "project_root": str(root)})
    assert planned["plan"]["applied"] is False
    assert planned["plan"]["decision"]["approval_required"] is True
    assert not (root / ".artifex" / "integrations.json").exists()

    token = planned["plan"]["decision"]["confirmation_token"]
    assert dashboard.apply_provider(
        {
            "provider": "codex",
            "project_root": str(root),
            "confirmation_token": token,
        }
    ) == "codex"
    assert (root / ".artifex" / "integrations.json").is_file()


@pytest.mark.unit
def test_runtime_activity_is_a_read_only_runstore_projection(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    store = state / "runstore.sqlite3"
    with sqlite3.connect(store) as connection:
        connection.executescript(
            """
            CREATE TABLE runs (
                run_id TEXT, state TEXT, project_id TEXT, updated_at INTEGER
            );
            CREATE TABLE project_jobs (
                project_job_id TEXT, run_id TEXT, state TEXT, updated_at INTEGER
            );
            CREATE TABLE attempts (
                attempt_id TEXT, project_job_id TEXT, state TEXT, updated_at INTEGER
            );
            INSERT INTO runs VALUES ('run-1', 'RUNNING', 'project-1', 1);
            INSERT INTO project_jobs VALUES ('job-1', 'run-1', 'ACTIVE', 2);
            INSERT INTO attempts VALUES ('attempt-1', 'job-1', 'STARTED', 3);
            """
        )
    dashboard = PlatformDashboard(
        DashboardConfig.resolve(
            catalog_path=tmp_path / "catalog.sqlite3", state_root=state
        )
    )
    activity = dashboard.snapshot()["activity"]
    assert {(item["kind"], item["id"], item["project_id"]) for item in activity} == {
        ("Run", "run-1", "project-1"),
        ("ProjectJob", "job-1", "project-1"),
        ("Attempt", "attempt-1", "project-1"),
    }


@pytest.mark.unit
def test_project_dashboard_errors_are_friendly_and_do_not_leak_tracebacks(tmp_path: Path) -> None:
    dashboard = PlatformDashboard(
        DashboardConfig.resolve(
            catalog_path=tmp_path / "catalog.sqlite3", state_root=tmp_path / "state"
        )
    )
    try:
        dashboard.project_dashboard("Missing")
    except DashboardActionError as exc:
        rendered = dashboard.render_error(exc)
    else:
        raise AssertionError("missing Project must fail")
    assert "Suggested repair" in rendered
    assert "Traceback" not in rendered

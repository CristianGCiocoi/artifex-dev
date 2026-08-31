"""Durable instance-level Project Catalog authority."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from artifex.project.errors import CatalogConflictError, ProjectUnreachableError


def _alias_key(value: str) -> str:
    normalized = " ".join(value.split()).casefold()
    if not normalized:
        raise ValueError("Project name or alias must be non-empty")
    return normalized


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    project_id: str
    primary_name: str
    aliases: tuple[str, ...]
    locations: tuple[str, ...]
    location_mode: str
    lifecycle: str
    archived: bool
    last_semantic_revision: int
    runtime_association: str | None
    reachable: bool
    last_activity: str | None
    discovery_provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "primary_name": self.primary_name,
            "aliases": list(self.aliases),
            "locations": list(self.locations),
            "location_mode": self.location_mode,
            "lifecycle": self.lifecycle,
            "archived": self.archived,
            "last_semantic_revision": self.last_semantic_revision,
            "runtime_association": self.runtime_association,
            "reachable": self.reachable,
            "last_activity": self.last_activity,
            "discovery_provenance": self.discovery_provenance,
        }


class ProjectCatalog:
    """Catalog identity authority; never a store for Project semantic content."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def register(
        self,
        *,
        project_id: str,
        name: str,
        location: str | Path,
        lifecycle: str,
        last_semantic_revision: int,
        aliases: tuple[str, ...] = (),
        location_mode: str = "local",
        discovery_provenance: str = "explicit",
        last_activity: str | None = None,
    ) -> CatalogEntry:
        resolved_location = str(Path(location).expanduser().resolve())
        names = tuple(dict.fromkeys((name, *aliases)))
        with closing(self._connect()) as connection, connection:
            try:
                connection.execute(
                    """
                    INSERT INTO projects (
                        project_id, primary_name, location_mode, lifecycle, archived,
                        last_semantic_revision, runtime_association, reachable,
                        last_activity, discovery_provenance
                    ) VALUES (?, ?, ?, ?, 0, ?, NULL, 1, ?, ?)
                    """,
                    (
                        project_id,
                        name,
                        location_mode,
                        lifecycle,
                        last_semantic_revision,
                        last_activity,
                        discovery_provenance,
                    ),
                )
                connection.executemany(
                    "INSERT INTO aliases (alias_key, display_name, project_id) VALUES (?, ?, ?)",
                    [(_alias_key(alias), alias, project_id) for alias in names],
                )
                connection.execute(
                    "INSERT INTO locations (location, project_id, priority) VALUES (?, ?, 0)",
                    (resolved_location, project_id),
                )
            except sqlite3.IntegrityError as exc:
                raise CatalogConflictError(
                    "Project id, alias, or location already belongs to a catalog entry"
                ) from exc
        return self.get(project_id)

    def resolve(self, name_or_alias: str) -> CatalogEntry:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT project_id FROM aliases WHERE alias_key = ?",
                (_alias_key(name_or_alias),),
            ).fetchall()
        if not rows:
            raise KeyError(f"Project is not registered: {name_or_alias}")
        if len(rows) != 1:
            raise CatalogConflictError(f"Project alias is ambiguous: {name_or_alias}")
        return self.get(str(rows[0][0]))

    def get(self, project_id: str) -> CatalogEntry:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Project is not registered: {project_id}")
            aliases = tuple(
                str(item[0])
                for item in connection.execute(
                    "SELECT display_name FROM aliases WHERE project_id = ? ORDER BY alias_key",
                    (project_id,),
                )
            )
            locations = tuple(
                str(item[0])
                for item in connection.execute(
                    "SELECT location FROM locations WHERE project_id = ? "
                    "ORDER BY priority, location",
                    (project_id,),
                )
            )
        return CatalogEntry(
            project_id=str(row["project_id"]),
            primary_name=str(row["primary_name"]),
            aliases=aliases,
            locations=locations,
            location_mode=str(row["location_mode"]),
            lifecycle=str(row["lifecycle"]),
            archived=bool(row["archived"]),
            last_semantic_revision=int(row["last_semantic_revision"]),
            runtime_association=(
                str(row["runtime_association"])
                if row["runtime_association"] is not None
                else None
            ),
            reachable=bool(row["reachable"]),
            last_activity=str(row["last_activity"]) if row["last_activity"] is not None else None,
            discovery_provenance=str(row["discovery_provenance"]),
        )

    def list(self) -> tuple[CatalogEntry, ...]:
        with closing(self._connect()) as connection, connection:
            identifiers = tuple(
                str(row[0])
                for row in connection.execute("SELECT project_id FROM projects ORDER BY project_id")
            )
        return tuple(self.get(identifier) for identifier in identifiers)

    def reachable_location(self, name_or_alias: str) -> tuple[CatalogEntry, Path]:
        entry = self.resolve(name_or_alias)
        if entry.archived:
            raise ProjectUnreachableError(f"Project is archived: {entry.primary_name}")
        for location in entry.locations:
            candidate = Path(location)
            if candidate.is_dir():
                self._set_reachable(entry.project_id, True)
                return self.get(entry.project_id), candidate
        self._set_reachable(entry.project_id, False)
        raise ProjectUnreachableError(f"Project has no reachable location: {entry.primary_name}")

    def move(self, project_id: str, location: str | Path) -> CatalogEntry:
        resolved = str(Path(location).expanduser().resolve())
        with closing(self._connect()) as connection, connection:
            try:
                connection.execute("DELETE FROM locations WHERE project_id = ?", (project_id,))
                connection.execute(
                    "INSERT INTO locations (location, project_id, priority) VALUES (?, ?, 0)",
                    (resolved, project_id),
                )
            except sqlite3.IntegrityError as exc:
                raise CatalogConflictError(
                    "Project location already belongs to another entry"
                ) from exc
        return self.get(project_id)

    def record_revision(self, project_id: str, revision: int, activity: str) -> CatalogEntry:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE projects
                SET last_semantic_revision = ?, last_activity = ?, reachable = 1
                WHERE project_id = ?
                """,
                (revision, activity, project_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Project is not registered: {project_id}")
        return self.get(project_id)

    def platform_projection(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "scope": "PLATFORM",
            "authoritative": False,
            "derived_from": "PROJECT_CATALOG",
            "projects": [entry.to_dict() for entry in self.list()],
        }

    def _set_reachable(self, project_id: str, reachable: bool) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "UPDATE projects SET reachable = ? WHERE project_id = ?",
                (int(reachable), project_id),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    primary_name TEXT NOT NULL,
                    location_mode TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    archived INTEGER NOT NULL CHECK (archived IN (0, 1)),
                    last_semantic_revision INTEGER NOT NULL CHECK (last_semantic_revision >= 1),
                    runtime_association TEXT,
                    reachable INTEGER NOT NULL CHECK (reachable IN (0, 1)),
                    last_activity TEXT,
                    discovery_provenance TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS aliases (
                    alias_key TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS locations (
                    location TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    priority INTEGER NOT NULL
                );
                """
            )


def default_catalog_path() -> Path:
    """Return the user-scoped catalog path without requiring a service runtime."""

    return Path.home() / ".artifex" / "catalog.sqlite3"


__all__ = ["CatalogEntry", "ProjectCatalog", "default_catalog_path"]

"""Capture an immutable, SHA-256 V1 release fixture from a Git ref."""

from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import yaml


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
    )
    return completed.stdout


def capture(root: Path, source_ref: str, intake_commit: str) -> dict[str, Any]:
    """Return a content-hash manifest without checking out or changing the source ref."""

    repository = root.resolve()
    source_commit = _git(repository, "rev-parse", f"{source_ref}^{{commit}}").decode().strip()
    tree_sha = _git(repository, "rev-parse", f"{source_ref}^{{tree}}").decode().strip()
    archive = _git(repository, "archive", "--format=tar", source_ref)
    files: list[dict[str, Any]] = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        for member in sorted(stream.getmembers(), key=lambda item: item.name):
            if not member.isfile():
                continue
            extracted = stream.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"unable to read archived file: {member.name}")
            content = extracted.read()
            files.append(
                {
                    "path": member.name,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
    aggregate = hashlib.sha256()
    for item in files:
        aggregate.update(f"{item['sha256']}  {item['path']}\n".encode())
    return {
        "schema_version": "1.0",
        "fixture_id": "ARTIFEX-V1-RELEASE-GOLDEN",
        "purpose": "Immutable M0 migration and regression corpus; no Project mutation",
        "source_ref": source_ref,
        "source_commit": source_commit,
        "source_tree": tree_sha,
        "intake_commit": intake_commit,
        "file_count": len(files),
        "aggregate_sha256": aggregate.hexdigest(),
        "files": files,
    }


def write_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(value, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--source-ref", default="v1.0.0")
    parser.add_argument("--intake-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    value = capture(arguments.repo_root, arguments.source_ref, arguments.intake_commit)
    write_yaml(arguments.output, value)
    print(
        f"v1-fixture=PASS files={value['file_count']} aggregate_sha256={value['aggregate_sha256']}"
    )


if __name__ == "__main__":
    main()

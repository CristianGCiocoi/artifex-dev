"""Seal a completed J21 observation log into independently verifiable evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from tools.artifex2.validate_j21 import J21EvidenceError, build_j21_evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Post-process J21 observations without repairing the journey"
    )
    for name in ("contract", "capture", "installer", "provenance", "evidence-root", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_j21_evidence(
            args.contract, args.capture, args.installer, args.provenance, args.evidence_root
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, yaml.YAMLError, J21EvidenceError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "evidence": str(args.output),
                "source_commit": result["candidate"]["source_commit"],
                "installer_sha256": result["candidate"]["installer_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

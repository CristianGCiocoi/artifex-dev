"""Launch the M12 J09 harness from the existing interactive Windows token."""

from __future__ import annotations

import json
import runpy
import sys
import traceback
from pathlib import Path

MEDIA_ROOT = Path(r"C:\ARTIFEX-M12-Media")
USER_ROOT = Path(r"C:\Users\crugger\AppData\Local")
HARNESS = MEDIA_ROOT / "qualify_m9_black_box.py"
OUTPUT = USER_ROOT / "ARTIFEX-M12-J09-PASS.json"
DIAGNOSTIC = USER_ROOT / "ARTIFEX-M12-J09-wrapper.json"
QUALIFICATION_ROOT = USER_ROOT / "ARTIFEX-M12-J09-Qualification-V3"


def _write_diagnostic(*, status: str, exit_code: int, detail: str | None = None) -> None:
    value = {
        "schema_version": "1.0",
        "status": status,
        "exit_code": exit_code,
        "detail": detail,
        "output_present": OUTPUT.is_file(),
        "qualification_root_present": QUALIFICATION_ROOT.is_dir(),
    }
    DIAGNOSTIC.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    required = (
        HARNESS,
        MEDIA_ROOT / "ARTIFEX-Setup.exe",
        Path(r"C:\Program Files\ARTIFEX\artifex.exe"),
        Path(r"C:\ARTIFEX-M9-Qualification\v1-project\.git"),
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        _write_diagnostic(status="FAIL", exit_code=1, detail="required J09 input is absent")
        raise SystemExit(1)
    if any(path.exists() for path in (OUTPUT, DIAGNOSTIC, QUALIFICATION_ROOT)):
        raise SystemExit("refusing to overwrite prior J09 retry state")

    sys.argv = [
        str(HARNESS),
        "--artifex-executable",
        r"C:\Program Files\ARTIFEX\artifex.exe",
        "--candidate-artifact",
        str(MEDIA_ROOT / "ARTIFEX-Setup.exe"),
        "--expected-artifact-sha256",
        "9f57889b2e0e685ba72e27853a1eda1eb9ea7fd8770f4a2338041bb4421141a9",
        "--expected-source-commit",
        "717b9781c2f1d2b11b95725826db21746c252c09",
        "--v1-repository",
        r"C:\ARTIFEX-M9-Qualification\v1-project",
        "--qualification-root",
        str(QUALIFICATION_ROOT),
        "--output",
        str(OUTPUT),
    ]
    try:
        runpy.run_path(str(HARNESS), run_name="__main__")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        _write_diagnostic(
            status="PASS" if code == 0 and OUTPUT.is_file() else "FAIL",
            exit_code=code,
        )
        raise
    except BaseException:
        _write_diagnostic(
            status="FAIL",
            exit_code=1,
            detail=traceback.format_exc(limit=12),
        )
        raise


if __name__ == "__main__":
    main()

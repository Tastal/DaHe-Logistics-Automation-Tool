from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.verification.production_backup_restore import (
    ProductionBackupRestoreError,
    verify_production_backup_restore,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create one online production backup, restore it into a temporary "
            "directory, and publish immutable verification evidence."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute, required=True)
    parser.add_argument("--output", type=_absolute, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        evidence = verify_production_backup_restore(
            project_root=ROOT,
            data_root=arguments.data_root,
            output=arguments.output,
        )
    except ProductionBackupRestoreError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "canonical_sha256": evidence.canonical_sha256,
                "kind": evidence.payload["kind"],
                "output": str(arguments.output),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

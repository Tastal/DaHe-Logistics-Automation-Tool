from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.verification.operational_fast_capture import (
    build_operational_fast_capture_evidence,
    publish_operational_fast_capture_evidence,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _job_id(value: str) -> str:
    if len(value) != 32 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("job ID must be 32 lowercase hexadecimal characters")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one completed fast Chengfeng business capture from local "
            "SQLite and content-addressed evidence without network access."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument("--job-id", type=_job_id, required=True)
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    evidence = build_operational_fast_capture_evidence(
        project_root=ROOT,
        data_root=arguments.data_root,
        job_id=arguments.job_id,
    )
    output = publish_operational_fast_capture_evidence(
        evidence=evidence,
        output=arguments.output,
    )
    print(
        json.dumps(
            {
                "canonical_sha256": evidence.canonical_sha256,
                "output": str(output),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

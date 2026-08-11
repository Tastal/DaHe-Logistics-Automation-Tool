from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from dahe.verification.daily_report_parity import verify_daily_report_parity

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare a generated daily report with the locked reference format."
    )
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main() -> None:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit(f"Use the project interpreter: {EXPECTED_PYTHON}")
    arguments = _parser().parse_args()
    for name in ("reference", "candidate", "output"):
        value = getattr(arguments, name)
        if not value.is_absolute():
            raise SystemExit(f"--{name} must be absolute")
    result = verify_daily_report_parity(
        reference=arguments.reference,
        candidate=arguments.candidate,
    )
    payload: dict[str, object] = {
        "schema_version": 1,
        "reference_sha256": result.reference_sha256,
        "candidate_sha256": result.candidate_sha256,
        "format_contract": result.candidate_contract.as_dict(),
        "allowed_differences": list(result.allowed_differences),
        "passed": True,
    }
    output = arguments.output
    if output.exists():
        raise SystemExit("--output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dahe.verification.loop9_fault_injection import (
    Loop9FaultInjectionError,
    Loop9FaultInjectionRunner,
    publish_fault_injection_result,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (
    ROOT / ".venv" / "Scripts" / "python.exe"
).resolve()


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("data root must be absolute")
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the four fixed Loop 9 offline fault scenarios against "
            "the stopped, current-build formal Chengfeng shadow data root."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
        help=(
            "Absolute formal Loop 9 data root; the main application must "
            "be stopped."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        result = Loop9FaultInjectionRunner(
            project_root=ROOT,
            data_root=arguments.data_root,
        ).run()
        evidence_path = publish_fault_injection_result(
            data_root=arguments.data_root,
            result=result,
        )
    except Loop9FaultInjectionError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                **result.to_dict(),
                "evidence_path": str(evidence_path),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

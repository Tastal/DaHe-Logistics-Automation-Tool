from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.adapters.chengfeng.contract_freezer import (
    rollover_live_list_request_contract,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a development-only Chengfeng contract candidate from "
            "a sealed official reset-list request structure and the current "
            "selected response contract."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--request-structure-evidence",
        type=_absolute_path,
        required=True,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    result = rollover_live_list_request_contract(
        request_structure_evidence_path=(
            arguments.request_structure_evidence
        ),
        data_root=arguments.data_root,
    )
    print(
        json.dumps(
            {
                "contract_canonical_sha256": (
                    result.contract_canonical_sha256
                ),
                "contract_file_sha256": result.contract_file_sha256,
                "contract_file": result.contract_path.name,
                "freeze_evidence_file": result.evidence_path.name,
                "freeze_evidence_sha256": (
                    result.freeze_evidence_sha256
                ),
                "requires_live_validation": True,
                "source_discovery_sha256": (
                    result.source_discovery_sha256
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

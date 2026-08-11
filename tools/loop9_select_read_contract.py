from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.adapters.chengfeng.live_contract_selection import (
    select_live_read_contract,
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
            "Select one already frozen Loop 9 Chengfeng read contract without "
            "connecting to Chengfeng."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument("--contract-canonical-sha256", required=True)
    parser.add_argument("--contract-file-sha256", required=True)
    parser.add_argument("--freeze-evidence-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    selected = select_live_read_contract(
        data_root=arguments.data_root,
        contract_canonical_sha256=arguments.contract_canonical_sha256,
        contract_file_sha256=arguments.contract_file_sha256,
        freeze_evidence_sha256=arguments.freeze_evidence_sha256,
    )
    print(
        json.dumps(
            {
                "contract_canonical_sha256": selected.manifest.canonical_sha256,
                "contract_file_sha256": selected.contract_file_sha256,
                "freeze_evidence_sha256": selected.freeze_evidence_sha256,
                "selection_file": selected.selection_path.name,
                "selection_sha256": selected.selection_sha256,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

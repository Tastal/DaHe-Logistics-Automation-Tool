from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.adapters.chengfeng.contract_freezer import freeze_live_read_contract

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
            "Freeze the exact Chengfeng list, detail, and response-derived "
            "ticket-image read shapes from sealed Loop 9 discovery evidence."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument("--discovery-evidence", type=_absolute_path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    result = freeze_live_read_contract(
        discovery_evidence_path=arguments.discovery_evidence,
        data_root=arguments.data_root,
    )
    print(
        json.dumps(
            {
                "contract_canonical_sha256": result.contract_canonical_sha256,
                "contract_file_sha256": result.contract_file_sha256,
                "contract_file": result.contract_path.name,
                "excluded_observation_count": result.excluded_observation_count,
                "freeze_evidence_file": result.evidence_path.name,
                "freeze_evidence_sha256": result.freeze_evidence_sha256,
                "potentially_mutating_observation_count": (
                    result.potentially_mutating_observation_count
                ),
                "selected_observation_count": result.selected_observation_count,
                "source_discovery_sha256": result.source_discovery_sha256,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

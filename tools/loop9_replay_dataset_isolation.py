from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe.adapters.chengfeng.daily_contract_selection import (
    load_selected_daily_read_contract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    load_selected_live_read_contract,
)
from dahe.application.template_studio.formal_development_authority import (
    load_formal_development_authority,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_dataset_isolation import (
    Loop9DatasetIsolationError,
    exclusion_source_boundary_from_formal_development_authority,
    load_loop9_dataset_isolation_evidence,
    load_loop9_dataset_manifest,
    validate_loop9_dataset_isolation,
)
from dahe.verification.loop9_exclusion_authority import (
    load_stored_loop9_full_history_exclusion_authority,
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
            "Independently replay persisted Loop 9 dataset-isolation evidence "
            "without connecting to Chengfeng or reading business images."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    for option in (
        "discovery-development",
        "current-locked-50",
        "real-shadow-30",
        "daily-validation",
        "source-development-authority",
    ):
        parser.add_argument(
            f"--{option}",
            type=_absolute_path,
            required=True,
        )
    parser.add_argument("--evidence", type=_absolute_path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    selected_settlement = load_selected_live_read_contract(
        arguments.data_root
    )
    selected_daily = load_selected_daily_read_contract(arguments.data_root)
    source_authority = load_formal_development_authority(
        arguments.source_development_authority
    )
    source_boundary = (
        exclusion_source_boundary_from_formal_development_authority(
            source_authority
        )
    )
    persisted = load_loop9_dataset_isolation_evidence(arguments.evidence)
    full_history = load_stored_loop9_full_history_exclusion_authority(
        data_root=arguments.data_root,
        authority_sha256=(
            persisted.full_history_exclusion_authority_sha256
        ),
    )
    replayed = validate_loop9_dataset_isolation(
        expected_current_build_sha256=current_loop9_build_sha256(ROOT),
        expected_settlement_contract_sha256=(
            selected_settlement.manifest.canonical_sha256
        ),
        expected_daily_contract_sha256=(
            selected_daily.manifest.canonical_sha256
        ),
        expected_settlement_selection_sha256=(
            selected_settlement.selection_sha256
        ),
        expected_daily_selection_sha256=(
            selected_daily.selection_sha256
        ),
        discovery_development=load_loop9_dataset_manifest(
            arguments.discovery_development
        ),
        current_locked_50=load_loop9_dataset_manifest(
            arguments.current_locked_50
        ),
        real_shadow_30=load_loop9_dataset_manifest(
            arguments.real_shadow_30
        ),
        daily_validation=load_loop9_dataset_manifest(
            arguments.daily_validation
        ),
        development_exclusions=full_history.development_exclusions,
        legacy_loop7_exclusions=full_history.legacy_loop7_exclusions,
        expected_exclusion_source_boundary=source_boundary,
        full_history_exclusion_authority=full_history,
    )
    if (
        replayed.canonical_sha256 != persisted.canonical_sha256
        or replayed.to_payload() != persisted.to_payload()
    ):
        raise Loop9DatasetIsolationError(
            "persisted isolation evidence does not match independent replay"
        )
    print(
        json.dumps(
            {
                "canonical_sha256": replayed.canonical_sha256,
                "isolation_replayed": True,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

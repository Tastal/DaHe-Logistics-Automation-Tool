from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

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
    load_loop9_dataset_manifest,
    validate_loop9_dataset_isolation,
)
from dahe.verification.loop9_exclusion_authority import (
    load_current_loop9_full_history_exclusion_authority,
    persist_loop9_full_history_exclusion_authority,
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
            "Validate replayable Loop 9 dataset-isolation evidence without "
            "connecting to Chengfeng or reading business images."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--discovery-development",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--current-locked-50",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--real-shadow-30",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--daily-validation",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--source-development-authority",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _write_exclusive_json(
    *,
    output: Path,
    payload: dict[str, object],
) -> None:
    if output.exists() or output.is_symlink():
        raise Loop9DatasetIsolationError("output already exists")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise Loop9DatasetIsolationError("output parent is unavailable") from exc
    if not parent.is_dir():
        raise Loop9DatasetIsolationError("output parent must be a directory")
    resolved = output.resolve(strict=False)
    if resolved.parent != parent:
        raise Loop9DatasetIsolationError("output path is unsafe")
    staged = parent / f".{output.name}.{uuid4().hex}.tmp"
    try:
        with staged.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, resolved)
        except FileExistsError as exc:
            raise Loop9DatasetIsolationError("output already exists") from exc
        except OSError as exc:
            raise Loop9DatasetIsolationError(
                "output could not be published atomically"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)


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
    expected_build_sha256 = current_loop9_build_sha256(ROOT)
    settlement_contract_sha256 = (
        selected_settlement.manifest.canonical_sha256
    )
    daily_contract_sha256 = selected_daily.manifest.canonical_sha256
    settlement_selection_sha256 = (
        selected_settlement.selection_sha256
    )
    daily_selection_sha256 = selected_daily.selection_sha256
    full_history = (
        load_current_loop9_full_history_exclusion_authority(
            data_root=arguments.data_root,
            source_boundary=source_boundary,
            expected_current_build_sha256=expected_build_sha256,
            expected_settlement_contract_sha256=(
                settlement_contract_sha256
            ),
            expected_daily_contract_sha256=daily_contract_sha256,
            expected_settlement_selection_sha256=(
                settlement_selection_sha256
            ),
            expected_daily_selection_sha256=daily_selection_sha256,
        )
    )
    evidence = validate_loop9_dataset_isolation(
        expected_current_build_sha256=expected_build_sha256,
        expected_settlement_contract_sha256=settlement_contract_sha256,
        expected_daily_contract_sha256=daily_contract_sha256,
        expected_settlement_selection_sha256=(
            settlement_selection_sha256
        ),
        expected_daily_selection_sha256=daily_selection_sha256,
        discovery_development=load_loop9_dataset_manifest(
            arguments.discovery_development
        ),
        current_locked_50=load_loop9_dataset_manifest(
            arguments.current_locked_50
        ),
        real_shadow_30=load_loop9_dataset_manifest(arguments.real_shadow_30),
        daily_validation=load_loop9_dataset_manifest(
            arguments.daily_validation
        ),
        development_exclusions=full_history.development_exclusions,
        legacy_loop7_exclusions=full_history.legacy_loop7_exclusions,
        expected_exclusion_source_boundary=source_boundary,
        full_history_exclusion_authority=full_history,
    )
    persist_loop9_full_history_exclusion_authority(
        data_root=arguments.data_root,
        authority=full_history,
    )
    _write_exclusive_json(
        output=arguments.output,
        payload=evidence.to_payload(),
    )
    print(
        json.dumps(
            {
                "canonical_sha256": evidence.canonical_sha256,
                "isolation_passed": True,
                "output": arguments.output.name,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

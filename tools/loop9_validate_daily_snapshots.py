from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    SelectedDailyReadContract,
    load_selected_daily_read_contract,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.verification.daily_snapshot_validation import (
    DailyContractSelectionBinding,
    validate_daily_snapshot_triplet,
)
from dahe.verification.loop9_build import current_loop9_build_sha256

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (
    ROOT / ".venv" / "Scripts" / "python.exe"
).resolve()


class DailySnapshotValidationToolError(RuntimeError):
    """Raised when formal daily validation evidence cannot be written."""


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate three independently captured daily snapshots with one "
            "frozen read scope and write replayable Loop 9 evidence."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--snapshot-id",
        action="append",
        required=True,
    )
    parser.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )
    return parser


def _validated_paths(
    data_root: Path,
    output: Path,
) -> tuple[Path, Path]:
    root = data_root.resolve(strict=True)
    if data_root.is_symlink() or not root.is_dir():
        raise DailySnapshotValidationToolError(
            "data root must be a real directory"
        )
    if output.exists() or output.is_symlink():
        raise DailySnapshotValidationToolError(
            "output already exists"
        )
    try:
        resolved_output = output.resolve(strict=False)
        resolved_output.relative_to(root)
    except ValueError as exc:
        raise DailySnapshotValidationToolError(
            "output must remain inside the data root"
        ) from exc
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    if (
        resolved_output.parent.is_symlink()
        or resolved_output.parent.resolve(strict=True)
        != resolved_output.parent
    ):
        raise DailySnapshotValidationToolError(
            "output parent must be a real directory"
        )
    return root, resolved_output


def _write_exclusive_atomic(
    output: Path,
    payload: dict[str, object],
) -> None:
    temporary = output.with_name(
        f".{output.name}.{secrets.token_hex(8)}.tmp"
    )
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if output.exists() or output.is_symlink():
            raise DailySnapshotValidationToolError(
                "output already exists"
            )
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise DailySnapshotValidationToolError(
                "output already exists"
            ) from exc
        except OSError as exc:
            raise DailySnapshotValidationToolError(
                "output could not be published atomically"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _selection_binding(
    selected: SelectedDailyReadContract,
) -> DailyContractSelectionBinding:
    return DailyContractSelectionBinding(
        contract_canonical_sha256=selected.manifest.canonical_sha256,
        contract_file_sha256=selected.contract_file_sha256,
        freeze_evidence_sha256=selected.freeze_evidence_sha256,
        selection_sha256=selected.selection_sha256,
        source_discovery_sha256=(
            selected.manifest.source_discovery_sha256
        ),
    )


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    snapshot_ids = tuple(arguments.snapshot_id)
    if (
        len(snapshot_ids) != 3
        or any(
            type(snapshot_id) is not str
            or not snapshot_id
            or len(snapshot_id) > 128
            for snapshot_id in snapshot_ids
        )
    ):
        raise DailySnapshotValidationToolError(
            "exactly three bounded snapshot IDs are required"
        )
    data_root, output = _validated_paths(
        arguments.data_root,
        arguments.output,
    )
    try:
        contract_selection = _selection_binding(
            load_selected_daily_read_contract(data_root)
        )
    except DailyContractSelectionError as exc:
        raise DailySnapshotValidationToolError(
            "selected daily contract evidence is unavailable"
        ) from exc
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=ROOT,
        instance_id=f"loop9-daily-validator-{secrets.token_hex(8)}",
    )
    try:
        store = SqliteDailyStore(runtime)
        authorities = tuple(
            store.get_formal_snapshot_authority(snapshot_id)
            for snapshot_id in snapshot_ids
        )
        evidence = validate_daily_snapshot_triplet(
            authorities,
            build_sha256=current_loop9_build_sha256(ROOT),
            expected_contract_sha256=(
                authorities[0].snapshot.source_contract_sha256
            ),
            contract_selection=contract_selection,
        )
        _write_exclusive_atomic(output, evidence)
    finally:
        runtime.close()
    print(
        json.dumps(
            {
                "candidate_count": evidence["candidate_count"],
                "evidence_sha256": evidence["canonical_sha256"],
                "output": output.name,
                "snapshot_count": evidence["snapshot_count"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

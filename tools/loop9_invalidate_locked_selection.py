from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from uuid import uuid4

from dahe.adapters.chengfeng.daily_contract_selection import (
    load_selected_daily_read_contract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    load_selected_live_read_contract,
)
from dahe.adapters.files.shadow_selection_lifecycle import (
    FormalSelectionLifecycleStore,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.application.chengfeng.shadow_selection_lifecycle import (
    FormalSelectionLifecycleEvent,
    FormalSelectionLifecycleNode,
)
from dahe.application.template_studio.formal_development_authority import (
    build_current_formal_development_authority,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_dataset_isolation import (
    exclusion_source_boundary_from_formal_development_authority,
)
from dahe.verification.loop9_exclusion_authority import (
    append_loop9_exclusion_child,
    load_current_loop9_full_history_exclusion_authority,
    load_verified_loop9_exclusion_snapshot,
    persist_loop9_full_history_exclusion_authority,
    register_loop9_development_exclusion_inventory,
)
from dahe.verification.loop9_human_review import (
    load_loop9_review_package,
)
from dahe.verification.loop9_locked_selection_rollover import (
    build_locked_selection_coverage_failure_attestation,
    development_inventory_from_failed_locked_selection,
    persist_locked_selection_failure_attestation,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 20 * 1024 * 1024


class Loop9LockedSelectionInvalidationError(RuntimeError):
    """Raised when one failed locked generation cannot be retired safely."""


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _sha256_argument(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "value must be a lowercase SHA-256"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Retire one fully reviewed Loop 9 locked selection that failed "
            "natural coverage, without connecting to Chengfeng."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--selection-sha256",
        type=_sha256_argument,
        required=True,
    )
    parser.add_argument(
        "--review-package",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--review-answers",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--expected-current-build-sha256",
        type=_sha256_argument,
        required=True,
    )
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _safe_existing_directory(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or _is_reparse_point(path):
        raise Loop9LockedSelectionInvalidationError(
            f"{label} path is unsafe"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9LockedSelectionInvalidationError(
            f"{label} is unavailable"
        ) from exc
    if (
        resolved != path
        or not resolved.is_dir()
        or resolved.is_symlink()
        or _is_reparse_point(resolved)
    ):
        raise Loop9LockedSelectionInvalidationError(
            f"{label} path is unsafe"
        )
    return resolved


def _safe_existing_file(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or _is_reparse_point(path):
        raise Loop9LockedSelectionInvalidationError(
            f"{label} path is unsafe"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9LockedSelectionInvalidationError(
            f"{label} is unavailable"
        ) from exc
    if (
        resolved != path
        or not resolved.is_file()
        or resolved.is_symlink()
        or _is_reparse_point(resolved)
    ):
        raise Loop9LockedSelectionInvalidationError(
            f"{label} path is unsafe"
        )
    return resolved


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9LockedSelectionInvalidationError(
                "human review answers contain duplicate fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise Loop9LockedSelectionInvalidationError(
        f"human review answers contain a non-finite value: {value}"
    )


def _load_review_answers(path: Path) -> object:
    resolved = _safe_existing_file(path, label="human review answers")
    try:
        size = resolved.stat().st_size
        if size < 2 or size > _MAX_JSON_BYTES:
            raise Loop9LockedSelectionInvalidationError(
                "human review answers file size is invalid"
            )
        return json.loads(
            resolved.read_bytes().decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except Loop9LockedSelectionInvalidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9LockedSelectionInvalidationError(
            "human review answers are not readable UTF-8 JSON"
        ) from exc


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _write_idempotent_json(
    *,
    output: Path,
    payload: dict[str, object],
) -> None:
    if output.is_symlink() or _is_reparse_point(output):
        raise Loop9LockedSelectionInvalidationError(
            "output path is unsafe"
        )
    parent = _safe_existing_directory(output.parent, label="output parent")
    candidate = Path(os.path.abspath(os.fspath(output)))
    if candidate.parent != parent:
        raise Loop9LockedSelectionInvalidationError(
            "output path is unsafe"
        )
    content = _canonical_json_bytes(payload)
    if candidate.exists():
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or _is_reparse_point(candidate)
            or candidate.resolve(strict=True) != candidate
            or candidate.read_bytes() != content
        ):
            raise Loop9LockedSelectionInvalidationError(
                "output already exists with different content"
            )
        return
    staged = parent / f".{candidate.name}.{uuid4().hex}.tmp"
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, candidate)
        except FileExistsError:
            if (
                not candidate.is_file()
                or candidate.is_symlink()
                or candidate.read_bytes() != content
            ):
                raise Loop9LockedSelectionInvalidationError(
                    "output already exists with different content"
                ) from None
        except OSError as exc:
            raise Loop9LockedSelectionInvalidationError(
                "output could not be published atomically"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)


def _load_target_generation(
    *,
    data_root: Path,
    expected_selection_sha256: str,
) -> tuple[
    FormalShadowSelectionManifest,
    FormalSelectionLifecycleStore,
    FormalSelectionLifecycleNode,
]:
    selection_store = FormalShadowSelectionStore(data_root)
    lifecycle = FormalSelectionLifecycleStore(data_root)
    state = lifecycle.load_state()
    if state is None:
        active = selection_store.load(
            ShadowBatchTargetKind.CURRENT_LOCKED_50
        )
        if active.canonical_sha256 != expected_selection_sha256:
            raise Loop9LockedSelectionInvalidationError(
                "requested selection is not the current lifecycle generation"
            )
    tip = lifecycle.load_tip()
    if tip is None or tip.selection_sha256 != expected_selection_sha256:
        raise Loop9LockedSelectionInvalidationError(
            "requested selection is not the current lifecycle generation"
        )
    if tip.event_kind is FormalSelectionLifecycleEvent.ACTIVATED:
        selection = selection_store.load_active_current_locked_manifest(
            expected_selection_sha256
        )
    elif tip.event_kind is FormalSelectionLifecycleEvent.INVALIDATED:
        selection = selection_store.load_manifest(
            expected_selection_sha256
        )
        batch = selection.batch_manifest
        if (
            tip.source_build_sha256 != batch.source_build_sha256
            or tip.pipeline_fingerprint != batch.pipeline_fingerprint
            or tip.identity_context_sha256
            != batch.identity_context_sha256
        ):
            raise Loop9LockedSelectionInvalidationError(
                "invalidated lifecycle generation binding is inconsistent"
            )
    else:  # pragma: no cover - enum exhaustiveness guard
        raise Loop9LockedSelectionInvalidationError(
            "selection lifecycle event is unsupported"
        )
    return selection, lifecycle, tip


def _relative_artifact(path: Path, *, data_root: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(data_root).as_posix()
    except ValueError as exc:
        raise Loop9LockedSelectionInvalidationError(
            "persisted evidence escaped the data root"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    data_root = _safe_existing_directory(
        arguments.data_root,
        label="data root",
    )
    package_root = _safe_existing_directory(
        arguments.review_package,
        label="review package",
    )
    review_answers = _load_review_answers(arguments.review_answers)
    current_build_sha256 = current_loop9_build_sha256(ROOT)
    if (
        arguments.expected_current_build_sha256
        != current_build_sha256
    ):
        raise Loop9LockedSelectionInvalidationError(
            "Loop 9 build fingerprint changed"
        )
    package = load_loop9_review_package(package_root)
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=ROOT,
        instance_id=f"loop9-locked-invalidation-{uuid4().hex}",
    )
    try:
        selected_settlement = load_selected_live_read_contract(data_root)
        selected_daily = load_selected_daily_read_contract(data_root)
        selection, lifecycle, _ = _load_target_generation(
            data_root=data_root,
            expected_selection_sha256=arguments.selection_sha256,
        )
        batch = selection.batch_manifest
        if (
            batch.source_build_sha256 != current_build_sha256
            or batch.contract_canonical_sha256
            != selected_settlement.manifest.canonical_sha256
            or batch.contract_selection_sha256
            != selected_settlement.selection_sha256
        ):
            raise Loop9LockedSelectionInvalidationError(
                "locked selection build or settlement contract binding changed"
            )
        development_authority = (
            build_current_formal_development_authority(runtime)
        )
        source_boundary = (
            exclusion_source_boundary_from_formal_development_authority(
                development_authority
            )
        )
        if (
            source_boundary.canonical_sha256
            != selection.exclusion_source_boundary_sha256
            or source_boundary.source_inventory_high_watermark
            != selection.exclusion_source_inventory_high_watermark
        ):
            raise Loop9LockedSelectionInvalidationError(
                "locked selection exclusion source boundary changed"
            )
        attestation = (
            build_locked_selection_coverage_failure_attestation(
                selection=selection,
                package=package,
                review_answers=review_answers,
            )
        )
        inventory = development_inventory_from_failed_locked_selection(
            selection=selection,
            failure_attestation=attestation,
        )
        attestation_path = (
            persist_locked_selection_failure_attestation(
                data_root=data_root,
                attestation=attestation,
            )
        )
        inventory_path = (
            register_loop9_development_exclusion_inventory(
                data_root=data_root,
                inventory=inventory,
            )
        )
        append_loop9_exclusion_child(
            data_root=data_root,
            source_boundary=source_boundary,
            child_inventory=inventory,
            expected_current_build_sha256=current_build_sha256,
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
        )
        authority = (
            load_current_loop9_full_history_exclusion_authority(
                data_root=data_root,
                source_boundary=source_boundary,
                expected_current_build_sha256=current_build_sha256,
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
            )
        )
        authority_path = (
            persist_loop9_full_history_exclusion_authority(
                data_root=data_root,
                authority=authority,
            )
        )
        exclusion_snapshot = load_verified_loop9_exclusion_snapshot(
            data_root=data_root,
            source_boundary=source_boundary,
            expected_current_build_sha256=current_build_sha256,
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
        )
        invalidation = lifecycle.invalidate_current_locked_selection(
            selection=selection,
            failure_attestation=attestation,
            exclusion_inventory=inventory,
            exclusion_snapshot=exclusion_snapshot,
        )
    finally:
        runtime.close()
    core: dict[str, object] = {
        "coverage_gate_passed": False,
        "current_build_sha256": current_build_sha256,
        "daily_contract_sha256": (
            selected_daily.manifest.canonical_sha256
        ),
        "daily_selection_sha256": selected_daily.selection_sha256,
        "exclusion_authority_path": _relative_artifact(
            authority_path,
            data_root=data_root,
        ),
        "exclusion_authority_sha256": (
            exclusion_snapshot.authority_sha256
        ),
        "exclusion_child_index_head_sha256": (
            exclusion_snapshot.child_index_head_sha256
        ),
        "exclusion_inventory_path": _relative_artifact(
            inventory_path,
            data_root=data_root,
        ),
        "exclusion_inventory_sha256": inventory.canonical_sha256,
        "failure_attestation_path": _relative_artifact(
            attestation_path,
            data_root=data_root,
        ),
        "failure_attestation_sha256": attestation.canonical_sha256,
        "kind": "loop9_locked_selection_coverage_invalidation",
        "lifecycle_generation": invalidation.generation,
        "lifecycle_head_sha256": invalidation.canonical_sha256,
        "missing_conditions": list(attestation.missing_conditions),
        "review_answers_sha256": attestation.review_answers_sha256,
        "schema_version": 1,
        "selection_sha256": selection.canonical_sha256,
        "settlement_contract_sha256": (
            selected_settlement.manifest.canonical_sha256
        ),
        "settlement_selection_sha256": (
            selected_settlement.selection_sha256
        ),
        "source_boundary_sha256": source_boundary.canonical_sha256,
        "status": "invalidated",
    }
    result = {
        **core,
        "canonical_sha256": _canonical_sha256(core),
    }
    _write_idempotent_json(output=arguments.output, payload=result)
    print(
        json.dumps(
            {
                "canonical_sha256": result["canonical_sha256"],
                "coverage_gate_passed": False,
                "lifecycle_generation": invalidation.generation,
                "missing_conditions": list(attestation.missing_conditions),
                "selection_sha256": selection.canonical_sha256,
                "status": "invalidated",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
    Loop9DatasetExclusionInventory,
    Loop9DatasetIsolationError,
    build_loop9_full_history_exclusion_authority,
    exclusion_source_boundary_from_formal_development_authority,
    load_loop9_exclusion_inventory,
)
from dahe.verification.loop9_exclusion_authority import (
    append_loop9_exclusion_child,
    load_current_loop9_full_history_exclusion_authority,
    load_loop9_development_exclusion_registry,
    load_sealed_loop9_full_history_exclusion_authority,
    persist_loop9_full_history_exclusion_authority,
    validate_loop9_exclusion_producer_registries,
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
            "Build the canonical Loop 9 full-history exclusion authority "
            "without connecting to Chengfeng or reading business images."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--source-development-authority",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--child-inventory",
        type=_absolute_path,
        action="append",
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
        raise Loop9DatasetIsolationError(
            "output parent is unavailable"
        ) from exc
    if not parent.is_dir():
        raise Loop9DatasetIsolationError(
            "output parent must be a directory"
        )
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
            raise Loop9DatasetIsolationError(
                "output already exists"
            ) from exc
        except OSError as exc:
            raise Loop9DatasetIsolationError(
                "output could not be published atomically"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)


def _deduplicate_child_inventories(
    values: tuple[Loop9DatasetExclusionInventory, ...],
) -> tuple[Loop9DatasetExclusionInventory, ...]:
    ordered: list[Loop9DatasetExclusionInventory] = []
    by_sha256: dict[str, Loop9DatasetExclusionInventory] = {}
    for value in values:
        existing = by_sha256.get(value.canonical_sha256)
        if existing is None:
            by_sha256[value.canonical_sha256] = value
            ordered.append(value)
            continue
        if existing.to_payload() != value.to_payload():
            raise Loop9DatasetIsolationError(
                "duplicate exclusion child SHA-256 has different content"
            )
    return tuple(ordered)


def _merge_child_inventories_preserving_append_order(
    *,
    existing: tuple[Loop9DatasetExclusionInventory, ...],
    candidates: tuple[Loop9DatasetExclusionInventory, ...],
) -> tuple[Loop9DatasetExclusionInventory, ...]:
    """Keep the sealed chain order and append only newly registered children."""

    candidates_by_sha256 = {
        child.canonical_sha256: child for child in candidates
    }
    ordered = list(existing)
    existing_sha256s: set[str] = set()
    for child in existing:
        candidate = candidates_by_sha256.get(child.canonical_sha256)
        if candidate is None:
            raise Loop9DatasetIsolationError(
                "existing exclusion child is missing from the complete registry"
            )
        if candidate.to_payload() != child.to_payload():
            raise Loop9DatasetIsolationError(
                "existing exclusion child content changed"
            )
        existing_sha256s.add(child.canonical_sha256)
    ordered.extend(
        child
        for child in candidates
        if child.canonical_sha256 not in existing_sha256s
    )
    return tuple(ordered)


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
    explicit_child_inventories = tuple(
        load_loop9_exclusion_inventory(path)
        for path in arguments.child_inventory
    )
    child_inventories = _deduplicate_child_inventories(
        (
            *load_loop9_development_exclusion_registry(
                arguments.data_root
            ),
            *explicit_child_inventories,
        )
    )
    validate_loop9_exclusion_producer_registries(
        data_root=arguments.data_root,
        child_inventories=child_inventories,
    )
    authority_bindings = {
        "data_root": arguments.data_root,
        "source_boundary": source_boundary,
        "expected_current_build_sha256": current_loop9_build_sha256(ROOT),
        "expected_settlement_contract_sha256": (
            selected_settlement.manifest.canonical_sha256
        ),
        "expected_daily_contract_sha256": (
            selected_daily.manifest.canonical_sha256
        ),
        "expected_settlement_selection_sha256": (
            selected_settlement.selection_sha256
        ),
        "expected_daily_selection_sha256": (
            selected_daily.selection_sha256
        ),
    }
    head_path = (
        arguments.data_root
        / "verification"
        / "loop9-exclusion-authority"
        / "head.json"
    )
    ordered_child_inventories = child_inventories
    if head_path.exists() or head_path.is_symlink():
        existing_authority = (
            load_sealed_loop9_full_history_exclusion_authority(
                **authority_bindings
            )
        )
        ordered_child_inventories = (
            _merge_child_inventories_preserving_append_order(
                existing=existing_authority.child_inventories,
                candidates=child_inventories,
            )
        )
    preflight_authority = build_loop9_full_history_exclusion_authority(
        **{
            key: value
            for key, value in authority_bindings.items()
            if key != "data_root"
        },
        child_inventories=ordered_child_inventories,
    )
    for child_inventory in ordered_child_inventories:
        append_loop9_exclusion_child(
            **authority_bindings,
            child_inventory=child_inventory,
        )
    authority = load_current_loop9_full_history_exclusion_authority(
        **authority_bindings
    )
    if authority.to_payload() != preflight_authority.to_payload():
        raise Loop9DatasetIsolationError(
            "persisted exclusion authority differs from the complete preflight"
        )
    persist_loop9_full_history_exclusion_authority(
        data_root=arguments.data_root,
        authority=authority,
    )
    _write_exclusive_json(
        output=arguments.output,
        payload=authority.to_payload(),
    )
    print(
        json.dumps(
            {
                "canonical_sha256": authority.canonical_sha256,
                "child_inventory_count": (
                    authority.child_inventory_count
                ),
                "child_index_head_sha256": (
                    authority.child_index_head_sha256
                ),
                "output": arguments.output.name,
                "source_completeness_sha256": (
                    authority.source_completeness_sha256
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

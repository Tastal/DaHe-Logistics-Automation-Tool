from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.shadow_batch import (
    chengfeng_shadow_identity_context_sha256,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)
from dahe.verification.loop9_dataset_isolation import (
    ExclusionKind,
    Loop9DatasetExclusionInventory,
    Loop9DatasetIsolationError,
    Loop9ExclusionSourceBoundary,
)
from dahe.verification.loop9_exclusion_authority import (
    Loop9ExclusionChildIndexNode,
    append_loop9_exclusion_child,
    load_current_loop9_full_history_exclusion_authority,
    load_sealed_loop9_full_history_exclusion_authority,
    load_verified_loop9_exclusion_snapshot,
    load_verified_loop9_exclusion_snapshot_from_persisted_authority,
    persist_loop9_full_history_exclusion_authority,
    register_loop9_contract_discovery_exclusion,
)

BUILD_SHA256 = hashlib.sha256(b"build").hexdigest()
SETTLEMENT_CONTRACT_SHA256 = hashlib.sha256(
    b"settlement-contract"
).hexdigest()
DAILY_CONTRACT_SHA256 = hashlib.sha256(b"daily-contract").hexdigest()
SETTLEMENT_SELECTION_SHA256 = hashlib.sha256(
    b"settlement-selection"
).hexdigest()
DAILY_SELECTION_SHA256 = hashlib.sha256(b"daily-selection").hexdigest()
IDENTITY_CONTEXT_SHA256 = hashlib.sha256(b"identity-context").hexdigest()


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _fingerprint(label: str) -> ImagePerceptualFingerprint:
    content_sha256 = _sha(f"image:{label}")
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=content_sha256,
        width=320,
        height=180,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop,
                average_hash=_sha(f"average:{label}:{crop}"),
                difference_hash=_sha(f"difference:{label}:{crop}"),
            )
            for crop in (1000, 920, 840, 760)
        ),
    )


def _inventory(
    kind: ExclusionKind,
    label: str,
    *,
    identity_context_sha256: str = IDENTITY_CONTEXT_SHA256,
) -> Loop9DatasetExclusionInventory:
    fingerprint = _fingerprint(label)
    return Loop9DatasetExclusionInventory(
        inventory_id=f"inventory-{label}",
        exclusion_kind=kind,
        platform_identity_sha256s=(_sha(f"identity:{label}"),),
        image_sha256s=(fingerprint.content_sha256,),
        scope_exclusion_tokens=(),
        perceptual_fingerprints=(fingerprint,),
        identity_context_sha256=identity_context_sha256,
    )


def _boundary(
    *inventories: Loop9DatasetExclusionInventory,
) -> Loop9ExclusionSourceBoundary:
    fingerprints = tuple(
        fingerprint
        for inventory in inventories
        for fingerprint in inventory.perceptual_fingerprints
    )
    return Loop9ExclusionSourceBoundary(
        source_authority_sha256=_sha("source-authority"),
        source_exclusion_snapshot_sha256=_sha("source-snapshot"),
        source_inventory_high_watermark=23,
        image_sha256s=tuple(
            sorted(
                image
                for inventory in inventories
                for image in inventory.image_sha256s
            )
        ),
        platform_identity_count=sum(
            len(inventory.platform_identity_sha256s)
            for inventory in inventories
        ),
        perceptual_fingerprints=tuple(
            sorted(
                fingerprints,
                key=lambda fingerprint: fingerprint.content_sha256,
            )
        ),
    )


def _append(
    data_root: Path,
    *,
    boundary: Loop9ExclusionSourceBoundary,
    child: Loop9DatasetExclusionInventory,
    build_sha256: str = BUILD_SHA256,
) -> Loop9ExclusionChildIndexNode:
    _initialize_database(data_root)
    if child.exclusion_kind is ExclusionKind.DEVELOPMENT:
        registry = data_root / "loop9-development-exclusions"
        registry.mkdir(parents=True, exist_ok=True)
        _rewrite_json(
            registry / f"{child.canonical_sha256}.json",
            child.to_payload(),
        )
    return append_loop9_exclusion_child(
        data_root=data_root,
        source_boundary=boundary,
        child_inventory=child,
        expected_current_build_sha256=build_sha256,
        expected_settlement_contract_sha256=(
            SETTLEMENT_CONTRACT_SHA256
        ),
        expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
        expected_settlement_selection_sha256=(
            SETTLEMENT_SELECTION_SHA256
        ),
        expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
    )


def _load(
    data_root: Path,
    *,
    boundary: Loop9ExclusionSourceBoundary,
):
    _initialize_database(data_root)
    return load_current_loop9_full_history_exclusion_authority(
        data_root=data_root,
        source_boundary=boundary,
        expected_current_build_sha256=BUILD_SHA256,
        expected_settlement_contract_sha256=(
            SETTLEMENT_CONTRACT_SHA256
        ),
        expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
        expected_settlement_selection_sha256=(
            SETTLEMENT_SELECTION_SHA256
        ),
        expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
    )


def _store(data_root: Path) -> Path:
    return data_root / "verification" / "loop9-exclusion-authority"


def _initialize_database(data_root: Path) -> None:
    database = data_root / "database" / "dahe.sqlite3"
    if database.exists():
        return
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=Path(__file__).resolve().parents[3],
        instance_id="loop9-exclusion-authority-test",
    )
    runtime.close()


def _rewrite_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_request_rollover_side_evidence(data_root: Path) -> Path:
    root = data_root / "platform-contract-discovery"
    root.mkdir(parents=True, exist_ok=True)
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_request_rollover_source",
        "classification": "development_only",
        "parent_contract_canonical_sha256": _sha("parent-contract"),
        "parent_contract_file_sha256": _sha("parent-contract-file"),
        "parent_freeze_evidence_sha256": _sha("parent-freeze"),
        "parent_source_discovery_sha256": _sha("parent-discovery"),
        "request_structure_discovery_sha256": _sha(
            "request-structure"
        ),
        "request_structure_observation": {},
        "response_contract_inherited": True,
        "requires_live_validation": True,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    canonical_sha256 = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    path = root / f"{canonical_sha256}.request-rollover.json"
    _rewrite_json(
        path,
        {**body, "canonical_sha256": canonical_sha256},
    )
    return path


def _write_detail_encoding_rollover_side_evidence(
    data_root: Path,
) -> Path:
    root = data_root / "platform-contract-discovery"
    root.mkdir(parents=True, exist_ok=True)
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": (
            "loop9_live_read_contract_detail_encoding_rollover_source"
        ),
        "classification": "development_only",
        "parent_contract_canonical_sha256": _sha("parent-contract"),
        "parent_contract_file_sha256": _sha("parent-contract-file"),
        "parent_freeze_evidence_sha256": _sha("parent-freeze"),
        "parent_source_discovery_sha256": _sha("parent-discovery"),
        "encoding_change": {
            "operation": "get_waybill_detail",
            "from": "json",
            "to": "form",
        },
        "request_and_response_fields_inherited": True,
        "requires_live_validation": True,
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    canonical_sha256 = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    path = root / (
        f"{canonical_sha256}.detail-encoding-rollover.json"
    )
    _rewrite_json(
        path,
        {**body, "canonical_sha256": canonical_sha256},
    )
    return path


def test_append_chain_covers_source_and_allows_later_children(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    later = _inventory(ExclusionKind.DEVELOPMENT, "later-discovery")
    boundary = _boundary(development, loop7)

    first = _append(tmp_path, boundary=boundary, child=development)
    second = _append(tmp_path, boundary=boundary, child=loop7)
    third = _append(tmp_path, boundary=boundary, child=later)
    replay = _append(tmp_path, boundary=boundary, child=later)
    _write_request_rollover_side_evidence(tmp_path)
    _write_detail_encoding_rollover_side_evidence(tmp_path)
    authority = _load(tmp_path, boundary=boundary)

    assert (first.sequence, second.sequence, third.sequence) == (1, 2, 3)
    assert replay.canonical_sha256 == third.canonical_sha256
    assert authority.child_index_head_sha256 == third.canonical_sha256
    assert authority.child_inventory_count == 3
    assert later.image_sha256s[0] in authority.development_exclusions.image_sha256s
    verified = load_verified_loop9_exclusion_snapshot(
        data_root=tmp_path,
        source_boundary=boundary,
        expected_current_build_sha256=BUILD_SHA256,
        expected_settlement_contract_sha256=(
            SETTLEMENT_CONTRACT_SHA256
        ),
        expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
        expected_settlement_selection_sha256=(
            SETTLEMENT_SELECTION_SHA256
        ),
        expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
    )
    assert verified.authority_sha256 == authority.canonical_sha256
    assert verified.child_index_head_sha256 == third.canonical_sha256
    assert set(verified.excluded_platform_identity_sha256s) == {
        *development.platform_identity_sha256s,
        *loop7.platform_identity_sha256s,
        *later.platform_identity_sha256s,
    }
    assert set(verified.excluded_image_sha256s) == {
        *development.image_sha256s,
        *loop7.image_sha256s,
        *later.image_sha256s,
    }

    unknown = (
        tmp_path
        / "platform-contract-discovery"
        / "unexpected.json"
    )
    _rewrite_json(unknown, {"unexpected": True})
    with pytest.raises(
        Loop9DatasetIsolationError,
        match="unknown JSON",
    ):
        _load(tmp_path, boundary=boundary)


def test_sealed_chain_can_be_loaded_before_a_registered_child_is_appended(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    pending = _inventory(ExclusionKind.DEVELOPMENT, "pending")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    registry = tmp_path / "loop9-development-exclusions"
    _rewrite_json(
        registry / f"{pending.canonical_sha256}.json",
        pending.to_payload(),
    )

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="producer registry does not exactly match",
    ):
        _load(tmp_path, boundary=boundary)

    sealed = load_sealed_loop9_full_history_exclusion_authority(
        data_root=tmp_path,
        source_boundary=boundary,
        expected_current_build_sha256=BUILD_SHA256,
        expected_settlement_contract_sha256=(
            SETTLEMENT_CONTRACT_SHA256
        ),
        expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
        expected_settlement_selection_sha256=(
            SETTLEMENT_SELECTION_SHA256
        ),
        expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
    )

    assert sealed.child_inventories == (development, loop7)

def test_chain_rejects_missing_child_and_tampered_node(tmp_path: Path) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    first = _append(tmp_path, boundary=boundary, child=development)
    second = _append(tmp_path, boundary=boundary, child=loop7)
    store = _store(tmp_path)

    child_path = store / "children" / f"{development.canonical_sha256}.json"
    original_child = child_path.read_bytes()
    child_path.unlink()
    with pytest.raises(Loop9DatasetIsolationError, match=r"child.*missing"):
        _load(tmp_path, boundary=boundary)
    child_path.write_bytes(original_child)

    node_path = store / "nodes" / f"{second.canonical_sha256}.json"
    document = json.loads(node_path.read_text(encoding="utf-8"))
    document["sequence"] = 99
    _rewrite_json(node_path, document)
    with pytest.raises(Loop9DatasetIsolationError, match=r"node.*integrity"):
        _load(tmp_path, boundary=boundary)

    assert first.canonical_sha256 != second.canonical_sha256


def test_chain_rejects_head_rollback_and_fork(tmp_path: Path) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    later = _inventory(ExclusionKind.DEVELOPMENT, "later")
    boundary = _boundary(development, loop7)
    first = _append(tmp_path, boundary=boundary, child=development)
    second = _append(tmp_path, boundary=boundary, child=loop7)
    store = _store(tmp_path)
    head_path = store / "head.json"
    current_head = json.loads(head_path.read_text(encoding="utf-8"))

    rolled_back = dict(current_head)
    rolled_back["head_sha256"] = first.canonical_sha256
    rolled_back["sequence"] = first.sequence
    rolled_back.pop("canonical_sha256")
    rolled_back = {
        **rolled_back,
        "canonical_sha256": hashlib.sha256(
            json.dumps(
                rolled_back,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
    }
    _rewrite_json(head_path, rolled_back)
    with pytest.raises(Loop9DatasetIsolationError, match="rollback"):
        _load(tmp_path, boundary=boundary)
    _rewrite_json(head_path, current_head)

    fork = Loop9ExclusionChildIndexNode.create(
        sequence=second.sequence,
        previous_head_sha256=first.canonical_sha256,
        source_boundary=boundary,
        child_inventory=later,
        expected_current_build_sha256=BUILD_SHA256,
        expected_settlement_contract_sha256=(
            SETTLEMENT_CONTRACT_SHA256
        ),
        expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
        expected_settlement_selection_sha256=(
            SETTLEMENT_SELECTION_SHA256
        ),
        expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
    )
    _rewrite_json(
        store / "children" / f"{later.canonical_sha256}.json",
        later.to_payload(),
    )
    _rewrite_json(
        store / "nodes" / f"{fork.canonical_sha256}.json",
        fork.to_payload(),
    )
    with pytest.raises(Loop9DatasetIsolationError, match="fork"):
        _load(tmp_path, boundary=boundary)


def test_chain_rejects_binding_change_and_source_omission(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    unrelated = _inventory(ExclusionKind.DEVELOPMENT, "unrelated")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)

    with pytest.raises(Loop9DatasetIsolationError, match="build or contract"):
        append_loop9_exclusion_child(
            data_root=tmp_path,
            source_boundary=boundary,
            child_inventory=loop7,
            expected_current_build_sha256=_sha("changed-build"),
            expected_settlement_contract_sha256=(
                SETTLEMENT_CONTRACT_SHA256
            ),
            expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
            expected_settlement_selection_sha256=(
                SETTLEMENT_SELECTION_SHA256
            ),
            expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
        )

    empty_root = tmp_path / "empty"
    _append(empty_root, boundary=boundary, child=unrelated)
    _append(empty_root, boundary=boundary, child=loop7)
    with pytest.raises(
        Loop9DatasetIsolationError,
        match="complete source history",
    ):
        _load(empty_root, boundary=boundary)


def test_sqlite_anchor_detects_tail_deletion_plus_head_rollback(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    first = _append(tmp_path, boundary=boundary, child=development)
    second = _append(tmp_path, boundary=boundary, child=loop7)
    store = _store(tmp_path)

    (store / "nodes" / f"{second.canonical_sha256}.json").unlink()
    (store / "children" / f"{loop7.canonical_sha256}.json").unlink()
    first_head = {
        "expected_current_build_sha256": BUILD_SHA256,
        "expected_daily_contract_sha256": DAILY_CONTRACT_SHA256,
        "expected_daily_selection_sha256": DAILY_SELECTION_SHA256,
        "expected_settlement_contract_sha256": (
            SETTLEMENT_CONTRACT_SHA256
        ),
        "expected_settlement_selection_sha256": (
            SETTLEMENT_SELECTION_SHA256
        ),
        "head_sha256": first.canonical_sha256,
        "identity_context_sha256": IDENTITY_CONTEXT_SHA256,
        "kind": "loop9_exclusion_child_index_head",
        "schema_version": 1,
        "sequence": 1,
        "source_boundary_sha256": boundary.canonical_sha256,
        "source_inventory_high_watermark": (
            boundary.source_inventory_high_watermark
        ),
    }
    _rewrite_json(
        store / "head.json",
        {
            **first_head,
            "canonical_sha256": hashlib.sha256(
                json.dumps(
                    first_head,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
        },
    )

    with pytest.raises(Loop9DatasetIsolationError, match="SQLite anchor"):
        _load(tmp_path, boundary=boundary)


def test_read_only_verifier_does_not_create_a_missing_store(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    _initialize_database(tmp_path)

    with pytest.raises(Loop9DatasetIsolationError, match="store is missing"):
        _load(tmp_path, boundary=boundary)

    assert not _store(tmp_path).exists()


def test_persisted_authority_bootstraps_source_boundary_without_template_state(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    authority = _load(tmp_path, boundary=boundary)
    persist_loop9_full_history_exclusion_authority(
        data_root=tmp_path,
        authority=authority,
    )

    snapshot = (
        load_verified_loop9_exclusion_snapshot_from_persisted_authority(
            data_root=tmp_path,
            expected_current_build_sha256=BUILD_SHA256,
            expected_settlement_contract_sha256=(
                SETTLEMENT_CONTRACT_SHA256
            ),
            expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
            expected_settlement_selection_sha256=(
                SETTLEMENT_SELECTION_SHA256
            ),
            expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
        )
    )

    assert snapshot.authority_sha256 == authority.canonical_sha256
    assert snapshot.source_boundary_sha256 == boundary.canonical_sha256
    assert snapshot.child_index_head_sha256 == (
        authority.child_index_head_sha256
    )


def test_persisted_authority_loader_follows_current_head_and_retains_history(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    later = _inventory(ExclusionKind.DEVELOPMENT, "later")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    first = _load(tmp_path, boundary=boundary)
    first_path = persist_loop9_full_history_exclusion_authority(
        data_root=tmp_path,
        authority=first,
    )
    _append(tmp_path, boundary=boundary, child=later)
    current = _load(tmp_path, boundary=boundary)
    current_path = persist_loop9_full_history_exclusion_authority(
        data_root=tmp_path,
        authority=current,
    )

    snapshot = (
        load_verified_loop9_exclusion_snapshot_from_persisted_authority(
            data_root=tmp_path,
            expected_current_build_sha256=BUILD_SHA256,
            expected_settlement_contract_sha256=(
                SETTLEMENT_CONTRACT_SHA256
            ),
            expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
            expected_settlement_selection_sha256=(
                SETTLEMENT_SELECTION_SHA256
            ),
            expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
        )
    )

    assert first_path.exists()
    assert current_path.exists()
    assert snapshot.authority_sha256 == current.canonical_sha256
    assert snapshot.child_index_head_sha256 == (
        current.child_index_head_sha256
    )


def test_persisted_authority_loader_fails_closed_for_missing_or_tampered_current(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    authority = _load(tmp_path, boundary=boundary)

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="persisted full-history exclusion authority",
    ):
        load_verified_loop9_exclusion_snapshot_from_persisted_authority(
            data_root=tmp_path,
            expected_current_build_sha256=BUILD_SHA256,
            expected_settlement_contract_sha256=(
                SETTLEMENT_CONTRACT_SHA256
            ),
            expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
            expected_settlement_selection_sha256=(
                SETTLEMENT_SELECTION_SHA256
            ),
            expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
        )

    current_path = persist_loop9_full_history_exclusion_authority(
        data_root=tmp_path,
        authority=authority,
    )
    tampered = authority.to_payload()
    source_boundary = dict(tampered["source_boundary"])
    source_boundary["source_authority_sha256"] = _sha("tampered-source")
    tampered["source_boundary"] = source_boundary
    _rewrite_json(current_path, tampered)

    with pytest.raises(Loop9DatasetIsolationError):
        load_verified_loop9_exclusion_snapshot_from_persisted_authority(
            data_root=tmp_path,
            expected_current_build_sha256=BUILD_SHA256,
            expected_settlement_contract_sha256=(
                SETTLEMENT_CONTRACT_SHA256
            ),
            expected_daily_contract_sha256=DAILY_CONTRACT_SHA256,
            expected_settlement_selection_sha256=(
                SETTLEMENT_SELECTION_SHA256
            ),
            expected_daily_selection_sha256=DAILY_SELECTION_SHA256,
        )


def test_sqlite_anchor_rows_are_append_only(tmp_path: Path) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    database = tmp_path / "database" / "dahe.sqlite3"

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE loop9_exclusion_authority_anchors "
                "SET sequence = sequence WHERE sequence = 2"
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM loop9_exclusion_authority_anchors "
                "WHERE sequence = 2"
            )


def test_new_build_starts_a_new_anchor_chain_without_deleting_history(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    boundary = _boundary(development, loop7)
    next_build_sha256 = _sha("next-build")

    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    shutil.move(
        _store(tmp_path),
        tmp_path / "previous-build-exclusion-authority",
    )

    first = _append(
        tmp_path,
        boundary=boundary,
        child=development,
        build_sha256=next_build_sha256,
    )
    second = _append(
        tmp_path,
        boundary=boundary,
        child=loop7,
        build_sha256=next_build_sha256,
    )

    assert first.sequence == 1
    assert second.sequence == 2
    database = tmp_path / "database" / "dahe.sqlite3"
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT authority_context_sha256, sequence "
            "FROM loop9_exclusion_authority_anchors "
            "ORDER BY authority_context_sha256, sequence"
        ).fetchall()
    assert len(rows) == 4
    assert len({str(row[0]) for row in rows}) == 2
    assert sorted(int(row[1]) for row in rows) == [1, 1, 2, 2]


def test_formal_loader_requires_exact_development_producer_registry(
    tmp_path: Path,
) -> None:
    development = _inventory(ExclusionKind.DEVELOPMENT, "development")
    loop7 = _inventory(ExclusionKind.LEGACY_LOOP7, "loop7")
    extra = _inventory(ExclusionKind.DEVELOPMENT, "unregistered-extra")
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    registry = tmp_path / "loop9-development-exclusions"
    development_path = registry / f"{development.canonical_sha256}.json"

    _rewrite_json(
        registry / f"{extra.canonical_sha256}.json",
        extra.to_payload(),
    )
    with pytest.raises(
        Loop9DatasetIsolationError,
        match="producer registry",
    ):
        _load(tmp_path, boundary=boundary)
    (registry / f"{extra.canonical_sha256}.json").unlink()

    development_payload = development_path.read_bytes()
    development_path.unlink()
    with pytest.raises(
        Loop9DatasetIsolationError,
        match="producer registry",
    ):
        _load(tmp_path, boundary=boundary)
    development_path.write_bytes(development_payload)

    tampered = development.to_payload()
    tampered["canonical_sha256"] = "0" * 64
    _rewrite_json(development_path, tampered)
    with pytest.raises(
        Loop9DatasetIsolationError,
        match="producer registry",
    ):
        _load(tmp_path, boundary=boundary)


def test_formal_loader_requires_every_contract_discovery_exclusion(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    identity_salt = b"x" * 32
    identity_context = chengfeng_shadow_identity_context_sha256(
        salt=identity_salt,
        namespace="chengfeng:waybill",
    )
    development = _inventory(
        ExclusionKind.DEVELOPMENT,
        "development",
        identity_context_sha256=identity_context,
    )
    loop7 = _inventory(
        ExclusionKind.LEGACY_LOOP7,
        "loop7",
        identity_context_sha256=identity_context,
    )
    boundary = _boundary(development, loop7)
    _append(tmp_path, boundary=boundary, child=development)
    _append(tmp_path, boundary=boundary, child=loop7)
    discovery = DiscoveryEvidenceStore(tmp_path.resolve()).seal(
        observations=[
            {
                "method": "POST",
                "origin": "https://pc.chengfengkuaiyun.com",
                "path": (
                    "/api/order-center-server/app/clientOrderItem/"
                    "getOrderItemDetailsByIdPC"
                ),
                "path_sha256": None,
                "query_keys": [],
                "request_fields": [
                    {"path": "$.orderItemId", "type": "integer"}
                ],
                "resource_kind": "json_api",
                "response_status": 200,
                "content_kind": "json",
                "response_fields": [
                    {"path": "$.data.id", "type": "integer"}
                ],
            }
        ],
        build_sha256=BUILD_SHA256,
        access_window_id="discovery-window",
        captured_at=datetime(2026, 7, 30, tzinfo=UTC),
    )

    with pytest.raises(
        Loop9DatasetIsolationError,
        match="contract discovery producer registry",
    ):
        _load(tmp_path, boundary=boundary)

    discovery_inventory = register_loop9_contract_discovery_exclusion(
        data_root=tmp_path.resolve(),
        discovery_evidence_path=discovery.path.resolve(),
        source_identities=("67011222",),
        identity_salt=identity_salt,
        identity_namespace="chengfeng:waybill",
    )
    _append(
        tmp_path,
        boundary=boundary,
        child=discovery_inventory,
    )

    authority = _load(tmp_path, boundary=boundary)
    assert (
        discovery_inventory.canonical_sha256
        in {
            child.canonical_sha256
            for child in authority.child_inventories
        }
    )

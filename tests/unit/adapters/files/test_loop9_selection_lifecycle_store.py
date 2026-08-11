from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from dahe.adapters.files.shadow_selection_lifecycle import (
    FormalSelectionLifecycleStore,
    FormalSelectionLifecycleStoreError,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchImage,
    ShadowBatchItem,
    ShadowBatchSource,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.application.chengfeng.shadow_selection_lifecycle import (
    FormalSelectionLifecycleEvent,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)
from dahe.verification.loop9_dataset_isolation import (
    ExclusionKind,
    Loop9DatasetExclusionInventory,
)
from dahe.verification.loop9_exclusion_authority import (
    Loop9VerifiedExclusionSnapshot,
)
from dahe.verification.loop9_locked_selection_rollover import (
    LockedSelectionCoverageFailureAttestation,
)


def _fingerprint(image_sha256: str, index: int) -> ImagePerceptualFingerprint:
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=image_sha256,
        width=640,
        height=480,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop,
                average_hash=hashlib.sha256(
                    f"average:{index}:{crop}".encode()
                ).hexdigest(),
                difference_hash=hashlib.sha256(
                    f"difference:{index}:{crop}".encode()
                ).hexdigest(),
            )
            for crop in (1000, 920, 840, 760)
        ),
    )


def _selection(
    *,
    offset: int = 0,
    exclusion_authority_sha256: str = "3" * 64,
    exclusion_head_sha256: str = "4" * 64,
) -> FormalShadowSelectionManifest:
    items: list[ShadowBatchItem] = []
    for index in range(50):
        images: list[ShadowBatchImage] = []
        for slot_index, slot in enumerate(("loading", "unloading")):
            image_index = offset + index * 2 + slot_index + 1
            image_sha256 = f"{image_index:064x}"
            images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=image_sha256,
                    relative_path=(
                        f"sha256/{image_sha256[:2]}/{image_sha256[2:4]}/"
                        f"{image_sha256}.blob"
                    ),
                    byte_size=1000 + image_index,
                    media_type="image/jpeg",
                    perceptual_fingerprint=_fingerprint(
                        image_sha256,
                        image_index,
                    ),
                )
            )
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=f"{1000 + offset + index:064x}",
                waybill_number_digest=f"{2000 + offset + index:064x}",
                vehicle_number_digest=f"{3000 + offset + index:064x}",
                platform_loading_net="32.10",
                platform_unloading_net="31.90",
                images=(images[0], images[1]),
            )
        )
    batch = ChengfengShadowBatchManifest(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        source_build_sha256="a" * 64,
        contract_canonical_sha256="b" * 64,
        contract_file_sha256="c" * 64,
        contract_selection_sha256="d" * 64,
        pipeline_fingerprint="e" * 64,
        identity_context_sha256="f" * 64,
        sources=(
            ShadowBatchSource(
                access_window_id=f"window-{offset}",
                job_id=f"job-{offset}",
                capture_id=f"capture-{offset}",
                scope="current",
                page_number=1,
                page_size=50,
                checkpoint_sha256=f"{offset + 1:064x}",
            ),
        ),
        items=tuple(items),
    )
    return FormalShadowSelectionManifest(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        source_capture_sha256=f"{offset + 2:064x}",
        full_history_exclusion_authority_sha256=(
            exclusion_authority_sha256
        ),
        exclusion_child_index_head_sha256=exclusion_head_sha256,
        exclusion_source_boundary_sha256="5" * 64,
        exclusion_source_inventory_high_watermark=7,
        selection_seed_authority_sha256="6" * 64,
        rank_commitment_sha256=f"{offset + 7:064x}",
        prior_selection_sha256s=(),
        batch_manifest=batch,
    )


def _inventory(
    selection: FormalShadowSelectionManifest,
) -> Loop9DatasetExclusionInventory:
    return Loop9DatasetExclusionInventory(
        inventory_id=(
            f"loop9-failed-locked-{selection.canonical_sha256[:16]}"
        ),
        exclusion_kind=ExclusionKind.DEVELOPMENT,
        platform_identity_sha256s=tuple(
            sorted(
                item.platform_waybill_id_digest
                for item in selection.batch_manifest.items
            )
        ),
        image_sha256s=tuple(
            sorted(
                image.sha256
                for item in selection.batch_manifest.items
                for image in item.images
            )
        ),
        scope_exclusion_tokens=(),
        perceptual_fingerprints=tuple(
            sorted(
                (
                    image.perceptual_fingerprint
                    for item in selection.batch_manifest.items
                    for image in item.images
                ),
                key=lambda value: value.content_sha256,
            )
        ),
        identity_context_sha256=(
            selection.batch_manifest.identity_context_sha256
        ),
    )


def _failure(
    selection: FormalShadowSelectionManifest,
) -> LockedSelectionCoverageFailureAttestation:
    return LockedSelectionCoverageFailureAttestation(
        selection_sha256=selection.canonical_sha256,
        source_batch_sha256=selection.batch_manifest.canonical_sha256,
        package_sha256="8" * 64,
        review_answers_sha256="9" * 64,
        review_count=50,
        image_truth_count=100,
        source_build_sha256=selection.batch_manifest.source_build_sha256,
        contract_canonical_sha256=(
            selection.batch_manifest.contract_canonical_sha256
        ),
        contract_selection_sha256=(
            selection.batch_manifest.contract_selection_sha256
        ),
        pipeline_fingerprint=(
            selection.batch_manifest.pipeline_fingerprint
        ),
        identity_context_sha256=(
            selection.batch_manifest.identity_context_sha256
        ),
        selection_exclusion_authority_sha256=(
            selection.full_history_exclusion_authority_sha256
        ),
        selection_exclusion_child_head_sha256=(
            selection.exclusion_child_index_head_sha256
        ),
        coverage={
            "blur": (),
            "crop": (),
            "glare": (),
            "printed": (),
            "rotation_0": tuple(
                image.sha256
                for item in selection.batch_manifest.items
                for image in item.images
            ),
            "rotation_90": (),
            "rotation_180": (),
            "rotation_270": (),
            "screen": (),
            "unknown_layout": (),
        },
        missing_conditions=(
            "blur",
            "crop",
            "glare",
            "printed",
            "rotation_90",
            "rotation_180",
            "rotation_270",
            "screen",
            "unknown_layout",
        ),
        reviews=tuple(
            {
                "item_identity_sha256": item.item_identity_sha256,
                "confirmed_at": "2026-07-30T01:02:03Z",
                "images": [
                    {
                        "slot": image.slot,
                        "image_sha256": image.sha256,
                        "role": image.slot,
                        "ordinary_net": (
                            "32.10"
                            if image.slot == "loading"
                            else "31.90"
                        ),
                        "quality_conditions": ["rotation_0"],
                    }
                    for image in item.images
                ],
                "pair_condition": "normal_pair",
                "confirmation": "corrected",
            }
            for item in sorted(
                selection.batch_manifest.items,
                key=lambda value: value.item_identity_sha256,
            )
        ),
    )


def _snapshot(
    *,
    selection: FormalShadowSelectionManifest,
    inventory: Loop9DatasetExclusionInventory,
    authority_sha256: str = "a" * 64,
    head_sha256: str = "b" * 64,
) -> Loop9VerifiedExclusionSnapshot:
    legacy_image = _fingerprint("f" * 64, 9999)
    legacy = Loop9DatasetExclusionInventory(
        inventory_id="legacy-loop7",
        exclusion_kind=ExclusionKind.LEGACY_LOOP7,
        platform_identity_sha256s=(),
        image_sha256s=(legacy_image.content_sha256,),
        scope_exclusion_tokens=(),
        perceptual_fingerprints=(legacy_image,),
        identity_context_sha256=(
            selection.batch_manifest.identity_context_sha256
        ),
    )
    return Loop9VerifiedExclusionSnapshot(
        authority_sha256=authority_sha256,
        child_index_head_sha256=head_sha256,
        source_boundary_sha256=selection.exclusion_source_boundary_sha256,
        source_inventory_high_watermark=(
            selection.exclusion_source_inventory_high_watermark
        ),
        identity_context_sha256=(
            selection.batch_manifest.identity_context_sha256
        ),
        expected_current_build_sha256=(
            selection.batch_manifest.source_build_sha256
        ),
        expected_settlement_contract_sha256=(
            selection.batch_manifest.contract_canonical_sha256
        ),
        expected_daily_contract_sha256="c" * 64,
        expected_settlement_selection_sha256=(
            selection.batch_manifest.contract_selection_sha256
        ),
        expected_daily_selection_sha256="d" * 64,
        development_exclusions=inventory,
        legacy_loop7_exclusions=legacy,
        excluded_platform_identity_sha256s=(
            inventory.platform_identity_sha256s
        ),
        excluded_image_sha256s=inventory.image_sha256s,
        excluded_scope_exclusion_tokens=(),
        excluded_perceptual_fingerprints=(
            inventory.perceptual_fingerprints
        ),
    )


def _initialize(data_root: Path) -> None:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=Path(__file__).resolve().parents[4],
        instance_id="loop9-selection-lifecycle-test",
    )
    runtime.close()


def test_lifecycle_bootstraps_generation_one_without_rewriting_selection(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    selection = _selection()
    protected = data_root / "loop9-formal-selections" / "protected.json"
    protected.parent.mkdir(parents=True, exist_ok=True)
    protected.write_bytes(b"legacy-authority\n")
    before = protected.read_bytes()
    store = FormalSelectionLifecycleStore(data_root)

    first = store.bootstrap_current_locked_selection(selection)
    replay = store.bootstrap_current_locked_selection(selection)
    state = store.load_state()

    assert first.canonical_sha256 == replay.canonical_sha256
    assert state is not None
    assert state.generation == 1
    assert state.event_kind is FormalSelectionLifecycleEvent.ACTIVATED
    assert state.active_selection_sha256 == selection.canonical_sha256
    assert protected.read_bytes() == before


def test_invalidation_requires_verified_exclusion_then_allows_generation_two(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    first_selection = _selection()
    inventory = _inventory(first_selection)
    failure = _failure(first_selection)
    store = FormalSelectionLifecycleStore(data_root)
    store.bootstrap_current_locked_selection(first_selection)

    incomplete = _snapshot(
        selection=first_selection,
        inventory=Loop9DatasetExclusionInventory(
            inventory_id="incomplete-failed-locked",
            exclusion_kind=ExclusionKind.DEVELOPMENT,
            platform_identity_sha256s=(
                inventory.platform_identity_sha256s[:-1]
            ),
            image_sha256s=inventory.image_sha256s[:-2],
            scope_exclusion_tokens=(),
            perceptual_fingerprints=(
                inventory.perceptual_fingerprints[:-2]
            ),
            identity_context_sha256=inventory.identity_context_sha256,
        ),
    )
    with pytest.raises(
        FormalSelectionLifecycleStoreError,
        match="does not cover",
    ):
        store.invalidate_current_locked_selection(
            selection=first_selection,
            failure_attestation=failure,
            exclusion_inventory=inventory,
            exclusion_snapshot=incomplete,
        )

    snapshot = _snapshot(
        selection=first_selection,
        inventory=inventory,
    )
    invalidated = store.invalidate_current_locked_selection(
        selection=first_selection,
        failure_attestation=failure,
        exclusion_inventory=inventory,
        exclusion_snapshot=snapshot,
    )
    replay = store.invalidate_current_locked_selection(
        selection=first_selection,
        failure_attestation=failure,
        exclusion_inventory=inventory,
        exclusion_snapshot=snapshot,
    )
    assert invalidated.canonical_sha256 == replay.canonical_sha256
    assert store.load_state().active_selection_sha256 is None  # type: ignore[union-attr]
    with pytest.raises(
        FormalSelectionLifecycleStoreError,
        match="not the active",
    ):
        store.require_active_selection(first_selection.canonical_sha256)

    replacement = _selection(
        offset=10000,
        exclusion_authority_sha256=snapshot.authority_sha256,
        exclusion_head_sha256=snapshot.child_index_head_sha256,
    )
    activated = store.activate_replacement(
        selection=replacement,
        exclusion_snapshot=snapshot,
    )
    state = store.load_state()
    assert activated.event_kind is FormalSelectionLifecycleEvent.ACTIVATED
    assert activated.generation == 2
    assert state is not None
    assert state.active_selection_sha256 == replacement.canonical_sha256


@pytest.mark.parametrize("fault_point", ["after_node_write", "after_anchor_commit"])
def test_lifecycle_append_recovers_idempotently_after_interruption(
    tmp_path: Path,
    fault_point: str,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    selection = _selection()
    fired = False

    def interrupt(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated interruption")

    store = FormalSelectionLifecycleStore(
        data_root,
        fault_injector=interrupt,
    )
    with pytest.raises(RuntimeError, match="simulated interruption"):
        store.bootstrap_current_locked_selection(selection)

    recovered = FormalSelectionLifecycleStore(
        data_root
    ).bootstrap_current_locked_selection(selection)
    state = FormalSelectionLifecycleStore(data_root).load_state()
    assert state is not None
    assert state.head_sha256 == recovered.canonical_sha256
    assert state.active_selection_sha256 == selection.canonical_sha256


@pytest.mark.parametrize("fault_point", ["after_node_write", "after_anchor_commit"])
def test_invalidation_recovers_idempotently_after_interruption(
    tmp_path: Path,
    fault_point: str,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    selection = _selection()
    inventory = _inventory(selection)
    failure = _failure(selection)
    snapshot = _snapshot(selection=selection, inventory=inventory)
    FormalSelectionLifecycleStore(
        data_root
    ).bootstrap_current_locked_selection(selection)
    fired = False

    def interrupt(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        FormalSelectionLifecycleStore(
            data_root,
            fault_injector=interrupt,
        ).invalidate_current_locked_selection(
            selection=selection,
            failure_attestation=failure,
            exclusion_inventory=inventory,
            exclusion_snapshot=snapshot,
        )

    recovered = FormalSelectionLifecycleStore(
        data_root
    ).invalidate_current_locked_selection(
        selection=selection,
        failure_attestation=failure,
        exclusion_inventory=inventory,
        exclusion_snapshot=snapshot,
    )
    state = FormalSelectionLifecycleStore(data_root).load_state()
    assert state is not None
    assert state.head_sha256 == recovered.canonical_sha256
    assert state.active_selection_sha256 is None


@pytest.mark.parametrize("fault_point", ["after_node_write", "after_anchor_commit"])
def test_replacement_activation_recovers_idempotently_after_interruption(
    tmp_path: Path,
    fault_point: str,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    selection = _selection()
    inventory = _inventory(selection)
    failure = _failure(selection)
    snapshot = _snapshot(selection=selection, inventory=inventory)
    lifecycle = FormalSelectionLifecycleStore(data_root)
    lifecycle.bootstrap_current_locked_selection(selection)
    lifecycle.invalidate_current_locked_selection(
        selection=selection,
        failure_attestation=failure,
        exclusion_inventory=inventory,
        exclusion_snapshot=snapshot,
    )
    replacement = _selection(
        offset=10000,
        exclusion_authority_sha256=snapshot.authority_sha256,
        exclusion_head_sha256=snapshot.child_index_head_sha256,
    )
    fired = False

    def interrupt(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        FormalSelectionLifecycleStore(
            data_root,
            fault_injector=interrupt,
        ).activate_replacement(
            selection=replacement,
            exclusion_snapshot=snapshot,
        )

    recovered = FormalSelectionLifecycleStore(
        data_root
    ).activate_replacement(
        selection=replacement,
        exclusion_snapshot=snapshot,
    )
    state = FormalSelectionLifecycleStore(data_root).load_state()
    assert state is not None
    assert state.head_sha256 == recovered.canonical_sha256
    assert state.generation == 2
    assert state.active_selection_sha256 == replacement.canonical_sha256


def test_lifecycle_rejects_file_or_sqlite_rollback(tmp_path: Path) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    selection = _selection()
    store = FormalSelectionLifecycleStore(data_root)
    store.bootstrap_current_locked_selection(selection)
    head = (
        data_root
        / "loop9-formal-selections"
        / "lifecycle"
        / "current_locked_50"
        / "head.json"
    )
    head.write_text("{}\n", encoding="utf-8")
    with pytest.raises(
        FormalSelectionLifecycleStoreError,
        match=r"head.*integrity",
    ):
        store.load_state()

    database = data_root / "database" / "dahe.sqlite3"
    with (
        sqlite3.connect(database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute(
            "DELETE FROM loop9_formal_selection_lifecycle_anchors"
        )

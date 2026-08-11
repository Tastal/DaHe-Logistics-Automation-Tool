from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import dahe.adapters.files.shadow_selection_manifest as selection_store_module
from dahe.adapters.files.settlement_capture_manifest import (
    SettlementCaptureManifestStore,
    SettlementCaptureManifestStoreError,
)
from dahe.adapters.files.shadow_selection_lifecycle import (
    FormalSelectionLifecycleStore,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
    FormalShadowSelectionStoreError,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.settlement_capture import (
    SCHEMA_VERSION as SETTLEMENT_CAPTURE_SCHEMA_VERSION,
)
from dahe.application.chengfeng.settlement_capture import (
    SettlementCaptureAccessWindowLineage,
    SettlementCaptureManifest,
    SettlementCaptureReadAccessBinding,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchImage,
    ShadowBatchItem,
    ShadowBatchSource,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalSelectionExclusionSnapshot,
    FormalShadowSelectionManifest,
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
from dahe.verification.loop9_locked_gate import (
    CurrentLockedGateAuthority,
    Loop9CurrentLockedGateError,
)
from dahe.verification.loop9_locked_selection_rollover import (
    LockedSelectionCoverageFailureAttestation,
    development_inventory_from_failed_locked_selection,
)

PIPELINE_SHA = "e" * 64


class _GateAuthorityStore:
    def __init__(self) -> None:
        self.package_sha256 = "7" * 64
        self.calls: list[tuple[str, str, str]] = []

    def load_for_selection(
        self,
        *,
        locked_selection: FormalShadowSelectionManifest,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
    ) -> CurrentLockedGateAuthority:
        batch = locked_selection.batch_manifest
        self.calls.append(
            (
                locked_selection.canonical_sha256,
                expected_current_build_sha256,
                expected_settlement_contract_sha256,
            )
        )
        if (
            expected_current_build_sha256
            != batch.source_build_sha256
            or expected_settlement_contract_sha256
            != batch.contract_canonical_sha256
        ):
            raise Loop9CurrentLockedGateError(
                "current locked gate build or selection binding changed"
            )
        return CurrentLockedGateAuthority(
            selection_sha256=locked_selection.canonical_sha256,
            source_batch_sha256=batch.canonical_sha256,
            source_build_sha256=batch.source_build_sha256,
            settlement_contract_sha256=(
                batch.contract_canonical_sha256
            ),
            package_sha256=self.package_sha256,
            human_review_seal_sha256="8" * 64,
            machine_result_sha256="9" * 64,
            machine_evaluation_sha256="a" * 64,
            package_relative_path="verification/loop9/package",
            seal_relative_path="verification/loop9/seal.json",
            machine_result_relative_path=(
                "verification/loop9/machine-result.json"
            ),
            machine_evaluation_relative_path=(
                "verification/loop9/machine-evaluation.json"
            ),
        )


class _CaptureAuthorityStore:
    def __init__(
        self,
        *captures: SettlementCaptureManifest,
    ) -> None:
        self.captures = {
            capture.canonical_sha256: capture
            for capture in captures
        }
        self.calls: list[str] = []

    def load(
        self,
        canonical_sha256: str,
    ) -> SettlementCaptureManifest:
        self.calls.append(canonical_sha256)
        try:
            return self.captures[canonical_sha256]
        except KeyError as exc:
            raise SettlementCaptureManifestStoreError(
                "settlement capture manifest is unavailable"
            ) from exc


def _initialize(data_root: Path) -> None:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=Path(__file__).resolve().parents[4],
        instance_id="loop9-formal-selection-store-test",
    )
    runtime.close()


def _fingerprint(sha256: str, seed: int) -> ImagePerceptualFingerprint:
    average = hashlib.sha256(f"average:{seed}".encode()).hexdigest()
    difference = hashlib.sha256(
        f"difference:{seed}".encode()
    ).hexdigest()
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=sha256,
        width=8,
        height=8,
        view_hashes=tuple(
            PerceptualViewHash(
                crop_permille=crop,
                average_hash=average,
                difference_hash=difference,
            )
            for crop in (1000, 920, 840, 760)
        ),
    )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _request_audit_body(
    *,
    count: int,
    purpose: str,
    job_id: str,
) -> dict[str, object]:
    target_purpose = {
        "formal_locked_set": "current_locked_50",
        "production_shadow": "real_shadow_30",
    }[purpose]
    succeeded = {
        "download_ticket_image": count * 2,
        "get_waybill_detail": count,
        "list_daily_waybills": 0,
        "list_waybills": 1,
    }
    operation_counts = {
        operation: {
            "allowed": operation_count,
            "attempted": operation_count,
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": operation_count,
        }
        for operation, operation_count in succeeded.items()
    }
    total = sum(succeeded.values())
    return {
        "authority": {
            "build_sha256": "a" * 64,
            "daily_contract_selection_sha256": None,
            "daily_contract_sha256": None,
            "settlement_contract_selection_sha256": "d" * 64,
            "settlement_contract_sha256": "b" * 64,
        },
        "event_chain_sha256": hashlib.sha256(
            f"{target_purpose}:{count}".encode("ascii")
        ).hexdigest(),
        "event_count": total * 3,
        "expected_succeeded_operations": {
            "download_ticket_image": count * 2,
            "get_waybill_detail": count,
            "list_waybills": 1,
        },
        "job_id_sha256": hashlib.sha256(job_id.encode("utf-8")).hexdigest(),
        "kind": "loop9_platform_read_audit",
        "operation_counts": operation_counts,
        "platform_write_request_count": 0,
        "purpose": target_purpose,
        "redirect_count": 0,
        "request_counts": {
            "allowed": total,
            "attempted": total,
            "denied": 0,
            "succeeded": total,
        },
        "schema_version": 1,
    }


def _capture(
    count: int = 90,
    *,
    audited: bool = True,
    purpose: str = "formal_locked_set",
) -> SettlementCaptureManifest:
    job_id = "job-one"
    scope = (
        "settled_history"
        if purpose == "formal_locked_set"
        else "current"
    )
    page_size = 100 if scope == "settled_history" else 50
    items: list[ShadowBatchItem] = []
    for index in range(count):
        images: list[ShadowBatchImage] = []
        for slot_index, slot in enumerate(("loading", "unloading")):
            sha256 = f"{(index * 2) + slot_index + 1:064x}"
            images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=sha256,
                    relative_path=(
                        f"sha256/{sha256[:2]}/{sha256[2:4]}/"
                        f"{sha256}.blob"
                    ),
                    byte_size=100 + index,
                    media_type="image/png",
                    perceptual_fingerprint=_fingerprint(
                        sha256,
                        (index * 2) + slot_index + 1,
                    ),
                )
            )
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=f"{1000 + index:064x}",
                waybill_number_digest=f"{2000 + index:064x}",
                vehicle_number_digest=f"{3000 + index:064x}",
                platform_loading_net="32.10",
                platform_unloading_net="31.90",
                images=(images[0], images[1]),
            )
        )
    if not audited:
        return SettlementCaptureManifest(
            source_build_sha256="a" * 64,
            contract_canonical_sha256="b" * 64,
            contract_file_sha256="c" * 64,
            contract_selection_sha256="d" * 64,
            identity_context_sha256="f" * 64,
            sources=(
                ShadowBatchSource(
                    access_window_id="window-one",
                    job_id=job_id,
                    capture_id="capture-one",
                    scope=scope,
                    page_number=1,
                    page_size=page_size,
                    checkpoint_sha256="1" * 64,
                ),
            ),
            items=tuple(items),
        )
    audit_body = _request_audit_body(
        count=count,
        purpose=purpose,
        job_id=job_id,
    )
    read_bindings = [
        SettlementCaptureReadAccessBinding(
            capture_id="capture-one",
            read_kind="list",
            subject_sha256="9" * 64,
            access_window_id="window-one",
        )
    ]
    for index, item in enumerate(items):
        read_bindings.append(
            SettlementCaptureReadAccessBinding(
                capture_id="capture-one",
                read_kind="detail",
                subject_sha256=hashlib.sha256(
                    f"detail:{index}".encode("ascii")
                ).hexdigest(),
                access_window_id="window-one",
            )
        )
        read_bindings.extend(
            SettlementCaptureReadAccessBinding(
                capture_id="capture-one",
                read_kind="image",
                subject_sha256=image.sha256,
                access_window_id="window-one",
            )
            for image in item.images
        )
    return SettlementCaptureManifest(
        source_build_sha256="a" * 64,
        contract_canonical_sha256="b" * 64,
        contract_file_sha256="c" * 64,
        contract_selection_sha256="d" * 64,
        identity_context_sha256="f" * 64,
        sources=(
            ShadowBatchSource(
                access_window_id="window-one",
                job_id=job_id,
                capture_id="capture-one",
                scope=scope,
                page_number=1,
                page_size=page_size,
                checkpoint_sha256="1" * 64,
            ),
        ),
        items=tuple(items),
        access_window_lineage=SettlementCaptureAccessWindowLineage(
            job_id=job_id,
            session_id="session-one",
            purpose=purpose,
            source_build_sha256="a" * 64,
            contract_canonical_sha256="b" * 64,
            contract_file_sha256="c" * 64,
            contract_selection_sha256="d" * 64,
            identity_context_sha256="f" * 64,
            access_window_ids=("window-one",),
        ),
        read_access_bindings=tuple(read_bindings),
        request_audit_sha256=_canonical_sha256(audit_body),
        request_audit_counts=audit_body,
        schema_version=SETTLEMENT_CAPTURE_SCHEMA_VERSION,
    )


def _exclusions(
    capture: SettlementCaptureManifest,
) -> FormalSelectionExclusionSnapshot:
    return FormalSelectionExclusionSnapshot(
        authority_sha256="4" * 64,
        child_index_head_sha256="5" * 64,
        source_boundary_sha256="6" * 64,
        source_inventory_high_watermark=1,
        identity_context_sha256=capture.identity_context_sha256,
        expected_current_build_sha256=capture.source_build_sha256,
        expected_settlement_contract_sha256=(
            capture.contract_canonical_sha256
        ),
        expected_settlement_selection_sha256=(
            capture.contract_selection_sha256
        ),
        excluded_platform_identity_sha256s=(),
        excluded_image_sha256s=(),
        excluded_scope_exclusion_tokens=(),
        excluded_perceptual_fingerprints=(),
    )


def _coverage_failure(
    selection: FormalShadowSelectionManifest,
) -> LockedSelectionCoverageFailureAttestation:
    images = tuple(
        image
        for item in selection.batch_manifest.items
        for image in item.images
    )
    return LockedSelectionCoverageFailureAttestation(
        selection_sha256=selection.canonical_sha256,
        source_batch_sha256=selection.batch_manifest.canonical_sha256,
        package_sha256="7" * 64,
        review_answers_sha256="8" * 64,
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
            "rotation_0": tuple(image.sha256 for image in images),
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
            for item in selection.batch_manifest.items
        ),
    )


def _verified_rollover_snapshot(
    *,
    selection: FormalShadowSelectionManifest,
    inventory: Loop9DatasetExclusionInventory,
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
        authority_sha256="9" * 64,
        child_index_head_sha256="0" * 64,
        source_boundary_sha256=(
            selection.exclusion_source_boundary_sha256
        ),
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
        expected_daily_contract_sha256="1" * 64,
        expected_settlement_selection_sha256=(
            selection.batch_manifest.contract_selection_sha256
        ),
        expected_daily_selection_sha256="2" * 64,
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


def test_capture_store_is_content_addressed_and_idempotent(
    tmp_path: Path,
) -> None:
    store = SettlementCaptureManifestStore(tmp_path.resolve())
    capture = _capture(audited=False)

    first = store.seal(capture)
    second = store.seal(capture)
    loaded = store.load(capture.canonical_sha256)

    assert first == second
    assert loaded.canonical_sha256 == capture.canonical_sha256
    assert first.name == f"{capture.canonical_sha256}.json"

    payload = json.loads(first.read_text(encoding="utf-8"))
    payload["source_build_sha256"] = "0" * 64
    first.write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    with pytest.raises(
        SettlementCaptureManifestStoreError,
        match="integrity",
    ):
        store.load(capture.canonical_sha256)


def test_selection_store_owns_stable_seed_and_target_authorities(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture()
    shadow_capture = _capture(purpose="production_shadow")
    gate_store = _GateAuthorityStore()
    capture_store = _CaptureAuthorityStore(capture, shadow_capture)
    store = FormalShadowSelectionStore(
        data_root,
        gate_authority_store=gate_store,
        capture_authority_store=capture_store,
    )

    locked = store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    locked_replay = store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    shadow = store.select(
        capture=shadow_capture,
        target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(shadow_capture),
        expected_current_build_sha256=shadow_capture.source_build_sha256,
        expected_settlement_contract_sha256=(
            shadow_capture.contract_canonical_sha256
        ),
    )

    assert locked.canonical_sha256 == locked_replay.canonical_sha256
    assert (
        store.load_manifest(locked.canonical_sha256).canonical_sha256
        == locked.canonical_sha256
    )
    assert (
        store.load_active_current_locked_manifest(
            locked.canonical_sha256
        ).canonical_sha256
        == locked.canonical_sha256
    )
    assert store.load(
        ShadowBatchTargetKind.CURRENT_LOCKED_50
    ).canonical_sha256 == locked.canonical_sha256
    assert store.load(
        ShadowBatchTargetKind.REAL_SHADOW_30
    ).canonical_sha256 == shadow.canonical_sha256
    assert shadow.locked_gate_evidence_sha256 is not None
    assert gate_store.calls
    assert capture_store.calls
    assert {
        item.item_identity_sha256
        for item in locked.batch_manifest.items
    }.isdisjoint(
        {
            item.item_identity_sha256
            for item in shadow.batch_manifest.items
        }
    )
    encoded = json.dumps(
        shadow.to_payload(),
        ensure_ascii=False,
        sort_keys=True,
    )
    assert "selection-seed" not in encoded
    del capture_store.captures[capture.canonical_sha256]
    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="source capture is unavailable",
    ):
        store.load_manifest(locked.canonical_sha256)


def test_real_shadow_selection_fails_without_current_locked_gate(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture()
    shadow_capture = _capture(purpose="production_shadow")
    store = FormalShadowSelectionStore(
        data_root,
        capture_authority_store=_CaptureAuthorityStore(
            capture,
            shadow_capture,
        ),
    )
    store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )

    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="gate authority is unavailable",
    ):
        store.select(
            capture=shadow_capture,
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            pipeline_fingerprint=PIPELINE_SHA,
            exclusion_snapshot=_exclusions(shadow_capture),
            expected_current_build_sha256=(
                shadow_capture.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                shadow_capture.contract_canonical_sha256
            ),
        )


def test_active_real_shadow_replays_exact_gate_binding(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture()
    shadow_capture = _capture(purpose="production_shadow")
    gate_store = _GateAuthorityStore()
    store = FormalShadowSelectionStore(
        data_root,
        gate_authority_store=gate_store,
        capture_authority_store=_CaptureAuthorityStore(
            capture,
            shadow_capture,
        ),
    )
    store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    shadow = store.select(
        capture=shadow_capture,
        target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(shadow_capture),
        expected_current_build_sha256=shadow_capture.source_build_sha256,
        expected_settlement_contract_sha256=(
            shadow_capture.contract_canonical_sha256
        ),
    )

    loaded = store.load_active_real_shadow_manifest(
        shadow.canonical_sha256,
        expected_current_build_sha256=shadow_capture.source_build_sha256,
        expected_settlement_contract_sha256=(
            shadow_capture.contract_canonical_sha256
        ),
    )
    assert loaded.canonical_sha256 == shadow.canonical_sha256

    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="build or selection binding changed",
    ):
        store.load_active_real_shadow_manifest(
            shadow.canonical_sha256,
            expected_current_build_sha256="0" * 64,
            expected_settlement_contract_sha256=(
                shadow_capture.contract_canonical_sha256
            ),
        )

    gate_store.package_sha256 = "b" * 64
    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="gate binding changed",
    ):
        store.load_active_real_shadow_manifest(
            shadow.canonical_sha256,
            expected_current_build_sha256=(
                shadow_capture.source_build_sha256
            ),
            expected_settlement_contract_sha256=(
                shadow_capture.contract_canonical_sha256
            ),
        )


def test_content_addressed_load_rejects_another_installation_seed(
    tmp_path: Path,
) -> None:
    first_root = (tmp_path / "first").resolve()
    second_root = (tmp_path / "second").resolve()
    first_root.mkdir()
    second_root.mkdir()
    _initialize(first_root)
    _initialize(second_root)
    capture = _capture()
    first_store = FormalShadowSelectionStore(
        first_root,
        capture_authority_store=_CaptureAuthorityStore(capture),
    )
    locked = first_store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    second_store = FormalShadowSelectionStore(second_root)
    source = (
        first_root
        / "loop9-formal-selections"
        / f"{locked.canonical_sha256}.json"
    )
    target = (
        second_root
        / "loop9-formal-selections"
        / source.name
    )
    target.write_bytes(source.read_bytes())

    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="another seed authority",
    ):
        second_store.load_manifest(locked.canonical_sha256)


def test_content_addressed_load_rejects_reparse_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture()
    store = FormalShadowSelectionStore(
        data_root,
        capture_authority_store=_CaptureAuthorityStore(capture),
    )
    locked = store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    original = selection_store_module._is_reparse_point
    monkeypatch.setattr(
        selection_store_module,
        "_is_reparse_point",
        lambda path: (
            path.name == f"{locked.canonical_sha256}.json"
            or original(path)
        ),
    )

    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="unsafe",
    ):
        store.load_manifest(locked.canonical_sha256)


def test_target_authority_rejects_another_capture(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture()
    changed = _capture(count=89)
    store = FormalShadowSelectionStore(
        data_root,
        capture_authority_store=_CaptureAuthorityStore(
            capture,
            changed,
        ),
    )
    store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="another capture",
    ):
        store.select(
            capture=changed,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            exclusion_snapshot=_exclusions(changed),
        )


def test_target_authority_cannot_bypass_new_exclusion_head(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture()
    store = FormalShadowSelectionStore(
        data_root,
        capture_authority_store=_CaptureAuthorityStore(capture),
    )
    exclusions = _exclusions(capture)
    store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=exclusions,
    )

    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="another capture",
    ):
        store.select(
            capture=capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            exclusion_snapshot=FormalSelectionExclusionSnapshot(
                authority_sha256="7" * 64,
                child_index_head_sha256="8" * 64,
                source_boundary_sha256=(
                    exclusions.source_boundary_sha256
                ),
                source_inventory_high_watermark=(
                    exclusions.source_inventory_high_watermark
                ),
                identity_context_sha256=(
                    exclusions.identity_context_sha256
                ),
                expected_current_build_sha256=(
                    exclusions.expected_current_build_sha256
                ),
                expected_settlement_contract_sha256=(
                    exclusions.expected_settlement_contract_sha256
                ),
                expected_settlement_selection_sha256=(
                    exclusions.expected_settlement_selection_sha256
                ),
                excluded_platform_identity_sha256s=(),
                excluded_image_sha256s=(),
                excluded_scope_exclusion_tokens=(),
                excluded_perceptual_fingerprints=(),
            ),
        )


def test_failed_locked_generation_is_excluded_before_replacement_activation(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    _initialize(data_root)
    capture = _capture(count=100)
    store = FormalShadowSelectionStore(
        data_root,
        capture_authority_store=_CaptureAuthorityStore(capture),
    )
    first = store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=_exclusions(capture),
    )
    legacy_pointer = (
        data_root
        / "loop9-formal-selections"
        / "active-current_locked_50.json"
    )
    protected_pointer = legacy_pointer.read_bytes()
    failure = _coverage_failure(first)
    inventory = development_inventory_from_failed_locked_selection(
        selection=first,
        failure_attestation=failure,
    )
    verified = _verified_rollover_snapshot(
        selection=first,
        inventory=inventory,
    )
    FormalSelectionLifecycleStore(
        data_root
    ).invalidate_current_locked_selection(
        selection=first,
        failure_attestation=failure,
        exclusion_inventory=inventory,
        exclusion_snapshot=verified,
    )

    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="invalidated",
    ):
        store.load(ShadowBatchTargetKind.CURRENT_LOCKED_50)
    with pytest.raises(
        FormalShadowSelectionStoreError,
        match="not the active",
    ):
        store.load_active_current_locked_manifest(
            first.canonical_sha256
        )

    replacement_exclusions = FormalSelectionExclusionSnapshot(
        authority_sha256=verified.authority_sha256,
        child_index_head_sha256=verified.child_index_head_sha256,
        source_boundary_sha256=verified.source_boundary_sha256,
        source_inventory_high_watermark=(
            verified.source_inventory_high_watermark
        ),
        identity_context_sha256=verified.identity_context_sha256,
        expected_current_build_sha256=(
            verified.expected_current_build_sha256
        ),
        expected_settlement_contract_sha256=(
            verified.expected_settlement_contract_sha256
        ),
        expected_settlement_selection_sha256=(
            verified.expected_settlement_selection_sha256
        ),
        excluded_platform_identity_sha256s=(
            verified.excluded_platform_identity_sha256s
        ),
        excluded_image_sha256s=verified.excluded_image_sha256s,
        excluded_scope_exclusion_tokens=(
            verified.excluded_scope_exclusion_tokens
        ),
        excluded_perceptual_fingerprints=(
            verified.excluded_perceptual_fingerprints
        ),
    )
    replacement = store.select(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        exclusion_snapshot=replacement_exclusions,
    )

    assert replacement.canonical_sha256 != first.canonical_sha256
    assert legacy_pointer.read_bytes() == protected_pointer
    assert {
        item.item_identity_sha256
        for item in first.batch_manifest.items
    }.isdisjoint(
        {
            item.item_identity_sha256
            for item in replacement.batch_manifest.items
        }
    )
    assert (
        store.load_active_current_locked_manifest(
            replacement.canonical_sha256
        ).canonical_sha256
        == replacement.canonical_sha256
    )
    state = FormalSelectionLifecycleStore(data_root).load_state()
    assert state is not None
    assert state.generation == 2

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import BytesIO

import pytest
from PIL import Image

import dahe.application.chengfeng.shadow_selection as shadow_selection_module
from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
)
from dahe.application.chengfeng.settlement_capture import (
    ProtectedBusinessIdentity,
    SettlementCaptureAccessWindowLineage,
    SettlementCaptureContractError,
    SettlementCaptureManifest,
    build_settlement_capture_manifest,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
    ShadowCaptureBinding,
    chengfeng_shadow_identity_context_sha256,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalSelectionExclusionSnapshot,
    FormalShadowSelectionContractError,
    SelectionSeedAuthority,
    select_formal_shadow_batch,
)
from dahe.ports.chengfeng import (
    ChengfengStage,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)
from dahe.verification.image_similarity import (
    ALGORITHM_VERSION,
    ImagePerceptualFingerprint,
    PerceptualViewHash,
)
from dahe.verification.loop9_dataset_isolation import (
    discovery_scope_exclusion_token,
)

BUILD_SHA = "a" * 64
CONTRACT_CANONICAL_SHA = "b" * 64
CONTRACT_FILE_SHA = "c" * 64
CONTRACT_SELECTION_SHA = "d" * 64
PIPELINE_SHA = "e" * 64
LOCKED_GATE_SHA = "7" * 64
IDENTITY_SALT = b"loop9-test-identity-salt-32-bytes"
IDENTITY_NAMESPACE = "chengfeng-production-account-v1"
SELECTION_SEED = SelectionSeedAuthority(
    seed=b"loop9-formal-selection-seed-v1!!",
)


def _exclusions(
    *,
    capture: SettlementCaptureManifest,
    platform_identity_sha256s: tuple[str, ...] = (),
    image_sha256s: tuple[str, ...] = (),
    scope_exclusion_tokens: tuple[str, ...] = (),
    perceptual_fingerprints: tuple[
        ImagePerceptualFingerprint,
        ...,
    ] = (),
) -> FormalSelectionExclusionSnapshot:
    return FormalSelectionExclusionSnapshot(
        authority_sha256="1" * 64,
        child_index_head_sha256="2" * 64,
        source_boundary_sha256="3" * 64,
        source_inventory_high_watermark=1,
        identity_context_sha256=capture.identity_context_sha256,
        expected_current_build_sha256=capture.source_build_sha256,
        expected_settlement_contract_sha256=(
            capture.contract_canonical_sha256
        ),
        expected_settlement_selection_sha256=(
            capture.contract_selection_sha256
        ),
        excluded_platform_identity_sha256s=(
            platform_identity_sha256s
        ),
        excluded_image_sha256s=image_sha256s,
        excluded_scope_exclusion_tokens=scope_exclusion_tokens,
        excluded_perceptual_fingerprints=perceptual_fingerprints,
    )


class MemorySafeReader:
    def __init__(self, content_by_path: dict[str, bytes]) -> None:
        self.content_by_path = content_by_path

    def read_verified_image(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
    ) -> bytes:
        content = self.content_by_path[relative_path]
        assert hashlib.sha256(content).hexdigest() == expected_sha256
        return content


def _png(seed: int) -> bytes:
    image = Image.new("RGB", (32, 32))
    image.putdata(
        [
            tuple(
                hashlib.sha256(
                    f"{seed}:{index}".encode()
                ).digest()[:3]
            )
            for index in range(32 * 32)
        ]
    )
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _distinct_fingerprint(
    *,
    image_sha256: str,
    seed: str,
) -> ImagePerceptualFingerprint:
    average = hashlib.sha256(f"average:{seed}".encode()).hexdigest()
    difference = hashlib.sha256(
        f"difference:{seed}".encode()
    ).hexdigest()
    return ImagePerceptualFingerprint(
        algorithm_version=ALGORITHM_VERSION,
        content_sha256=image_sha256,
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


def _stored_image(
    *,
    ticket_ref: str,
    content: bytes,
) -> PersistedTicketImage:
    sha256 = hashlib.sha256(content).hexdigest()
    return PersistedTicketImage(
        ticket_ref=ticket_ref,
        sha256=sha256,
        relative_path=f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}.blob",
        byte_size=len(content),
        media_type="image/png",
    )


def _binding(
    *,
    count: int,
    start: int,
    page_number: int,
    page_size: int,
    total: int,
    job_id: str = "source-job-001",
    access_window_id: str = "access-window-001",
    build_sha256: str = BUILD_SHA,
    scope: str = "current",
) -> tuple[ShadowCaptureBinding, dict[str, bytes]]:
    summaries: list[WaybillSummary] = []
    details: list[WaybillDetail] = []
    images: dict[str, PersistedTicketImage] = {}
    content_by_path: dict[str, bytes] = {}
    for offset in range(count):
        index = start + offset
        platform_id = f"platform-{index:03d}"
        waybill_number = f"CF-{202607290000 + index}"
        vehicle_number = f"陕A{index:05d}"
        summaries.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=vehicle_number,
            )
        )
        tickets: list[TicketReference] = []
        for slot, seed in (
            ("loading", index * 2),
            ("unloading", index * 2 + 1),
        ):
            ticket_ref = f"ticket-{slot}-{index:03d}"
            content = _png(seed)
            image = _stored_image(ticket_ref=ticket_ref, content=content)
            tickets.append(
                TicketReference(
                    slot=slot,
                    ticket_ref=ticket_ref,
                    media_type="image/png",
                )
            )
            images[ticket_ref] = image
            content_by_path[image.relative_path] = content
        details.append(
            WaybillDetail(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=vehicle_number,
                loading_net=f"{30 + index % 10}.10",
                unloading_net=f"{29 + index % 10}.90",
                tickets=tuple(tickets),
            )
        )
    checkpoint = DurableCaptureCheckpoint(
        capture_id=f"capture-{job_id}-{page_number}",
        job_id=job_id,
        scope=scope,
        page_number=page_number,
        page_size=page_size,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        revision=4 + (count * 3),
        completed_list=True,
        completed_detail_ids=tuple(
            detail.platform_waybill_id for detail in details
        ),
        ticket_images=images,
        page=WaybillPage(
            page_number=page_number,
            page_size=page_size,
            total=total,
            items=tuple(summaries),
        ),
        details=tuple(details),
    )
    return (
        ShadowCaptureBinding(
            checkpoint=checkpoint,
            access_window_id=access_window_id,
            source_build_sha256=build_sha256,
            contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
            contract_file_sha256=CONTRACT_FILE_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
        ),
        content_by_path,
    )


def _capture(
    *,
    count: int = 90,
    page_size: int | None = None,
    start: int = 0,
    purpose: str = "formal_locked_set",
    build_sha256: str = BUILD_SHA,
    source_scope: str | None = None,
) -> tuple[SettlementCaptureManifest, tuple[ProtectedBusinessIdentity, ...]]:
    scope = source_scope or (
        "settled_history" if purpose == "formal_locked_set" else "current"
    )
    page_size = 100 if scope == "settled_history" else 50
    bindings: list[ShadowCaptureBinding] = []
    content: dict[str, bytes] = {}
    for page_number, offset in enumerate(
        range(0, count, page_size),
        start=1,
    ):
        binding, page_content = _binding(
            count=min(page_size, count - offset),
            start=start + offset,
            page_number=page_number,
            page_size=page_size,
            total=count,
            build_sha256=build_sha256,
            scope=scope,
        )
        bindings.append(binding)
        content.update(page_content)
    job_id = bindings[0].checkpoint.job_id
    access_window_id = bindings[0].access_window_id
    expected_operations = {
        "download_ticket_image": count * 2,
        "get_waybill_detail": count,
        "list_waybills": len(bindings),
    }
    total_requests = sum(expected_operations.values())
    operation_counts = {
        operation: {
            "allowed": expected_operations.get(operation, 0),
            "attempted": expected_operations.get(operation, 0),
            "denied": 0,
            "failed": 0,
            "redirect": 0,
            "succeeded": expected_operations.get(operation, 0),
        }
        for operation in (
            "list_waybills",
            "get_waybill_detail",
            "download_ticket_image",
            "list_daily_waybills",
        )
    }
    audit_body = {
        "authority": {
            "build_sha256": build_sha256,
            "daily_contract_selection_sha256": None,
            "daily_contract_sha256": None,
            "settlement_contract_selection_sha256": (
                CONTRACT_SELECTION_SHA
            ),
            "settlement_contract_sha256": CONTRACT_CANONICAL_SHA,
        },
        "event_chain_sha256": hashlib.sha256(
            f"{job_id}:{purpose}:events".encode()
        ).hexdigest(),
        "event_count": total_requests * 3,
        "expected_succeeded_operations": expected_operations,
        "job_id_sha256": hashlib.sha256(job_id.encode()).hexdigest(),
        "kind": "loop9_platform_read_audit",
        "operation_counts": operation_counts,
        "platform_write_request_count": 0,
        "purpose": (
            "current_locked_50"
            if purpose == "formal_locked_set"
            else "real_shadow_30"
        ),
        "redirect_count": 0,
        "request_counts": {
            "allowed": total_requests,
            "attempted": total_requests,
            "denied": 0,
            "succeeded": total_requests,
        },
        "schema_version": 1,
    }
    audit_sha256 = hashlib.sha256(
        json.dumps(
            audit_body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return build_settlement_capture_manifest(
        bindings=bindings,
        identity_salt=IDENTITY_SALT,
        identity_namespace=IDENTITY_NAMESPACE,
        image_reader=MemorySafeReader(content),
        access_window_lineage=SettlementCaptureAccessWindowLineage(
            job_id=job_id,
            session_id="session-001",
            purpose=purpose,
            source_build_sha256=build_sha256,
            contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
            contract_file_sha256=CONTRACT_FILE_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
            identity_context_sha256=(
                chengfeng_shadow_identity_context_sha256(
                    salt=IDENTITY_SALT,
                    namespace=IDENTITY_NAMESPACE,
                )
            ),
            access_window_ids=(access_window_id,),
        ),
        request_audit_sha256=audit_sha256,
        request_audit_counts=audit_body,
    )


def test_seals_complete_capture_without_raw_identity_in_outward_manifest() -> None:
    manifest, protected = _capture()

    assert len(manifest.items) == 90
    assert len(protected) == 90
    assert all(isinstance(item, ProtectedBusinessIdentity) for item in protected)
    assert {item.source_page_number for item in protected} == {1}
    encoded = json.dumps(
        manifest.to_payload(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert "platform-000" not in encoded
    assert "CF-202607290000" not in encoded
    assert "陕A00000" not in encoded
    assert manifest.canonical_sha256 == SettlementCaptureManifest.from_payload(
        manifest.to_payload()
    ).canonical_sha256


def test_capture_rejects_partial_pagination_and_missing_images() -> None:
    first, content = _binding(
        count=40,
        start=0,
        page_number=1,
        page_size=40,
        total=90,
    )
    third, third_content = _binding(
        count=10,
        start=80,
        page_number=3,
        page_size=40,
        total=90,
    )
    content.update(third_content)
    with pytest.raises(SettlementCaptureContractError, match="partial"):
        build_settlement_capture_manifest(
            bindings=(first, third),
            identity_salt=IDENTITY_SALT,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=MemorySafeReader(content),
        )

    complete_first = replace(
        first,
        checkpoint=replace(
            first.checkpoint,
            page=replace(first.checkpoint.page, total=40),
        ),
    )
    missing_ref = next(iter(complete_first.checkpoint.ticket_images))
    incomplete_checkpoint = replace(
        complete_first.checkpoint,
        ticket_images={
            key: value
            for key, value in complete_first.checkpoint.ticket_images.items()
            if key != missing_ref
        },
    )
    with pytest.raises(SettlementCaptureContractError, match="every required"):
        build_settlement_capture_manifest(
            bindings=(
                replace(first, checkpoint=incomplete_checkpoint),
            ),
            identity_salt=IDENTITY_SALT,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=MemorySafeReader(content),
        )


def test_locked_selection_accepts_current_pending_only_with_a_30_item_reserve() -> None:
    current_capture, _protected = _capture(
        count=80,
        source_scope="current",
    )

    selected = select_formal_shadow_batch(
        capture=current_capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=current_capture),
        prior_selections=(),
    )

    assert len(selected.batch_manifest.items) == 50
    assert {source.scope for source in selected.batch_manifest.sources} == {
        "current"
    }

    insufficient_reserve, _protected = _capture(
        count=79,
        source_scope="current",
    )
    with pytest.raises(
        FormalShadowSelectionContractError,
        match="reserve",
    ):
        select_formal_shadow_batch(
            capture=insufficient_reserve,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=insufficient_reserve),
            prior_selections=(),
        )


def test_selection_is_exact_deterministic_and_never_overlaps() -> None:
    capture, _protected = _capture()

    locked = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )
    locked_replay = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )
    shadow_capture, _ = _capture(
        start=100,
        purpose="production_shadow",
    )
    shadow = select_formal_shadow_batch(
        capture=shadow_capture,
        target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=shadow_capture),
        prior_selections=(locked,),
        locked_gate_evidence_sha256=LOCKED_GATE_SHA,
    )

    locked_ids = {
        item.item_identity_sha256 for item in locked.batch_manifest.items
    }
    shadow_ids = {
        item.item_identity_sha256 for item in shadow.batch_manifest.items
    }
    assert len(locked_ids) == 50
    assert len(shadow_ids) == 30
    assert locked_ids.isdisjoint(shadow_ids)
    assert locked.canonical_sha256 == locked_replay.canonical_sha256
    assert locked.selection_policy == "hmac_rank_v1"
    assert locked.selection_seed_authority_sha256 == (
        SELECTION_SEED.authority_sha256
    )
    assert locked.locked_gate_evidence_sha256 is None
    assert shadow.locked_gate_evidence_sha256 == LOCKED_GATE_SHA


def test_selection_requires_gate_only_for_real_shadow_target() -> None:
    capture, _ = _capture()
    shadow_capture, _ = _capture(
        start=100,
        purpose="production_shadow",
    )
    locked = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )

    with pytest.raises(
        FormalShadowSelectionContractError,
        match="gate",
    ):
        select_formal_shadow_batch(
            capture=shadow_capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=shadow_capture),
            prior_selections=(),
            locked_gate_evidence_sha256=LOCKED_GATE_SHA,
        )

    with pytest.raises(
        FormalShadowSelectionContractError,
        match="gate",
    ):
        select_formal_shadow_batch(
            capture=shadow_capture,
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=shadow_capture),
            prior_selections=(locked,),
        )


def test_selection_rejects_insufficient_cross_build_and_missing_locked_authority() -> None:
    small_capture, _ = _capture(count=40, page_size=40)
    with pytest.raises(
        FormalShadowSelectionContractError,
        match="eligible",
    ):
        select_formal_shadow_batch(
            capture=small_capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=small_capture),
            prior_selections=(),
        )

    capture, _ = _capture()
    shadow_capture, _ = _capture(
        start=100,
        purpose="production_shadow",
    )
    with pytest.raises(
        FormalShadowSelectionContractError,
        match="locked",
    ):
        select_formal_shadow_batch(
            capture=shadow_capture,
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=shadow_capture),
            prior_selections=(),
            locked_gate_evidence_sha256=LOCKED_GATE_SHA,
        )

    locked = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )
    changed_capture, _ = _capture(
        start=100,
        purpose="production_shadow",
        build_sha256="f" * 64,
    )
    with pytest.raises(
        FormalShadowSelectionContractError,
        match="authority",
    ):
        select_formal_shadow_batch(
            capture=changed_capture,
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=changed_capture),
            prior_selections=(locked,),
            locked_gate_evidence_sha256=LOCKED_GATE_SHA,
        )


def test_capture_preserves_duplicate_images_but_selection_skips_them() -> None:
    capture, _ = _capture(count=53, page_size=53)
    first = capture.items[0]
    second = capture.items[1]
    same_slot_pair = replace(
        first,
        images=(
            first.images[0],
            replace(first.images[0], slot="unloading"),
        ),
    )
    cross_waybill_duplicate = replace(
        second,
        images=(
            replace(first.images[1], slot="loading"),
            second.images[1],
        ),
    )
    duplicate_capture = replace(
        capture,
        items=(
            same_slot_pair,
            cross_waybill_duplicate,
            *capture.items[2:],
        ),
    )

    duplicate_capture.verify_integrity()
    selected = select_formal_shadow_batch(
        capture=duplicate_capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=duplicate_capture),
        prior_selections=(),
    )

    selected_images = [
        image.sha256
        for item in selected.batch_manifest.items
        for image in item.images
    ]
    assert len(selected.batch_manifest.items) == 50
    assert len(selected_images) == len(set(selected_images)) == 100
    assert same_slot_pair.item_identity_sha256 not in {
        item.item_identity_sha256
        for item in selected.batch_manifest.items
    }


def test_selection_reports_insufficient_after_duplicate_filtering() -> None:
    capture, _ = _capture(count=50, page_size=50)
    first = capture.items[0]
    duplicate_capture = replace(
        capture,
        items=(
            replace(
                first,
                images=(
                    first.images[0],
                    replace(first.images[0], slot="unloading"),
                ),
            ),
            *capture.items[1:],
        ),
    )

    with pytest.raises(
        FormalShadowSelectionContractError,
        match="insufficient eligible",
    ):
        select_formal_shadow_batch(
            capture=duplicate_capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(capture=duplicate_capture),
            prior_selections=(),
        )


def test_locked_selection_accepts_two_bounded_historical_pages() -> None:
    capture, _ = _capture(count=120)

    selected = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )

    assert len(capture.sources) == 2
    assert [source.page_number for source in capture.sources] == [1, 2]
    assert len(selected.batch_manifest.items) == 50


def test_historical_capture_rejects_unbounded_third_page() -> None:
    with pytest.raises(
        SettlementCaptureContractError,
        match="bounded historical capture",
    ):
        _capture(count=201)


def test_historical_capture_rejects_incomplete_second_page() -> None:
    first, first_content = _binding(
        count=100,
        start=0,
        page_number=1,
        page_size=100,
        total=150,
        scope="settled_history",
    )
    incomplete_second, second_content = _binding(
        count=49,
        start=100,
        page_number=2,
        page_size=100,
        total=150,
        scope="settled_history",
    )

    with pytest.raises(
        SettlementCaptureContractError,
        match="bounded historical capture",
    ):
        build_settlement_capture_manifest(
            bindings=(first, incomplete_second),
            identity_salt=IDENTITY_SALT,
            identity_namespace=IDENTITY_NAMESPACE,
            image_reader=MemorySafeReader(
                {**first_content, **second_content}
            ),
        )


def test_selection_applies_and_binds_full_history_exclusions() -> None:
    capture, _ = _capture(count=54, page_size=54)
    excluded_identity = capture.items[0]
    excluded_exact_image = capture.items[1]
    exclusions = _exclusions(
        capture=capture,
        platform_identity_sha256s=(
            excluded_identity.platform_waybill_id_digest,
        ),
        image_sha256s=(
            excluded_exact_image.images[0].sha256,
        ),
    )

    selected = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=exclusions,
        prior_selections=(),
    )

    selected_item_ids = {
        item.item_identity_sha256
        for item in selected.batch_manifest.items
    }
    assert excluded_identity.item_identity_sha256 not in selected_item_ids
    assert (
        excluded_exact_image.item_identity_sha256
        not in selected_item_ids
    )
    assert selected.full_history_exclusion_authority_sha256 == (
        exclusions.authority_sha256
    )
    assert selected.exclusion_child_index_head_sha256 == (
        exclusions.child_index_head_sha256
    )
    assert (
        selected.canonical_sha256
        == type(selected).from_payload(selected.to_payload()).canonical_sha256
    )


def test_selection_filters_perceptual_overlap_before_ranking() -> None:
    capture, _ = _capture(count=52, page_size=52)
    target = capture.items[0]
    target_loading = replace(
        target.images[0],
        perceptual_fingerprint=_distinct_fingerprint(
            image_sha256=target.images[0].sha256,
            seed="excluded-target",
        ),
    )
    target = replace(
        target,
        images=(target_loading, target.images[1]),
    )
    capture = replace(
        capture,
        items=(target, *capture.items[1:]),
    )

    selected = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(
            capture=capture,
            perceptual_fingerprints=(
                target_loading.perceptual_fingerprint,
            ),
        ),
        prior_selections=(),
    )

    assert target.item_identity_sha256 not in {
        item.item_identity_sha256
        for item in selected.batch_manifest.items
    }


def test_selection_filters_perceptual_overlap_inside_the_same_target_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture, _ = _capture(count=52, page_size=52)
    first = capture.items[0]
    second = capture.items[1]
    shared_views = first.images[0].perceptual_fingerprint.view_hashes
    second_loading = replace(
        second.images[0],
        perceptual_fingerprint=ImagePerceptualFingerprint(
            algorithm_version=ALGORITHM_VERSION,
            content_sha256=second.images[0].sha256,
            width=first.images[0].perceptual_fingerprint.width,
            height=first.images[0].perceptual_fingerprint.height,
            view_hashes=shared_views,
        ),
    )
    second = replace(
        second,
        images=(second_loading, second.images[1]),
    )
    capture = replace(
        capture,
        items=(first, second, *capture.items[2:]),
    )
    ranked_identity = {
        item.item_identity_sha256: f"{index:064x}"
        for index, item in enumerate(capture.items)
    }
    monkeypatch.setattr(
        shadow_selection_module,
        "_rank",
        lambda *, item, **_: ranked_identity[item.item_identity_sha256],
    )

    selected = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )

    selected_ids = {
        item.item_identity_sha256
        for item in selected.batch_manifest.items
    }
    selected_images = tuple(
        image
        for item in selected.batch_manifest.items
        for image in item.images
    )
    assert first.item_identity_sha256 in selected_ids
    assert second.item_identity_sha256 not in selected_ids
    assert len(selected.batch_manifest.items) == 50
    assert len(selected_images) == 100
    assert len({image.sha256 for image in selected_images}) == 100


def test_selection_filters_perceptually_duplicate_slots_in_one_waybill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture, _ = _capture(count=51, page_size=51)
    unsafe = capture.items[0]
    loading = unsafe.images[0]
    unloading = replace(
        unsafe.images[1],
        perceptual_fingerprint=ImagePerceptualFingerprint(
            algorithm_version=ALGORITHM_VERSION,
            content_sha256=unsafe.images[1].sha256,
            width=loading.perceptual_fingerprint.width,
            height=loading.perceptual_fingerprint.height,
            view_hashes=loading.perceptual_fingerprint.view_hashes,
        ),
    )
    unsafe = replace(unsafe, images=(loading, unloading))
    capture = replace(
        capture,
        items=(unsafe, *capture.items[1:]),
    )
    ranked_identity = {
        item.item_identity_sha256: f"{index:064x}"
        for index, item in enumerate(capture.items)
    }
    monkeypatch.setattr(
        shadow_selection_module,
        "_rank",
        lambda *, item, **_: ranked_identity[item.item_identity_sha256],
    )

    selected = select_formal_shadow_batch(
        capture=capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=capture),
        prior_selections=(),
    )

    assert unsafe.item_identity_sha256 not in {
        item.item_identity_sha256
        for item in selected.batch_manifest.items
    }
    assert len(selected.batch_manifest.items) == 50


def test_selection_rejects_excluded_discovery_scope_before_ranking() -> None:
    capture, _ = _capture(count=52, page_size=52)
    scope_token = discovery_scope_exclusion_token(
        source_job_id=capture.source_job_id,
        source_snapshot_sha256=capture.canonical_sha256,
    )

    with pytest.raises(
        FormalShadowSelectionContractError,
        match="discovery scope",
    ):
        select_formal_shadow_batch(
            capture=capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=_exclusions(
                capture=capture,
                scope_exclusion_tokens=(scope_token,),
            ),
            prior_selections=(),
        )


def test_real_shadow_excludes_prior_platform_and_perceptual_overlap() -> None:
    locked_capture, _ = _capture(count=52, page_size=52)
    locked = select_formal_shadow_batch(
        capture=locked_capture,
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=locked_capture),
        prior_selections=(),
    )
    shadow_capture, _ = _capture(
        count=80,
        page_size=80,
        start=100,
        purpose="production_shadow",
    )
    changed_items = list(shadow_capture.items)
    prior_items = locked.batch_manifest.items
    platform_conflicts: set[str] = set()
    perceptual_conflicts: set[str] = set()
    for index in range(25):
        changed_items[index] = replace(
            changed_items[index],
            platform_waybill_id_digest=(
                prior_items[index].platform_waybill_id_digest
            ),
        )
        platform_conflicts.add(
            changed_items[index].item_identity_sha256
        )
    for index in range(25, 50):
        item = changed_items[index]
        source_fingerprint = prior_items[
            index
        ].images[0].perceptual_fingerprint
        near_duplicate = ImagePerceptualFingerprint(
            algorithm_version=source_fingerprint.algorithm_version,
            content_sha256=item.images[0].sha256,
            width=source_fingerprint.width,
            height=source_fingerprint.height,
            view_hashes=source_fingerprint.view_hashes,
        )
        changed_items[index] = replace(
            item,
            images=(
                replace(
                    item.images[0],
                    perceptual_fingerprint=near_duplicate,
                ),
                item.images[1],
            ),
        )
        perceptual_conflicts.add(
            changed_items[index].item_identity_sha256
        )
    shadow_capture = replace(
        shadow_capture,
        items=tuple(changed_items),
    )

    shadow = select_formal_shadow_batch(
        capture=shadow_capture,
        target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
        pipeline_fingerprint=PIPELINE_SHA,
        seed_authority=SELECTION_SEED,
        exclusion_snapshot=_exclusions(capture=shadow_capture),
        prior_selections=(locked,),
        locked_gate_evidence_sha256=LOCKED_GATE_SHA,
    )

    selected_ids = {
        item.item_identity_sha256
        for item in shadow.batch_manifest.items
    }
    assert selected_ids.isdisjoint(platform_conflicts)
    assert selected_ids.isdisjoint(perceptual_conflicts)
    assert len(selected_ids) == 30


def test_selection_fails_closed_for_missing_or_mismatched_exclusions() -> None:
    capture, _ = _capture(count=52, page_size=52)

    with pytest.raises(TypeError):
        select_formal_shadow_batch(
            capture=capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            prior_selections=(),
        )

    mismatched = replace(
        _exclusions(capture=capture),
        expected_current_build_sha256="f" * 64,
    )
    with pytest.raises(
        FormalShadowSelectionContractError,
        match="does not match",
    ):
        select_formal_shadow_batch(
            capture=capture,
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
            pipeline_fingerprint=PIPELINE_SHA,
            seed_authority=SELECTION_SEED,
            exclusion_snapshot=mismatched,
            prior_selections=(),
        )

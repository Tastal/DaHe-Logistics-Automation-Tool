from __future__ import annotations

import pytest

from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
)
from dahe.application.chengfeng.operational_capture import (
    operational_capture_sha256,
    scheduled_job_from_operational_checkpoints,
    scheduled_whole_run_review_job,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    ChengfengStage,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)


def _checkpoint() -> DurableCaptureCheckpoint:
    loading = PersistedTicketImage(
        ticket_ref="loading-ref",
        sha256="a" * 64,
        relative_path=f"sha256/aa/aa/{'a' * 64}.blob",
        byte_size=10,
        media_type="image/jpeg",
    )
    unloading = PersistedTicketImage(
        ticket_ref="unloading-ref",
        sha256="b" * 64,
        relative_path=f"sha256/bb/bb/{'b' * 64}.blob",
        byte_size=11,
        media_type="image/jpeg",
    )
    return DurableCaptureCheckpoint(
        capture_id="capture-1",
        job_id="capture-job",
        scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
        page_number=1,
        page_size=50,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        revision=5,
        completed_list=True,
        completed_detail_ids=("platform-1",),
        ticket_images={
            loading.ticket_ref: loading,
            unloading.ticket_ref: unloading,
        },
        page=WaybillPage(
            page_number=1,
            page_size=50,
            total=1,
            items=(
                WaybillSummary(
                    platform_waybill_id="platform-1",
                    waybill_number="YD202607310001",
                    vehicle_number="鲁H12345",
                ),
            ),
        ),
        details=(
            WaybillDetail(
                platform_waybill_id="platform-1",
                waybill_number="YD202607310001",
                vehicle_number="鲁H12345",
                loading_net="32.80",
                unloading_net="32.76",
                tickets=(
                    TicketReference(
                        slot="loading",
                        ticket_ref="loading-ref",
                        media_type="image/jpeg",
                    ),
                    TicketReference(
                        slot="unloading",
                        ticket_ref="unloading-ref",
                        media_type="image/jpeg",
                    ),
                ),
            ),
        ),
    )


def test_operational_capture_creates_existing_local_audit_contract() -> None:
    checkpoints = (_checkpoint(),)

    spec = scheduled_job_from_operational_checkpoints(
        checkpoints=checkpoints,
        pipeline_fingerprint="c" * 64,
    )

    assert spec.run_mode == "operational"
    assert spec.task_type == "audit"
    assert spec.ocr_execution_mode == "local"
    assert spec.items[0].item_key == "YD202607310001"
    assert spec.items[0].vehicle_number == "鲁H12345"
    assert spec.items[0].loading_image_relative_path == (
        f"evidence/sha256/aa/aa/{'a' * 64}.blob"
    )
    assert spec.items[0].unloading_image_relative_path == (
        f"evidence/sha256/bb/bb/{'b' * 64}.blob"
    )
    assert spec.items[0].evidence_preloaded is True


def test_operational_capture_hash_reconciles_all_items() -> None:
    checkpoints = (_checkpoint(),)

    assert operational_capture_sha256(checkpoints) == (
        operational_capture_sha256(tuple(reversed(checkpoints)))
    )


def test_identical_whole_run_captures_get_distinct_review_scopes() -> None:
    checkpoint = _checkpoint()

    first = scheduled_whole_run_review_job(
        checkpoint=checkpoint,
        pipeline_fingerprint="c" * 64,
        source_job_id="a" * 32,
        business_kind="settlement",
        scope_label="First capture",
    )
    second = scheduled_whole_run_review_job(
        checkpoint=checkpoint,
        pipeline_fingerprint="c" * 64,
        source_job_id="b" * 32,
        business_kind="settlement",
        scope_label="Second capture",
    )

    assert first.items == second.items
    assert first.fixture_id != second.fixture_id
    assert first.conflict_key != second.conflict_key
    assert first.conflict_key == f"settlement-ocr:{'a' * 32}:whole"
    assert second.conflict_key == f"settlement-ocr:{'b' * 32}:whole"


def test_preloaded_evidence_is_limited_to_local_ocr_audit_jobs() -> None:
    with pytest.raises(
        ValueError,
        match="preloaded evidence is limited to local OCR audit jobs",
    ):
        ScheduledJobSpec(
            fixture_id="invalid-preloaded",
            job_kind="business",
            task_type="audit",
            scope_label="Invalid",
            conflict_key="invalid:preloaded",
            items=(
                ScheduledWorkItemSpec(
                    item_key="YD-invalid",
                    expected_outcome=None,
                    evidence_preloaded=True,
                ),
            ),
        )


def test_preloaded_local_evidence_requires_content_hashes() -> None:
    with pytest.raises(
        ValueError,
        match="preloaded evidence must be complete",
    ):
        ScheduledJobSpec(
            fixture_id="invalid-preloaded-local",
            job_kind="observation",
            task_type="audit",
            scope_label="Invalid",
            conflict_key="invalid:preloaded-local",
            items=(
                ScheduledWorkItemSpec(
                    item_key="YD-invalid-local",
                    expected_outcome=None,
                    loading_image_relative_path="evidence/loading.blob",
                    unloading_image_relative_path="evidence/unloading.blob",
                    evidence_preloaded=True,
                ),
            ),
            pipeline_fingerprint="c" * 64,
            ocr_execution_mode="local",
            run_mode="operational",
        )


def _paged_checkpoint(
    *,
    page_number: int,
    item_count: int,
    first_index: int,
    total: int,
) -> DurableCaptureCheckpoint:
    summaries: list[WaybillSummary] = []
    details: list[WaybillDetail] = []
    images: dict[str, PersistedTicketImage] = {}
    completed_ids: list[str] = []
    for offset in range(item_count):
        index = first_index + offset
        platform_id = f"platform-{index:03d}"
        waybill_number = f"YD20260731{index:04d}"
        loading_ref = f"loading-{index:03d}"
        unloading_ref = f"unloading-{index:03d}"
        loading_sha = f"{index * 2 - 1:064x}"
        unloading_sha = f"{index * 2:064x}"
        summaries.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=f"TEST-{index:03d}",
            )
        )
        details.append(
            WaybillDetail(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=f"TEST-{index:03d}",
                loading_net="32.80",
                unloading_net="32.76",
                tickets=(
                    TicketReference(
                        slot="loading",
                        ticket_ref=loading_ref,
                        media_type="image/jpeg",
                    ),
                    TicketReference(
                        slot="unloading",
                        ticket_ref=unloading_ref,
                        media_type="image/jpeg",
                    ),
                ),
            )
        )
        completed_ids.append(platform_id)
        for ticket_ref, sha256 in (
            (loading_ref, loading_sha),
            (unloading_ref, unloading_sha),
        ):
            images[ticket_ref] = PersistedTicketImage(
                ticket_ref=ticket_ref,
                sha256=sha256,
                relative_path=(
                    f"sha256/{sha256[:2]}/{sha256[2:4]}/"
                    f"{sha256}.blob"
                ),
                byte_size=100,
                media_type="image/jpeg",
            )
    return DurableCaptureCheckpoint(
        capture_id=f"capture-{page_number}",
        job_id="capture-job",
        scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
        page_number=page_number,
        page_size=50,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        revision=page_number * 100,
        completed_list=True,
        completed_detail_ids=tuple(completed_ids),
        ticket_images=images,
        page=WaybillPage(
            page_number=page_number,
            page_size=50,
            total=total,
            items=tuple(summaries),
        ),
        details=tuple(details),
    )


@pytest.mark.parametrize("total", [0, 1, 49, 50, 51, 137])
def test_operational_capture_reconciles_dynamic_platform_total(
    total: int,
) -> None:
    page_size = 50
    page_count = max(1, (total + page_size - 1) // page_size)
    checkpoints = tuple(
        _paged_checkpoint(
            page_number=page_number,
            item_count=max(
                0,
                min(page_size, total - ((page_number - 1) * page_size)),
            ),
            first_index=((page_number - 1) * page_size) + 1,
            total=total,
        )
        for page_number in range(1, page_count + 1)
    )

    spec = scheduled_job_from_operational_checkpoints(
        checkpoints=checkpoints,
        pipeline_fingerprint="d" * 64,
    )

    assert len(spec.items) == total
    assert len({item.item_key for item in spec.items}) == total
    if total:
        assert spec.items[0].item_key == "YD202607310001"
        assert spec.items[-1].item_key == f"YD20260731{total:04d}"


def test_operational_capture_rejects_missing_or_changed_dynamic_page() -> None:
    checkpoints = tuple(
        _paged_checkpoint(
            page_number=page_number,
            item_count=item_count,
            first_index=first_index,
            total=137,
        )
        for page_number, item_count, first_index in (
            (1, 50, 1),
            (2, 50, 51),
            (3, 37, 101),
        )
    )

    with pytest.raises(
        ValueError,
        match="pagination is incomplete",
    ):
        scheduled_job_from_operational_checkpoints(
            checkpoints=(checkpoints[0], checkpoints[2]),
            pipeline_fingerprint="d" * 64,
        )

    changed_total = _paged_checkpoint(
        page_number=2,
        item_count=50,
        first_index=51,
        total=138,
    )
    with pytest.raises(
        ValueError,
        match="pagination is incomplete",
    ):
        scheduled_job_from_operational_checkpoints(
            checkpoints=(checkpoints[0], changed_total, checkpoints[2]),
            pipeline_fingerprint="d" * 64,
        )

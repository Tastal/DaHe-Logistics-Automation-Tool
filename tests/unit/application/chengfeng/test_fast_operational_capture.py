from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

import pytest

from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
)
from dahe.application.chengfeng.operational_capture import (
    OPERATIONAL_BATCH_SIZE,
    FastOperationalSettlementCaptureCoordinator,
    OperationalCaptureRun,
    scheduled_job_from_operational_batch,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    ChengfengStage,
    DownloadedTicketImage,
    OperationalBatchTimeoutError,
    OperationalWaybillEvidence,
    TicketReference,
    TransientNetworkError,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)


@dataclass(frozen=True)
class Invocation:
    invocation_id: str = "invocation-1"
    job_id: str = "job-1"
    access_window_id: str = "window-1"
    scope: str = "current"
    page_size: int = 50
    record_version: int = 1
    status: str = "collecting"


AUTHORITY = BrowserCommandAuthority(
    session_id="session-1",
    instance_id="instance-1",
    worker_id="worker-1",
    job_id="job-1",
    control_epoch=1,
    fencing_token="secret-fence",
)


class AllowNavigation:
    def authorize(self, authority: BrowserCommandAuthority) -> None:
        assert authority == AUTHORITY


class FakeAdapter:
    ticket_capability_authority_id = "fixture-worker"

    def __init__(self, *, total: int, fail_detail: int | None = None) -> None:
        self.total = total
        self.fail_detail = fail_detail
        self.list_calls: list[int] = []
        self.detail_calls: list[str] = []
        self.image_calls: list[str] = []

    def ticket_image_capability_is_current(self, ticket_ref: str) -> bool:
        return bool(ticket_ref)

    def list_waybills(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> WaybillPage:
        assert authority == AUTHORITY
        assert scope == "current"
        self.list_calls.append(page_number)
        start = (page_number - 1) * page_size
        end = min(self.total, start + page_size)
        return WaybillPage(
            page_number=page_number,
            page_size=page_size,
            total=self.total,
            items=tuple(
                WaybillSummary(
                    platform_waybill_id=f"platform-{index:03d}",
                    waybill_number=f"YD-{index:03d}",
                    vehicle_number=f"TEST-{index:03d}",
                )
                for index in range(start, end)
            ),
        )

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail:
        assert authority == AUTHORITY
        index = int(platform_waybill_id.rsplit("-", 1)[1])
        self.detail_calls.append(platform_waybill_id)
        if self.fail_detail == index:
            raise RuntimeError("fixture crash")
        return WaybillDetail(
            platform_waybill_id=platform_waybill_id,
            waybill_number=f"YD-{index:03d}",
            vehicle_number=f"TEST-{index:03d}",
            loading_net="32.80",
            unloading_net="32.76",
            tickets=(
                TicketReference(
                    slot="loading",
                    ticket_ref=f"loading-{index:03d}",
                    media_type="image/jpeg",
                ),
                TicketReference(
                    slot="unloading",
                    ticket_ref=f"unloading-{index:03d}",
                    media_type="image/jpeg",
                ),
            ),
        )

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage:
        assert authority == AUTHORITY
        self.image_calls.append(ticket_ref)
        content = ticket_ref.encode("utf-8")
        return DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type="image/jpeg",
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )


class MemoryBatchStore:
    def __init__(self) -> None:
        self.run: OperationalCaptureRun | None = None
        self.checkpoints: dict[int, DurableCaptureCheckpoint] = {}
        self.freeze_calls = 0
        self.commit_calls = 0
        self.reuse_candidate_calls = 0

    def load_reuse_candidates(
        self,
        *,
        summaries: tuple[WaybillSummary, ...],
    ) -> tuple[object, ...]:
        self.reuse_candidate_calls += 1
        raise AssertionError(
            "platform-first capture must not inspect reuse candidates online"
        )

    @staticmethod
    def capture_id(
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> str:
        return f"{job_id}:{scope}:{page_number}:{page_size}"

    def load_operational_run(self, *, job_id: str) -> OperationalCaptureRun | None:
        if self.run is not None:
            assert self.run.job_id == job_id
        return self.run

    def freeze_operational_run(
        self,
        *,
        job_id: str,
        scope: str,
        items: tuple[WaybillSummary, ...],
        batch_size: int,
        detail_concurrency: int,
        image_concurrency: int,
        authority: BrowserCommandAuthority,
    ) -> OperationalCaptureRun:
        assert authority == AUTHORITY
        self.freeze_calls += 1
        self.run = OperationalCaptureRun(
            job_id=job_id,
            scope=scope,
            total=len(items),
            items=items,
            next_item_index=0,
            committed_batch_count=0,
            batch_size=batch_size,
            detail_concurrency=detail_concurrency,
            image_concurrency=image_concurrency,
            status="collecting",
            record_version=1,
        )
        return self.run

    def commit_operational_batch(
        self,
        *,
        run: OperationalCaptureRun,
        checkpoint: DurableCaptureCheckpoint,
        images: tuple[DownloadedTicketImage, ...],
        authority: BrowserCommandAuthority,
        access_window_id: str,
        source_revisions: dict[str, str],
    ) -> tuple[OperationalCaptureRun, DurableCaptureCheckpoint]:
        assert authority == AUTHORITY
        assert access_window_id == "window-1"
        assert run == self.run
        assert isinstance(source_revisions, dict)
        self.commit_calls += 1
        persisted = {
            image.ticket_ref: PersistedTicketImage(
                ticket_ref=image.ticket_ref,
                sha256=image.sha256,
                relative_path=(
                    f"sha256/{image.sha256[:2]}/"
                    f"{image.sha256[2:4]}/{image.sha256}.blob"
                ),
                byte_size=len(image.content),
                media_type=image.media_type,
            )
            for image in images
        }
        committed = replace(
            checkpoint,
            revision=1,
            ticket_images=persisted,
        )
        self.checkpoints[checkpoint.page_number] = committed
        next_index = min(
            run.total,
            run.next_item_index + len(checkpoint.details),
        )
        self.run = replace(
            run,
            next_item_index=next_index,
            committed_batch_count=run.committed_batch_count + 1,
            status="complete" if next_index == run.total else "collecting",
            record_version=run.record_version + 1,
        )
        return self.run, committed

    def load(
        self,
        *,
        job_id: str,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> DurableCaptureCheckpoint | None:
        assert self.run is not None
        assert (job_id, scope, page_size) == (
            self.run.job_id,
            self.run.scope,
            self.run.batch_size,
        )
        return self.checkpoints.get(page_number)


def _coordinator(
    *,
    adapter: FakeAdapter,
    store: MemoryBatchStore,
    batch_size: int = OPERATIONAL_BATCH_SIZE,
) -> FastOperationalSettlementCaptureCoordinator:
    return FastOperationalSettlementCaptureCoordinator(
        adapter=adapter,
        navigation_authorizer=AllowNavigation(),
        batch_store=store,
        batch_size_provider=lambda: batch_size,
    )


def test_fast_capture_freezes_dynamic_list_then_commits_configured_batches() -> None:
    adapter = FakeAdapter(total=31)
    store = MemoryBatchStore()
    coordinator = _coordinator(adapter=adapter, store=store)

    first = coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    second = coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    third = coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    fourth = coordinator.advance(invocation=Invocation(), authority=AUTHORITY)

    assert first.has_more is True
    assert fourth.has_more is False
    assert fourth.capture_sha256 is not None
    assert adapter.list_calls == [1]
    assert len(adapter.detail_calls) == 31
    assert len(adapter.image_calls) == 62
    assert store.freeze_calls == 1
    assert store.commit_calls == 2
    assert store.reuse_candidate_calls == 0
    assert tuple(len(item.details) for item in fourth.checkpoints) == (
        20,
        11,
    )
    assert second.checkpoint_revision == 2
    assert third.checkpoint_revision == 3


def test_fast_capture_does_not_commit_a_partial_batch_and_retries_only_that_batch() -> None:
    adapter = FakeAdapter(total=21, fail_detail=5)
    store = MemoryBatchStore()
    coordinator = _coordinator(adapter=adapter, store=store)
    coordinator.advance(invocation=Invocation(), authority=AUTHORITY)

    with pytest.raises(RuntimeError, match="fixture crash"):
        coordinator.advance(invocation=Invocation(), authority=AUTHORITY)

    assert store.commit_calls == 0
    assert store.run is not None
    assert store.run.next_item_index == 0
    adapter.fail_detail = None
    coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    completed = coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    assert completed.has_more is False
    assert store.commit_calls == 2


def test_fast_capture_can_resume_a_legacy_fifteen_item_strategy() -> None:
    adapter = FakeAdapter(total=16)
    store = MemoryBatchStore()
    items = tuple(
        WaybillSummary(
            platform_waybill_id=f"platform-{index:03d}",
            waybill_number=f"YD-{index:03d}",
            vehicle_number=f"TEST-{index:03d}",
        )
        for index in range(16)
    )
    store.run = OperationalCaptureRun(
        job_id="job-1",
        scope="current",
        total=16,
        items=items,
        next_item_index=0,
        committed_batch_count=0,
        batch_size=15,
        detail_concurrency=4,
        image_concurrency=6,
        status="collecting",
        record_version=1,
    )
    coordinator = _coordinator(adapter=adapter, store=store)

    coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    completed = coordinator.advance(invocation=Invocation(), authority=AUTHORITY)

    assert completed.has_more is False
    assert store.run is not None
    assert store.run.batch_size == 15
    assert tuple(len(item.details) for item in completed.checkpoints) == (15, 1)


def test_fast_capture_handles_an_empty_authoritative_list() -> None:
    adapter = FakeAdapter(total=0)
    store = MemoryBatchStore()
    result = _coordinator(adapter=adapter, store=store).advance(
        invocation=Invocation(),
        authority=AUTHORITY,
    )

    assert result.has_more is False
    assert result.capture_sha256 is not None
    assert len(result.checkpoints) == 1
    assert result.checkpoints[0].page is not None
    assert result.checkpoints[0].page.total == 0
    assert store.freeze_calls == 1
    assert store.commit_calls == 1


def test_fast_capture_retries_transient_batch_with_bounded_downshift() -> None:
    class BatchAdapter(FakeAdapter):
        def __init__(self) -> None:
            super().__init__(total=1)
            self.batch_limits: list[tuple[int, int]] = []

        def read_waybill_batch(
            self,
            *,
            authority: BrowserCommandAuthority,
            summaries: tuple[WaybillSummary, ...],
            detail_concurrency: int,
            image_concurrency: int,
        ) -> tuple[OperationalWaybillEvidence, ...]:
            assert authority == AUTHORITY
            self.batch_limits.append(
                (detail_concurrency, image_concurrency)
            )
            if len(self.batch_limits) < 3:
                raise TransientNetworkError(
                    stage=ChengfengStage.DETAIL_QUERY
                )
            result: list[OperationalWaybillEvidence] = []
            for summary in summaries:
                detail = self.get_waybill_detail(
                    authority=authority,
                    platform_waybill_id=summary.platform_waybill_id,
                )
                result.append(
                    OperationalWaybillEvidence(
                        detail=detail,
                        images=tuple(
                            self.download_ticket_image(
                                authority=authority,
                                ticket_ref=ticket.ticket_ref,
                            )
                            for ticket in detail.tickets
                        ),
                    )
                )
            return tuple(result)

    adapter = BatchAdapter()
    store = MemoryBatchStore()
    coordinator = _coordinator(adapter=adapter, store=store)
    coordinator.advance(invocation=Invocation(), authority=AUTHORITY)

    completed = coordinator.advance(
        invocation=Invocation(),
        authority=AUTHORITY,
    )

    assert completed.has_more is False
    assert adapter.batch_limits == [(4, 6), (2, 3), (1, 1)]
    assert store.commit_calls == 1


def test_fast_capture_does_not_repeat_a_full_worker_timeout() -> None:
    class BatchAdapter(FakeAdapter):
        def __init__(self) -> None:
            super().__init__(total=1)
            self.batch_limits: list[tuple[int, int]] = []

        def read_waybill_batch(
            self,
            *,
            authority: BrowserCommandAuthority,
            summaries: tuple[WaybillSummary, ...],
            detail_concurrency: int,
            image_concurrency: int,
        ) -> tuple[OperationalWaybillEvidence, ...]:
            assert authority == AUTHORITY
            assert len(summaries) == 1
            self.batch_limits.append(
                (detail_concurrency, image_concurrency)
            )
            raise OperationalBatchTimeoutError()

    adapter = BatchAdapter()
    store = MemoryBatchStore()
    coordinator = _coordinator(adapter=adapter, store=store)
    coordinator.advance(invocation=Invocation(), authority=AUTHORITY)

    with pytest.raises(OperationalBatchTimeoutError):
        coordinator.advance(
            invocation=Invocation(),
            authority=AUTHORITY,
        )

    assert adapter.batch_limits == [(4, 6)]
    assert store.commit_calls == 0


def test_platform_missing_ticket_is_committed_as_business_review_input() -> None:
    class MissingTicketAdapter(FakeAdapter):
        def get_waybill_detail(
            self,
            *,
            authority: BrowserCommandAuthority,
            platform_waybill_id: str,
        ) -> WaybillDetail:
            detail = super().get_waybill_detail(
                authority=authority,
                platform_waybill_id=platform_waybill_id,
            )
            return replace(detail, tickets=detail.tickets[:1])

    adapter = MissingTicketAdapter(total=1)
    store = MemoryBatchStore()
    coordinator = _coordinator(adapter=adapter, store=store)
    coordinator.advance(invocation=Invocation(), authority=AUTHORITY)
    result = coordinator.advance(
        invocation=Invocation(),
        authority=AUTHORITY,
    )

    assert result.has_more is False
    spec = scheduled_job_from_operational_batch(
        checkpoint=result.checkpoints[0],
        pipeline_fingerprint="a" * 64,
    )
    assert len(spec.items) == 1
    assert spec.items[0].expected_outcome == "awaiting_review"
    assert spec.items[0].review_reason == "missing_ticket"
    assert spec.items[0].loading_image_sha256 is not None
    assert spec.items[0].unloading_image_sha256 is None

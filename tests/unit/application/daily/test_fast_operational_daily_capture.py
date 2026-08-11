from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from types import SimpleNamespace

import pytest

from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureRequest,
)
from dahe.application.daily.operational_capture import (
    FastOperationalDailyCaptureCoordinator,
    OperationalCaptureContractError,
)
from dahe.domain.daily.calendar import SHANGHAI
from dahe.ports.daily import DailyWaybillPage, DailyWaybillSummary
from tests.unit.application.chengfeng.test_fast_operational_capture import (
    AUTHORITY,
    AllowNavigation,
    FakeAdapter,
    MemoryBatchStore,
)


class MemoryDailyStore:
    def __init__(self) -> None:
        self.snapshot = None
        self.observations: dict[str, object] = {}

    def save_snapshot(self, snapshot: object) -> SimpleNamespace:
        if self.snapshot is None:
            self.snapshot = snapshot
        assert self.snapshot == snapshot
        return SimpleNamespace(snapshot=snapshot)

    def get_snapshot(self, snapshot_id: str) -> object:
        if self.snapshot is None:
            raise RuntimeError("snapshot unavailable")
        assert self.snapshot.snapshot_id == snapshot_id
        return self.snapshot

    def save_observation(self, observation: object) -> SimpleNamespace:
        prior = self.observations.setdefault(
            observation.observation_id,
            observation,
        )
        assert prior == observation
        return SimpleNamespace(observation=observation)


class FakeDailyList:
    def __init__(self, total: int) -> None:
        self.total = total
        self.calls: list[int] = []

    def list_waybills(
        self,
        *,
        query_window: object,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage:
        del query_window
        assert receive_place == "榆林"
        self.calls.append(page_number)
        start = (page_number - 1) * page_size
        end = min(self.total, start + page_size)
        return DailyWaybillPage(
            page_number=page_number,
            page_size=page_size,
            total=self.total,
            platform_display_total=self.total,
            response_total=self.total,
            response_page_count=max(1, (self.total + page_size - 1) // page_size),
            query_scope_sha256="a" * 64,
            scope_complete=True,
            scope_diagnostic_code=None,
            items=tuple(
                DailyWaybillSummary(
                    platform_waybill_id=f"platform-{index:03d}",
                    waybill_number=(
                        None if index == 0 else f"YD-{index:03d}"
                    ),
                    vehicle_number=f"TEST-{index:03d}",
                    platform_loading_time=None,
                )
                for index in range(start, end)
            ),
        )


NOW = datetime(2026, 8, 1, 10, 0, tzinfo=SHANGHAI)
REQUEST = DailyCaptureRequest(
    invocation_id="job-1",
    business_date=date(2026, 7, 30),
    receive_place="榆林",
    now=NOW,
    source_contract_sha256="d" * 64,
    page_size=100,
)


@dataclass(frozen=True)
class DailyInvocation:
    invocation_id: str = "job-1"
    job_id: str = "job-1"
    access_window_id: str = "window-1"
    record_version: int = 1
    request: DailyCaptureRequest = REQUEST
    checkpoint: DailyCaptureCheckpoint | None = None


def test_daily_fast_capture_freezes_once_and_commits_twenty_item_batches() -> None:
    adapter = FakeAdapter(total=21)
    batch_store = MemoryBatchStore()
    daily_store = MemoryDailyStore()
    daily_list = FakeDailyList(total=21)
    current_time = [NOW]
    coordinator = FastOperationalDailyCaptureCoordinator(
        detail_adapter=adapter,
        navigation_authorizer=AllowNavigation(),
        batch_store=batch_store,
        daily_store=daily_store,
        clock=lambda: current_time[0],
    )
    invocation = DailyInvocation()

    first = coordinator.advance(
        invocation=invocation,
        authority=AUTHORITY,
        list_port=daily_list,
    )
    invocation = replace(
        invocation,
        record_version=2,
        checkpoint=first.checkpoint,
    )
    second = coordinator.advance(
        invocation=invocation,
        authority=AUTHORITY,
        list_port=daily_list,
    )
    invocation = replace(
        invocation,
        record_version=3,
        checkpoint=second.checkpoint,
    )
    current_time[0] = NOW + timedelta(seconds=1)
    third = coordinator.advance(
        invocation=invocation,
        authority=AUTHORITY,
        list_port=daily_list,
    )

    assert first.has_more is True
    assert second.has_more is True
    assert third.has_more is False
    assert daily_list.calls == [1]
    assert batch_store.commit_calls == 2
    assert len(daily_store.observations) == 21
    assert len(third.checkpoint.completed_observation_ids) == 21
    assert third.checkpoint.revision == 3


def test_daily_fast_capture_preserves_platform_missing_ticket_as_missing_data() -> None:
    class MissingAdapter(FakeAdapter):
        def get_waybill_detail(self, **kwargs: object):
            detail = super().get_waybill_detail(**kwargs)
            return replace(detail, tickets=detail.tickets[:1])

    adapter = MissingAdapter(total=1)
    batch_store = MemoryBatchStore()
    daily_store = MemoryDailyStore()
    coordinator = FastOperationalDailyCaptureCoordinator(
        detail_adapter=adapter,
        navigation_authorizer=AllowNavigation(),
        batch_store=batch_store,
        daily_store=daily_store,
        clock=lambda: NOW,
    )
    first = coordinator.advance(
        invocation=DailyInvocation(),
        authority=AUTHORITY,
        list_port=FakeDailyList(total=1),
    )
    completed = coordinator.advance(
        invocation=replace(
            DailyInvocation(),
            record_version=2,
            checkpoint=first.checkpoint,
        ),
        authority=AUTHORITY,
        list_port=FakeDailyList(total=1),
    )

    assert completed.has_more is False
    observation = next(iter(daily_store.observations.values()))
    assert observation.loading_ticket_sha256 is not None
    assert observation.unloading_ticket_sha256 is None


def test_daily_fast_capture_preserves_every_identity_from_authoritative_scope() -> None:
    class DateLevelDailyList:
        def list_waybills(
            self,
            *,
            query_window: object,
            receive_place: str,
            page_number: int,
            page_size: int,
        ) -> DailyWaybillPage:
            del query_window
            assert receive_place == "榆林"
            assert page_number == 1
            assert page_size == 100
            return DailyWaybillPage(
                page_number=1,
                page_size=100,
                total=3,
                platform_display_total=3,
                response_total=3,
                query_scope_sha256="b" * 64,
                scope_complete=True,
                scope_diagnostic_code=None,
                items=(
                    DailyWaybillSummary(
                        platform_waybill_id="before-window",
                        waybill_number="YD-BEFORE",
                        vehicle_number="TEST-BEFORE",
                        platform_loading_time=datetime(
                            2026, 7, 30, 13, 45, tzinfo=SHANGHAI
                        ),
                    ),
                    DailyWaybillSummary(
                        platform_waybill_id="inside-window",
                        waybill_number="YD-INSIDE",
                        vehicle_number="TEST-INSIDE",
                        platform_loading_time=datetime(
                            2026, 7, 30, 14, 0, tzinfo=SHANGHAI
                        ),
                    ),
                    DailyWaybillSummary(
                        platform_waybill_id="next-window",
                        waybill_number="YD-NEXT",
                        vehicle_number="TEST-NEXT",
                        platform_loading_time=datetime(
                            2026, 7, 31, 14, 0, tzinfo=SHANGHAI
                        ),
                    ),
                ),
            )

    coordinator = FastOperationalDailyCaptureCoordinator(
        detail_adapter=FakeAdapter(total=1),
        navigation_authorizer=AllowNavigation(),
        batch_store=MemoryBatchStore(),
        daily_store=MemoryDailyStore(),
        clock=lambda: NOW,
    )

    candidates = coordinator._freeze_daily_list(
        request=REQUEST,
        list_port=DateLevelDailyList(),
    )

    assert tuple(
        item.platform_waybill_id for item in candidates.candidates
    ) == (
        "before-window",
        "inside-window",
        "next-window",
    )
    assert len(candidates.candidates) == candidates.response_total == 3


def test_daily_fast_capture_rejects_scope_without_page_total_evidence() -> None:
    class IncompleteDailyList(FakeDailyList):
        def list_waybills(self, **kwargs: object) -> DailyWaybillPage:
            page = super().list_waybills(**kwargs)
            return replace(
                page,
                platform_display_total=None,
                scope_complete=False,
                scope_diagnostic_code=(
                    "CF-DAILY-SCOPE-DISPLAY-TOTAL-MISSING"
                ),
            )

    daily_store = MemoryDailyStore()
    coordinator = FastOperationalDailyCaptureCoordinator(
        detail_adapter=FakeAdapter(total=1),
        navigation_authorizer=AllowNavigation(),
        batch_store=MemoryBatchStore(),
        daily_store=daily_store,
        clock=lambda: NOW,
    )

    with pytest.raises(
        OperationalCaptureContractError,
        match="operational daily scope is incomplete",
    ):
        coordinator.advance(
            invocation=DailyInvocation(),
            authority=AUTHORITY,
            list_port=IncompleteDailyList(total=1),
        )

    assert daily_store.snapshot.scope_complete is False
    assert daily_store.snapshot.scope_diagnostic_code == (
        "CF-DAILY-SCOPE-DISPLAY-TOTAL-MISSING"
    )


def test_daily_fast_capture_accepts_complete_scope_without_page_total() -> None:
    class PageOwnedDailyList(FakeDailyList):
        def list_waybills(self, **kwargs: object) -> DailyWaybillPage:
            page = super().list_waybills(**kwargs)
            return replace(page, platform_display_total=None)

    daily_store = MemoryDailyStore()
    coordinator = FastOperationalDailyCaptureCoordinator(
        detail_adapter=FakeAdapter(total=1),
        navigation_authorizer=AllowNavigation(),
        batch_store=MemoryBatchStore(),
        daily_store=daily_store,
        clock=lambda: NOW,
    )

    result = coordinator.advance(
        invocation=DailyInvocation(),
        authority=AUTHORITY,
        list_port=PageOwnedDailyList(total=1),
    )

    assert result.platform_read_performed is True
    assert daily_store.snapshot.scope_complete is True
    assert daily_store.snapshot.platform_display_total is None


def test_daily_fast_capture_rejects_response_page_count_mismatch() -> None:
    class MismatchedPageCountDailyList(FakeDailyList):
        def list_waybills(self, **kwargs: object) -> DailyWaybillPage:
            page = super().list_waybills(**kwargs)
            return replace(page, response_page_count=page.response_page_count + 1)

    daily_store = MemoryDailyStore()
    coordinator = FastOperationalDailyCaptureCoordinator(
        detail_adapter=FakeAdapter(total=1),
        navigation_authorizer=AllowNavigation(),
        batch_store=MemoryBatchStore(),
        daily_store=daily_store,
        clock=lambda: NOW,
    )

    with pytest.raises(
        OperationalCaptureContractError,
        match="operational daily scope is incomplete",
    ):
        coordinator.advance(
            invocation=DailyInvocation(),
            authority=AUTHORITY,
            list_port=MismatchedPageCountDailyList(total=1),
        )

    assert daily_store.snapshot.scope_complete is False
    assert daily_store.snapshot.scope_diagnostic_code == (
        "CF-DAILY-SCOPE-PAGE-COUNT-MISMATCH"
    )

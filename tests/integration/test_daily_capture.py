from __future__ import annotations

import hashlib
from datetime import date, datetime
from pathlib import Path

from sqlalchemy import text

from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.daily.capture import (
    DailyCaptureRequest,
    DailyCaptureService,
)
from dahe.domain.daily.calendar import SHANGHAI, CandidateQueryWindow
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyObservationFields,
)
from dahe.ports.daily import (
    DailyDetailEvidence,
    DailyWaybillPage,
    DailyWaybillSummary,
)

PROJECT_ROOT = Path(__file__).parents[2]
CONTRACT_SHA = hashlib.sha256(b"daily-contract").hexdigest()
DETAIL_SHA = hashlib.sha256(b"daily-detail").hexdigest()


class TwoPagePlatform:
    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage:
        assert query_window.business_date == date(2026, 7, 29)
        assert receive_place == "Test receiving place"
        assert page_size == 1
        summary = DailyWaybillSummary(
            platform_waybill_id=str(1000 + page_number),
            waybill_number=f"WB-{page_number:03d}",
            vehicle_number=None,
            platform_loading_time=None,
        )
        return DailyWaybillPage(
            page_number=page_number,
            page_size=page_size,
            total=2,
            items=(summary,),
        )


class EmptyDetailEvidence:
    def observe(
        self,
        *,
        candidate: DailyCandidate,
    ) -> DailyDetailEvidence:
        return DailyDetailEvidence(
            platform_waybill_id=candidate.platform_waybill_id,
            waybill_number=candidate.waybill_number,
            fields=DailyObservationFields(
                shipping_mine=None,
                planned_date=None,
                loading_time=None,
                vehicle_number=None,
                loading_net_tonnes=None,
                unloading_net_tonnes=None,
                coal_type=None,
                unloading_place=None,
                unloading_time=None,
            ),
            loading_ticket_sha256=None,
            unloading_ticket_sha256=None,
            source_detail_sha256=DETAIL_SHA,
        )


class SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self._values = iter(values)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return next(self._values)


def test_daily_capture_is_idempotent_through_the_sqlite_store(
    tmp_path: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="daily-capture-test",
        )
    try:
        store = SqliteDailyStore(runtime)
        capture_time = datetime(2026, 7, 29, 20, 1, tzinfo=SHANGHAI)
        observation_times = (
            datetime(2026, 7, 29, 20, 2, tzinfo=SHANGHAI),
            datetime(2026, 7, 29, 20, 3, tzinfo=SHANGHAI),
        )
        clock = SequenceClock(capture_time, *observation_times)
        service = DailyCaptureService(
            platform=TwoPagePlatform(),
            detail_evidence=EmptyDetailEvidence(),
            store=store,
            clock=clock,
        )
        request = DailyCaptureRequest(
            invocation_id="daily-job-20260729",
            business_date=date(2026, 7, 29),
            receive_place="Test receiving place",
            now=datetime(2026, 7, 29, 20, 0, tzinfo=SHANGHAI),
            source_contract_sha256=CONTRACT_SHA,
            page_size=1,
        )

        first_page = service.advance(request=request, checkpoint=None)
        list_complete = service.advance(
            request=request,
            checkpoint=first_page.checkpoint,
        )
        verification_first_page = service.advance(
            request=request,
            checkpoint=list_complete.checkpoint,
        )
        verification_complete = service.advance(
            request=request,
            checkpoint=verification_first_page.checkpoint,
        )
        assert verification_complete.checkpoint.snapshot_captured_at == capture_time

        first_snapshot_commit = service.advance(
            request=request,
            checkpoint=verification_complete.checkpoint,
        )
        replayed_snapshot_commit = service.advance(
            request=request,
            checkpoint=verification_complete.checkpoint,
        )
        assert first_snapshot_commit.checkpoint == replayed_snapshot_commit.checkpoint

        checkpoint = first_snapshot_commit.checkpoint
        observation_fingerprints: list[str] = []
        for _ in range(2):
            pending = service.advance(request=request, checkpoint=checkpoint)
            assert pending.checkpoint.pending_observation is not None
            observation_fingerprints.append(
                pending.checkpoint.pending_observation.fingerprint
            )
            committed = service.advance(
                request=request,
                checkpoint=pending.checkpoint,
            )
            replayed_commit = service.advance(
                request=request,
                checkpoint=pending.checkpoint,
            )
            assert committed.checkpoint == replayed_commit.checkpoint
            checkpoint = committed.checkpoint

        assert checkpoint.completed_observation_count == 2
        assert checkpoint.snapshot is not None
        assert checkpoint.snapshot.captured_at == capture_time
        assert len(set(observation_fingerprints)) == 2
        assert clock.calls == 3
        with runtime.engine.connect() as connection:
            counts = {
                table: connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
                for table in (
                    "daily_candidate_snapshots",
                    "daily_observations",
                    "daily_record_revisions",
                )
            }
            payloads = tuple(
                connection.execute(
                    text("SELECT payload_json FROM daily_observations ORDER BY platform_waybill_id")
                ).scalars()
            )
            observed_at_values = tuple(
                connection.execute(
                    text("SELECT observed_at FROM daily_observations ORDER BY platform_waybill_id")
                ).scalars()
            )
        assert counts == {
            "daily_candidate_snapshots": 1,
            "daily_observations": 2,
            "daily_record_revisions": 2,
        }
        assert observed_at_values == tuple(
            value.isoformat() for value in observation_times
        )
        assert all('"loading_time":null' in str(payload) for payload in payloads)
        assert all('"unloading_time":null' in str(payload) for payload in payloads)
    finally:
        runtime.close()

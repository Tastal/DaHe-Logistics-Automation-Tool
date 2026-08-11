from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal

import pytest

from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureError,
    DailyCaptureRequest,
    DailyCaptureService,
    DailyCaptureStage,
)
from dahe.domain.daily.calendar import SHANGHAI, CandidateQueryWindow
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyRecordRevision,
    DailyWaybillObservation,
    revision_id_for,
)
from dahe.ports.daily import (
    DailyDetailEvidence,
    DailyObservationSaveResult,
    DailySnapshotSaveResult,
    DailyWaybillPage,
    DailyWaybillSummary,
)

CONTRACT_SHA = hashlib.sha256(b"daily-contract").hexdigest()
DETAIL_SHA = hashlib.sha256(b"daily-detail").hexdigest()
LOADING_SHA = hashlib.sha256(b"loading-ticket").hexdigest()


def _request() -> DailyCaptureRequest:
    return DailyCaptureRequest(
        invocation_id="daily-job-20260729",
        business_date=date(2026, 7, 29),
        receive_place="Test receiving place",
        now=datetime(2026, 7, 29, 20, 0, tzinfo=SHANGHAI),
        source_contract_sha256=CONTRACT_SHA,
        page_size=2,
    )


def _summary(
    suffix: int,
    *,
    vehicle_number: str | None = None,
    platform_loading_time: datetime | None = None,
) -> DailyWaybillSummary:
    return DailyWaybillSummary(
        platform_waybill_id=str(1000 + suffix),
        waybill_number=f"WB-{suffix:03d}",
        vehicle_number=vehicle_number,
        platform_loading_time=platform_loading_time,
    )


@dataclass
class FakeDailyPlatform:
    pages: dict[int, DailyWaybillPage]

    def __post_init__(self) -> None:
        self.calls: list[tuple[CandidateQueryWindow, str, int, int]] = []

    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage:
        self.calls.append((query_window, receive_place, page_number, page_size))
        return self.pages[page_number]


@dataclass
class SequenceDailyPlatform:
    responses: list[DailyWaybillPage]

    def __post_init__(self) -> None:
        self.calls: list[tuple[CandidateQueryWindow, str, int, int]] = []

    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage:
        self.calls.append(
            (query_window, receive_place, page_number, page_size)
        )
        return self.responses.pop(0)


@dataclass
class FakeDetailEvidence:
    values: dict[str, DailyDetailEvidence]

    def __post_init__(self) -> None:
        self.calls: list[DailyCandidate] = []

    def observe(
        self,
        *,
        candidate: DailyCandidate,
    ) -> DailyDetailEvidence:
        self.calls.append(candidate)
        return self.values[candidate.platform_waybill_id]


class MemoryDailyStore:
    def __init__(self) -> None:
        self.snapshots: dict[str, DailyCandidateSnapshot] = {}
        self.observations: dict[str, DailyWaybillObservation] = {}
        self.snapshot_save_calls = 0
        self.observation_save_calls = 0

    def save_snapshot(
        self,
        snapshot: DailyCandidateSnapshot,
    ) -> DailySnapshotSaveResult:
        self.snapshot_save_calls += 1
        previous = self.snapshots.setdefault(snapshot.snapshot_id, snapshot)
        if previous != snapshot:
            raise RuntimeError("snapshot conflict")
        return DailySnapshotSaveResult(
            snapshot=previous,
            replayed=previous is not snapshot,
        )

    def get_snapshot(self, snapshot_id: str) -> DailyCandidateSnapshot:
        return self.snapshots[snapshot_id]

    def save_observation(
        self,
        observation: DailyWaybillObservation,
    ) -> DailyObservationSaveResult:
        self.observation_save_calls += 1
        previous = self.observations.setdefault(
            observation.observation_id,
            observation,
        )
        if previous != observation:
            raise RuntimeError("observation conflict")
        revision = DailyRecordRevision(
            revision_id=revision_id_for(
                platform_waybill_id=observation.platform_waybill_id,
                revision_number=1,
                field_fingerprint=observation.field_fingerprint,
            ),
            platform_waybill_id=observation.platform_waybill_id,
            revision_number=1,
            observation_id=observation.observation_id,
            field_fingerprint=observation.field_fingerprint,
            fields=observation.fields,
            waybill_number=observation.waybill_number,
            loading_ticket_sha256=observation.loading_ticket_sha256,
            unloading_ticket_sha256=observation.unloading_ticket_sha256,
            created_at=observation.observed_at,
        )
        return DailyObservationSaveResult(
            observation=previous,
            revision=revision,
            replayed=previous is not observation,
            revision_appended=previous is observation,
        )

    def list_revisions(
        self,
        platform_waybill_id: str,
    ) -> tuple[DailyRecordRevision, ...]:
        del platform_waybill_id
        return ()


def _evidence(summary: DailyWaybillSummary) -> DailyDetailEvidence:
    return DailyDetailEvidence(
        platform_waybill_id=summary.platform_waybill_id,
        waybill_number=summary.waybill_number,
        fields=DailyObservationFields(
            shipping_mine=None,
            planned_date=None,
            loading_time=summary.platform_loading_time,
            vehicle_number=summary.vehicle_number,
            loading_net_tonnes=Decimal("32.80"),
            unloading_net_tonnes=None,
            coal_type=None,
            unloading_place=None,
            unloading_time=None,
        ),
        loading_ticket_sha256=LOADING_SHA,
        unloading_ticket_sha256=None,
        source_detail_sha256=DETAIL_SHA,
    )


def _service(
    pages: dict[int, DailyWaybillPage],
    *,
    clock: Callable[[], datetime] | None = None,
) -> tuple[
    DailyCaptureService,
    FakeDailyPlatform,
    FakeDetailEvidence,
    MemoryDailyStore,
]:
    summaries = tuple(item for page in pages.values() for item in page.items)
    platform = FakeDailyPlatform(pages)
    evidence = FakeDetailEvidence({item.platform_waybill_id: _evidence(item) for item in summaries})
    store = MemoryDailyStore()
    service = DailyCaptureService(
        platform=platform,
        detail_evidence=evidence,
        store=store,
        clock=(
            clock
            if clock is not None
            else lambda: datetime(2026, 7, 29, 20, 1, tzinfo=SHANGHAI)
        ),
    )
    return service, platform, evidence, store


class SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self._values = iter(values)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return next(self._values)


def test_advance_performs_one_platform_read_or_one_store_commit() -> None:
    loading_time = datetime(2026, 7, 29, 15, 0, tzinfo=SHANGHAI)
    first = _summary(
        1,
        vehicle_number="TEST-01",
        platform_loading_time=loading_time,
    )
    second = _summary(2)
    third = _summary(3)
    capture_time = datetime(2026, 7, 29, 20, 1, tzinfo=SHANGHAI)
    observation_times = tuple(
        datetime(2026, 7, 29, 20, minute, tzinfo=SHANGHAI)
        for minute in (2, 3, 4)
    )
    clock = SequenceClock(capture_time, *observation_times)
    service, platform, evidence, store = _service(
        {
            1: DailyWaybillPage(1, 2, 3, (first, second)),
            2: DailyWaybillPage(2, 2, 3, (third,)),
        },
        clock=clock,
    )

    checkpoint: DailyCaptureCheckpoint | None = None
    observed_stages: list[DailyCaptureStage] = []
    for expected_operation_count in range(1, 12):
        before = (
            len(platform.calls)
            + len(evidence.calls)
            + store.snapshot_save_calls
            + store.observation_save_calls
        )
        result = service.advance(request=_request(), checkpoint=checkpoint)
        checkpoint = result.checkpoint
        observed_stages.append(result.completed_stage)
        after = (
            len(platform.calls)
            + len(evidence.calls)
            + store.snapshot_save_calls
            + store.observation_save_calls
        )
        assert after - before == 1
        assert after == expected_operation_count
        if not result.has_more:
            break

    assert checkpoint is not None
    assert checkpoint.completed_observation_count == 3
    assert observed_stages == [
        DailyCaptureStage.LIST_PAGE,
        DailyCaptureStage.LIST_PAGE,
        DailyCaptureStage.LIST_PAGE,
        DailyCaptureStage.LIST_PAGE,
        DailyCaptureStage.SAVE_SNAPSHOT,
        DailyCaptureStage.OBSERVE_CANDIDATE,
        DailyCaptureStage.SAVE_OBSERVATION,
        DailyCaptureStage.OBSERVE_CANDIDATE,
        DailyCaptureStage.SAVE_OBSERVATION,
        DailyCaptureStage.OBSERVE_CANDIDATE,
        DailyCaptureStage.SAVE_OBSERVATION,
    ]
    assert result.has_more is False

    snapshot = next(iter(store.snapshots.values()))
    assert snapshot.snapshot_id == "daily-job-20260729"
    assert snapshot.target_business_date == date(2026, 7, 29)
    assert snapshot.receive_place == "Test receiving place"
    assert snapshot.captured_at == capture_time
    assert snapshot.source_contract_sha256 == CONTRACT_SHA
    assert snapshot.candidates[0] == DailyCandidate(
        platform_waybill_id=first.platform_waybill_id,
        waybill_number=first.waybill_number,
        vehicle_number="TEST-01",
        platform_loading_time=loading_time,
    )
    assert platform.calls[0][0].end == _request().now
    assert tuple(
        observation.observed_at
        for observation in store.observations.values()
    ) == observation_times
    assert len(platform.calls) == 4
    assert clock.calls == 4


def test_second_pagination_pass_rejects_same_count_identity_drift() -> None:
    first = DailyWaybillPage(
        1,
        2,
        2,
        (_summary(1), _summary(2)),
    )
    changed = DailyWaybillPage(
        1,
        2,
        2,
        (_summary(1), _summary(3)),
    )
    platform = SequenceDailyPlatform([first, changed])
    store = MemoryDailyStore()
    service = DailyCaptureService(
        platform=platform,
        detail_evidence=FakeDetailEvidence({}),
        store=store,
        clock=lambda: datetime(
            2026,
            7,
            29,
            20,
            1,
            tzinfo=SHANGHAI,
        ),
    )

    primary = service.advance(request=_request(), checkpoint=None)
    with pytest.raises(DailyCaptureError, match="stability"):
        service.advance(
            request=_request(),
            checkpoint=primary.checkpoint,
        )

    assert len(platform.calls) == 2
    assert store.snapshot_save_calls == 0


def test_second_pagination_pass_rejects_summary_field_drift() -> None:
    loading_time = datetime(
        2026,
        7,
        29,
        15,
        0,
        tzinfo=SHANGHAI,
    )
    first = DailyWaybillPage(
        1,
        2,
        1,
        (
            _summary(
                1,
                vehicle_number="TEST-01",
                platform_loading_time=loading_time,
            ),
        ),
    )
    changed = DailyWaybillPage(
        1,
        2,
        1,
        (
            _summary(
                1,
                vehicle_number="TEST-02",
                platform_loading_time=loading_time,
            ),
        ),
    )
    platform = SequenceDailyPlatform([first, changed])
    store = MemoryDailyStore()
    service = DailyCaptureService(
        platform=platform,
        detail_evidence=FakeDetailEvidence({}),
        store=store,
        clock=lambda: datetime(
            2026,
            7,
            29,
            20,
            1,
            tzinfo=SHANGHAI,
        ),
    )

    primary = service.advance(request=_request(), checkpoint=None)
    with pytest.raises(DailyCaptureError, match="stability"):
        service.advance(
            request=_request(),
            checkpoint=primary.checkpoint,
        )

    assert len(platform.calls) == 2
    assert store.snapshot_save_calls == 0


def test_restored_checkpoint_revalidates_both_pagination_passes() -> None:
    primary_page = DailyWaybillPage(
        1,
        2,
        1,
        (_summary(1),),
    )
    service, _, _, store = _service({1: primary_page})
    primary = service.advance(
        request=_request(),
        checkpoint=None,
    ).checkpoint
    mismatched_total = replace(
        primary,
        verification_pages=(
            DailyWaybillPage(
                1,
                2,
                2,
                (_summary(1), _summary(2)),
            ),
        ),
    )
    with pytest.raises(DailyCaptureError, match="stability passes"):
        service.advance(
            request=_request(),
            checkpoint=mismatched_total,
        )

    mismatched_identity = replace(
        primary,
        verification_pages=(
            DailyWaybillPage(
                1,
                2,
                1,
                (_summary(2),),
            ),
        ),
    )
    with pytest.raises(DailyCaptureError, match="stability check"):
        service.advance(
            request=_request(),
            checkpoint=mismatched_identity,
        )

    assert store.snapshot_save_calls == 0


def test_pause_resume_preserves_the_actual_snapshot_time() -> None:
    request = replace(_request(), page_size=1)
    capture_time = datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI)
    clock = SequenceClock(capture_time)
    service, _, _, store = _service(
        {
            1: DailyWaybillPage(1, 1, 2, (_summary(1),)),
            2: DailyWaybillPage(2, 1, 2, (_summary(2),)),
        },
        clock=clock,
    )

    paused = service.advance(request=request, checkpoint=None).checkpoint
    resumed = DailyCaptureCheckpoint.from_payload(
        json.loads(json.dumps(paused.to_payload()))
    )
    completed_primary_list = service.advance(
        request=request,
        checkpoint=resumed,
    ).checkpoint
    verified_first = service.advance(
        request=request,
        checkpoint=completed_primary_list,
    ).checkpoint
    completed_list = service.advance(
        request=request,
        checkpoint=verified_first,
    ).checkpoint
    restored = DailyCaptureCheckpoint.from_payload(
        json.loads(json.dumps(completed_list.to_payload()))
    )

    assert restored.snapshot_captured_at == capture_time
    saved = service.advance(request=request, checkpoint=restored)
    assert saved.checkpoint.snapshot is not None
    assert saved.checkpoint.snapshot.captured_at == capture_time
    assert next(iter(store.snapshots.values())).captured_at == capture_time
    assert clock.calls == 1


def test_snapshot_and_observation_commit_replay_keep_checkpointed_fingerprints() -> None:
    capture_time = datetime(2026, 7, 29, 20, 1, tzinfo=SHANGHAI)
    observed_at = datetime(2026, 7, 29, 20, 2, tzinfo=SHANGHAI)
    clock = SequenceClock(capture_time, observed_at)
    service, _, _, store = _service(
        {1: DailyWaybillPage(1, 2, 1, (_summary(1),))},
        clock=clock,
    )
    list_checkpoint = service.advance(
        request=_request(),
        checkpoint=None,
    ).checkpoint
    verified_checkpoint = service.advance(
        request=_request(),
        checkpoint=list_checkpoint,
    ).checkpoint

    first_snapshot_save = service.advance(
        request=_request(),
        checkpoint=verified_checkpoint,
    )
    replayed_snapshot_save = service.advance(
        request=_request(),
        checkpoint=verified_checkpoint,
    )
    assert first_snapshot_save.checkpoint == replayed_snapshot_save.checkpoint
    assert first_snapshot_save.checkpoint.snapshot is not None
    assert replayed_snapshot_save.checkpoint.snapshot is not None
    assert (
        first_snapshot_save.checkpoint.snapshot.fingerprint
        == replayed_snapshot_save.checkpoint.snapshot.fingerprint
    )

    pending = service.advance(
        request=_request(),
        checkpoint=first_snapshot_save.checkpoint,
    ).checkpoint
    assert pending.pending_observation is not None
    first_observation_fingerprint = pending.pending_observation.fingerprint
    first_observation_save = service.advance(
        request=_request(),
        checkpoint=pending,
    )
    replayed_observation_save = service.advance(
        request=_request(),
        checkpoint=pending,
    )

    assert first_observation_save.checkpoint == replayed_observation_save.checkpoint
    assert pending.pending_observation.fingerprint == first_observation_fingerprint
    assert next(iter(store.observations.values())).observed_at == observed_at
    assert store.snapshot_save_calls == 2
    assert store.observation_save_calls == 2
    assert clock.calls == 2


@pytest.mark.parametrize(
    ("clock_value", "message"),
    [
        (datetime(2026, 7, 29, 20, 1), "timezone-aware"),
        (
            datetime(2026, 7, 29, 19, 59, tzinfo=SHANGHAI),
            "precedes its source read",
        ),
    ],
)
def test_snapshot_clock_must_be_aware_and_not_precede_the_query(
    clock_value: datetime,
    message: str,
) -> None:
    service, _, _, store = _service(
        {1: DailyWaybillPage(1, 2, 0, ())},
        clock=lambda: clock_value,
    )

    listed = service.advance(request=_request(), checkpoint=None)
    with pytest.raises(DailyCaptureError, match=message):
        service.advance(
            request=_request(),
            checkpoint=listed.checkpoint,
        )

    assert store.snapshot_save_calls == 0


def test_observation_clock_must_not_precede_the_snapshot() -> None:
    capture_time = datetime(2026, 7, 29, 20, 2, tzinfo=SHANGHAI)
    earlier_observation = datetime(2026, 7, 29, 20, 1, tzinfo=SHANGHAI)
    service, _, _, store = _service(
        {1: DailyWaybillPage(1, 2, 1, (_summary(1),))},
        clock=SequenceClock(capture_time, earlier_observation),
    )
    listed = service.advance(request=_request(), checkpoint=None)
    verified = service.advance(
        request=_request(),
        checkpoint=listed.checkpoint,
    )
    saved = service.advance(
        request=_request(),
        checkpoint=verified.checkpoint,
    )

    with pytest.raises(DailyCaptureError, match="precedes its source read"):
        service.advance(request=_request(), checkpoint=saved.checkpoint)

    assert store.observation_save_calls == 0


def test_empty_snapshot_is_saved_after_two_independent_list_passes() -> None:
    service, platform, evidence, store = _service({1: DailyWaybillPage(1, 2, 0, ())})

    first = service.advance(request=_request(), checkpoint=None)
    second = service.advance(
        request=_request(),
        checkpoint=first.checkpoint,
    )
    third = service.advance(
        request=_request(),
        checkpoint=second.checkpoint,
    )

    assert first.completed_stage is DailyCaptureStage.LIST_PAGE
    assert second.completed_stage is DailyCaptureStage.LIST_PAGE
    assert third.completed_stage is DailyCaptureStage.SAVE_SNAPSHOT
    assert third.has_more is False
    assert len(platform.calls) == 2
    assert evidence.calls == []
    assert store.snapshot_save_calls == 1


def test_pagination_must_reconcile_total_order_and_unique_identities() -> None:
    request = replace(_request(), page_size=1)
    first = _summary(1)
    duplicate = DailyWaybillSummary(
        platform_waybill_id=_summary(2).platform_waybill_id,
        waybill_number=first.waybill_number,
        vehicle_number=None,
        platform_loading_time=None,
    )
    service, _, _, store = _service(
        {
            1: DailyWaybillPage(1, 1, 2, (first,)),
            2: DailyWaybillPage(2, 1, 2, (duplicate,)),
        }
    )
    first_step = service.advance(request=request, checkpoint=None)

    with pytest.raises(DailyCaptureError, match="duplicate"):
        service.advance(
            request=request,
            checkpoint=first_step.checkpoint,
        )
    assert store.snapshot_save_calls == 0

    changed_total, _, _, _ = _service(
        {
            1: DailyWaybillPage(1, 1, 2, (_summary(1),)),
            2: DailyWaybillPage(2, 1, 3, (_summary(2),)),
        }
    )
    checkpoint = changed_total.advance(
        request=request,
        checkpoint=None,
    ).checkpoint
    with pytest.raises(DailyCaptureError, match="pagination changed"):
        changed_total.advance(request=request, checkpoint=checkpoint)


def test_checkpoint_rejects_changed_invocation_inputs() -> None:
    service, _, _, _ = _service({1: DailyWaybillPage(1, 2, 0, ())})
    checkpoint = service.advance(
        request=_request(),
        checkpoint=None,
    ).checkpoint

    changed = replace(_request(), receive_place="Different place")
    with pytest.raises(DailyCaptureError, match="invocation"):
        service.advance(request=changed, checkpoint=checkpoint)


def test_checkpoint_round_trips_at_a_pending_observation_boundary() -> None:
    summary = _summary(
        1,
        vehicle_number="TEST-01",
        platform_loading_time=datetime(
            2026,
            7,
            29,
            15,
            0,
            tzinfo=SHANGHAI,
        ),
    )
    service, _, _, _ = _service({1: DailyWaybillPage(1, 2, 1, (summary,))})
    checkpoint: DailyCaptureCheckpoint | None = None
    for _ in range(4):
        checkpoint = service.advance(
            request=_request(),
            checkpoint=checkpoint,
        ).checkpoint

    assert checkpoint is not None
    encoded = json.dumps(
        checkpoint.to_payload(),
        ensure_ascii=False,
        sort_keys=True,
    )
    restored = DailyCaptureCheckpoint.from_payload(json.loads(encoded))

    assert restored == checkpoint
    assert restored.pending_observation is not None
    assert restored.pending_observation.fields.vehicle_number == "TEST-01"


def test_capture_request_round_trips_as_a_strict_persisted_contract() -> None:
    request = _request()

    restored = DailyCaptureRequest.from_payload(
        json.loads(
            json.dumps(
                request.to_payload(),
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    )

    assert restored == request
    assert restored.fingerprint == request.fingerprint
    with pytest.raises(DailyCaptureError):
        DailyCaptureRequest.from_payload(
            {**request.to_payload(), "unexpected": "rejected"}
        )


def test_detail_identity_mismatch_and_system_errors_are_raised() -> None:
    summary = _summary(1)
    service, _, evidence, store = _service({1: DailyWaybillPage(1, 2, 1, (summary,))})
    evidence.values[summary.platform_waybill_id] = replace(
        _evidence(summary),
        platform_waybill_id="different-platform-id",
    )
    checkpoint: DailyCaptureCheckpoint | None = None
    for _ in range(3):
        checkpoint = service.advance(
            request=_request(),
            checkpoint=checkpoint,
        ).checkpoint

    with pytest.raises(DailyCaptureError, match="requested candidate"):
        service.advance(request=_request(), checkpoint=checkpoint)
    assert store.observation_save_calls == 0

    class BrokenEvidence(FakeDetailEvidence):
        def observe(
            self,
            *,
            candidate: DailyCandidate,
        ) -> DailyDetailEvidence:
            raise OSError("controlled worker failed")

    service = DailyCaptureService(
        platform=FakeDailyPlatform({1: DailyWaybillPage(1, 2, 1, (summary,))}),
        detail_evidence=BrokenEvidence({}),
        store=MemoryDailyStore(),
        clock=lambda: datetime(2026, 7, 29, 20, 1, tzinfo=SHANGHAI),
    )
    checkpoint = None
    for _ in range(3):
        checkpoint = service.advance(
            request=_request(),
            checkpoint=checkpoint,
        ).checkpoint
    with pytest.raises(OSError, match="controlled worker failed"):
        service.advance(request=_request(), checkpoint=checkpoint)


def test_missing_detail_values_remain_none_in_observation() -> None:
    summary = _summary(1)
    service, _, evidence, store = _service({1: DailyWaybillPage(1, 2, 1, (summary,))})
    evidence.values[summary.platform_waybill_id] = DailyDetailEvidence(
        platform_waybill_id=summary.platform_waybill_id,
        waybill_number=summary.waybill_number,
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

    checkpoint: DailyCaptureCheckpoint | None = None
    while True:
        result = service.advance(
            request=_request(),
            checkpoint=checkpoint,
        )
        checkpoint = result.checkpoint
        if not result.has_more:
            break

    observation = next(iter(store.observations.values()))
    assert observation.fields.to_payload() == {
        "coal_type": None,
        "loading_net_tonnes": None,
        "loading_time": None,
        "planned_date": None,
        "shipping_mine": None,
        "unloading_net_tonnes": None,
        "unloading_place": None,
        "unloading_time": None,
        "vehicle_number": None,
    }
    assert observation.loading_ticket_sha256 is None
    assert observation.unloading_ticket_sha256 is None

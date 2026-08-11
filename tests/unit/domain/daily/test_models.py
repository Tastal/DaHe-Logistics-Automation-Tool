from __future__ import annotations

import hashlib
from datetime import date, datetime
from decimal import Decimal

import pytest

from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyDomainError,
    DailyObservationFields,
    DailyWaybillObservation,
)

HASH_A = hashlib.sha256(b"a").hexdigest()
HASH_B = hashlib.sha256(b"b").hexdigest()
HASH_C = hashlib.sha256(b"c").hexdigest()


def _snapshot() -> DailyCandidateSnapshot:
    captured_at = datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI)
    return DailyCandidateSnapshot(
        snapshot_id="daily-snapshot-1",
        target_business_date=date(2026, 7, 29),
        receive_place="Test receiving place",
        query_window=candidate_query_window(
            date(2026, 7, 29),
            now=captured_at,
        ),
        source_contract_sha256=HASH_A,
        candidates=(
            DailyCandidate(
                platform_waybill_id="platform-1",
                waybill_number="WB-001",
            ),
        ),
        captured_at=captured_at,
    )


@pytest.mark.domain
def test_snapshot_and_observation_are_stably_fingerprinted() -> None:
    first = _snapshot()
    second = _snapshot()

    assert first.fingerprint == second.fingerprint
    assert first.to_payload() == second.to_payload()

    observation = DailyWaybillObservation(
        observation_id="daily-observation-1",
        snapshot_id=first.snapshot_id,
        platform_waybill_id="platform-1",
        waybill_number="WB-001",
        fields=DailyObservationFields(
            shipping_mine="Test mine",
            planned_date=date(2026, 7, 29),
            loading_time=datetime(
                2026,
                7,
                29,
                15,
                0,
                tzinfo=SHANGHAI,
            ),
            vehicle_number="TEST-01",
            loading_net_tonnes=Decimal("32.80"),
            unloading_net_tonnes=None,
            coal_type=None,
            unloading_place=None,
            unloading_time=None,
        ),
        loading_ticket_sha256=HASH_B,
        unloading_ticket_sha256=None,
        source_detail_sha256=HASH_C,
        observed_at=datetime(2026, 7, 29, 20, 16, tzinfo=SHANGHAI),
    )

    restored = DailyWaybillObservation.from_payload(observation.to_payload())
    assert restored == observation
    assert restored.fingerprint == observation.fingerprint
    assert restored.field_fingerprint == observation.field_fingerprint
    assert restored.fields.unloading_net_tonnes is None
    assert restored.fields.unloading_time is None


@pytest.mark.domain
def test_missing_business_values_must_be_none_not_empty_strings() -> None:
    with pytest.raises(DailyDomainError, match="None"):
        DailyObservationFields(
            shipping_mine="",
            planned_date=None,
            loading_time=None,
            vehicle_number=None,
            loading_net_tonnes=None,
            unloading_net_tonnes=None,
            coal_type=None,
            unloading_place=None,
            unloading_time=None,
        )


@pytest.mark.domain
def test_candidate_snapshot_rejects_duplicate_platform_identity() -> None:
    captured_at = datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI)
    with pytest.raises(DailyDomainError, match="duplicate"):
        DailyCandidateSnapshot(
            snapshot_id="daily-snapshot-1",
            target_business_date=date(2026, 7, 29),
            receive_place="Test receiving place",
            query_window=candidate_query_window(
                date(2026, 7, 29),
                now=captured_at,
            ),
            source_contract_sha256=HASH_A,
            candidates=(
                DailyCandidate("platform-1", "WB-001"),
                DailyCandidate("platform-1", "WB-002"),
            ),
            captured_at=captured_at,
        )

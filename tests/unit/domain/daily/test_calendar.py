from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from dahe.domain.daily.calendar import (
    SHANGHAI,
    DailyDomainError,
    business_date_for,
    business_day_window,
    candidate_query_window,
    latest_completed_business_date,
)


@pytest.mark.domain
def test_business_day_is_left_closed_at_1400_shanghai() -> None:
    just_before = datetime(2026, 7, 29, 13, 59, 59, tzinfo=SHANGHAI)
    boundary = datetime(2026, 7, 29, 14, 0, 0, tzinfo=SHANGHAI)

    assert business_date_for(just_before) == date(2026, 7, 28)
    assert business_date_for(boundary) == date(2026, 7, 29)

    window = business_day_window(date(2026, 7, 29))
    assert window.start == boundary
    assert window.end == datetime(2026, 7, 30, 14, 0, tzinfo=SHANGHAI)


@pytest.mark.domain
def test_business_date_converts_an_aware_instant_to_shanghai() -> None:
    assert business_date_for(datetime(2026, 7, 29, 5, 59, 59, tzinfo=UTC)) == date(2026, 7, 28)
    assert business_date_for(datetime(2026, 7, 29, 6, 0, 0, tzinfo=UTC)) == date(2026, 7, 29)


@pytest.mark.domain
@pytest.mark.parametrize(
    ("instant", "expected"),
    [
        (
            datetime(2026, 7, 29, 14, 29, 59, tzinfo=SHANGHAI),
            date(2026, 7, 27),
        ),
        (
            datetime(2026, 7, 29, 14, 30, tzinfo=SHANGHAI),
            date(2026, 7, 28),
        ),
        (
            datetime(2026, 7, 30, 13, 0, tzinfo=SHANGHAI),
            date(2026, 7, 28),
        ),
    ],
)
def test_latest_completed_business_date_waits_for_the_safety_end(
    instant: datetime,
    expected: date,
) -> None:
    assert latest_completed_business_date(instant) == expected


@pytest.mark.domain
def test_candidate_window_starts_at_business_day_boundary() -> None:
    window = candidate_query_window(
        date(2026, 7, 29),
        now=datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI),
    )

    assert window.start == datetime(2026, 7, 29, 14, 0, tzinfo=SHANGHAI)
    assert window.end == datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI)
    assert window.safety_end == window.end


@pytest.mark.domain
def test_candidate_window_has_no_artificial_day_cap() -> None:
    window = candidate_query_window(
        date(2026, 7, 29),
        now=datetime(2026, 7, 31, 8, 0, tzinfo=SHANGHAI),
    )

    assert window.end == datetime(2026, 7, 31, 8, 0, tzinfo=SHANGHAI)


@pytest.mark.domain
def test_candidate_window_supports_a_frozen_fixed_end() -> None:
    window = candidate_query_window(
        date(2026, 7, 29),
        now=datetime(2026, 7, 31, 8, 0, tzinfo=SHANGHAI),
        end_mode="fixed_time",
        fixed_end_day_offset=1,
        fixed_end_time=datetime.min.time().replace(hour=15, minute=30),
    )

    assert window.end == datetime(2026, 7, 30, 15, 30, tzinfo=SHANGHAI)
    assert window.safety_end == window.end


@pytest.mark.domain
def test_candidate_window_rejects_naive_or_pre_window_now() -> None:
    with pytest.raises(DailyDomainError, match="timezone-aware"):
        candidate_query_window(
            date(2026, 7, 29),
            now=datetime(2026, 7, 29, 14, 0),
        )
    with pytest.raises(DailyDomainError, match="precedes"):
        candidate_query_window(
            date(2026, 7, 29),
            now=datetime(2026, 7, 29, 13, 59, 59, tzinfo=SHANGHAI),
        )

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SHANGHAI: tzinfo
try:
    SHANGHAI = ZoneInfo("Asia/Shanghai")
except ZoneInfoNotFoundError:
    # Windows does not always ship the IANA database. China has had a stable
    # UTC+08:00 civil offset since 1991, which covers all supported records.
    SHANGHAI = timezone(timedelta(hours=8), name="Asia/Shanghai")
BUSINESS_DAY_START = time(14, 0)
CANDIDATE_BUFFER = timedelta(minutes=30)


class DailyDomainError(ValueError):
    """Raised when loading/unloading domain input violates its contract."""


def _aware_shanghai(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DailyDomainError(f"{field} must be timezone-aware")
    return value.astimezone(SHANGHAI)


def _date_only(value: date, *, field: str) -> date:
    if isinstance(value, datetime) or not isinstance(value, date):
        raise DailyDomainError(f"{field} must be a date")
    return value


@dataclass(frozen=True, slots=True)
class BusinessDayWindow:
    business_date: date
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        _date_only(self.business_date, field="business_date")
        start = _aware_shanghai(self.start, field="start")
        end = _aware_shanghai(self.end, field="end")
        expected_start = datetime.combine(
            self.business_date,
            BUSINESS_DAY_START,
            tzinfo=SHANGHAI,
        )
        if start != expected_start:
            raise DailyDomainError("business day start must be 14:00 Asia/Shanghai")
        if end != expected_start + timedelta(days=1):
            raise DailyDomainError("business day end must be the next day at 14:00")


@dataclass(frozen=True, slots=True)
class CandidateQueryWindow:
    business_date: date
    start: datetime
    end: datetime
    safety_end: datetime

    def __post_init__(self) -> None:
        business_date = _date_only(
            self.business_date,
            field="business_date",
        )
        start = _aware_shanghai(self.start, field="start")
        end = _aware_shanghai(self.end, field="end")
        safety_end = _aware_shanghai(
            self.safety_end,
            field="safety_end",
        )
        business_window = business_day_window(business_date)
        # New reads start at the real business boundary.  The former 13:30
        # value remains accepted only so sealed historical snapshots can be
        # replayed without rewriting their evidence.
        if start not in {
            business_window.start,
            business_window.start - CANDIDATE_BUFFER,
        }:
            raise DailyDomainError(
                "candidate query must start at the business day boundary"
            )
        if safety_end != business_window.end + CANDIDATE_BUFFER:
            raise DailyDomainError("candidate query safety end must be the next day at 14:30")
        if not start <= end <= safety_end:
            raise DailyDomainError("candidate query end is outside the safe window")


def business_date_for(instant: datetime) -> date:
    local = _aware_shanghai(instant, field="instant")
    if local.timetz().replace(tzinfo=None) < BUSINESS_DAY_START:
        return local.date() - timedelta(days=1)
    return local.date()


def latest_completed_business_date(instant: datetime) -> date:
    """Return the newest business date whose 14:30 safety window has closed."""

    local = _aware_shanghai(instant, field="instant")
    candidate = local.date() - timedelta(days=1)
    safety_end = (
        business_day_window(candidate).end + CANDIDATE_BUFFER
    )
    if local < safety_end:
        candidate -= timedelta(days=1)
    return candidate


def business_day_window(business_date: date) -> BusinessDayWindow:
    target = _date_only(business_date, field="business_date")
    start = datetime.combine(
        target,
        BUSINESS_DAY_START,
        tzinfo=SHANGHAI,
    )
    return BusinessDayWindow(
        business_date=target,
        start=start,
        end=start + timedelta(days=1),
    )


def candidate_query_window(
    business_date: date,
    *,
    now: datetime,
) -> CandidateQueryWindow:
    business_window = business_day_window(business_date)
    local_now = _aware_shanghai(now, field="now")
    start = business_window.start
    safety_end = business_window.end + CANDIDATE_BUFFER
    if local_now < start:
        raise DailyDomainError("now precedes the candidate query window")
    return CandidateQueryWindow(
        business_date=business_window.business_date,
        start=start,
        end=min(local_now, safety_end),
        safety_end=safety_end,
    )

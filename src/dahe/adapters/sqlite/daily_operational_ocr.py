from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.engine import RowMapping

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_OPERATIONAL_OCR_BATCHES,
    JOBS,
    OPERATIONAL_CAPTURE_RUNS,
    WORK_ITEMS,
)


class DailyOperationalOcrStoreError(RuntimeError):
    """Raised when a daily batch-to-OCR link changes after commit."""


@dataclass(frozen=True, slots=True)
class DailyOperationalOcrBatch:
    daily_job_id: str
    batch_number: int
    ocr_job_id: str | None
    eligible_item_count: int
    missing_ticket_count: int


@dataclass(frozen=True, slots=True)
class DailyOperationalProgress:
    total: int
    fetched: int
    recognized: int
    missing_ticket: int
    technical_failed: int
    committed_batches: int
    first_ocr_batch_at: str | None
    last_ocr_job_updated_at: str | None


class SqliteDailyOperationalOcrStore:
    def __init__(self, runtime: SqliteRuntime) -> None:
        self._runtime = runtime

    def get_batch(
        self,
        *,
        daily_job_id: str,
        batch_number: int,
    ) -> DailyOperationalOcrBatch | None:
        with self._runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    select(DAILY_OPERATIONAL_OCR_BATCHES).where(
                        DAILY_OPERATIONAL_OCR_BATCHES.c.daily_job_id
                        == daily_job_id,
                        DAILY_OPERATIONAL_OCR_BATCHES.c.batch_number
                        == batch_number,
                    )
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _batch(row)

    def register_batch(
        self,
        *,
        daily_job_id: str,
        batch_number: int,
        ocr_job_id: str | None,
        eligible_item_count: int,
        missing_ticket_count: int,
    ) -> DailyOperationalOcrBatch:
        proposed = DailyOperationalOcrBatch(
            daily_job_id=daily_job_id,
            batch_number=batch_number,
            ocr_job_id=ocr_job_id,
            eligible_item_count=eligible_item_count,
            missing_ticket_count=missing_ticket_count,
        )
        _validate(proposed)
        with self._runtime.commit_gate.transaction(
            self._runtime.engine
        ) as connection:
            existing = (
                connection.execute(
                    select(DAILY_OPERATIONAL_OCR_BATCHES).where(
                        DAILY_OPERATIONAL_OCR_BATCHES.c.daily_job_id
                        == daily_job_id,
                        DAILY_OPERATIONAL_OCR_BATCHES.c.batch_number
                        == batch_number,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                stored = _batch(existing)
                if stored != proposed:
                    raise DailyOperationalOcrStoreError(
                        "daily OCR batch link changed after commit"
                    )
                return stored
            daily_job = connection.execute(
                select(JOBS.c.task_type).where(
                    JOBS.c.job_id == daily_job_id
                )
            ).scalar_one_or_none()
            if daily_job != "daily":
                raise DailyOperationalOcrStoreError(
                    "daily OCR link has no daily source job"
                )
            if ocr_job_id is not None:
                ocr_job = connection.execute(
                    select(JOBS.c.task_type, JOBS.c.job_kind).where(
                        JOBS.c.job_id == ocr_job_id
                    )
                ).one_or_none()
                if ocr_job is None or tuple(ocr_job) != (
                    "audit",
                    "observation",
                ):
                    raise DailyOperationalOcrStoreError(
                        "daily OCR link has an invalid observation job"
                    )
            connection.execute(
                DAILY_OPERATIONAL_OCR_BATCHES.insert().values(
                    daily_job_id=daily_job_id,
                    batch_number=batch_number,
                    ocr_job_id=ocr_job_id,
                    eligible_item_count=eligible_item_count,
                    missing_ticket_count=missing_ticket_count,
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
        return proposed

    def progress(self, *, daily_job_id: str) -> DailyOperationalProgress:
        with self._runtime.engine.connect() as connection:
            run = connection.execute(
                select(
                    OPERATIONAL_CAPTURE_RUNS.c.total,
                    OPERATIONAL_CAPTURE_RUNS.c.next_item_index,
                    OPERATIONAL_CAPTURE_RUNS.c.committed_batch_count,
                ).where(
                    OPERATIONAL_CAPTURE_RUNS.c.job_id == daily_job_id
                )
            ).one_or_none()
            rows = tuple(
                connection.execute(
                    select(DAILY_OPERATIONAL_OCR_BATCHES).where(
                        DAILY_OPERATIONAL_OCR_BATCHES.c.daily_job_id
                        == daily_job_id
                    )
                ).mappings()
            )
            ocr_job_ids = tuple(
                str(row["ocr_job_id"])
                for row in rows
                if row["ocr_job_id"] is not None
            )
            status_counts: dict[str, int] = {}
            last_ocr_job_updated_at: str | None = None
            if ocr_job_ids:
                status_counts = {
                    str(status): int(count)
                    for status, count in connection.execute(
                        select(WORK_ITEMS.c.status, func.count())
                        .where(WORK_ITEMS.c.job_id.in_(ocr_job_ids))
                        .group_by(WORK_ITEMS.c.status)
                    )
                }
                last_ocr_job_updated_at = connection.execute(
                    select(func.max(JOBS.c.updated_at)).where(
                        JOBS.c.job_id.in_(ocr_job_ids)
                    )
                ).scalar_one()
        missing = sum(int(row["missing_ticket_count"]) for row in rows)
        return DailyOperationalProgress(
            total=0 if run is None else int(run.total),
            fetched=(
                0 if run is None else int(run.next_item_index)
            ),
            recognized=status_counts.get("succeeded", 0),
            missing_ticket=missing,
            technical_failed=status_counts.get("failed", 0),
            committed_batches=(
                0 if run is None else int(run.committed_batch_count)
            ),
            first_ocr_batch_at=(
                None
                if not rows
                else min(str(row["created_at"]) for row in rows)
            ),
            last_ocr_job_updated_at=(
                None
                if last_ocr_job_updated_at is None
                else str(last_ocr_job_updated_at)
            ),
        )


def _batch(row: RowMapping) -> DailyOperationalOcrBatch:
    return DailyOperationalOcrBatch(
        daily_job_id=str(row["daily_job_id"]),
        batch_number=int(row["batch_number"]),
        ocr_job_id=(
            None
            if row["ocr_job_id"] is None
            else str(row["ocr_job_id"])
        ),
        eligible_item_count=int(row["eligible_item_count"]),
        missing_ticket_count=int(row["missing_ticket_count"]),
    )


def _validate(value: DailyOperationalOcrBatch) -> None:
    if (
        not value.daily_job_id
        or value.batch_number < 1
        or value.eligible_item_count < 0
        or value.missing_ticket_count < 0
        or not 1
        <= value.eligible_item_count + value.missing_ticket_count
        <= 100
        or (value.eligible_item_count == 0)
        != (value.ocr_job_id is None)
    ):
        raise DailyOperationalOcrStoreError(
            "daily OCR batch link is invalid"
        )

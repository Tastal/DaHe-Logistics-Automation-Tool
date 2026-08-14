from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.engine import RowMapping

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import JOBS, OPERATIONAL_REVIEW_LINKS


class OperationalReviewLinkError(RuntimeError):
    """Raised when a whole-run review link changes after publication."""


@dataclass(frozen=True, slots=True)
class OperationalReviewLink:
    source_job_id: str
    business_kind: str
    review_job_id: str | None
    eligible_item_count: int
    missing_item_count: int
    source_manifest_sha256: str


class SqliteOperationalReviewLinkStore:
    def __init__(self, runtime: SqliteRuntime) -> None:
        self._runtime = runtime

    def get(self, source_job_id: str) -> OperationalReviewLink | None:
        with self._runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    select(OPERATIONAL_REVIEW_LINKS).where(
                        OPERATIONAL_REVIEW_LINKS.c.source_job_id == source_job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _link(row)

    def register(
        self,
        *,
        source_job_id: str,
        business_kind: str,
        review_job_id: str | None,
        eligible_item_count: int,
        missing_item_count: int,
        source_manifest_sha256: str,
    ) -> OperationalReviewLink:
        proposed = OperationalReviewLink(
            source_job_id=source_job_id,
            business_kind=business_kind,
            review_job_id=review_job_id,
            eligible_item_count=eligible_item_count,
            missing_item_count=missing_item_count,
            source_manifest_sha256=source_manifest_sha256,
        )
        _validate(proposed)
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            existing = (
                connection.execute(
                    select(OPERATIONAL_REVIEW_LINKS).where(
                        OPERATIONAL_REVIEW_LINKS.c.source_job_id == source_job_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                stored = _link(existing)
                if stored != proposed:
                    raise OperationalReviewLinkError(
                        "operational review link changed after publication"
                    )
                return stored
            source_kind = connection.execute(
                select(JOBS.c.task_type).where(JOBS.c.job_id == source_job_id)
            ).scalar_one_or_none()
            expected_source = "settlement_capture" if business_kind == "settlement" else "daily"
            if source_kind != expected_source:
                raise OperationalReviewLinkError("operational review source is invalid")
            if review_job_id is not None:
                review_kind = connection.execute(
                    select(JOBS.c.task_type, JOBS.c.job_kind).where(
                        JOBS.c.job_id == review_job_id
                    )
                ).one_or_none()
                if review_kind is None or tuple(review_kind) not in {
                    ("audit", "business"),
                    ("audit", "observation"),
                }:
                    raise OperationalReviewLinkError("operational review job is invalid")
            connection.execute(
                OPERATIONAL_REVIEW_LINKS.insert().values(
                    source_job_id=source_job_id,
                    business_kind=business_kind,
                    review_job_id=review_job_id,
                    eligible_item_count=eligible_item_count,
                    missing_item_count=missing_item_count,
                    source_manifest_sha256=source_manifest_sha256,
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
        return proposed


def _link(row: RowMapping) -> OperationalReviewLink:
    return OperationalReviewLink(
        source_job_id=str(row["source_job_id"]),
        business_kind=str(row["business_kind"]),
        review_job_id=None if row["review_job_id"] is None else str(row["review_job_id"]),
        eligible_item_count=int(row["eligible_item_count"]),
        missing_item_count=int(row["missing_item_count"]),
        source_manifest_sha256=str(row["source_manifest_sha256"]),
    )


def _validate(value: OperationalReviewLink) -> None:
    if (
        not value.source_job_id
        or value.business_kind not in {"settlement", "daily"}
        or value.eligible_item_count < 0
        or value.missing_item_count < 0
        or len(value.source_manifest_sha256) != 64
        or (value.eligible_item_count == 0) != (value.review_job_id is None)
    ):
        raise OperationalReviewLinkError("operational review link is invalid")

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from sqlalchemy import func, select, update
from sqlalchemy.engine import Connection

from dahe.adapters.sqlite.schema import SCHEDULER_META, STAGE_ATTEMPTS
from dahe.jobs.models import JobRecord

GetJob = Callable[[Connection, str], JobRecord]


class AppendEvent(Protocol):
    def __call__(
        self,
        connection: Connection,
        *,
        event_type: str,
        aggregate_id: str,
        record_version: int,
        payload: dict[str, object],
        created_at: str,
        aggregate_type: str = "job",
    ) -> None: ...


def next_sequence(connection: Connection) -> int:
    current = connection.execute(
        select(SCHEDULER_META.c.value).where(SCHEDULER_META.c.key == "sequence")
    ).scalar_one()
    sequence = int(str(current)) + 1
    connection.execute(
        update(SCHEDULER_META).where(SCHEDULER_META.c.key == "sequence").values(value=str(sequence))
    )
    return sequence


def attempt_number(
    connection: Connection,
    *,
    owner_kind: str,
    owner_id: str,
    stage: str,
) -> int:
    value = connection.execute(
        select(func.count())
        .select_from(STAGE_ATTEMPTS)
        .where(
            STAGE_ATTEMPTS.c.owner_kind == owner_kind,
            STAGE_ATTEMPTS.c.owner_id == owner_id,
            STAGE_ATTEMPTS.c.stage == stage,
        )
    ).scalar_one()
    return int(value) + 1

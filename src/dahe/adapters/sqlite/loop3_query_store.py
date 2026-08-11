from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.engine import Engine

from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    LEASES,
    RESOURCE_SLOTS,
    SHARED_EVIDENCE_WORK,
    STAGE_ATTEMPTS,
    WORK_ITEMS,
)
from dahe.jobs.models import WorkItemStatus


class SqliteLoop3QueryStore:
    """Read scheduler diagnostics and runtime/resource projections."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def list_stage_attempts(self) -> list[dict[str, object]]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(STAGE_ATTEMPTS).order_by(
                    STAGE_ATTEMPTS.c.started_sequence,
                    STAGE_ATTEMPTS.c.stage_attempt_id,
                )
            ).mappings()
            return [dict(row) for row in rows]

    def count_stage_attempts(self, *, job_id: str, stage: str) -> int:
        with self.engine.connect() as connection:
            value = connection.execute(
                select(func.count())
                .select_from(STAGE_ATTEMPTS)
                .where(
                    STAGE_ATTEMPTS.c.consumer_job_id == job_id,
                    STAGE_ATTEMPTS.c.stage == stage,
                )
            ).scalar_one()
            return int(value)

    def list_shared_evidence_work(self) -> list[dict[str, object]]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(SHARED_EVIDENCE_WORK).order_by(SHARED_EVIDENCE_WORK.c.shared_work_id)
            ).mappings()
            return [dict(row) for row in rows]

    def runtime_projection(self, job_id: str) -> dict[str, object]:
        with self.engine.connect() as connection:
            checkpoint = (
                connection.execute(
                    select(CHECKPOINTS)
                    .where(CHECKPOINTS.c.job_id == job_id)
                    .order_by(CHECKPOINTS.c.sequence.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
            active_leases = tuple(
                connection.execute(
                    select(LEASES).where(
                        LEASES.c.job_id == job_id,
                        LEASES.c.status == "active",
                    )
                ).mappings()
            )
            items = tuple(
                connection.execute(
                    select(WORK_ITEMS).where(WORK_ITEMS.c.job_id == job_id)
                ).mappings()
            )
            blockers: list[dict[str, object]] = []
            for item in items:
                if item["waiting_reason"] is not None:
                    blockers.append(
                        {
                            "kind": str(item["waiting_reason_kind"]),
                            "reason": str(item["waiting_reason"]),
                            "work_item_id": str(item["work_item_id"]),
                        }
                    )
                elif item["status"] == WorkItemStatus.WAITING_USER.value:
                    blockers.append(
                        {
                            "kind": "user",
                            "reason": str(item["review_reason"]),
                            "work_item_id": str(item["work_item_id"]),
                        }
                    )
            active_stages = sorted(
                {
                    str(item["current_stage"])
                    for item in items
                    if item["status"] == WorkItemStatus.RUNNING.value
                }
            )
            return {
                "active_stages": active_stages,
                "blockers": blockers,
                "checkpoint": (
                    None
                    if checkpoint is None
                    else {
                        "stage": str(checkpoint["stage"]),
                        "sequence": int(checkpoint["sequence"]),
                        "owner_kind": str(checkpoint["owner_kind"]),
                    }
                ),
                "leases": [
                    {
                        "lease_id": str(lease["lease_id"]),
                        "resource_name": str(lease["resource_name"]),
                        "holder_kind": str(lease["holder_kind"]),
                        "job_id": (None if lease["job_id"] is None else str(lease["job_id"])),
                        "work_item_id": (
                            None if lease["work_item_id"] is None else str(lease["work_item_id"])
                        ),
                    }
                    for lease in active_leases
                ],
            }

    def resources_projection(self) -> list[dict[str, object]]:
        with self.engine.connect() as connection:
            slots = tuple(
                connection.execute(
                    select(RESOURCE_SLOTS).order_by(RESOURCE_SLOTS.c.resource_name)
                ).mappings()
            )
            resources: list[dict[str, object]] = []
            for slot in slots:
                resource_name = str(slot["resource_name"])
                leases = tuple(
                    connection.execute(
                        select(LEASES).where(
                            LEASES.c.resource_name == resource_name,
                            LEASES.c.status == "active",
                        )
                    ).mappings()
                )
                waiting = tuple(
                    connection.execute(
                        select(
                            WORK_ITEMS.c.job_id,
                            WORK_ITEMS.c.work_item_id,
                            WORK_ITEMS.c.waiting_reason,
                        ).where(
                            WORK_ITEMS.c.status == WorkItemStatus.WAITING_RESOURCE.value,
                            WORK_ITEMS.c.waiting_reason == f"resource:{resource_name}",
                        )
                    ).mappings()
                )
                resources.append(
                    {
                        "resource_name": resource_name,
                        "capacity": int(slot["capacity"]),
                        "active_leases": [
                            {
                                "lease_id": str(lease["lease_id"]),
                                "holder_kind": str(lease["holder_kind"]),
                                "job_id": (
                                    None if lease["job_id"] is None else str(lease["job_id"])
                                ),
                                "work_item_id": (
                                    None
                                    if lease["work_item_id"] is None
                                    else str(lease["work_item_id"])
                                ),
                                "stage_attempt_id": str(lease["stage_attempt_id"]),
                            }
                            for lease in leases
                        ],
                        "queue": [
                            {
                                "job_id": str(wait["job_id"]),
                                "work_item_id": str(wait["work_item_id"]),
                                "reason": str(wait["waiting_reason"]),
                            }
                            for wait in waiting
                        ],
                        "grant_sequence": int(slot["grant_sequence"]),
                    }
                )
            return resources

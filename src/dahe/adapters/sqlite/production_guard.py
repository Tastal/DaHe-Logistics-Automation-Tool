from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.engine import Connection, Row

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    JOBS,
    PRODUCTION_READ_ONLY_GUARD,
    PRODUCTION_READ_ONLY_GUARD_ITEMS,
    WORK_ITEMS,
)

_WITH_GUARD = "operational_read_only_with_guard"
_ACCEPTED = "operational_read_only_accepted"
_ACTIVE = "operational_read_only_active"


class ProductionGuardConflictError(RuntimeError):
    """Raised when protected machine and manual evidence is inconsistent."""


@dataclass(frozen=True, slots=True)
class ProductionGuardStatus:
    status: str
    target_count: int
    registered_count: int
    reviewed_target_count: int
    false_normal_count: int
    record_version: int

    def to_payload(self) -> dict[str, object]:
        return {
            "false_normal_count": self.false_normal_count,
            "guard_active": self.status == _WITH_GUARD,
            "record_version": self.record_version,
            "registered_count": self.registered_count,
            "reviewed_count": self.reviewed_target_count,
            "status": self.status,
            "target_count": self.target_count,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _business_identity(waybill_number: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(waybill_number)).strip().upper()
    if not normalized:
        raise ProductionGuardConflictError("waybill identity is empty")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class ProductionReadOnlyGuardStore:
    """Persist the first 30 manual checks without creating user identities."""

    def __init__(
        self,
        runtime: SqliteRuntime,
        *,
        enforce_first_batch: bool = False,
    ) -> None:
        self._runtime = runtime
        self._initial_status = _WITH_GUARD if enforce_first_batch else _ACTIVE

    def status(self) -> ProductionGuardStatus:
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            row = self._ensure_state(connection)
            return self._status(row)

    def register_result(
        self,
        *,
        work_item_id: str,
        machine_outcome: str,
    ) -> bool:
        if machine_outcome not in {
            "normal_ready",
            "awaiting_review",
            "confirmed_problem",
            "technical_failure",
        }:
            raise ValueError("machine_outcome is invalid")
        if machine_outcome == "technical_failure":
            return False
        now = _now()
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            existing = connection.execute(
                select(PRODUCTION_READ_ONLY_GUARD_ITEMS).where(
                    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.work_item_id == work_item_id
                )
            ).one_or_none()
            if existing is not None:
                if existing.machine_outcome != machine_outcome:
                    raise ProductionGuardConflictError(
                        "machine outcome changed after guard registration"
                    )
                return bool(existing.protected) and not bool(existing.released)
            item = connection.execute(
                select(WORK_ITEMS, JOBS.c.run_mode)
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
            ).one_or_none()
            if item is None or item.run_mode != "operational":
                raise ProductionGuardConflictError(
                    "only operational audit items can enter the production guard"
                )
            state = self._ensure_state(connection)
            if state.status == _ACTIVE:
                return False
            business_identity = _business_identity(item.waybill_number)
            identity_exists = connection.execute(
                select(func.count())
                .select_from(PRODUCTION_READ_ONLY_GUARD_ITEMS)
                .where(
                    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.business_identity_sha256
                    == business_identity
                )
            ).scalar_one() > 0
            ordinal = int(
                connection.execute(
                    select(func.count()).select_from(
                        PRODUCTION_READ_ONLY_GUARD_ITEMS
                    )
                ).scalar_one()
            ) + 1
            target_count = int(
                connection.execute(
                    select(func.count())
                    .select_from(PRODUCTION_READ_ONLY_GUARD_ITEMS)
                    .where(
                        PRODUCTION_READ_ONLY_GUARD_ITEMS.c.counts_toward_gate
                        == 1
                    )
                ).scalar_one()
            )
            counts_toward_gate = (
                not identity_exists and target_count < int(state.target_count)
            )
            protected = (
                machine_outcome == "normal_ready" and state.status == _WITH_GUARD
            )
            connection.execute(
                PRODUCTION_READ_ONLY_GUARD_ITEMS.insert().values(
                    work_item_id=work_item_id,
                    ordinal=ordinal,
                    business_identity_sha256=business_identity,
                    counts_toward_gate=int(counts_toward_gate),
                    machine_outcome=machine_outcome,
                    manual_outcome=None,
                    manual_action_id=None,
                    protected=int(protected),
                    released=0,
                    registered_at=now,
                    reviewed_at=None,
                )
            )
            if protected:
                next_version = int(item.record_version) + 1
                connection.execute(
                    update(WORK_ITEMS)
                    .where(WORK_ITEMS.c.work_item_id == work_item_id)
                    .values(
                        record_version=next_version,
                        status="waiting_user",
                        current_stage="audit.compare",
                        business_outcome="awaiting_review",
                        decision="review",
                        review_reason="production_first_batch_guard",
                        waiting_reason_kind="user",
                        waiting_reason="production_first_batch_guard",
                    )
                )
                connection.execute(
                    update(JOBS)
                    .where(JOBS.c.job_id == item.job_id)
                    .values(
                        status="waiting_user",
                        current_stage="audit.compare",
                        record_version=JOBS.c.record_version + 1,
                        updated_at=now,
                    )
                )
            connection.execute(
                update(PRODUCTION_READ_ONLY_GUARD)
                .where(PRODUCTION_READ_ONLY_GUARD.c.guard_id == "primary")
                .values(
                    registered_count=(
                        int(state.registered_count) + (0 if identity_exists else 1)
                    ),
                    record_version=int(state.record_version) + 1,
                )
            )
            return protected

    def record_manual_decision(
        self,
        *,
        work_item_id: str,
        action_id: str,
        manual_outcome: str,
    ) -> ProductionGuardStatus:
        if manual_outcome not in {"normal_ready", "confirmed_problem"}:
            raise ValueError("manual_outcome is invalid")
        now = _now()
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            item = connection.execute(
                select(PRODUCTION_READ_ONLY_GUARD_ITEMS).where(
                    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.work_item_id == work_item_id
                )
            ).one_or_none()
            if item is None:
                return self._status(self._ensure_state(connection))
            target = connection.execute(
                select(PRODUCTION_READ_ONLY_GUARD_ITEMS).where(
                    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.business_identity_sha256
                    == item.business_identity_sha256,
                    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.counts_toward_gate == 1,
                )
            ).one_or_none()
            decision_row = target if target is not None else item
            if decision_row.manual_outcome is not None:
                if decision_row.manual_outcome != manual_outcome:
                    raise ProductionGuardConflictError(
                        "guarded manual decision already exists"
                    )
                return self._status(self._ensure_state(connection))
            connection.execute(
                update(PRODUCTION_READ_ONLY_GUARD_ITEMS)
                .where(
                    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.work_item_id
                    == decision_row.work_item_id
                )
                .values(
                    manual_outcome=manual_outcome,
                    manual_action_id=action_id,
                    reviewed_at=now,
                )
            )
            target_rows = tuple(
                connection.execute(
                    select(PRODUCTION_READ_ONLY_GUARD_ITEMS).where(
                        PRODUCTION_READ_ONLY_GUARD_ITEMS.c.counts_toward_gate == 1
                    )
                )
            )
            all_rows = tuple(
                connection.execute(select(PRODUCTION_READ_ONLY_GUARD_ITEMS))
            )
            normal_identities = {
                row.business_identity_sha256
                for row in all_rows
                if row.machine_outcome == "normal_ready"
            }
            reviewed = sum(row.manual_outcome is not None for row in target_rows)
            false_normals = sum(
                row.manual_outcome == "confirmed_problem"
                and row.business_identity_sha256 in normal_identities
                for row in target_rows
            )
            state = self._ensure_state(connection)
            accepted = reviewed == int(state.target_count) and false_normals == 0
            status = _ACCEPTED if accepted else _WITH_GUARD
            if accepted:
                overflow = tuple(
                    connection.execute(
                        select(PRODUCTION_READ_ONLY_GUARD_ITEMS.c.work_item_id).where(
                            PRODUCTION_READ_ONLY_GUARD_ITEMS.c.counts_toward_gate == 0,
                            PRODUCTION_READ_ONLY_GUARD_ITEMS.c.protected == 1,
                            PRODUCTION_READ_ONLY_GUARD_ITEMS.c.released == 0,
                            PRODUCTION_READ_ONLY_GUARD_ITEMS.c.manual_outcome.is_(None),
                        )
                    ).scalars()
                )
                if overflow:
                    connection.execute(
                        update(WORK_ITEMS)
                        .where(WORK_ITEMS.c.work_item_id.in_(overflow))
                        .values(
                            record_version=WORK_ITEMS.c.record_version + 1,
                            status="succeeded",
                            current_stage="audit.recheck",
                            business_outcome="normal_ready",
                            decision="pass",
                            review_reason=None,
                            waiting_reason_kind=None,
                            waiting_reason=None,
                        )
                    )
                    connection.execute(
                        update(PRODUCTION_READ_ONLY_GUARD_ITEMS)
                        .where(
                            PRODUCTION_READ_ONLY_GUARD_ITEMS.c.work_item_id.in_(
                                overflow
                            )
                        )
                        .values(released=1)
                    )
            connection.execute(
                update(PRODUCTION_READ_ONLY_GUARD)
                .where(PRODUCTION_READ_ONLY_GUARD.c.guard_id == "primary")
                .values(
                    status=status,
                    reviewed_target_count=reviewed,
                    false_normal_count=false_normals,
                    record_version=int(state.record_version) + 1,
                    resolved_at=now if accepted else None,
                )
            )
            current = connection.execute(
                select(PRODUCTION_READ_ONLY_GUARD).where(
                    PRODUCTION_READ_ONLY_GUARD.c.guard_id == "primary"
                )
            ).one()
            return self._status(current)

    def _ensure_state(self, connection: Connection) -> Row[Any]:
        row = connection.execute(
            select(PRODUCTION_READ_ONLY_GUARD).where(
                PRODUCTION_READ_ONLY_GUARD.c.guard_id == "primary"
            )
        ).one_or_none()
        if row is not None:
            return row
        now = _now()
        connection.execute(
            PRODUCTION_READ_ONLY_GUARD.insert().values(
                guard_id="primary",
                status=self._initial_status,
                target_count=30,
                registered_count=0,
                reviewed_target_count=0,
                false_normal_count=0,
                record_version=1,
                activated_at=now,
                resolved_at=None,
            )
        )
        return connection.execute(
            select(PRODUCTION_READ_ONLY_GUARD).where(
                PRODUCTION_READ_ONLY_GUARD.c.guard_id == "primary"
            )
        ).one()

    @staticmethod
    def _status(row: Row[Any]) -> ProductionGuardStatus:
        return ProductionGuardStatus(
            status=str(row.status),
            target_count=int(row.target_count),
            registered_count=int(row.registered_count),
            reviewed_target_count=int(row.reviewed_target_count),
            false_normal_count=int(row.false_normal_count),
            record_version=int(row.record_version),
        )

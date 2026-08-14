from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select, update

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_CAPTURE_INVOCATIONS,
    OPERATIONAL_CAPTURE_RUNS,
    PLATFORM_CONTRACT_SUBJECT_STATE,
    PLATFORM_JOB_SUBJECTS,
    SETTLEMENT_CAPTURE_INVOCATIONS,
)
from dahe.application.chengfeng.contract_subject import (
    CONTRACT_SUBJECTS,
    DEFAULT_CONTRACT_SUBJECT_CODE,
    require_contract_subject_code,
)
from dahe.ports.jobs import RecordVersionConflictError


@dataclass(frozen=True, slots=True)
class ContractSubjectState:
    current_subject_code: str
    record_version: int
    updated_at: str

    def to_payload(self) -> dict[str, object]:
        return {
            "available_subjects": [
                {"code": subject.code, "label": subject.label}
                for subject in CONTRACT_SUBJECTS
            ],
            "current_subject_code": self.current_subject_code,
            "record_version": self.record_version,
            "updated_at": self.updated_at,
        }


class SqliteContractSubjectStore:
    """Own the local subject selection and immutable platform-job binding."""

    def __init__(self, runtime: SqliteRuntime) -> None:
        self._runtime = runtime

    def initialize(self) -> ContractSubjectState:
        now = datetime.now(UTC).isoformat()
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            row = connection.execute(
                select(PLATFORM_CONTRACT_SUBJECT_STATE).where(
                    PLATFORM_CONTRACT_SUBJECT_STATE.c.state_id == "primary"
                )
            ).mappings().one_or_none()
            if row is None:
                connection.execute(
                    PLATFORM_CONTRACT_SUBJECT_STATE.insert().values(
                        state_id="primary",
                        current_subject_code=DEFAULT_CONTRACT_SUBJECT_CODE,
                        record_version=1,
                        updated_at=now,
                    )
                )
        return self.get()

    def get(self) -> ContractSubjectState:
        with self._runtime.engine.connect() as connection:
            row = connection.execute(
                select(PLATFORM_CONTRACT_SUBJECT_STATE).where(
                    PLATFORM_CONTRACT_SUBJECT_STATE.c.state_id == "primary"
                )
            ).mappings().one_or_none()
        if row is None:
            return self.initialize()
        return ContractSubjectState(
            current_subject_code=require_contract_subject_code(
                row["current_subject_code"]
            ),
            record_version=int(row["record_version"]),
            updated_at=str(row["updated_at"]),
        )

    def select(
        self,
        *,
        subject_code: str,
        expected_record_version: int,
    ) -> ContractSubjectState:
        selected = require_contract_subject_code(subject_code)
        now = datetime.now(UTC).isoformat()
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            row = connection.execute(
                select(PLATFORM_CONTRACT_SUBJECT_STATE).where(
                    PLATFORM_CONTRACT_SUBJECT_STATE.c.state_id == "primary"
                )
            ).mappings().one()
            current = ContractSubjectState(
                current_subject_code=require_contract_subject_code(
                    row["current_subject_code"]
                ),
                record_version=int(row["record_version"]),
                updated_at=str(row["updated_at"]),
            )
            if current.record_version != expected_record_version:
                raise RecordVersionConflictError("contract subject changed")
            if current.current_subject_code == selected:
                return current
            next_version = current.record_version + 1
            changed = connection.execute(
                update(PLATFORM_CONTRACT_SUBJECT_STATE)
                .where(
                    PLATFORM_CONTRACT_SUBJECT_STATE.c.state_id == "primary",
                    PLATFORM_CONTRACT_SUBJECT_STATE.c.record_version
                    == expected_record_version,
                )
                .values(
                    current_subject_code=selected,
                    record_version=next_version,
                    updated_at=now,
                )
            )
            if changed.rowcount != 1:
                raise RecordVersionConflictError("contract subject changed")
        return ContractSubjectState(
            current_subject_code=selected,
            record_version=next_version,
            updated_at=now,
        )

    def bind_job(self, *, job_id: str, subject_code: str) -> None:
        selected = require_contract_subject_code(subject_code)
        now = datetime.now(UTC).isoformat()
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            existing = connection.execute(
                select(PLATFORM_JOB_SUBJECTS.c.contract_subject_code).where(
                    PLATFORM_JOB_SUBJECTS.c.job_id == job_id
                )
            ).scalar_one_or_none()
            if existing is not None:
                if str(existing) != selected:
                    raise RecordVersionConflictError(
                        "platform job subject cannot be changed"
                    )
                return
            connection.execute(
                PLATFORM_JOB_SUBJECTS.insert().values(
                    job_id=job_id,
                    contract_subject_code=selected,
                    created_at=now,
                )
            )
            for table in (
                SETTLEMENT_CAPTURE_INVOCATIONS,
                DAILY_CAPTURE_INVOCATIONS,
                OPERATIONAL_CAPTURE_RUNS,
            ):
                connection.execute(
                    update(table)
                    .where(table.c.job_id == job_id)
                    .values(contract_subject_code=selected)
                )

    def subject_for_job(self, job_id: str) -> str:
        with self._runtime.engine.connect() as connection:
            value = connection.execute(
                select(PLATFORM_JOB_SUBJECTS.c.contract_subject_code).where(
                    PLATFORM_JOB_SUBJECTS.c.job_id == job_id
                )
            ).scalar_one_or_none()
        if value is None:
            return DEFAULT_CONTRACT_SUBJECT_CODE
        return require_contract_subject_code(value)

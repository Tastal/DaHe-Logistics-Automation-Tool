from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise

from sqlalchemy import select, text, update
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_CAPTURE_INVOCATIONS,
    DAILY_CAPTURE_START_REQUESTS,
    JOBS,
    OUTBOX,
    PLATFORM_ACCESS_EVENTS,
    PLATFORM_ACCESS_WINDOWS,
    PLATFORM_CONTROL_IDEMPOTENCY,
    PLATFORM_JOB_SUBJECTS,
    WORK_ITEMS,
)
from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureError,
    DailyCaptureRequest,
    DailyCaptureStage,
)
from dahe.ports.jobs import IdempotencyConflictError

_DIAGNOSTIC = re.compile(r"^[A-Z0-9][A-Z0-9_-]{0,99}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DAILY_ACCESS_PURPOSE = "production_shadow"


class DailyInvocationConflictError(RuntimeError):
    """Raised when a daily invocation cannot be replayed or advanced safely."""


@dataclass(frozen=True, slots=True)
class DailyInvocationAuthority:
    source_build_sha256: str
    daily_contract_sha256: str
    daily_contract_file_sha256: str
    daily_contract_selection_sha256: str
    settlement_contract_sha256: str
    settlement_contract_selection_sha256: str

    def __post_init__(self) -> None:
        if any(
            _SHA256.fullmatch(value) is None
            for value in self.to_payload().values()
        ):
            raise DailyInvocationConflictError(
                "daily invocation authority is invalid"
            )

    def to_payload(self) -> dict[str, str]:
        return {
            "daily_contract_file_sha256": (
                self.daily_contract_file_sha256
            ),
            "daily_contract_selection_sha256": (
                self.daily_contract_selection_sha256
            ),
            "daily_contract_sha256": self.daily_contract_sha256,
            "settlement_contract_selection_sha256": (
                self.settlement_contract_selection_sha256
            ),
            "settlement_contract_sha256": (
                self.settlement_contract_sha256
            ),
            "source_build_sha256": self.source_build_sha256,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(
            _canonical(self.to_payload()).encode("utf-8")
        ).hexdigest()

    @classmethod
    def from_payload(cls, payload: object) -> DailyInvocationAuthority:
        keys = {
            "daily_contract_file_sha256",
            "daily_contract_selection_sha256",
            "daily_contract_sha256",
            "settlement_contract_selection_sha256",
            "settlement_contract_sha256",
            "source_build_sha256",
        }
        if (
            not isinstance(payload, dict)
            or set(payload) != keys
            or any(type(payload[key]) is not str for key in keys)
        ):
            raise DailyInvocationConflictError(
                "stored daily invocation authority is invalid"
            )
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class DailyAccessWindowLineage:
    job_id: str
    session_id: str
    authority_sha256: str
    access_window_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DailyAccessRolloverRecord:
    invocation: DailyInvocationRecord
    old_access_window_id: str
    new_access_window_id: str
    idempotent_replay: bool


@dataclass(frozen=True, slots=True)
class DailyInvocationRecord:
    invocation_id: str
    job_id: str
    access_window_id: str
    authority: DailyInvocationAuthority | None
    request: DailyCaptureRequest
    checkpoint: DailyCaptureCheckpoint | None
    next_stage: DailyCaptureStage | None
    status: str
    diagnostic_code: str | None
    record_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class DailyCaptureStartRecord:
    idempotency_key: str
    request_hash: str
    job_id: str
    access_window_id: str
    status: str
    invocation_id: str | None
    record_version: int
    created_at: datetime
    updated_at: datetime


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DailyInvocationConflictError(
            "daily invocation timestamp must be timezone-aware"
        )
    return value.astimezone(UTC).isoformat()


def _parse_time(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise DailyInvocationConflictError(
            "stored daily invocation timestamp is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DailyInvocationConflictError(
            "stored daily invocation timestamp is invalid"
        )
    return parsed.astimezone(UTC)


def _record(row: RowMapping) -> DailyInvocationRecord:
    try:
        request = DailyCaptureRequest.from_payload(
            json.loads(str(row["request_json"]))
        )
        checkpoint = (
            None
            if row["checkpoint_json"] is None
            else DailyCaptureCheckpoint.from_payload(
                json.loads(str(row["checkpoint_json"]))
            )
        )
        authority = (
            None
            if row["authority_json"] is None
            else DailyInvocationAuthority.from_payload(
                json.loads(str(row["authority_json"]))
            )
        )
    except (DailyCaptureError, TypeError, ValueError) as exc:
        raise DailyInvocationConflictError(
            "stored daily invocation content is invalid"
        ) from exc
    if (
        request.invocation_id != str(row["invocation_id"])
        or request.fingerprint != str(row["request_fingerprint"])
        or (
            checkpoint is not None
            and (
                checkpoint.invocation_id != request.invocation_id
                or checkpoint.invocation_fingerprint
                != request.fingerprint
            )
        )
    ):
        raise DailyInvocationConflictError(
            "stored daily invocation identity is invalid"
        )
    raw_stage = str(row["next_stage"])
    if raw_stage == "daily.complete":
        next_stage = None
    else:
        try:
            next_stage = DailyCaptureStage(raw_stage)
        except ValueError as exc:
            raise DailyInvocationConflictError(
                "stored daily invocation stage is invalid"
            ) from exc
    status = str(row["status"])
    if (
        status not in {"ready", "running", "succeeded", "failed"}
        or (status == "succeeded" and next_stage is not None)
        or (status != "succeeded" and next_stage is None)
    ):
        raise DailyInvocationConflictError(
            "stored daily invocation status is invalid"
        )
    return DailyInvocationRecord(
        invocation_id=request.invocation_id,
        job_id=str(row["job_id"]),
        access_window_id=str(row["access_window_id"]),
        authority=authority,
        request=request,
        checkpoint=checkpoint,
        next_stage=next_stage,
        status=status,
        diagnostic_code=(
            None
            if row["diagnostic_code"] is None
            else str(row["diagnostic_code"])
        ),
        record_version=int(row["record_version"]),
        created_at=_parse_time(row["created_at"]),
        updated_at=_parse_time(row["updated_at"]),
    )


def _start_record(row: RowMapping) -> DailyCaptureStartRecord:
    status = str(row["status"])
    invocation_id = (
        None
        if row["invocation_id"] is None
        else str(row["invocation_id"])
    )
    if (
        status not in {"reserved", "completed"}
        or (status == "reserved" and invocation_id is not None)
        or (status == "completed" and invocation_id is None)
    ):
        raise DailyInvocationConflictError(
            "stored daily capture start request is invalid"
        )
    return DailyCaptureStartRecord(
        idempotency_key=str(row["idempotency_key"]),
        request_hash=str(row["request_hash"]),
        job_id=str(row["job_id"]),
        access_window_id=str(row["access_window_id"]),
        status=status,
        invocation_id=invocation_id,
        record_version=int(row["record_version"]),
        created_at=_parse_time(row["created_at"]),
        updated_at=_parse_time(row["updated_at"]),
    )


def _require_access_binding(
    connection: Connection,
    *,
    access_window_id: str,
    job_id: str,
) -> None:
    binding = (
        connection.execute(
            select(
                PLATFORM_ACCESS_WINDOWS.c.job_id,
                PLATFORM_ACCESS_WINDOWS.c.purpose,
            ).where(
                PLATFORM_ACCESS_WINDOWS.c.access_window_id
                == access_window_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        binding is None
        or str(binding["job_id"]) != job_id
        or str(binding["purpose"]) != _DAILY_ACCESS_PURPOSE
    ):
        raise DailyInvocationConflictError(
            "daily access window does not match the job"
        )


class SqliteDailyInvocationStore:
    """Persist restartable daily capture inputs and atomic checkpoints."""

    def __init__(self, runtime: SqliteRuntime) -> None:
        self._engine = runtime.engine
        self._commit_gate = runtime.commit_gate

    def get_start(
        self,
        idempotency_key: str,
    ) -> DailyCaptureStartRecord | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(DAILY_CAPTURE_START_REQUESTS).where(
                        DAILY_CAPTURE_START_REQUESTS.c.idempotency_key
                        == idempotency_key
                    )
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _start_record(row)

    def job_run_mode(self, job_id: str) -> str:
        with self._engine.connect() as connection:
            run_mode = connection.execute(
                select(JOBS.c.run_mode).where(JOBS.c.job_id == job_id)
            ).scalar_one_or_none()
        if run_mode not in {"operational", "shadow"}:
            raise DailyInvocationConflictError(
                "daily job run mode is unavailable"
            )
        return str(run_mode)

    def capture_strategy(self, job_id: str) -> str:
        with self._engine.connect() as connection:
            fixture_id = connection.execute(
                select(JOBS.c.scope_fixture_id).where(
                    JOBS.c.job_id == job_id
                )
            ).scalar_one_or_none()
        if fixture_id is None:
            raise DailyInvocationConflictError(
                "daily invocation job is unavailable"
            )
        return (
            "whole_run_v1"
            if str(fixture_id).startswith("daily-operational-whole-run-v1:")
            else
            "batch_v1"
            if str(fixture_id).startswith(
                (
                    "daily-operational-batch-v1:",
                    "daily-operational-network-only-v1:",
                )
            )
            else "legacy"
        )

    def is_network_only_measurement(self, job_id: str) -> bool:
        with self._engine.connect() as connection:
            fixture_id = connection.execute(
                select(JOBS.c.scope_fixture_id).where(
                    JOBS.c.job_id == job_id
                )
            ).scalar_one_or_none()
        if fixture_id is None:
            raise DailyInvocationConflictError(
                "daily invocation job is unavailable"
            )
        return str(fixture_id).startswith(
            "daily-operational-network-only-v1:"
        )

    def reserve_start(
        self,
        *,
        idempotency_key: str,
        request_hash: str,
        job_id: str,
        access_window_id: str,
        now: datetime | None = None,
    ) -> tuple[DailyCaptureStartRecord, bool]:
        if (
            type(idempotency_key) is not str
            or not idempotency_key
            or len(idempotency_key) > 200
            or type(request_hash) is not str
            or len(request_hash) != 64
            or type(job_id) is not str
            or not job_id
            or len(job_id) > 32
            or type(access_window_id) is not str
            or not access_window_id
            or len(access_window_id) > 32
        ):
            raise DailyInvocationConflictError(
                "daily capture start identity is invalid"
            )
        instant = datetime.now(UTC) if now is None else now
        timestamp = _timestamp(instant)
        try:
            with self._commit_gate.transaction(self._engine) as connection:
                _require_access_binding(
                    connection,
                    access_window_id=access_window_id,
                    job_id=job_id,
                )
                replay = (
                    connection.execute(
                        select(DAILY_CAPTURE_START_REQUESTS).where(
                            DAILY_CAPTURE_START_REQUESTS.c.idempotency_key
                            == idempotency_key
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replay is not None:
                    record = _start_record(replay)
                    if (
                        record.request_hash != request_hash
                        or record.job_id != job_id
                        or record.access_window_id != access_window_id
                    ):
                        raise DailyInvocationConflictError(
                            "idempotency key belongs to a different daily capture"
                        )
                    return record, True
                job = (
                    connection.execute(
                        select(JOBS.c.task_type).where(
                            JOBS.c.job_id == job_id
                        )
                    ).scalar_one_or_none()
                )
                if job != "daily":
                    raise DailyInvocationConflictError(
                        "daily capture start job is unavailable"
                    )
                connection.execute(
                    DAILY_CAPTURE_START_REQUESTS.insert().values(
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        job_id=job_id,
                        access_window_id=access_window_id,
                        status="reserved",
                        invocation_id=None,
                        record_version=1,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                row = (
                    connection.execute(
                        select(DAILY_CAPTURE_START_REQUESTS).where(
                            DAILY_CAPTURE_START_REQUESTS.c.idempotency_key
                            == idempotency_key
                        )
                    )
                    .mappings()
                    .one()
                )
                return _start_record(row), False
        except IntegrityError as exc:
            raise DailyInvocationConflictError(
                "daily capture job already has a start request"
            ) from exc

    def complete_start(
        self,
        *,
        idempotency_key: str,
        expected_record_version: int,
        invocation_id: str,
        now: datetime | None = None,
    ) -> DailyCaptureStartRecord:
        instant = datetime.now(UTC) if now is None else now
        with self._commit_gate.transaction(self._engine) as connection:
            row = (
                connection.execute(
                    select(DAILY_CAPTURE_START_REQUESTS).where(
                        DAILY_CAPTURE_START_REQUESTS.c.idempotency_key
                        == idempotency_key
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise DailyInvocationConflictError(
                    "daily capture start request does not exist"
                )
            current = _start_record(row)
            if current.record_version != expected_record_version:
                raise DailyInvocationConflictError(
                    "daily capture start request version changed"
                )
            if current.status == "completed":
                if current.invocation_id != invocation_id:
                    raise DailyInvocationConflictError(
                        "daily capture start invocation changed"
                    )
                return current
            invocation = (
                connection.execute(
                    select(
                        DAILY_CAPTURE_INVOCATIONS.c.invocation_id,
                        DAILY_CAPTURE_INVOCATIONS.c.job_id,
                        DAILY_CAPTURE_INVOCATIONS.c.access_window_id,
                    ).where(
                        DAILY_CAPTURE_INVOCATIONS.c.invocation_id
                        == invocation_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                invocation is None
                or str(invocation["job_id"]) != current.job_id
                or str(invocation["access_window_id"])
                != current.access_window_id
            ):
                raise DailyInvocationConflictError(
                    "daily capture invocation does not match start request"
                )
            result = connection.execute(
                update(DAILY_CAPTURE_START_REQUESTS)
                .where(
                    DAILY_CAPTURE_START_REQUESTS.c.idempotency_key
                    == idempotency_key,
                    DAILY_CAPTURE_START_REQUESTS.c.record_version
                    == expected_record_version,
                )
                .values(
                    status="completed",
                    invocation_id=invocation_id,
                    record_version=expected_record_version + 1,
                    updated_at=_timestamp(instant),
                )
            )
            if result.rowcount != 1:
                raise DailyInvocationConflictError(
                    "daily capture start request version changed"
                )
            updated = (
                connection.execute(
                    select(DAILY_CAPTURE_START_REQUESTS).where(
                        DAILY_CAPTURE_START_REQUESTS.c.idempotency_key
                        == idempotency_key
                    )
                )
                .mappings()
                .one()
            )
            return _start_record(updated)

    def create(
        self,
        *,
        job_id: str,
        access_window_id: str,
        request: DailyCaptureRequest,
        authority: DailyInvocationAuthority | None = None,
        now: datetime | None = None,
    ) -> DailyInvocationRecord:
        if (
            type(job_id) is not str
            or not job_id
            or len(job_id) > 32
            or type(access_window_id) is not str
            or not access_window_id
            or len(access_window_id) > 32
        ):
            raise DailyInvocationConflictError(
                "daily invocation binding is invalid"
            )
        instant = datetime.now(UTC) if now is None else now
        timestamp = _timestamp(instant)
        with self._commit_gate.transaction(self._engine) as connection:
            job = (
                connection.execute(
                    select(JOBS.c.task_type).where(JOBS.c.job_id == job_id)
                ).scalar_one_or_none()
            )
            if job != "daily":
                raise DailyInvocationConflictError(
                    "daily invocation job is unavailable"
                )
            _require_access_binding(
                connection,
                access_window_id=access_window_id,
                job_id=job_id,
            )
            existing = (
                connection.execute(
                    select(DAILY_CAPTURE_INVOCATIONS).where(
                        (
                            DAILY_CAPTURE_INVOCATIONS.c.invocation_id
                            == request.invocation_id
                        )
                        | (DAILY_CAPTURE_INVOCATIONS.c.job_id == job_id)
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                stored = _record(existing)
                if (
                    stored.job_id != job_id
                    or stored.access_window_id != access_window_id
                    or stored.request.fingerprint != request.fingerprint
                    or stored.authority != authority
                ):
                    raise DailyInvocationConflictError(
                        "daily invocation identity has different content"
                    )
                return stored
            subject_code = connection.execute(
                select(PLATFORM_JOB_SUBJECTS.c.contract_subject_code).where(
                    PLATFORM_JOB_SUBJECTS.c.job_id == job_id
                )
            ).scalar_one_or_none()
            if subject_code is None:
                subject_code = "shanxi_guienbo"
            connection.execute(
                DAILY_CAPTURE_INVOCATIONS.insert().values(
                    invocation_id=request.invocation_id,
                    job_id=job_id,
                    contract_subject_code=str(subject_code),
                    access_window_id=access_window_id,
                    request_fingerprint=request.fingerprint,
                    request_json=_canonical(request.to_payload()),
                    authority_json=(
                        None
                        if authority is None
                        else _canonical(authority.to_payload())
                    ),
                    checkpoint_json=None,
                    next_stage=DailyCaptureStage.LIST_PAGE.value,
                    status="ready",
                    diagnostic_code=None,
                    record_version=1,
                    created_at=timestamp,
                    updated_at=timestamp,
                )
            )
            return self._get(connection, job_id)

    def get_by_job(self, job_id: str) -> DailyInvocationRecord:
        with self._engine.connect() as connection:
            return self._get(connection, job_id)

    @staticmethod
    def _access_window_lineage(
        connection: Connection,
        invocation: DailyInvocationRecord,
    ) -> DailyAccessWindowLineage:
        if invocation.authority is None:
            raise DailyInvocationConflictError(
                "legacy daily invocation cannot roll over access"
            )
        rows = tuple(
            connection.execute(
                select(OUTBOX)
                .where(
                    OUTBOX.c.aggregate_type == "daily_capture",
                    OUTBOX.c.aggregate_id == invocation.job_id,
                    OUTBOX.c.event_type
                    == "daily_capture.access_window_rebound",
                )
                .order_by(OUTBOX.c.event_id)
            ).mappings()
        )
        access_ids: list[str] = []
        previous_version: int | None = None
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise DailyInvocationConflictError(
                    "daily access lineage is invalid"
                ) from exc
            required = {
                "authority_sha256",
                "job_id",
                "new_access_window_id",
                "new_invocation_record_version",
                "old_access_window_id",
                "previous_invocation_record_version",
                "session_id",
            }
            if (
                not isinstance(payload, dict)
                or set(payload) != required
                or payload["authority_sha256"]
                != invocation.authority.sha256
                or payload["job_id"] != invocation.job_id
                or type(payload["old_access_window_id"]) is not str
                or type(payload["new_access_window_id"]) is not str
                or type(payload["session_id"]) is not str
                or type(payload["previous_invocation_record_version"])
                is not int
                or type(payload["new_invocation_record_version"]) is not int
                or payload["new_invocation_record_version"]
                != int(row["record_version"])
                or payload["new_invocation_record_version"]
                != payload["previous_invocation_record_version"] + 1
                or (
                    previous_version is not None
                    and payload["previous_invocation_record_version"]
                    < previous_version
                )
            ):
                raise DailyInvocationConflictError(
                    "daily access lineage is not append-only"
                )
            old_id = payload["old_access_window_id"]
            new_id = payload["new_access_window_id"]
            if not access_ids:
                access_ids.append(old_id)
            if access_ids[-1] != old_id or new_id in access_ids:
                raise DailyInvocationConflictError(
                    "daily access lineage is not append-only"
                )
            access_ids.append(new_id)
            previous_version = payload[
                "new_invocation_record_version"
            ]
        if not access_ids:
            access_ids = [invocation.access_window_id]
        if access_ids[-1] != invocation.access_window_id:
            raise DailyInvocationConflictError(
                "daily access lineage was superseded"
            )
        access_rows = tuple(
            connection.execute(
                select(PLATFORM_ACCESS_WINDOWS).where(
                    PLATFORM_ACCESS_WINDOWS.c.access_window_id.in_(
                        tuple(access_ids)
                    )
                )
            ).mappings()
        )
        by_id = {
            str(row["access_window_id"]): row for row in access_rows
        }
        if set(by_id) != set(access_ids):
            raise DailyInvocationConflictError(
                "daily access lineage is unavailable"
            )
        ordered = tuple(by_id[access_id] for access_id in access_ids)
        first = ordered[0]
        session_id = str(first["session_id"])
        if (
            str(first["purpose"]) != _DAILY_ACCESS_PURPOSE
            or str(first["build_sha256"])
            != invocation.authority.source_build_sha256
            or any(
                str(row["job_id"]) != invocation.job_id
                or str(row["session_id"]) != session_id
                or str(row["purpose"]) != _DAILY_ACCESS_PURPOSE
                or str(row["build_sha256"])
                != invocation.authority.source_build_sha256
                for row in ordered
            )
            or any(
                _parse_time(left["issued_at"])
                >= _parse_time(right["issued_at"])
                for left, right in pairwise(ordered)
            )
        ):
            raise DailyInvocationConflictError(
                "daily access lineage authority changed"
            )
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            assert isinstance(payload, dict)
            if payload["session_id"] != session_id:
                raise DailyInvocationConflictError(
                    "daily access lineage session changed"
                )
        return DailyAccessWindowLineage(
            job_id=invocation.job_id,
            session_id=session_id,
            authority_sha256=invocation.authority.sha256,
            access_window_ids=tuple(access_ids),
        )

    def access_window_lineage(
        self,
        job_id: str,
    ) -> DailyAccessWindowLineage:
        with self._engine.connect() as connection:
            invocation = self._get(connection, job_id)
            return self._access_window_lineage(
                connection,
                invocation,
            )

    def rebind_access_window(
        self,
        *,
        job_id: str,
        new_access_window_id: str,
        expected_invocation_record_version: int,
        expected_browser_record_version: int,
        session_id: str,
        authority: DailyInvocationAuthority,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> DailyAccessRolloverRecord:
        """Replace an expired window while preserving the paused invocation."""

        if (
            not isinstance(job_id, str)
            or not job_id
            or len(job_id) > 32
            or not isinstance(new_access_window_id, str)
            or not new_access_window_id
            or len(new_access_window_id) > 32
            or not isinstance(session_id, str)
            or not session_id
            or len(session_id) > 100
            or type(expected_invocation_record_version) is not int
            or expected_invocation_record_version < 1
            or type(expected_browser_record_version) is not int
            or expected_browser_record_version < 1
            or not isinstance(idempotency_key, str)
            or not idempotency_key
            or len(idempotency_key) > 200
            or _SHA256.fullmatch(request_hash) is None
            or not isinstance(authority, DailyInvocationAuthority)
        ):
            raise DailyInvocationConflictError(
                "daily access rollover identity is invalid"
            )
        instant = now.astimezone(UTC)
        timestamp = _timestamp(instant)
        operation = "daily_capture_access_window_rebind"
        try:
            with self._commit_gate.transaction(
                self._engine
            ) as connection:
                replay = (
                    connection.execute(
                        select(PLATFORM_CONTROL_IDEMPOTENCY).where(
                            PLATFORM_CONTROL_IDEMPOTENCY.c.operation
                            == operation,
                            PLATFORM_CONTROL_IDEMPOTENCY.c.idempotency_key
                            == idempotency_key,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replay is not None:
                    if (
                        str(replay["request_hash"]) != request_hash
                        or str(replay["session_id"]) != session_id
                        or str(replay["access_window_id"])
                        != new_access_window_id
                    ):
                        raise IdempotencyConflictError(
                            "the idempotency key belongs to a different request"
                        )
                    current = self._get(connection, job_id)
                    lineage = self._access_window_lineage(
                        connection,
                        current,
                    )
                    if (
                        current.authority != authority
                        or current.access_window_id
                        != new_access_window_id
                        or current.record_version
                        != int(replay["result_record_version"])
                        or len(lineage.access_window_ids) < 2
                    ):
                        raise DailyInvocationConflictError(
                            "daily access rollover replay was superseded"
                        )
                    return DailyAccessRolloverRecord(
                        invocation=current,
                        old_access_window_id=(
                            lineage.access_window_ids[-2]
                        ),
                        new_access_window_id=new_access_window_id,
                        idempotent_replay=True,
                    )

                invocation = self._get(connection, job_id)
                if (
                    invocation.authority != authority
                    or invocation.status not in {"ready", "running"}
                    or invocation.record_version
                    != expected_invocation_record_version
                ):
                    raise DailyInvocationConflictError(
                        "daily rollover authority changed"
                    )
                lineage = self._access_window_lineage(
                    connection,
                    invocation,
                )
                read_windows: set[str] = set()
                if invocation.checkpoint is not None:
                    read_windows.update(
                        invocation.checkpoint.list_read_access_window_ids
                    )
                    for capture in (
                        *invocation.checkpoint.completed_detail_captures,
                        invocation.checkpoint.pending_detail_capture,
                        invocation.checkpoint.pending_observation_capture,
                    ):
                        if capture is None:
                            continue
                        read_windows.update(
                            capture.detail_read_access_window_ids
                        )
                        read_windows.update(
                            dict(
                                capture.image_read_access_window_ids
                            ).values()
                        )
                if not read_windows.issubset(
                    set(lineage.access_window_ids)
                ):
                    raise DailyInvocationConflictError(
                        "daily checkpoint references another access lineage"
                    )
                job = (
                    connection.execute(
                        select(JOBS).where(JOBS.c.job_id == job_id)
                    )
                    .mappings()
                    .one_or_none()
                )
                items = tuple(
                    connection.execute(
                        select(WORK_ITEMS).where(
                            WORK_ITEMS.c.job_id == job_id
                        )
                    ).mappings()
                )
                if (
                    job is None
                    or str(job["status"]) != "paused"
                    or len(items) != 1
                    or str(items[0]["status"])
                    != "waiting_external"
                    or str(items[0]["current_stage"])
                    != (
                        invocation.next_stage.value
                        if invocation.next_stage is not None
                        else ""
                    )
                    or items[0]["business_outcome"] is not None
                    or items[0]["review_reason"] is not None
                ):
                    raise DailyInvocationConflictError(
                        "daily capture must be paused on an external wait"
                    )
                old = (
                    connection.execute(
                        select(PLATFORM_ACCESS_WINDOWS).where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == invocation.access_window_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                replacement = (
                    connection.execute(
                        select(PLATFORM_ACCESS_WINDOWS).where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == new_access_window_id
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if old is None or replacement is None:
                    raise DailyInvocationConflictError(
                        "daily access rollover window is unavailable"
                    )
                old_expired = _parse_time(old["expires_at"]) <= instant
                if old["consumed_at"] is None and not old_expired:
                    raise DailyInvocationConflictError(
                        "prior daily access window is still active"
                    )
                if (
                    new_access_window_id
                    == invocation.access_window_id
                    or any(
                        str(row["job_id"]) != job_id
                        or str(row["session_id"]) != session_id
                        or str(row["purpose"])
                        != _DAILY_ACCESS_PURPOSE
                        or str(row["build_sha256"])
                        != authority.source_build_sha256
                        for row in (old, replacement)
                    )
                    or replacement["consumed_at"] is not None
                    or _parse_time(replacement["expires_at"])
                    <= instant
                    or _parse_time(replacement["issued_at"])
                    <= _parse_time(old["issued_at"])
                ):
                    raise DailyInvocationConflictError(
                        "replacement daily access authority is invalid"
                    )
                browser = (
                    connection.execute(
                        text(
                            """
                            SELECT * FROM browser_control_sessions
                            WHERE session_id = :session_id
                            """
                        ),
                        {"session_id": session_id},
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    browser is None
                    or int(browser["record_version"])
                    != expected_browser_record_version
                    or str(browser["browser_control_mode"]) != "idle"
                    or str(browser["browser_lifecycle"])
                    not in {"ready", "stopped"}
                    or any(
                        browser[field] is not None
                        for field in (
                            "holder_kind",
                            "holder_id",
                            "instance_id",
                            "worker_id",
                            "job_id",
                            "fencing_token",
                        )
                    )
                ):
                    raise DailyInvocationConflictError(
                        "browser must be idle before daily access rollover"
                    )

                next_browser_epoch = int(browser["control_epoch"]) + 1
                browser_update = connection.execute(
                    text(
                        """
                        UPDATE browser_control_sessions
                        SET control_epoch = :control_epoch,
                            record_version = :record_version,
                            updated_at = :updated_at
                        WHERE session_id = :session_id
                          AND record_version = :expected_record_version
                          AND browser_control_mode = 'idle'
                          AND browser_lifecycle IN ('ready', 'stopped')
                          AND holder_kind IS NULL
                          AND holder_id IS NULL
                          AND instance_id IS NULL
                          AND worker_id IS NULL
                          AND job_id IS NULL
                          AND fencing_token IS NULL
                        """
                    ),
                    {
                        "control_epoch": next_browser_epoch,
                        "record_version": (
                            expected_browser_record_version + 1
                        ),
                        "updated_at": timestamp,
                        "session_id": session_id,
                        "expected_record_version": (
                            expected_browser_record_version
                        ),
                    },
                )
                if browser_update.rowcount != 1:
                    raise DailyInvocationConflictError(
                        "browser changed during daily access rollover"
                    )
                connection.execute(
                    text(
                        """
                        INSERT INTO browser_control_events (
                            session_id, event_type, control_epoch,
                            payload_json, created_at
                        ) VALUES (
                            :session_id, :event_type, :control_epoch,
                            :payload_json, :created_at
                        )
                        """
                    ),
                    {
                        "session_id": session_id,
                        "event_type": (
                            "browser.access_window_rebound"
                        ),
                        "control_epoch": next_browser_epoch,
                        "payload_json": _canonical(
                            {
                                "authority_sha256": authority.sha256,
                                "new_access_window_id": (
                                    new_access_window_id
                                ),
                                "old_access_window_id": (
                                    invocation.access_window_id
                                ),
                            }
                        ),
                        "created_at": timestamp,
                    },
                )
                if old["consumed_at"] is None:
                    old_version = int(old["record_version"])
                    retired = connection.execute(
                        update(PLATFORM_ACCESS_WINDOWS)
                        .where(
                            PLATFORM_ACCESS_WINDOWS.c.access_window_id
                            == invocation.access_window_id,
                            PLATFORM_ACCESS_WINDOWS.c.record_version
                            == old_version,
                            PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                        )
                        .values(
                            consumed_at=timestamp,
                            record_version=old_version + 1,
                            updated_at=timestamp,
                        )
                    )
                    if retired.rowcount != 1:
                        raise DailyInvocationConflictError(
                            "prior daily access changed concurrently"
                        )
                    connection.execute(
                        PLATFORM_ACCESS_EVENTS.insert().values(
                            access_window_id=(
                                invocation.access_window_id
                            ),
                            event_type="consumed",
                            record_version=old_version + 1,
                            created_at=timestamp,
                        )
                    )
                next_version = invocation.record_version + 1
                rebound = connection.execute(
                    update(DAILY_CAPTURE_INVOCATIONS)
                    .where(
                        DAILY_CAPTURE_INVOCATIONS.c.invocation_id
                        == invocation.invocation_id,
                        DAILY_CAPTURE_INVOCATIONS.c.record_version
                        == expected_invocation_record_version,
                        DAILY_CAPTURE_INVOCATIONS.c.access_window_id
                        == invocation.access_window_id,
                    )
                    .values(
                        access_window_id=new_access_window_id,
                        record_version=next_version,
                        updated_at=timestamp,
                    )
                )
                if rebound.rowcount != 1:
                    raise DailyInvocationConflictError(
                        "daily access rollover changed concurrently"
                    )
                event_payload = {
                    "authority_sha256": authority.sha256,
                    "job_id": job_id,
                    "new_access_window_id": new_access_window_id,
                    "new_invocation_record_version": next_version,
                    "old_access_window_id": (
                        invocation.access_window_id
                    ),
                    "previous_invocation_record_version": (
                        invocation.record_version
                    ),
                    "session_id": session_id,
                }
                connection.execute(
                    PLATFORM_CONTROL_IDEMPOTENCY.insert().values(
                        operation=operation,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        session_id=session_id,
                        access_window_id=new_access_window_id,
                        result_record_version=next_version,
                        created_at=timestamp,
                    )
                )
                connection.execute(
                    OUTBOX.insert().values(
                        event_type=(
                            "daily_capture.access_window_rebound"
                        ),
                        aggregate_type="daily_capture",
                        aggregate_id=job_id,
                        record_version=next_version,
                        payload_json=_canonical(event_payload),
                        created_at=timestamp,
                    )
                )
                updated = self._get(connection, job_id)
                return DailyAccessRolloverRecord(
                    invocation=updated,
                    old_access_window_id=(
                        invocation.access_window_id
                    ),
                    new_access_window_id=new_access_window_id,
                    idempotent_replay=False,
                )
        except IntegrityError as exc:
            raise DailyInvocationConflictError(
                "daily access rollover changed concurrently"
            ) from exc

    def cleanup_candidates(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[DailyInvocationRecord, ...]:
        instant = datetime.now(UTC) if now is None else now
        _timestamp(instant)
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    select(
                        DAILY_CAPTURE_INVOCATIONS,
                        JOBS.c.status.label("job_status"),
                        PLATFORM_ACCESS_WINDOWS.c.expires_at.label(
                            "access_expires_at"
                        ),
                        PLATFORM_ACCESS_WINDOWS.c.consumed_at.label(
                            "access_consumed_at"
                        ),
                    )
                    .join(
                        JOBS,
                        JOBS.c.job_id
                        == DAILY_CAPTURE_INVOCATIONS.c.job_id,
                    )
                    .join(
                        PLATFORM_ACCESS_WINDOWS,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == DAILY_CAPTURE_INVOCATIONS.c.access_window_id,
                    )
                    .order_by(
                        DAILY_CAPTURE_INVOCATIONS.c.created_at,
                        DAILY_CAPTURE_INVOCATIONS.c.job_id,
                    )
                )
                .mappings()
                .all()
            )
        candidates: list[DailyInvocationRecord] = []
        for row in rows:
            invocation = _record(row)
            expires_at = _parse_time(row["access_expires_at"])
            if (
                invocation.status in {"succeeded", "failed"}
                or str(row["job_status"])
                in {"cancelled", "succeeded", "failed"}
                or row["access_consumed_at"] is not None
                or expires_at <= instant.astimezone(UTC)
            ):
                candidates.append(invocation)
        return tuple(candidates)

    def is_cleanup_candidate(
        self,
        job_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        return any(
            record.job_id == job_id
            for record in self.cleanup_candidates(now=now)
        )

    def orphaned_start_job_ids(self) -> tuple[str, ...]:
        """Return persisted starts that have no corresponding invocation."""

        with self._engine.connect() as connection:
            job_ids = tuple(
                connection.execute(
                    select(DAILY_CAPTURE_START_REQUESTS.c.job_id)
                    .outerjoin(
                        DAILY_CAPTURE_INVOCATIONS,
                        DAILY_CAPTURE_INVOCATIONS.c.job_id
                        == DAILY_CAPTURE_START_REQUESTS.c.job_id,
                    )
                    .where(
                        DAILY_CAPTURE_START_REQUESTS.c.status
                        == "reserved",
                        DAILY_CAPTURE_INVOCATIONS.c.invocation_id.is_(
                            None
                        ),
                    )
                    .order_by(
                        DAILY_CAPTURE_START_REQUESTS.c.created_at,
                        DAILY_CAPTURE_START_REQUESTS.c.job_id,
                    )
                ).scalars()
            )
        return tuple(str(job_id) for job_id in job_ids)

    @staticmethod
    def _get(
        connection: Connection,
        job_id: str,
    ) -> DailyInvocationRecord:
        row = (
            connection.execute(
                select(DAILY_CAPTURE_INVOCATIONS).where(
                    DAILY_CAPTURE_INVOCATIONS.c.job_id == job_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise DailyInvocationConflictError(
                "daily invocation does not exist"
            )
        return _record(row)

    def commit_checkpoint(
        self,
        *,
        job_id: str,
        expected_record_version: int,
        checkpoint: DailyCaptureCheckpoint,
        next_stage: DailyCaptureStage | None,
        completed: bool,
        now: datetime | None = None,
    ) -> DailyInvocationRecord:
        instant = datetime.now(UTC) if now is None else now
        with self._commit_gate.transaction(self._engine) as connection:
            current = self._get(connection, job_id)
            if current.record_version != expected_record_version:
                raise DailyInvocationConflictError(
                    "daily invocation record version changed"
                )
            if current.status in {"succeeded", "failed"}:
                raise DailyInvocationConflictError(
                    "daily invocation is already terminal"
                )
            if (
                checkpoint.invocation_id != current.request.invocation_id
                or checkpoint.invocation_fingerprint
                != current.request.fingerprint
                or (
                    current.checkpoint is not None
                    and checkpoint.revision <= current.checkpoint.revision
                )
                or completed != (next_stage is None)
            ):
                raise DailyInvocationConflictError(
                    "daily invocation checkpoint is inconsistent"
                )
            result = connection.execute(
                update(DAILY_CAPTURE_INVOCATIONS)
                .where(
                    DAILY_CAPTURE_INVOCATIONS.c.job_id == job_id,
                    DAILY_CAPTURE_INVOCATIONS.c.record_version
                    == expected_record_version,
                )
                .values(
                    checkpoint_json=_canonical(checkpoint.to_payload()),
                    next_stage=(
                        "daily.complete"
                        if next_stage is None
                        else next_stage.value
                    ),
                    status="succeeded" if completed else "ready",
                    diagnostic_code=None,
                    record_version=expected_record_version + 1,
                    updated_at=_timestamp(instant),
                )
            )
            if result.rowcount != 1:
                raise DailyInvocationConflictError(
                    "daily invocation record version changed"
                )
            return self._get(connection, job_id)

    def fail(
        self,
        *,
        job_id: str,
        expected_record_version: int,
        diagnostic_code: str,
        now: datetime | None = None,
    ) -> DailyInvocationRecord:
        if _DIAGNOSTIC.fullmatch(diagnostic_code) is None:
            raise DailyInvocationConflictError(
                "daily invocation diagnostic code is invalid"
            )
        instant = datetime.now(UTC) if now is None else now
        with self._commit_gate.transaction(self._engine) as connection:
            current = self._get(connection, job_id)
            if current.record_version != expected_record_version:
                raise DailyInvocationConflictError(
                    "daily invocation record version changed"
                )
            if current.status == "succeeded":
                raise DailyInvocationConflictError(
                    "completed daily invocation cannot fail"
                )
            result = connection.execute(
                update(DAILY_CAPTURE_INVOCATIONS)
                .where(
                    DAILY_CAPTURE_INVOCATIONS.c.job_id == job_id,
                    DAILY_CAPTURE_INVOCATIONS.c.record_version
                    == expected_record_version,
                )
                .values(
                    status="failed",
                    diagnostic_code=diagnostic_code,
                    record_version=expected_record_version + 1,
                    updated_at=_timestamp(instant),
                )
            )
            if result.rowcount != 1:
                raise DailyInvocationConflictError(
                    "daily invocation record version changed"
                )
            return self._get(connection, job_id)

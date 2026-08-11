from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    BUSINESS_CONNECTION_IDEMPOTENCY,
    BUSINESS_CONNECTION_READS,
    BUSINESS_CONNECTION_SESSIONS,
    JOBS,
)
from dahe.application.chengfeng.business_session import (
    BusinessConnectionSession,
    BusinessConnectionSessionError,
)
from dahe.ports.jobs import IdempotencyConflictError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLOSE_REASONS = {"explicit", "expired", "browser_closed", "shutdown"}


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BusinessConnectionSessionError(
            "business session timestamp must be timezone-aware"
        )
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: object | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BusinessConnectionSessionError(
            "stored business session timestamp is invalid"
        )
    return parsed.astimezone(UTC)


def _record(row: RowMapping) -> BusinessConnectionSession:
    expires_at = _parse_timestamp(row["expires_at"])
    created_at = _parse_timestamp(row["created_at"])
    updated_at = _parse_timestamp(row["updated_at"])
    assert expires_at is not None
    assert created_at is not None
    assert updated_at is not None
    return BusinessConnectionSession(
        business_session_id=str(row["business_session_id"]),
        platform_session_id=str(row["platform_session_id"]),
        build_sha256=str(row["build_sha256"]),
        login_access_window_id=str(row["login_access_window_id"]),
        confirmation_sha256=str(row["confirmation_sha256"]),
        status=str(row["status"]),
        expires_at=expires_at,
        closed_at=_parse_timestamp(row["closed_at"]),
        close_reason=(
            None if row["close_reason"] is None else str(row["close_reason"])
        ),
        record_version=int(row["record_version"]),
        created_at=created_at,
        updated_at=updated_at,
    )


class SqliteBusinessConnectionSessionStore:
    """Persist one lightweight working-day confirmation and read lineage."""

    def __init__(self, runtime: SqliteRuntime) -> None:
        self._engine = runtime.engine
        self._commit_gate = runtime.commit_gate

    @staticmethod
    def _get(connection: Connection, business_session_id: str) -> RowMapping:
        row = (
            connection.execute(
                select(BUSINESS_CONNECTION_SESSIONS).where(
                    BUSINESS_CONNECTION_SESSIONS.c.business_session_id
                    == business_session_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise BusinessConnectionSessionError(
                "business connection session does not exist"
            )
        return row

    @staticmethod
    def _validate_identity(
        *,
        platform_session_id: str,
        build_sha256: str,
        confirmation_sha256: str,
        idempotency_key: str,
        request_hash: str,
    ) -> None:
        if (
            not platform_session_id
            or len(platform_session_id) > 100
            or _SHA256.fullmatch(build_sha256) is None
            or _SHA256.fullmatch(confirmation_sha256) is None
            or not idempotency_key
            or len(idempotency_key) > 200
            or _SHA256.fullmatch(request_hash) is None
        ):
            raise BusinessConnectionSessionError(
                "business connection session identity is invalid"
            )

    def start(
        self,
        *,
        platform_session_id: str,
        build_sha256: str,
        login_access_window_id: str,
        confirmation_sha256: str,
        expires_at: datetime,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> tuple[BusinessConnectionSession, bool]:
        self._validate_identity(
            platform_session_id=platform_session_id,
            build_sha256=build_sha256,
            confirmation_sha256=confirmation_sha256,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        timestamp = _timestamp(now)
        expiry = _timestamp(expires_at)
        if expires_at <= now:
            raise BusinessConnectionSessionError(
                "business connection session expiry is invalid"
            )
        operation = "business_session_start"
        try:
            with self._commit_gate.transaction(self._engine) as connection:
                replay = (
                    connection.execute(
                        select(BUSINESS_CONNECTION_IDEMPOTENCY).where(
                            BUSINESS_CONNECTION_IDEMPOTENCY.c.operation
                            == operation,
                            BUSINESS_CONNECTION_IDEMPOTENCY.c.idempotency_key
                            == idempotency_key,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if replay is not None:
                    if str(replay["request_hash"]) != request_hash:
                        raise IdempotencyConflictError(
                            "the idempotency key belongs to another request"
                        )
                    return (
                        _record(
                            self._get(
                                connection,
                                str(replay["business_session_id"]),
                            )
                        ),
                        True,
                    )
                active_rows = (
                    connection.execute(
                        select(BUSINESS_CONNECTION_SESSIONS).where(
                            BUSINESS_CONNECTION_SESSIONS.c.platform_session_id
                            == platform_session_id,
                            BUSINESS_CONNECTION_SESSIONS.c.status == "active",
                        )
                    )
                    .mappings()
                    .all()
                )
                for active in active_rows:
                    active_expiry = _parse_timestamp(active["expires_at"])
                    assert active_expiry is not None
                    if now < active_expiry:
                        raise BusinessConnectionSessionError(
                            "an active business connection session already exists"
                        )
                    connection.execute(
                        update(BUSINESS_CONNECTION_SESSIONS)
                        .where(
                            BUSINESS_CONNECTION_SESSIONS.c.business_session_id
                            == active["business_session_id"],
                            BUSINESS_CONNECTION_SESSIONS.c.record_version
                            == active["record_version"],
                        )
                        .values(
                            status="closed",
                            closed_at=timestamp,
                            close_reason="expired",
                            record_version=int(active["record_version"]) + 1,
                            updated_at=timestamp,
                        )
                    )
                business_session_id = uuid4().hex
                connection.execute(
                    BUSINESS_CONNECTION_SESSIONS.insert().values(
                        business_session_id=business_session_id,
                        platform_session_id=platform_session_id,
                        build_sha256=build_sha256,
                        login_access_window_id=login_access_window_id,
                        confirmation_sha256=confirmation_sha256,
                        status="active",
                        expires_at=expiry,
                        closed_at=None,
                        close_reason=None,
                        record_version=1,
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )
                connection.execute(
                    BUSINESS_CONNECTION_IDEMPOTENCY.insert().values(
                        operation=operation,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        business_session_id=business_session_id,
                        result_record_version=1,
                        created_at=timestamp,
                    )
                )
                return _record(self._get(connection, business_session_id)), False
        except IntegrityError as exc:
            raise BusinessConnectionSessionError(
                "business connection session changed concurrently"
            ) from exc

    def latest(
        self,
        *,
        platform_session_id: str,
    ) -> BusinessConnectionSession | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(BUSINESS_CONNECTION_SESSIONS)
                    .where(
                        BUSINESS_CONNECTION_SESSIONS.c.platform_session_id
                        == platform_session_id
                    )
                    .order_by(BUSINESS_CONNECTION_SESSIONS.c.created_at.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _record(row)

    def get(
        self,
        business_session_id: str,
    ) -> BusinessConnectionSession:
        with self._engine.connect() as connection:
            return _record(self._get(connection, business_session_id))

    def owns_access_window(
        self,
        *,
        business_session_id: str,
        access_window_id: str,
    ) -> bool:
        with self._engine.connect() as connection:
            session = self._get(connection, business_session_id)
            if str(session["login_access_window_id"]) == access_window_id:
                return True
            read = connection.execute(
                select(BUSINESS_CONNECTION_READS.c.access_window_id).where(
                    BUSINESS_CONNECTION_READS.c.business_session_id
                    == business_session_id,
                    BUSINESS_CONNECTION_READS.c.access_window_id
                    == access_window_id,
                )
            ).scalar_one_or_none()
        return read is not None

    def active_read_job_id(
        self,
        *,
        business_session_id: str,
    ) -> str | None:
        with self._engine.connect() as connection:
            job_id = connection.execute(
                select(JOBS.c.job_id)
                .select_from(
                    BUSINESS_CONNECTION_READS.join(
                        JOBS,
                        JOBS.c.job_id == BUSINESS_CONNECTION_READS.c.job_id,
                    )
                )
                .where(
                    BUSINESS_CONNECTION_READS.c.business_session_id
                    == business_session_id,
                    JOBS.c.status.not_in(
                        ("cancelled", "succeeded", "failed")
                    ),
                )
                .order_by(JOBS.c.created_sequence.desc())
                .limit(1)
            ).scalar_one_or_none()
        return None if job_id is None else str(job_id)

    def close(
        self,
        *,
        business_session_id: str,
        expected_record_version: int,
        reason: str,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> tuple[BusinessConnectionSession, bool]:
        if (
            reason not in _CLOSE_REASONS
            or not idempotency_key
            or len(idempotency_key) > 200
            or _SHA256.fullmatch(request_hash) is None
        ):
            raise BusinessConnectionSessionError(
                "business connection close request is invalid"
            )
        timestamp = _timestamp(now)
        operation = "business_session_close"
        with self._commit_gate.transaction(self._engine) as connection:
            replay = (
                connection.execute(
                    select(BUSINESS_CONNECTION_IDEMPOTENCY).where(
                        BUSINESS_CONNECTION_IDEMPOTENCY.c.operation
                        == operation,
                        BUSINESS_CONNECTION_IDEMPOTENCY.c.idempotency_key
                        == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if (
                    str(replay["request_hash"]) != request_hash
                    or str(replay["business_session_id"])
                    != business_session_id
                ):
                    raise IdempotencyConflictError(
                        "the idempotency key belongs to another request"
                    )
                return _record(self._get(connection, business_session_id)), True
            current = self._get(connection, business_session_id)
            record = _record(current)
            if record.record_version != expected_record_version:
                raise BusinessConnectionSessionError(
                    "business connection session record version is stale"
                )
            if record.status != "active":
                raise BusinessConnectionSessionError(
                    "business connection session is already closed"
                )
            next_version = record.record_version + 1
            result = connection.execute(
                update(BUSINESS_CONNECTION_SESSIONS)
                .where(
                    BUSINESS_CONNECTION_SESSIONS.c.business_session_id
                    == business_session_id,
                    BUSINESS_CONNECTION_SESSIONS.c.record_version
                    == expected_record_version,
                )
                .values(
                    status="closed",
                    closed_at=timestamp,
                    close_reason=reason,
                    record_version=next_version,
                    updated_at=timestamp,
                )
            )
            if result.rowcount != 1:
                raise BusinessConnectionSessionError(
                    "business connection session changed concurrently"
                )
            connection.execute(
                BUSINESS_CONNECTION_IDEMPOTENCY.insert().values(
                    operation=operation,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    business_session_id=business_session_id,
                    result_record_version=next_version,
                    created_at=timestamp,
                )
            )
            return _record(self._get(connection, business_session_id)), False

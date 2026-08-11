from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.engine import RowMapping

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    JOBS,
    PLATFORM_ACCESS_EVENTS,
    PLATFORM_ACCESS_WINDOWS,
)
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowGrant,
    authorize_access_window,
    issue_access_window,
)


class PlatformAccessConflictError(RuntimeError):
    """Raised when an access-window write conflicts with durable state."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("platform access timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat()


def _parse_timestamp(value: object | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        raise PlatformAccessConflictError("stored access timestamp is invalid")
    return parsed.astimezone(UTC)


def _record(row: RowMapping) -> AccessWindowGrant:
    issued_at = _parse_timestamp(row["issued_at"])
    expires_at = _parse_timestamp(row["expires_at"])
    assert issued_at is not None
    assert expires_at is not None
    return AccessWindowGrant(
        access_window_id=str(row["access_window_id"]),
        purpose=AccessPurpose(str(row["purpose"])),
        job_id=str(row["job_id"]),
        session_id=str(row["session_id"]),
        build_sha256=str(row["build_sha256"]),
        issued_at=issued_at,
        expires_at=expires_at,
        token_digest=str(row["token_digest"]),
        consumed_at=_parse_timestamp(row["consumed_at"]),
        token="",
    )


class SqlitePlatformAccessRepository:
    """Persist short-lived real-platform authorization without human identity."""

    def __init__(self, runtime: SqliteRuntime) -> None:
        self._engine = runtime.engine
        self._commit_gate = runtime.commit_gate

    def issue(
        self,
        *,
        purpose: AccessPurpose,
        job_id: str,
        session_id: str,
        build_sha256: str,
        duration_minutes: int,
        legacy_idle_confirmed: bool,
        no_settlement_or_payment_confirmed: bool,
        same_account_session_risk_accepted: bool,
        run_mode: str,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> tuple[AccessWindowGrant, bool]:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ValueError("idempotency key is invalid")
        if len(request_hash) != 64:
            raise ValueError("request hash is invalid")
        with self._commit_gate.transaction(self._engine) as connection:
            replay = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.idempotency_key
                        == idempotency_key
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if str(replay["request_hash"]) != request_hash:
                    raise PlatformAccessConflictError(
                        "idempotency key belongs to a different request"
                    )
                return _record(replay), True

            overlapping = tuple(
                connection.execute(
                    select(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                        PLATFORM_ACCESS_WINDOWS.c.purpose,
                        JOBS.c.run_mode,
                    )
                    .outerjoin(
                        JOBS,
                        JOBS.c.job_id == PLATFORM_ACCESS_WINDOWS.c.job_id,
                    )
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.session_id
                        == session_id,
                        PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                    )
                ).mappings()
            )
            if overlapping and (
                run_mode != "operational"
                or any(
                    str(row["run_mode"]) != "operational"
                    for row in overlapping
                )
            ):
                raise PlatformAccessConflictError(
                    "browser session already has an unconsumed access window"
                )

            grant = issue_access_window(
                purpose=purpose,
                job_id=job_id,
                session_id=session_id,
                build_sha256=build_sha256,
                duration_minutes=duration_minutes,
                legacy_idle_confirmed=legacy_idle_confirmed,
                no_settlement_or_payment_confirmed=(
                    no_settlement_or_payment_confirmed
                ),
                same_account_session_risk_accepted=(
                    same_account_session_risk_accepted
                ),
                run_mode=run_mode,
                now=now,
            )
            issued_at = _timestamp(grant.issued_at)
            connection.execute(
                PLATFORM_ACCESS_WINDOWS.insert().values(
                    **grant.to_persisted_payload(),
                    record_version=1,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    created_at=issued_at,
                    updated_at=issued_at,
                )
            )
            connection.execute(
                PLATFORM_ACCESS_EVENTS.insert().values(
                    access_window_id=grant.access_window_id,
                    event_type="issued",
                    record_version=1,
                    created_at=issued_at,
                )
            )
            return grant, False

    def get(self, access_window_id: str) -> AccessWindowGrant:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == access_window_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise PlatformAccessConflictError("access window does not exist")
        return _record(row)

    def get_with_version(
        self,
        access_window_id: str,
    ) -> tuple[AccessWindowGrant, int]:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == access_window_id
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise PlatformAccessConflictError("access window does not exist")
        return _record(row), int(row["record_version"])

    def latest_for_session(
        self,
        session_id: str,
    ) -> tuple[AccessWindowGrant, int] | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS)
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.session_id == session_id
                    )
                    .order_by(PLATFORM_ACCESS_WINDOWS.c.issued_at.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        return _record(row), int(row["record_version"])

    def production_shadow_windows_for_job(
        self,
        job_id: str,
    ) -> tuple[tuple[AccessWindowGrant, int], ...]:
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS)
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.job_id == job_id,
                        PLATFORM_ACCESS_WINDOWS.c.purpose
                        == AccessPurpose.PRODUCTION_SHADOW.value,
                    )
                    .order_by(
                        PLATFORM_ACCESS_WINDOWS.c.issued_at,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                    )
                )
                .mappings()
                .all()
            )
        return tuple(
            (_record(row), int(row["record_version"]))
            for row in rows
        )

    def unconsumed_for_job(
        self,
        *,
        session_id: str,
        job_id: str,
    ) -> tuple[AccessWindowGrant, ...]:
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.session_id
                        == session_id,
                        PLATFORM_ACCESS_WINDOWS.c.job_id == job_id,
                        PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                    )
                    .order_by(
                        PLATFORM_ACCESS_WINDOWS.c.issued_at,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                    )
                )
                .mappings()
                .all()
            )
        return tuple(_record(row) for row in rows)

    def unconsumed_for_session(
        self,
        session_id: str,
    ) -> tuple[tuple[AccessWindowGrant, int], ...]:
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS)
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.session_id
                        == session_id,
                        PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
                    )
                    .order_by(
                        PLATFORM_ACCESS_WINDOWS.c.issued_at,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                    )
                )
                .mappings()
                .all()
            )
        return tuple(
            (_record(row), int(row["record_version"]))
            for row in rows
        )

    def terminal_or_expired_daily_job_ids(
        self,
        *,
        now: datetime,
    ) -> tuple[str, ...]:
        instant = _utc(now)
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    select(
                        PLATFORM_ACCESS_WINDOWS.c.job_id,
                        PLATFORM_ACCESS_WINDOWS.c.expires_at,
                        JOBS.c.status.label("job_status"),
                    )
                    .join(
                        JOBS,
                        JOBS.c.job_id
                        == PLATFORM_ACCESS_WINDOWS.c.job_id,
                    )
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.purpose
                        == AccessPurpose.PRODUCTION_SHADOW.value,
                        JOBS.c.task_type == "daily",
                    )
                    .order_by(
                        PLATFORM_ACCESS_WINDOWS.c.issued_at,
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                    )
                )
                .mappings()
                .all()
            )
        candidates: set[str] = set()
        for row in rows:
            expires_at = _parse_timestamp(row["expires_at"])
            if (
                str(row["job_status"])
                in {"cancelled", "succeeded", "failed"}
                or (
                    expires_at is not None
                    and expires_at <= instant
                )
            ):
                candidates.add(str(row["job_id"]))
        return tuple(sorted(candidates))

    def authorize(
        self,
        *,
        access_window_id: str,
        purpose: AccessPurpose,
        job_id: str,
        session_id: str,
        build_sha256: str,
        now: datetime,
    ) -> AccessWindowGrant:
        grant = self.get(access_window_id)
        return authorize_access_window(
            grant,
            purpose=purpose,
            job_id=job_id,
            session_id=session_id,
            build_sha256=build_sha256,
            now=now,
        )

    def consume(
        self,
        *,
        access_window_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> AccessWindowGrant:
        instant = _utc(now)
        with self._commit_gate.transaction(self._engine) as connection:
            row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == access_window_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise PlatformAccessConflictError("access window does not exist")
            if int(row["record_version"]) != expected_record_version:
                raise PlatformAccessConflictError(
                    "access window record version is stale"
                )
            consumed = _record(row).consume(now=instant)
            next_version = expected_record_version + 1
            result = connection.execute(
                update(PLATFORM_ACCESS_WINDOWS)
                .where(
                    PLATFORM_ACCESS_WINDOWS.c.access_window_id
                    == access_window_id,
                    PLATFORM_ACCESS_WINDOWS.c.record_version
                    == expected_record_version,
                )
                .values(
                    consumed_at=_timestamp(instant),
                    record_version=next_version,
                    updated_at=_timestamp(instant),
                )
            )
            if result.rowcount != 1:
                raise PlatformAccessConflictError(
                    "access window record changed concurrently"
                )
            connection.execute(
                PLATFORM_ACCESS_EVENTS.insert().values(
                    access_window_id=access_window_id,
                    event_type="consumed",
                    record_version=next_version,
                    created_at=_timestamp(instant),
                )
            )
        return consumed

    def retire(
        self,
        *,
        access_window_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> AccessWindowGrant:
        """Idempotently invalidate a terminal window, including after expiry."""

        instant = _utc(now)
        with self._commit_gate.transaction(self._engine) as connection:
            row = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == access_window_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise PlatformAccessConflictError(
                    "access window does not exist"
                )
            current = _record(row)
            if current.consumed_at is not None:
                return current
            if int(row["record_version"]) != expected_record_version:
                raise PlatformAccessConflictError(
                    "access window record version is stale"
                )
            next_version = expected_record_version + 1
            result = connection.execute(
                update(PLATFORM_ACCESS_WINDOWS)
                .where(
                    PLATFORM_ACCESS_WINDOWS.c.access_window_id
                    == access_window_id,
                    PLATFORM_ACCESS_WINDOWS.c.record_version
                    == expected_record_version,
                )
                .values(
                    consumed_at=_timestamp(instant),
                    record_version=next_version,
                    updated_at=_timestamp(instant),
                )
            )
            if result.rowcount != 1:
                raise PlatformAccessConflictError(
                    "access window record changed concurrently"
                )
            connection.execute(
                PLATFORM_ACCESS_EVENTS.insert().values(
                    access_window_id=access_window_id,
                    event_type="consumed",
                    record_version=next_version,
                    created_at=_timestamp(instant),
                )
            )
            updated = (
                connection.execute(
                    select(PLATFORM_ACCESS_WINDOWS).where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == access_window_id
                    )
                )
                .mappings()
                .one()
            )
        return _record(updated)

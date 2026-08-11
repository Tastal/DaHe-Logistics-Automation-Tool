from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine, RowMapping

from dahe.adapters.sqlite.runtime import ShortTransactionCommitGate


class BrowserControlError(RuntimeError):
    """Raised when a browser control transition is not safe."""


class NavigationRejectedError(BrowserControlError):
    """Raised when a command does not carry the current browser grant."""


class RecoveryProofMissingError(BrowserControlError):
    """Raised when automatic browser recovery lacks a required proof."""


@dataclass(frozen=True, slots=True)
class BrowserControlRecord:
    session_id: str
    browser_lifecycle: str
    browser_control_mode: str
    holder_kind: str | None
    holder_id: str | None
    instance_id: str | None
    worker_id: str | None
    job_id: str | None
    control_epoch: int
    record_version: int
    fencing_token: str | None = field(default=None, repr=False)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("browser control timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _aware_utc(value).isoformat()


def _parse_timestamp(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        raise BrowserControlError("stored browser control timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _record(
    row: RowMapping,
    *,
    fencing_token: str | None = None,
) -> BrowserControlRecord:
    return BrowserControlRecord(
        session_id=str(row["session_id"]),
        browser_lifecycle=str(row["browser_lifecycle"]),
        browser_control_mode=str(row["browser_control_mode"]),
        holder_kind=None if row["holder_kind"] is None else str(row["holder_kind"]),
        holder_id=None if row["holder_id"] is None else str(row["holder_id"]),
        instance_id=None if row["instance_id"] is None else str(row["instance_id"]),
        worker_id=None if row["worker_id"] is None else str(row["worker_id"]),
        job_id=None if row["job_id"] is None else str(row["job_id"]),
        control_epoch=int(row["control_epoch"]),
        record_version=int(row["record_version"]),
        fencing_token=fencing_token,
    )


def authorize_navigation_in_transaction(
    connection: Connection,
    *,
    session_id: str,
    instance_id: str,
    worker_id: str,
    job_id: str,
    control_epoch: int,
    fencing_token: str,
    now: datetime | None = None,
) -> None:
    """Fence a connector commit using the same transaction as its result."""

    row = (
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
    if row is None:
        raise NavigationRejectedError("browser control session does not exist")
    expires_at = row["expires_at"]
    authorization_time = datetime.now(UTC) if now is None else _aware_utc(now)
    if (
        row["browser_lifecycle"] != "ready"
        or row["browser_control_mode"] != "automated"
        or row["instance_id"] != instance_id
        or row["worker_id"] != worker_id
        or row["job_id"] != job_id
        or int(row["control_epoch"]) != control_epoch
        or row["fencing_token"] != _token_digest(fencing_token)
        or expires_at is None
        or _parse_timestamp(expires_at) <= authorization_time
    ):
        raise NavigationRejectedError("browser navigation grant is stale or invalid")


class BrowserControlStore:
    """Keep the physical browser session behind an epoch and token fence."""

    def __init__(
        self,
        engine: Engine,
        commit_gate: ShortTransactionCommitGate,
    ) -> None:
        self._engine = engine
        self._commit_gate = commit_gate

    @staticmethod
    def _event(
        connection: Connection,
        *,
        session_id: str,
        event_type: str,
        control_epoch: int,
        payload: dict[str, object],
        now: datetime,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO browser_control_events (
                    session_id, event_type, control_epoch, payload_json, created_at
                ) VALUES (
                    :session_id, :event_type, :control_epoch, :payload_json, :created_at
                )
                """
            ),
            {
                "session_id": session_id,
                "event_type": event_type,
                "control_epoch": control_epoch,
                "payload_json": json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "created_at": _timestamp(now),
            },
        )

    @staticmethod
    def _idempotent_replay(
        connection: Connection,
        *,
        operation: str,
        idempotency_key: str,
        request_hash: str,
        session_id: str,
        access_window_id: str,
    ) -> bool:
        row = (
            connection.execute(
                text(
                    """
                    SELECT * FROM platform_control_idempotency
                    WHERE operation = :operation
                      AND idempotency_key = :idempotency_key
                    """
                ),
                {
                    "operation": operation,
                    "idempotency_key": idempotency_key,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return False
        if (
            row["request_hash"] != request_hash
            or row["session_id"] != session_id
            or row["access_window_id"] != access_window_id
        ):
            raise BrowserControlError("platform idempotency key was reused")
        return True

    @staticmethod
    def _record_idempotency(
        connection: Connection,
        *,
        operation: str,
        idempotency_key: str,
        request_hash: str,
        session_id: str,
        access_window_id: str,
        result_record_version: int,
        now: datetime,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO platform_control_idempotency (
                    operation, idempotency_key, request_hash, session_id,
                    access_window_id, result_record_version, created_at
                ) VALUES (
                    :operation, :idempotency_key, :request_hash, :session_id,
                    :access_window_id, :result_record_version, :created_at
                )
                """
            ),
            {
                "operation": operation,
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
                "session_id": session_id,
                "access_window_id": access_window_id,
                "result_record_version": result_record_version,
                "created_at": _timestamp(now),
            },
        )

    @staticmethod
    def _get(connection: Connection, session_id: str) -> RowMapping:
        row = (
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
        if row is None:
            raise BrowserControlError("browser control session does not exist")
        return row

    def initialize(
        self,
        *,
        session_id: str,
        now: datetime,
    ) -> BrowserControlRecord:
        instant = _timestamp(now)
        with self._commit_gate.transaction(self._engine) as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO browser_control_sessions (
                        session_id, browser_lifecycle, browser_control_mode,
                        holder_kind, holder_id, instance_id, worker_id, job_id,
                        control_epoch, fencing_token, acquired_at, heartbeat_at,
                        expires_at, returned_at, recovery_reason, record_version,
                        updated_at
                    ) VALUES (
                        :session_id, 'stopped', 'idle', NULL, NULL, NULL, NULL,
                        NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, 1, :now
                    )
                    ON CONFLICT(session_id) DO NOTHING
                    """
                ),
                {"session_id": session_id, "now": instant},
            )
            row = self._get(connection, session_id)
        return _record(row)

    def get(self, session_id: str) -> BrowserControlRecord:
        with self._engine.connect() as connection:
            row = self._get(connection, session_id)
        return _record(row)

    def mark_stopped(
        self,
        *,
        session_id: str,
        access_window_id: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> tuple[BrowserControlRecord, bool]:
        with self._commit_gate.transaction(self._engine) as connection:
            if self._idempotent_replay(
                connection,
                operation="browser_session_close",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                session_id=session_id,
                access_window_id=access_window_id,
            ):
                return _record(self._get(connection, session_id)), True
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if row["browser_control_mode"] != "idle":
                raise BrowserControlError("browser control must be returned before stop")
            next_epoch = int(row["control_epoch"]) + 1
            next_version = expected_record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = 'stopped',
                        browser_control_mode = 'idle',
                        holder_kind = NULL, holder_id = NULL, instance_id = NULL,
                        worker_id = NULL, job_id = NULL,
                        control_epoch = :next_epoch, fencing_token = NULL,
                        acquired_at = NULL, heartbeat_at = NULL, expires_at = NULL,
                        returned_at = :now, recovery_reason = NULL,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_record_version": expected_record_version,
                    "next_epoch": next_epoch,
                    "next_version": next_version,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser control record changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.stopped",
                control_epoch=next_epoch,
                payload={},
                now=now,
            )
            self._record_idempotency(
                connection,
                operation="browser_session_close",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                session_id=session_id,
                access_window_id=access_window_id,
                result_record_version=next_version,
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated), False

    def mark_ready(
        self,
        *,
        session_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> BrowserControlRecord:
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if row["browser_control_mode"] != "idle":
                raise BrowserControlError("browser control is not idle")
            if row["browser_lifecycle"] not in {"stopped", "starting"}:
                raise BrowserControlError(
                    "browser lifecycle cannot become ready without recovery proofs"
                )
            next_version = expected_record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = 'ready', record_version = :next_version,
                        updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_record_version": expected_record_version,
                    "next_version": next_version,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser control record changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.ready",
                control_epoch=int(row["control_epoch"]),
                payload={},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def mark_human_session_closed(
        self,
        *,
        session_id: str,
        human_session_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> BrowserControlRecord:
        """Fail closed when the owned physical browser was visibly closed."""

        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if (
                row["browser_lifecycle"] != "ready"
                or str(row["browser_control_mode"]) not in {"human_login", "human_handoff"}
                or row["holder_kind"] != "human_session"
                or row["holder_id"] != human_session_id
            ):
                raise BrowserControlError("closed human browser holder does not match")
            next_epoch = int(row["control_epoch"]) + 1
            next_version = expected_record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = 'stopped',
                        browser_control_mode = 'idle',
                        holder_kind = NULL, holder_id = NULL,
                        instance_id = NULL, worker_id = NULL, job_id = NULL,
                        control_epoch = :next_epoch, fencing_token = NULL,
                        acquired_at = NULL, heartbeat_at = NULL,
                        expires_at = NULL, returned_at = :now,
                        recovery_reason = NULL,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_record_version": expected_record_version,
                    "next_epoch": next_epoch,
                    "next_version": next_version,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("closed human browser state changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.human_window_closed",
                control_epoch=next_epoch,
                payload={},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def mark_idle_runtime_missing(
        self,
        *,
        session_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> BrowserControlRecord:
        """Reconcile a ready idle record when no physical browser exists."""

        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if (
                row["browser_lifecycle"] != "ready"
                or row["browser_control_mode"] != "idle"
                or row["holder_kind"] is not None
            ):
                raise BrowserControlError("idle browser runtime state does not match")
            next_epoch = int(row["control_epoch"]) + 1
            next_version = expected_record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = 'stopped',
                        control_epoch = :next_epoch,
                        returned_at = :now, recovery_reason = NULL,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_record_version": expected_record_version,
                    "next_epoch": next_epoch,
                    "next_version": next_version,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("idle browser runtime changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.idle_runtime_missing",
                control_epoch=next_epoch,
                payload={},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def acquire_automated(
        self,
        *,
        session_id: str,
        instance_id: str,
        worker_id: str,
        job_id: str,
        expected_record_version: int,
        now: datetime,
        ttl: timedelta,
    ) -> BrowserControlRecord:
        if ttl <= timedelta(0):
            raise ValueError("browser grant TTL must be positive")
        raw_token = secrets.token_urlsafe(32)
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if str(row["browser_control_mode"]).startswith("human_"):
                raise BrowserControlError("human browser control has not been returned")
            if row["browser_lifecycle"] != "ready" or row["browser_control_mode"] != "idle":
                raise BrowserControlError("browser session is not ready and idle")
            epoch = int(row["control_epoch"]) + 1
            version = expected_record_version + 1
            acquired_at = _aware_utc(now)
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_control_mode = 'automated',
                        holder_kind = 'worker', holder_id = :worker_id,
                        instance_id = :instance_id, worker_id = :worker_id,
                        job_id = :job_id, control_epoch = :epoch,
                        fencing_token = :token_digest, acquired_at = :acquired_at,
                        heartbeat_at = :acquired_at, expires_at = :expires_at,
                        returned_at = NULL, recovery_reason = NULL,
                        record_version = :version, updated_at = :acquired_at
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "instance_id": instance_id,
                    "worker_id": worker_id,
                    "job_id": job_id,
                    "epoch": epoch,
                    "token_digest": _token_digest(raw_token),
                    "acquired_at": _timestamp(acquired_at),
                    "expires_at": _timestamp(acquired_at + ttl),
                    "version": version,
                    "expected_record_version": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser control record changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.automated_acquired",
                control_epoch=epoch,
                payload={"instance_id": instance_id, "worker_id": worker_id},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated, fencing_token=raw_token)

    def authorize_navigation(
        self,
        *,
        session_id: str,
        instance_id: str,
        worker_id: str,
        job_id: str,
        control_epoch: int,
        fencing_token: str,
        now: datetime | None = None,
    ) -> None:
        with self._engine.connect() as connection:
            authorize_navigation_in_transaction(
                connection,
                session_id=session_id,
                instance_id=instance_id,
                worker_id=worker_id,
                job_id=job_id,
                control_epoch=control_epoch,
                fencing_token=fencing_token,
                now=now,
            )

    def renew_automated(
        self,
        *,
        session_id: str,
        instance_id: str,
        worker_id: str,
        job_id: str,
        control_epoch: int,
        fencing_token: str,
        now: datetime,
        ttl: timedelta,
    ) -> BrowserControlRecord:
        """Extend only the current, unexpired automated browser grant."""
        if ttl <= timedelta(0):
            raise ValueError("browser grant TTL must be positive")
        renewal_time = _aware_utc(now)
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            expires_at = row["expires_at"]
            if (
                row["browser_lifecycle"] != "ready"
                or row["browser_control_mode"] != "automated"
                or row["instance_id"] != instance_id
                or row["worker_id"] != worker_id
                or row["job_id"] != job_id
                or int(row["control_epoch"]) != control_epoch
                or row["fencing_token"] != _token_digest(fencing_token)
                or expires_at is None
                or _parse_timestamp(expires_at) <= renewal_time
            ):
                raise BrowserControlError("automatic browser grant cannot be renewed")
            next_version = int(row["record_version"]) + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET heartbeat_at = :now, expires_at = :expires_at,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :record_version
                      AND control_epoch = :control_epoch
                      AND job_id = :job_id
                      AND fencing_token = :fencing_token
                    """
                ),
                {
                    "session_id": session_id,
                    "record_version": row["record_version"],
                    "control_epoch": control_epoch,
                    "job_id": job_id,
                    "fencing_token": _token_digest(fencing_token),
                    "now": _timestamp(renewal_time),
                    "expires_at": _timestamp(renewal_time + ttl),
                    "next_version": next_version,
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("automatic browser grant changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.automated_renewed",
                control_epoch=control_epoch,
                payload={"instance_id": instance_id, "worker_id": worker_id},
                now=renewal_time,
            )
            updated = self._get(connection, session_id)
        return _record(updated, fencing_token=fencing_token)

    def begin_automatic_recovery(
        self,
        *,
        session_id: str,
        instance_id: str,
        worker_id: str,
        job_id: str,
        expected_control_epoch: int,
        reason: str,
        now: datetime,
    ) -> BrowserControlRecord:
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if str(row["browser_control_mode"]).startswith("human_"):
                raise BrowserControlError("human browser control cannot be auto-recovered")
            if (
                row["browser_lifecycle"] != "ready"
                or row["browser_control_mode"] != "automated"
                or row["instance_id"] != instance_id
                or row["worker_id"] != worker_id
                or row["job_id"] != job_id
                or int(row["control_epoch"]) != expected_control_epoch
            ):
                raise BrowserControlError("automatic browser holder does not match")
            epoch = expected_control_epoch + 1
            version = int(row["record_version"]) + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = 'recovering',
                        browser_control_mode = 'idle',
                        holder_kind = NULL, holder_id = NULL, instance_id = NULL,
                        worker_id = NULL, job_id = :job_id, control_epoch = :epoch,
                        fencing_token = NULL, heartbeat_at = NULL,
                        expires_at = NULL, recovery_reason = :reason,
                        record_version = :version, updated_at = :now
                    WHERE session_id = :session_id
                      AND control_epoch = :expected_epoch
                      AND instance_id = :instance_id
                      AND worker_id = :worker_id
                      AND job_id = :job_id
                    """
                ),
                {
                    "session_id": session_id,
                    "instance_id": instance_id,
                    "worker_id": worker_id,
                    "job_id": job_id,
                    "expected_epoch": expected_control_epoch,
                    "epoch": epoch,
                    "reason": reason,
                    "version": version,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser control epoch changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.recovery_started",
                control_epoch=epoch,
                payload={"reason": reason},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def complete_automatic_recovery(
        self,
        *,
        session_id: str,
        expected_control_epoch: int,
        instance_id: str,
        worker_id: str,
        job_id: str,
        connector_stopped: bool,
        context_rebuilt: bool,
        read_only_firewall_verified: bool,
        now: datetime,
        ttl: timedelta,
    ) -> BrowserControlRecord:
        if ttl <= timedelta(0):
            raise ValueError("browser grant TTL must be positive")
        if not connector_stopped:
            raise RecoveryProofMissingError("connector stop proof is missing")
        if not context_rebuilt:
            raise RecoveryProofMissingError("browser context rebuild proof is missing")
        if not read_only_firewall_verified:
            raise RecoveryProofMissingError("read-only firewall proof is missing")
        raw_token = secrets.token_urlsafe(32)
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if (
                row["browser_lifecycle"] != "recovering"
                or row["browser_control_mode"] != "idle"
                or row["job_id"] != job_id
                or int(row["control_epoch"]) != expected_control_epoch
            ):
                raise BrowserControlError("browser recovery ticket is stale")
            version = int(row["record_version"]) + 1
            acquired_at = _aware_utc(now)
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = 'ready',
                        browser_control_mode = 'automated',
                        holder_kind = 'worker', holder_id = :worker_id,
                        instance_id = :instance_id, worker_id = :worker_id,
                        job_id = :job_id, fencing_token = :token_digest,
                        acquired_at = :acquired_at, heartbeat_at = :acquired_at,
                        expires_at = :expires_at, recovery_reason = NULL,
                        record_version = :version, updated_at = :acquired_at
                    WHERE session_id = :session_id
                      AND control_epoch = :expected_epoch
                      AND job_id = :job_id
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_epoch": expected_control_epoch,
                    "instance_id": instance_id,
                    "worker_id": worker_id,
                    "job_id": job_id,
                    "token_digest": _token_digest(raw_token),
                    "acquired_at": _timestamp(acquired_at),
                    "expires_at": _timestamp(acquired_at + ttl),
                    "version": version,
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser recovery epoch changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.recovery_completed",
                control_epoch=expected_control_epoch,
                payload={"instance_id": instance_id, "worker_id": worker_id},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated, fencing_token=raw_token)

    def acquire_human_control(
        self,
        *,
        session_id: str,
        control_mode: str,
        operator_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> BrowserControlRecord:
        if control_mode not in {"human_login", "human_handoff"}:
            raise ValueError("human browser control mode is invalid")
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if row["browser_lifecycle"] != "ready" or row["browser_control_mode"] != "idle":
                raise BrowserControlError("browser session is not ready for human control")
            epoch = int(row["control_epoch"]) + 1
            version = expected_record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_control_mode = :control_mode,
                        holder_kind = 'operator', holder_id = :operator_id,
                        instance_id = NULL, worker_id = NULL, job_id = NULL,
                        control_epoch = :epoch, fencing_token = NULL,
                        acquired_at = :now, heartbeat_at = NULL,
                        expires_at = NULL, returned_at = NULL,
                        record_version = :version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "control_mode": control_mode,
                    "operator_id": operator_id,
                    "epoch": epoch,
                    "version": version,
                    "now": _timestamp(now),
                    "expected_record_version": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser control record changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type=f"browser.{control_mode}_acquired",
                control_epoch=epoch,
                payload={"operator_id": operator_id},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def acquire_human_session_control(
        self,
        *,
        session_id: str,
        control_mode: str,
        human_session_id: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> tuple[BrowserControlRecord, bool]:
        if control_mode not in {"human_login", "human_handoff"}:
            raise ValueError("human browser control mode is invalid")
        if not human_session_id:
            raise ValueError("human session identity is required")
        with self._commit_gate.transaction(self._engine) as connection:
            if self._idempotent_replay(
                connection,
                operation="human_login_start",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                session_id=session_id,
                access_window_id=human_session_id,
            ):
                return _record(self._get(connection, session_id)), True
            row = self._get(connection, session_id)
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if row["browser_lifecycle"] != "ready" or row["browser_control_mode"] != "idle":
                raise BrowserControlError("browser session is not ready for human control")
            epoch = int(row["control_epoch"]) + 1
            version = expected_record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_control_mode = :control_mode,
                        holder_kind = 'human_session',
                        holder_id = :human_session_id,
                        instance_id = NULL, worker_id = NULL, job_id = NULL,
                        control_epoch = :epoch, fencing_token = NULL,
                        acquired_at = :now, heartbeat_at = NULL,
                        expires_at = NULL, returned_at = NULL,
                        record_version = :version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "control_mode": control_mode,
                    "human_session_id": human_session_id,
                    "epoch": epoch,
                    "version": version,
                    "now": _timestamp(now),
                    "expected_record_version": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("browser control record changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type=f"browser.{control_mode}_acquired",
                control_epoch=epoch,
                payload={"human_session_id": human_session_id},
                now=now,
            )
            self._record_idempotency(
                connection,
                operation="human_login_start",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                session_id=session_id,
                access_window_id=human_session_id,
                result_record_version=version,
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated), False

    def release_automated(
        self,
        *,
        session_id: str,
        instance_id: str,
        worker_id: str,
        job_id: str,
        control_epoch: int,
        fencing_token: str,
        now: datetime,
    ) -> BrowserControlRecord:
        """Return automatic control while permanently fencing the old grant."""
        next_epoch = control_epoch + 1
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            if (
                row["browser_lifecycle"] != "ready"
                or row["browser_control_mode"] != "automated"
                or row["instance_id"] != instance_id
                or row["worker_id"] != worker_id
                or row["job_id"] != job_id
                or int(row["control_epoch"]) != control_epoch
                or row["fencing_token"] != _token_digest(fencing_token)
            ):
                raise BrowserControlError("automatic browser grant does not match")
            next_version = int(row["record_version"]) + 1
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_control_mode = 'idle',
                        holder_kind = NULL, holder_id = NULL, instance_id = NULL,
                        worker_id = NULL, job_id = NULL,
                        control_epoch = :next_epoch, fencing_token = NULL,
                        heartbeat_at = NULL, expires_at = NULL, returned_at = :now,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND control_epoch = :control_epoch
                      AND job_id = :job_id
                      AND record_version = :record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "control_epoch": control_epoch,
                    "job_id": job_id,
                    "record_version": row["record_version"],
                    "next_epoch": next_epoch,
                    "next_version": next_version,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("automatic browser grant changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type="browser.automated_returned",
                control_epoch=next_epoch,
                payload={"instance_id": instance_id, "worker_id": worker_id},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def return_human_control(
        self,
        *,
        session_id: str,
        operator_id: str,
        expected_record_version: int,
        now: datetime,
    ) -> BrowserControlRecord:
        """Return a human-held session without treating elapsed time as authority."""
        with self._commit_gate.transaction(self._engine) as connection:
            row = self._get(connection, session_id)
            mode = str(row["browser_control_mode"])
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if (
                mode not in {"human_login", "human_handoff"}
                or row["holder_kind"] != "operator"
                or row["holder_id"] != operator_id
            ):
                raise BrowserControlError("human browser holder does not match")
            next_epoch = int(row["control_epoch"]) + 1
            next_version = expected_record_version + 1
            lifecycle = "recovering" if mode == "human_handoff" else "ready"
            recovery_reason = (
                "human_handoff_context_must_be_rebuilt" if mode == "human_handoff" else None
            )
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = :lifecycle,
                        browser_control_mode = 'idle',
                        holder_kind = NULL, holder_id = NULL,
                        instance_id = NULL, worker_id = NULL, job_id = NULL,
                        control_epoch = :next_epoch, fencing_token = NULL,
                        heartbeat_at = NULL, expires_at = NULL, returned_at = :now,
                        recovery_reason = :recovery_reason,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_record_version": expected_record_version,
                    "lifecycle": lifecycle,
                    "next_epoch": next_epoch,
                    "next_version": next_version,
                    "recovery_reason": recovery_reason,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("human browser grant changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type=f"browser.{mode}_returned",
                control_epoch=next_epoch,
                payload={"operator_id": operator_id},
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated)

    def return_human_session_control(
        self,
        *,
        session_id: str,
        human_session_id: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        now: datetime,
    ) -> tuple[BrowserControlRecord, bool]:
        with self._commit_gate.transaction(self._engine) as connection:
            if self._idempotent_replay(
                connection,
                operation="human_login_return",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                session_id=session_id,
                access_window_id=human_session_id,
            ):
                return _record(self._get(connection, session_id)), True
            row = self._get(connection, session_id)
            mode = str(row["browser_control_mode"])
            if int(row["record_version"]) != expected_record_version:
                raise BrowserControlError("browser control record version is stale")
            if (
                mode not in {"human_login", "human_handoff"}
                or row["holder_kind"] != "human_session"
                or row["holder_id"] != human_session_id
            ):
                raise BrowserControlError("human browser session does not match")
            next_epoch = int(row["control_epoch"]) + 1
            next_version = expected_record_version + 1
            lifecycle = "recovering" if mode == "human_handoff" else "ready"
            recovery_reason = (
                "human_handoff_context_must_be_rebuilt" if mode == "human_handoff" else None
            )
            result = connection.execute(
                text(
                    """
                    UPDATE browser_control_sessions
                    SET browser_lifecycle = :lifecycle,
                        browser_control_mode = 'idle',
                        holder_kind = NULL, holder_id = NULL,
                        instance_id = NULL, worker_id = NULL, job_id = NULL,
                        control_epoch = :next_epoch, fencing_token = NULL,
                        heartbeat_at = NULL, expires_at = NULL, returned_at = :now,
                        recovery_reason = :recovery_reason,
                        record_version = :next_version, updated_at = :now
                    WHERE session_id = :session_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "session_id": session_id,
                    "expected_record_version": expected_record_version,
                    "lifecycle": lifecycle,
                    "next_epoch": next_epoch,
                    "next_version": next_version,
                    "recovery_reason": recovery_reason,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise BrowserControlError("human browser grant changed concurrently")
            self._event(
                connection,
                session_id=session_id,
                event_type=f"browser.{mode}_returned",
                control_epoch=next_epoch,
                payload={"human_session_id": human_session_id},
                now=now,
            )
            self._record_idempotency(
                connection,
                operation="human_login_return",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                session_id=session_id,
                access_window_id=human_session_id,
                result_record_version=next_version,
                now=now,
            )
            updated = self._get(connection, session_id)
        return _record(updated), False

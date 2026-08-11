from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.engine import Engine, RowMapping
from sqlalchemy.exc import IntegrityError

from dahe.adapters.sqlite.runtime import ShortTransactionCommitGate


class RecoveryStoreError(RuntimeError):
    """Raised when persistent ownership state cannot be changed safely."""


class LeaseTakeoverRejected(RecoveryStoreError):
    """Raised when a new instance cannot prove that takeover is safe."""


class LeaseOwnershipError(RecoveryStoreError):
    """Raised when a lease mutation does not match its current owner."""


@dataclass(frozen=True, slots=True)
class DurableLeaseGrant:
    lease_id: str
    resource_name: str
    slot_index: int
    holder_kind: str
    holder_id: str
    instance_id: str
    worker_id: str | None
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime
    generation: int
    fencing_token: str


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("persistent lease timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _aware_utc(value).isoformat()


def _parse_timestamp(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    return _aware_utc(parsed)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _process_identity(value: str | datetime) -> str:
    if isinstance(value, datetime):
        return _timestamp(value)
    identity = value.strip()
    if not identity:
        raise ValueError("process start identity is required")
    return identity


def _lease_from_row(row: RowMapping, *, fencing_token: str) -> DurableLeaseGrant:
    instance_id = row["instance_id"]
    if instance_id is None:
        raise RecoveryStoreError("persistent lease has no application instance")
    return DurableLeaseGrant(
        lease_id=str(row["lease_id"]),
        resource_name=str(row["resource_name"]),
        slot_index=int(row["slot_index"]),
        holder_kind=str(row["holder_kind"]),
        holder_id=str(row["holder_id"]),
        instance_id=str(instance_id),
        worker_id=None if row["worker_id"] is None else str(row["worker_id"]),
        acquired_at=_parse_timestamp(row["acquired_at"]),
        heartbeat_at=_parse_timestamp(row["heartbeat_at"]),
        expires_at=_parse_timestamp(row["expires_at"]),
        generation=int(row["generation"]),
        fencing_token=fencing_token,
    )


class PersistentRecoveryStore:
    """Persist instance heartbeats and lease fencing in short transactions."""

    def __init__(
        self,
        engine: Engine,
        commit_gate: ShortTransactionCommitGate,
    ) -> None:
        self._engine = engine
        self._commit_gate = commit_gate

    def register_instance(
        self,
        *,
        instance_id: str,
        data_root_identity: str,
        pid: int,
        process_started_at: str | datetime,
        application_version: str,
        port: int,
        now: datetime,
    ) -> None:
        if not instance_id or len(data_root_identity) != 64:
            raise ValueError("instance identity is invalid")
        instant = _timestamp(now)
        with self._commit_gate.transaction(self._engine) as connection:
            result = connection.execute(
                text(
                    """
                    INSERT INTO application_instances (
                        instance_id, data_root_identity, pid, process_started_at,
                        application_version, port, status, registered_at,
                        heartbeat_at, stopped_at, record_version
                    ) VALUES (
                        :instance_id, :data_root_identity, :pid, :process_started_at,
                        :application_version, :port, 'running', :now, :now, NULL, 1
                    )
                    ON CONFLICT(instance_id) DO UPDATE SET
                        heartbeat_at = excluded.heartbeat_at,
                        status = CASE
                            WHEN application_instances.status = 'running'
                            THEN 'running'
                            ELSE application_instances.status
                        END,
                        record_version = application_instances.record_version + 1
                    WHERE application_instances.data_root_identity = excluded.data_root_identity
                      AND application_instances.pid = excluded.pid
                      AND application_instances.process_started_at =
                          excluded.process_started_at
                    """
                ),
                {
                    "instance_id": instance_id,
                    "data_root_identity": data_root_identity,
                    "pid": pid,
                    "process_started_at": _process_identity(process_started_at),
                    "application_version": application_version,
                    "port": port,
                    "now": instant,
                },
            )
            if result.rowcount != 1:
                raise RecoveryStoreError(
                    "application instance identity conflicts with an existing record"
                )

    def heartbeat_instance(self, *, instance_id: str, now: datetime) -> None:
        with self._commit_gate.transaction(self._engine) as connection:
            result = connection.execute(
                text(
                    """
                    UPDATE application_instances
                    SET heartbeat_at = :now, record_version = record_version + 1
                    WHERE instance_id = :instance_id AND status = 'running'
                    """
                ),
                {"instance_id": instance_id, "now": _timestamp(now)},
            )
            if result.rowcount != 1:
                raise RecoveryStoreError("application instance is not running")

    def mark_instance_crashed(
        self,
        *,
        instance_id: str,
        replacement_instance_id: str,
        data_root_identity: str,
        single_instance_proof: bool,
        now: datetime,
    ) -> bool:
        """Record a stale owner only after the replacement holds the OS mutex."""
        if not single_instance_proof:
            raise RecoveryStoreError("single-instance stop proof is required")
        if instance_id == replacement_instance_id:
            raise RecoveryStoreError("an instance cannot replace itself")
        with self._commit_gate.transaction(self._engine) as connection:
            replacement = (
                connection.execute(
                    text(
                        """
                    SELECT status, data_root_identity
                    FROM application_instances
                    WHERE instance_id = :instance_id
                    """
                    ),
                    {"instance_id": replacement_instance_id},
                )
                .mappings()
                .one_or_none()
            )
            if (
                replacement is None
                or replacement["status"] != "running"
                or replacement["data_root_identity"] != data_root_identity
            ):
                raise RecoveryStoreError(
                    "replacement instance identity is not active for this data root"
                )
            result = connection.execute(
                text(
                    """
                    UPDATE application_instances
                    SET status = 'crashed', stopped_at = :now,
                        record_version = record_version + 1
                    WHERE instance_id = :instance_id
                      AND data_root_identity = :data_root_identity
                      AND status = 'running'
                    """
                ),
                {
                    "instance_id": instance_id,
                    "data_root_identity": data_root_identity,
                    "now": _timestamp(now),
                },
            )
        return result.rowcount == 1

    def mark_other_instances_crashed(
        self,
        *,
        replacement_instance_id: str,
        data_root_identity: str,
        single_instance_proof: bool,
        now: datetime,
    ) -> int:
        """Fence every stale database owner after guarded replacement starts."""

        if not single_instance_proof:
            raise RecoveryStoreError("single-instance stop proof is required")
        with self._commit_gate.transaction(self._engine) as connection:
            replacement = (
                connection.execute(
                    text(
                        """
                    SELECT status, data_root_identity
                    FROM application_instances
                    WHERE instance_id = :instance_id
                    """
                    ),
                    {"instance_id": replacement_instance_id},
                )
                .mappings()
                .one_or_none()
            )
            if (
                replacement is None
                or replacement["status"] != "running"
                or replacement["data_root_identity"] != data_root_identity
            ):
                raise RecoveryStoreError(
                    "replacement instance identity is not active for this data root"
                )
            result = connection.execute(
                text(
                    """
                    UPDATE application_instances
                    SET status = 'crashed', stopped_at = :now,
                        record_version = record_version + 1
                    WHERE data_root_identity = :data_root_identity
                      AND instance_id != :replacement_instance_id
                      AND status = 'running'
                    """
                ),
                {
                    "data_root_identity": data_root_identity,
                    "now": _timestamp(now),
                    "replacement_instance_id": replacement_instance_id,
                },
            )
        return int(result.rowcount)

    def stop_instance(self, *, instance_id: str, now: datetime) -> None:
        with self._commit_gate.transaction(self._engine) as connection:
            result = connection.execute(
                text(
                    """
                    UPDATE application_instances
                    SET status = 'stopped', stopped_at = :now,
                        heartbeat_at = :now, record_version = record_version + 1
                    WHERE instance_id = :instance_id AND status = 'running'
                    """
                ),
                {"instance_id": instance_id, "now": _timestamp(now)},
            )
            if result.rowcount != 1:
                raise RecoveryStoreError("application instance cannot be stopped")

    def register_worker(
        self,
        *,
        instance_id: str,
        worker_id: str,
        worker_kind: str,
        pid: int,
        process_started_at: str | datetime,
        now: datetime,
    ) -> None:
        instant = _timestamp(now)
        with self._commit_gate.transaction(self._engine) as connection:
            try:
                connection.execute(
                    text(
                        """
                        INSERT INTO worker_processes (
                            worker_id, instance_id, worker_kind, pid,
                            process_started_at, status, heartbeat_at, stopped_at,
                            record_version
                        ) VALUES (
                            :worker_id, :instance_id, :worker_kind, :pid,
                            :process_started_at, 'ready', :now, NULL, 1
                        )
                        """
                    ),
                    {
                        "worker_id": worker_id,
                        "instance_id": instance_id,
                        "worker_kind": worker_kind,
                        "pid": pid,
                        "process_started_at": _process_identity(process_started_at),
                        "now": instant,
                    },
                )
            except IntegrityError as exc:
                raise RecoveryStoreError("worker identity is already registered") from exc

    def heartbeat_worker(
        self,
        *,
        instance_id: str,
        worker_id: str,
        now: datetime,
    ) -> None:
        with self._commit_gate.transaction(self._engine) as connection:
            result = connection.execute(
                text(
                    """
                    UPDATE worker_processes
                    SET heartbeat_at = :now, record_version = record_version + 1
                    WHERE worker_id = :worker_id
                      AND instance_id = :instance_id
                      AND status = 'ready'
                    """
                ),
                {
                    "instance_id": instance_id,
                    "worker_id": worker_id,
                    "now": _timestamp(now),
                },
            )
            if result.rowcount != 1:
                raise RecoveryStoreError("worker identity is not active")

    def acquire_lease(
        self,
        *,
        resource_name: str,
        slot_index: int,
        holder_kind: str,
        holder_id: str,
        instance_id: str,
        worker_id: str | None,
        now: datetime,
        ttl: timedelta,
    ) -> DurableLeaseGrant:
        if ttl <= timedelta(0):
            raise ValueError("lease TTL must be positive")
        acquired = _aware_utc(now)
        expires = acquired + ttl
        lease_id = secrets.token_hex(16)
        fencing_token = secrets.token_urlsafe(32)
        with self._commit_gate.transaction(self._engine) as connection:
            status = connection.execute(
                text(
                    """
                    SELECT status FROM application_instances
                    WHERE instance_id = :instance_id
                    """
                ),
                {"instance_id": instance_id},
            ).scalar_one_or_none()
            if status != "running":
                raise RecoveryStoreError("lease owner instance is not running")
            try:
                connection.execute(
                    text(
                        """
                        INSERT INTO leases (
                            lease_id, resource_name, slot_index, holder_kind,
                            holder_id, job_id, work_item_id, stage_attempt_id,
                            instance_id, worker_id, acquired_sequence,
                            released_sequence, acquired_at, heartbeat_at,
                            expires_at, released_at, generation, fencing_token,
                            release_reason, status
                        ) VALUES (
                            :lease_id, :resource_name, :slot_index, :holder_kind,
                            :holder_id, NULL, NULL, NULL, :instance_id, :worker_id,
                            0, NULL, :acquired_at, :heartbeat_at, :expires_at,
                            NULL, 1, :fencing_token, NULL, 'active'
                        )
                        """
                    ),
                    {
                        "lease_id": lease_id,
                        "resource_name": resource_name,
                        "slot_index": slot_index,
                        "holder_kind": holder_kind,
                        "holder_id": holder_id,
                        "instance_id": instance_id,
                        "worker_id": worker_id,
                        "acquired_at": _timestamp(acquired),
                        "heartbeat_at": _timestamp(acquired),
                        "expires_at": _timestamp(expires),
                        "fencing_token": _token_digest(fencing_token),
                    },
                )
            except IntegrityError as exc:
                raise RecoveryStoreError("resource slot already has an active lease") from exc
            row = (
                connection.execute(
                    text("SELECT * FROM leases WHERE lease_id = :lease_id"),
                    {"lease_id": lease_id},
                )
                .mappings()
                .one()
            )
        return _lease_from_row(row, fencing_token=fencing_token)

    def renew_lease(
        self,
        *,
        lease_id: str,
        instance_id: str,
        worker_id: str,
        fencing_token: str,
        now: datetime,
        ttl: timedelta,
    ) -> DurableLeaseGrant:
        if ttl <= timedelta(0):
            raise ValueError("lease TTL must be positive")
        instant = _aware_utc(now)
        expires = instant + ttl
        digest = _token_digest(fencing_token)
        with self._commit_gate.transaction(self._engine) as connection:
            result = connection.execute(
                text(
                    """
                    UPDATE leases
                    SET heartbeat_at = :heartbeat_at, expires_at = :expires_at
                    WHERE lease_id = :lease_id
                      AND instance_id = :instance_id
                      AND worker_id = :worker_id
                      AND fencing_token = :fencing_token
                      AND status = 'active'
                    """
                ),
                {
                    "heartbeat_at": _timestamp(instant),
                    "expires_at": _timestamp(expires),
                    "lease_id": lease_id,
                    "instance_id": instance_id,
                    "worker_id": worker_id,
                    "fencing_token": digest,
                },
            )
            if result.rowcount != 1:
                raise LeaseOwnershipError("lease owner or fencing token does not match")
            row = (
                connection.execute(
                    text("SELECT * FROM leases WHERE lease_id = :lease_id"),
                    {"lease_id": lease_id},
                )
                .mappings()
                .one()
            )
        return _lease_from_row(row, fencing_token=fencing_token)

    def takeover_expired_lease(
        self,
        *,
        lease_id: str,
        new_instance_id: str,
        data_root_identity: str,
        now: datetime,
        ttl: timedelta = timedelta(seconds=30),
    ) -> DurableLeaseGrant:
        if ttl <= timedelta(0):
            raise ValueError("lease TTL must be positive")
        instant = _aware_utc(now)
        new_token = secrets.token_urlsafe(32)
        replacement_id = secrets.token_hex(16)
        with self._commit_gate.transaction(self._engine) as connection:
            lease = (
                connection.execute(
                    text("SELECT * FROM leases WHERE lease_id = :lease_id"),
                    {"lease_id": lease_id},
                )
                .mappings()
                .one_or_none()
            )
            if lease is None or lease["status"] != "active":
                raise LeaseTakeoverRejected("lease is not active")
            if _parse_timestamp(lease["expires_at"]) > instant:
                raise LeaseTakeoverRejected("lease is not expired")

            old_instance_id = lease["instance_id"]
            if old_instance_id is None:
                raise LeaseTakeoverRejected("lease has no old instance identity")
            old_instance = (
                connection.execute(
                    text(
                        """
                    SELECT status, data_root_identity
                    FROM application_instances WHERE instance_id = :instance_id
                    """
                    ),
                    {"instance_id": old_instance_id},
                )
                .mappings()
                .one()
            )
            if old_instance["status"] not in {"stopped", "crashed"}:
                raise LeaseTakeoverRejected("old instance is still running")

            new_instance = (
                connection.execute(
                    text(
                        """
                    SELECT status, data_root_identity
                    FROM application_instances WHERE instance_id = :instance_id
                    """
                    ),
                    {"instance_id": new_instance_id},
                )
                .mappings()
                .one_or_none()
            )
            if new_instance is None or new_instance["status"] != "running":
                raise LeaseTakeoverRejected("new instance is not running")
            if (
                old_instance["data_root_identity"] != data_root_identity
                or new_instance["data_root_identity"] != data_root_identity
            ):
                raise LeaseTakeoverRejected("data root identity does not match")

            released = connection.execute(
                text(
                    """
                    UPDATE leases
                    SET status = 'expired', released_at = :now,
                        release_reason = 'taken_over'
                    WHERE lease_id = :lease_id AND status = 'active'
                    """
                ),
                {"lease_id": lease_id, "now": _timestamp(instant)},
            )
            if released.rowcount != 1:
                raise LeaseTakeoverRejected("lease changed during takeover")
            generation = int(lease["generation"]) + 1
            connection.execute(
                text(
                    """
                    INSERT INTO leases (
                        lease_id, resource_name, slot_index, holder_kind,
                        holder_id, job_id, work_item_id, stage_attempt_id,
                        instance_id, worker_id, acquired_sequence,
                        released_sequence, acquired_at, heartbeat_at,
                        expires_at, released_at, generation, fencing_token,
                        release_reason, status
                    ) VALUES (
                        :replacement_id, :resource_name, :slot_index,
                        :holder_kind, :holder_id, :job_id, :work_item_id,
                        :stage_attempt_id, :new_instance_id, :new_worker_id,
                        :acquired_sequence, NULL, :now, :now, :expires_at,
                        NULL, :generation, :fencing_token, NULL, 'active'
                    )
                    """
                ),
                {
                    "replacement_id": replacement_id,
                    "resource_name": lease["resource_name"],
                    "slot_index": lease["slot_index"],
                    "holder_kind": lease["holder_kind"],
                    "holder_id": lease["holder_id"],
                    "job_id": lease["job_id"],
                    "work_item_id": lease["work_item_id"],
                    "stage_attempt_id": lease["stage_attempt_id"],
                    "new_instance_id": new_instance_id,
                    "new_worker_id": f"recovery:{new_instance_id}",
                    "acquired_sequence": lease["acquired_sequence"],
                    "now": _timestamp(instant),
                    "expires_at": _timestamp(instant + ttl),
                    "generation": generation,
                    "fencing_token": _token_digest(new_token),
                },
            )
            row = (
                connection.execute(
                    text("SELECT * FROM leases WHERE lease_id = :lease_id"),
                    {"lease_id": replacement_id},
                )
                .mappings()
                .one()
            )
        return _lease_from_row(row, fencing_token=new_token)

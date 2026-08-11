from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import select
from sqlalchemy.engine import Connection, RowMapping

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    LOCKED_SET_REVIEW_IDEMPOTENCY,
    LOCKED_SET_REVIEW_ITEMS,
)


class LockedSetReviewPersistenceError(RuntimeError):
    """Base error for durable candidate-review operations."""


class LockedSetReviewIdempotencyConflictError(LockedSetReviewPersistenceError):
    """Raised when an idempotency key is reused for another review."""


class LockedSetReviewRecordVersionConflictError(LockedSetReviewPersistenceError):
    """Raised when a review write uses stale state."""


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class LockedSetReviewRecord:
    sample_id: str
    review_status: str
    decision: str
    review_payload: dict[str, object]
    record_version: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class LockedSetReviewIdempotencyRecord:
    idempotency_key: str
    sample_id: str
    request_hash: str
    resulting_record_version: int
    created_at: str


@dataclass(frozen=True, slots=True)
class LockedSetReviewAuthoritySnapshot:
    """Complete, deterministic review authority read from one transaction."""

    package_sha256: str
    latest_records: tuple[LockedSetReviewRecord, ...]
    history_records: tuple[LockedSetReviewRecord, ...]
    idempotency_records: tuple[LockedSetReviewIdempotencyRecord, ...]
    payload: dict[str, object]
    canonical_sha256: str


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise LockedSetReviewPersistenceError(
            "locked-set review authority contains invalid JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validate_text(
    value: str,
    *,
    label: str,
    maximum: int,
) -> None:
    if not value or value.strip() != value or len(value) > maximum:
        raise LockedSetReviewPersistenceError(f"stored locked-set review {label} is invalid")


def _validate_timestamp(value: str, *, label: str) -> datetime:
    _validate_text(value, label=label, maximum=40)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LockedSetReviewPersistenceError(
            f"stored locked-set review {label} is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LockedSetReviewPersistenceError(f"stored locked-set review {label} is invalid")
    return parsed


def _record_from_row(row: RowMapping) -> LockedSetReviewRecord:
    try:
        payload = json.loads(str(row["review_payload_json"]))
    except json.JSONDecodeError as exc:
        raise LockedSetReviewPersistenceError("stored locked-set review JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise LockedSetReviewPersistenceError("stored locked-set review must be an object")
    return LockedSetReviewRecord(
        sample_id=str(row["sample_id"]),
        review_status=str(row["review_status"]),
        decision=str(row["decision"]),
        review_payload=cast(dict[str, object], payload),
        record_version=int(row["record_version"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _idempotency_from_row(
    row: RowMapping,
) -> LockedSetReviewIdempotencyRecord:
    return LockedSetReviewIdempotencyRecord(
        idempotency_key=str(row["idempotency_key"]),
        sample_id=str(row["sample_id"]),
        request_hash=str(row["request_hash"]),
        resulting_record_version=int(row["resulting_record_version"]),
        created_at=str(row["created_at"]),
    )


def _validate_record(record: LockedSetReviewRecord) -> None:
    _validate_text(record.sample_id, label="sample ID", maximum=100)
    if (
        record.review_status not in {"confirmed", "replace_candidate"}
        or record.decision != record.review_status
    ):
        raise LockedSetReviewPersistenceError("stored locked-set review decision is invalid")
    if (
        isinstance(record.record_version, bool)
        or not isinstance(record.record_version, int)
        or record.record_version < 1
    ):
        raise LockedSetReviewPersistenceError("stored locked-set review record version is invalid")
    created_at = _validate_timestamp(
        record.created_at,
        label="creation time",
    )
    updated_at = _validate_timestamp(
        record.updated_at,
        label="update time",
    )
    if updated_at < created_at:
        raise LockedSetReviewPersistenceError(
            "stored locked-set review update time precedes creation time"
        )
    _canonical_json(record.review_payload)


def _validate_idempotency(
    record: LockedSetReviewIdempotencyRecord,
) -> None:
    _validate_text(
        record.idempotency_key,
        label="idempotency key",
        maximum=200,
    )
    _validate_text(record.sample_id, label="sample ID", maximum=100)
    if _SHA256_PATTERN.fullmatch(record.request_hash) is None:
        raise LockedSetReviewPersistenceError("stored locked-set review request hash is invalid")
    if (
        isinstance(record.resulting_record_version, bool)
        or not isinstance(record.resulting_record_version, int)
        or record.resulting_record_version < 1
    ):
        raise LockedSetReviewPersistenceError(
            "stored locked-set review idempotency version is invalid"
        )
    _validate_timestamp(
        record.created_at,
        label="idempotency creation time",
    )


def _record_payload(
    record: LockedSetReviewRecord,
) -> dict[str, object]:
    normalized_review_payload = json.loads(_canonical_json(record.review_payload))
    return {
        "sample_id": record.sample_id,
        "record_version": record.record_version,
        "review_status": record.review_status,
        "decision": record.decision,
        "review_payload": normalized_review_payload,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def _idempotency_payload(
    record: LockedSetReviewIdempotencyRecord,
) -> dict[str, object]:
    return {
        "sample_id": record.sample_id,
        "resulting_record_version": record.resulting_record_version,
        "idempotency_key": record.idempotency_key,
        "request_hash": record.request_hash,
        "created_at": record.created_at,
    }


class SqliteLockedSetReviewRepository:
    """Persist direct human reviews without mutating the source package."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        package_sha256: str,
    ) -> None:
        if _SHA256_PATTERN.fullmatch(package_sha256) is None:
            raise ValueError("package_sha256 must be a lowercase SHA-256")
        self.runtime = runtime
        self.package_sha256 = package_sha256

    def _get(
        self,
        connection: Connection,
        sample_id: str,
        *,
        record_version: int | None = None,
    ) -> LockedSetReviewRecord | None:
        statement = select(LOCKED_SET_REVIEW_ITEMS).where(
            LOCKED_SET_REVIEW_ITEMS.c.package_sha256 == self.package_sha256,
            LOCKED_SET_REVIEW_ITEMS.c.sample_id == sample_id,
        )
        if record_version is None:
            statement = statement.order_by(LOCKED_SET_REVIEW_ITEMS.c.record_version.desc()).limit(1)
        else:
            statement = statement.where(LOCKED_SET_REVIEW_ITEMS.c.record_version == record_version)
        row = connection.execute(statement).mappings().one_or_none()
        return None if row is None else _record_from_row(row)

    def get(self, sample_id: str) -> LockedSetReviewRecord | None:
        with self.runtime.engine.connect() as connection:
            return self._get(connection, sample_id)

    def list_records(self) -> tuple[LockedSetReviewRecord, ...]:
        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    select(LOCKED_SET_REVIEW_ITEMS)
                    .where(LOCKED_SET_REVIEW_ITEMS.c.package_sha256 == self.package_sha256)
                    .order_by(
                        LOCKED_SET_REVIEW_ITEMS.c.sample_id,
                        LOCKED_SET_REVIEW_ITEMS.c.record_version,
                    )
                )
                .mappings()
                .all()
            )
        latest: dict[str, LockedSetReviewRecord] = {}
        for row in rows:
            record = _record_from_row(row)
            latest[record.sample_id] = record
        return tuple(latest[key] for key in sorted(latest))

    def build_authority_snapshot(
        self,
    ) -> LockedSetReviewAuthoritySnapshot:
        """Read and validate all review authority without writing state."""

        with self.runtime.engine.connect() as connection, connection.begin():
            history_rows = (
                connection.execute(
                    select(LOCKED_SET_REVIEW_ITEMS)
                    .where(LOCKED_SET_REVIEW_ITEMS.c.package_sha256 == self.package_sha256)
                    .order_by(
                        LOCKED_SET_REVIEW_ITEMS.c.sample_id,
                        LOCKED_SET_REVIEW_ITEMS.c.record_version,
                    )
                )
                .mappings()
                .all()
            )
            idempotency_rows = (
                connection.execute(
                    select(LOCKED_SET_REVIEW_IDEMPOTENCY)
                    .where(LOCKED_SET_REVIEW_IDEMPOTENCY.c.package_sha256 == self.package_sha256)
                    .order_by(
                        LOCKED_SET_REVIEW_IDEMPOTENCY.c.sample_id,
                        LOCKED_SET_REVIEW_IDEMPOTENCY.c.resulting_record_version,
                        LOCKED_SET_REVIEW_IDEMPOTENCY.c.idempotency_key,
                    )
                )
                .mappings()
                .all()
            )

        history_records = tuple(_record_from_row(row) for row in history_rows)
        idempotency_records = tuple(_idempotency_from_row(row) for row in idempotency_rows)
        by_sample: dict[str, list[LockedSetReviewRecord]] = {}
        history_keys: set[tuple[str, int]] = set()
        for history_record in history_records:
            _validate_record(history_record)
            by_sample.setdefault(
                history_record.sample_id,
                [],
            ).append(history_record)
            history_keys.add(
                (
                    history_record.sample_id,
                    history_record.record_version,
                )
            )

        for sample_id, records in by_sample.items():
            versions = [record.record_version for record in records]
            expected = list(range(1, len(records) + 1))
            if versions != expected:
                raise LockedSetReviewPersistenceError(
                    f"locked-set review versions must be consecutive from 1 for sample {sample_id}"
                )

        idempotency_by_target: dict[
            tuple[str, int],
            LockedSetReviewIdempotencyRecord,
        ] = {}
        for idempotency_record in idempotency_records:
            _validate_idempotency(idempotency_record)
            target = (
                idempotency_record.sample_id,
                idempotency_record.resulting_record_version,
            )
            if target not in history_keys:
                raise LockedSetReviewPersistenceError(
                    "locked-set review idempotency evidence has no review version"
                )
            if target in idempotency_by_target:
                raise LockedSetReviewPersistenceError(
                    "locked-set review version has duplicate idempotency evidence"
                )
            idempotency_by_target[target] = idempotency_record

        if history_keys != set(idempotency_by_target):
            raise LockedSetReviewPersistenceError(
                "locked-set review version has no idempotency evidence"
            )

        latest_records = tuple(by_sample[sample_id][-1] for sample_id in sorted(by_sample))
        payload: dict[str, object] = {
            "schema_version": 1,
            "kind": "locked_set_review_authority_snapshot",
            "package_sha256": self.package_sha256,
            "sample_count": len(latest_records),
            "latest_record_count": len(latest_records),
            "history_record_count": len(history_records),
            "idempotency_record_count": len(idempotency_records),
            "latest_records": [_record_payload(record) for record in latest_records],
            "history_records": [_record_payload(record) for record in history_records],
            "idempotency_records": [_idempotency_payload(record) for record in idempotency_records],
        }
        return LockedSetReviewAuthoritySnapshot(
            package_sha256=self.package_sha256,
            latest_records=latest_records,
            history_records=history_records,
            idempotency_records=idempotency_records,
            payload=payload,
            canonical_sha256=_canonical_sha256(payload),
        )

    def save(
        self,
        *,
        sample_id: str,
        review_status: str,
        decision: str,
        review_payload: Mapping[str, object],
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[LockedSetReviewRecord, bool]:
        if review_status not in {"confirmed", "replace_candidate"}:
            raise ValueError("review status is invalid")
        if decision != review_status:
            raise ValueError("review decision and status must match")
        payload_json = json.dumps(
            dict(review_payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = (
                connection.execute(
                    select(LOCKED_SET_REVIEW_IDEMPOTENCY).where(
                        LOCKED_SET_REVIEW_IDEMPOTENCY.c.package_sha256 == self.package_sha256,
                        LOCKED_SET_REVIEW_IDEMPOTENCY.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if (
                    str(replay["request_hash"]) != request_hash
                    or str(replay["sample_id"]) != sample_id
                ):
                    raise LockedSetReviewIdempotencyConflictError(
                        "idempotency key belongs to different review input"
                    )
                record = self._get(
                    connection,
                    sample_id,
                    record_version=int(replay["resulting_record_version"]),
                )
                if record is None:
                    raise LockedSetReviewPersistenceError("idempotency record has no review result")
                return record, False

            current = self._get(connection, sample_id)
            current_version = 0 if current is None else current.record_version
            if current_version != expected_record_version:
                raise LockedSetReviewRecordVersionConflictError(
                    "locked-set review record version is stale"
                )
            next_version = current_version + 1
            connection.execute(
                LOCKED_SET_REVIEW_ITEMS.insert().values(
                    package_sha256=self.package_sha256,
                    sample_id=sample_id,
                    review_status=review_status,
                    decision=decision,
                    review_payload_json=payload_json,
                    record_version=next_version,
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                LOCKED_SET_REVIEW_IDEMPOTENCY.insert().values(
                    package_sha256=self.package_sha256,
                    idempotency_key=idempotency_key,
                    sample_id=sample_id,
                    request_hash=request_hash,
                    resulting_record_version=next_version,
                    created_at=now,
                )
            )
            saved = self._get(
                connection,
                sample_id,
                record_version=next_version,
            )
            if saved is None:
                raise LockedSetReviewPersistenceError("locked-set review was not persisted")
            return saved, True

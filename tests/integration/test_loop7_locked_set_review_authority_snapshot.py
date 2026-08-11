from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.engine import Connection

from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewPersistenceError,
    SqliteLockedSetReviewRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    LOCKED_SET_REVIEW_IDEMPOTENCY,
    LOCKED_SET_REVIEW_ITEMS,
)

pytestmark = pytest.mark.integration

PACKAGE_SHA256 = "a" * 64


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@pytest.fixture
def runtime(tmp_path: Path, project_root: Path) -> Iterator[SqliteRuntime]:
    opened = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="loop7-review-authority-test",
    )
    try:
        yield opened
    finally:
        opened.close()


def _repository(runtime: SqliteRuntime) -> SqliteLockedSetReviewRepository:
    return SqliteLockedSetReviewRepository(
        runtime=runtime,
        package_sha256=PACKAGE_SHA256,
    )


def _save(
    repository: SqliteLockedSetReviewRepository,
    *,
    sample_id: str,
    expected_record_version: int,
    marker: str,
) -> None:
    repository.save(
        sample_id=sample_id,
        review_status="confirmed",
        decision="confirmed",
        review_payload={
            "decision": "confirmed",
            "marker": marker,
            "reviewer_id": "operator-a",
        },
        expected_record_version=expected_record_version,
        idempotency_key=f"{sample_id}-v{expected_record_version + 1}",
        request_hash=hashlib.sha256(marker.encode("utf-8")).hexdigest(),
    )


def _row_counts(runtime: SqliteRuntime) -> tuple[int, int]:
    with runtime.engine.connect() as connection:
        review_count = connection.execute(
            select(func.count()).select_from(LOCKED_SET_REVIEW_ITEMS)
        ).scalar_one()
        idempotency_count = connection.execute(
            select(func.count()).select_from(LOCKED_SET_REVIEW_IDEMPOTENCY)
        ).scalar_one()
    return int(review_count), int(idempotency_count)


def test_builds_deterministic_read_only_complete_authority_snapshot(
    runtime: SqliteRuntime,
) -> None:
    repository = _repository(runtime)
    _save(
        repository,
        sample_id="L7-002",
        expected_record_version=0,
        marker="sample-2-v1",
    )
    _save(
        repository,
        sample_id="L7-001",
        expected_record_version=0,
        marker="sample-1-v1",
    )
    _save(
        repository,
        sample_id="L7-001",
        expected_record_version=1,
        marker="sample-1-v2",
    )
    before = _row_counts(runtime)

    observed_sql: list[tuple[int, bool, str]] = []

    def observe_read_transaction(
        connection: Connection,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "locked_set_review_" in statement:
            observed_sql.append(
                (
                    id(connection),
                    connection.in_transaction(),
                    statement.lstrip().split(maxsplit=1)[0].upper(),
                )
            )

    event.listen(
        runtime.engine,
        "before_cursor_execute",
        observe_read_transaction,
    )
    try:
        first = repository.build_authority_snapshot()
    finally:
        event.remove(
            runtime.engine,
            "before_cursor_execute",
            observe_read_transaction,
        )
    second = repository.build_authority_snapshot()

    assert first == second
    assert observed_sql
    assert len({connection_id for connection_id, _, _ in observed_sql}) == 1
    assert all(in_transaction for _, in_transaction, _ in observed_sql)
    assert {operation for _, _, operation in observed_sql} == {"SELECT"}
    assert _row_counts(runtime) == before == (3, 3)
    assert first.package_sha256 == PACKAGE_SHA256
    assert [(record.sample_id, record.record_version) for record in first.latest_records] == [
        ("L7-001", 2),
        ("L7-002", 1),
    ]
    assert [(record.sample_id, record.record_version) for record in first.history_records] == [
        ("L7-001", 1),
        ("L7-001", 2),
        ("L7-002", 1),
    ]
    assert [
        (
            record.sample_id,
            record.resulting_record_version,
            record.idempotency_key,
        )
        for record in first.idempotency_records
    ] == [
        ("L7-001", 1, "L7-001-v1"),
        ("L7-001", 2, "L7-001-v2"),
        ("L7-002", 1, "L7-002-v1"),
    ]

    payload = first.payload
    assert payload["schema_version"] == 1
    assert payload["kind"] == "locked_set_review_authority_snapshot"
    assert payload["package_sha256"] == PACKAGE_SHA256
    assert payload["sample_count"] == 2
    assert payload["latest_record_count"] == 2
    assert payload["history_record_count"] == 3
    assert payload["idempotency_record_count"] == 3
    assert [
        (record["sample_id"], record["record_version"]) for record in payload["latest_records"]
    ] == [("L7-001", 2), ("L7-002", 1)]
    assert [
        (record["sample_id"], record["record_version"]) for record in payload["history_records"]
    ] == [("L7-001", 1), ("L7-001", 2), ("L7-002", 1)]
    assert first.canonical_sha256 == _canonical_sha256(payload)


def test_rejects_a_gap_in_any_sample_history(
    runtime: SqliteRuntime,
) -> None:
    repository = _repository(runtime)
    _save(
        repository,
        sample_id="L7-001",
        expected_record_version=0,
        marker="sample-1-v1",
    )
    with runtime.engine.begin() as connection:
        connection.execute(
            LOCKED_SET_REVIEW_ITEMS.insert().values(
                package_sha256=PACKAGE_SHA256,
                sample_id="L7-001",
                review_status="confirmed",
                decision="confirmed",
                review_payload_json='{"decision":"confirmed"}',
                record_version=3,
                created_at="2026-07-26T00:03:00+00:00",
                updated_at="2026-07-26T00:03:00+00:00",
            )
        )
        connection.execute(
            LOCKED_SET_REVIEW_IDEMPOTENCY.insert().values(
                package_sha256=PACKAGE_SHA256,
                idempotency_key="L7-001-v3",
                sample_id="L7-001",
                request_hash="3" * 64,
                resulting_record_version=3,
                created_at="2026-07-26T00:03:00+00:00",
            )
        )

    with pytest.raises(
        LockedSetReviewPersistenceError,
        match="versions must be consecutive from 1",
    ):
        repository.build_authority_snapshot()


def test_rejects_missing_idempotency_evidence(
    runtime: SqliteRuntime,
) -> None:
    repository = _repository(runtime)
    _save(
        repository,
        sample_id="L7-001",
        expected_record_version=0,
        marker="sample-1-v1",
    )
    with runtime.engine.begin() as connection:
        connection.execute(LOCKED_SET_REVIEW_IDEMPOTENCY.delete())

    with pytest.raises(
        LockedSetReviewPersistenceError,
        match="review version has no idempotency evidence",
    ):
        repository.build_authority_snapshot()


def test_rejects_duplicate_idempotency_evidence_for_one_version(
    runtime: SqliteRuntime,
) -> None:
    repository = _repository(runtime)
    _save(
        repository,
        sample_id="L7-001",
        expected_record_version=0,
        marker="sample-1-v1",
    )
    with runtime.engine.begin() as connection:
        connection.execute(
            LOCKED_SET_REVIEW_IDEMPOTENCY.insert().values(
                package_sha256=PACKAGE_SHA256,
                idempotency_key="duplicate-key",
                sample_id="L7-001",
                request_hash="d" * 64,
                resulting_record_version=1,
                created_at="2026-07-26T00:01:00+00:00",
            )
        )

    with pytest.raises(
        LockedSetReviewPersistenceError,
        match="review version has duplicate idempotency evidence",
    ):
        repository.build_authority_snapshot()


def test_rejects_dangling_idempotency_evidence(
    runtime: SqliteRuntime,
) -> None:
    repository = _repository(runtime)
    _save(
        repository,
        sample_id="L7-001",
        expected_record_version=0,
        marker="sample-1-v1",
    )
    with sqlite3.connect(runtime.database_path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            """
            INSERT INTO locked_set_review_idempotency (
                package_sha256,
                idempotency_key,
                sample_id,
                request_hash,
                resulting_record_version,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                PACKAGE_SHA256,
                "dangling-key",
                "L7-999",
                "f" * 64,
                1,
                "2026-07-26T00:01:00+00:00",
            ),
        )

    with pytest.raises(
        LockedSetReviewPersistenceError,
        match="idempotency evidence has no review version",
    ):
        repository.build_authority_snapshot()

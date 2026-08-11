from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dahe.adapters.sqlite.platform_access import (
    PlatformAccessConflictError,
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
)

PROJECT_ROOT = Path(__file__).parents[2]
BUILD_SHA256 = hashlib.sha256(b"loop9-build").hexdigest()


def _runtime(tmp_path: Path, *, instance_id: str) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
    )


def _issue(
    repository: SqlitePlatformAccessRepository,
    *,
    idempotency_key: str = "access-window-1",
    request_hash: str | None = None,
    now: datetime,
):
    return repository.issue(
        purpose=AccessPurpose.CONTRACT_DISCOVERY,
        job_id="job-discovery-1",
        session_id="browser-session-1",
        build_sha256=BUILD_SHA256,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key=idempotency_key,
        request_hash=request_hash or hashlib.sha256(b"request-1").hexdigest(),
        now=now,
    )


def test_access_window_is_durable_but_raw_token_is_not_persisted(
    tmp_path: Path,
) -> None:
    issued_at = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
    first_runtime = _runtime(tmp_path, instance_id="first")
    first_repository = SqlitePlatformAccessRepository(first_runtime)
    grant, replay = _issue(first_repository, now=issued_at)
    assert replay is False
    assert grant.token
    raw_token = grant.token
    first_runtime.close()

    database_bytes = (tmp_path / "data" / "database" / "dahe.sqlite3").read_bytes()
    assert raw_token.encode("utf-8") not in database_bytes

    second_runtime = _runtime(tmp_path, instance_id="second")
    try:
        second_repository = SqlitePlatformAccessRepository(second_runtime)
        restored = second_repository.get(grant.access_window_id)
        assert restored.token == ""
        assert restored.to_persisted_payload() == grant.to_persisted_payload()
        second_repository.authorize(
            access_window_id=grant.access_window_id,
            purpose=AccessPurpose.CONTRACT_DISCOVERY,
            job_id="job-discovery-1",
            session_id="browser-session-1",
            build_sha256=BUILD_SHA256,
            now=issued_at + timedelta(minutes=30),
        )
    finally:
        second_runtime.close()


def test_issue_is_idempotent_and_rejects_key_reuse(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
    runtime = _runtime(tmp_path, instance_id="idempotency")
    try:
        repository = SqlitePlatformAccessRepository(runtime)
        first, first_replay = _issue(repository, now=now)
        second, second_replay = _issue(repository, now=now)
        assert first_replay is False
        assert second_replay is True
        assert second.access_window_id == first.access_window_id
        assert second.token == ""

        with pytest.raises(PlatformAccessConflictError, match="idempotency"):
            _issue(
                repository,
                request_hash=hashlib.sha256(b"different").hexdigest(),
                now=now,
            )
    finally:
        runtime.close()


def test_issue_rejects_overlapping_unconsumed_window_for_same_session(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
    runtime = _runtime(tmp_path, instance_id="overlap")
    try:
        repository = SqlitePlatformAccessRepository(runtime)
        first, _ = _issue(repository, now=now)

        with pytest.raises(
            PlatformAccessConflictError,
            match="unconsumed access window",
        ):
            _issue(
                repository,
                idempotency_key="access-window-overlap",
                request_hash=hashlib.sha256(b"overlap").hexdigest(),
                now=now + timedelta(minutes=1),
            )

        repository.consume(
            access_window_id=first.access_window_id,
            expected_record_version=1,
            now=now + timedelta(minutes=2),
        )
        second, replay = _issue(
            repository,
            idempotency_key="access-window-after-consume",
            request_hash=hashlib.sha256(b"after-consume").hexdigest(),
            now=now + timedelta(minutes=3),
        )
        assert replay is False
        assert second.access_window_id != first.access_window_id
    finally:
        runtime.close()


def test_consume_is_versioned_and_permanently_blocks_authorization(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
    runtime = _runtime(tmp_path, instance_id="consume")
    try:
        repository = SqlitePlatformAccessRepository(runtime)
        grant, _ = _issue(repository, now=now)
        consumed = repository.consume(
            access_window_id=grant.access_window_id,
            expected_record_version=1,
            now=now + timedelta(minutes=1),
        )
        assert consumed.consumed_at == now + timedelta(minutes=1)

        with pytest.raises(PlatformAccessConflictError, match="version"):
            repository.consume(
                access_window_id=grant.access_window_id,
                expected_record_version=1,
                now=now + timedelta(minutes=2),
            )
        with pytest.raises(AccessWindowError, match="consumed"):
            repository.authorize(
                access_window_id=grant.access_window_id,
                purpose=AccessPurpose.CONTRACT_DISCOVERY,
                job_id="job-discovery-1",
                session_id="browser-session-1",
                build_sha256=BUILD_SHA256,
                now=now + timedelta(minutes=2),
            )
    finally:
        runtime.close()


def test_retire_invalidates_an_expired_window_idempotently(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
    runtime = _runtime(tmp_path, instance_id="retire-expired")
    try:
        repository = SqlitePlatformAccessRepository(runtime)
        grant, _ = _issue(repository, now=now)
        retired = repository.retire(
            access_window_id=grant.access_window_id,
            expected_record_version=1,
            now=now + timedelta(minutes=61),
        )
        replay = repository.retire(
            access_window_id=grant.access_window_id,
            expected_record_version=1,
            now=now + timedelta(minutes=62),
        )

        assert retired.consumed_at == now + timedelta(minutes=61)
        assert replay == retired
        with runtime.engine.connect() as connection:
            events = tuple(
                connection.exec_driver_sql(
                    """
                    SELECT event_type
                    FROM platform_access_events
                    WHERE access_window_id = ?
                    ORDER BY record_version
                    """,
                    (grant.access_window_id,),
                ).scalars()
            )
        assert events == ("issued", "consumed")
    finally:
        runtime.close()


def test_access_window_rows_and_events_have_no_human_identity_fields(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, instance_id="identity-contract")
    try:
        forbidden = {
            "operator",
            "operator_id",
            "reviewer",
            "reviewer_id",
            "actor",
            "actor_id",
            "employee_id",
            "windows_sid",
        }
        with runtime.engine.connect() as connection:
            for table_name in ("platform_access_windows", "platform_access_events"):
                columns = {
                    str(row[1]).lower()
                    for row in connection.exec_driver_sql(
                        f"PRAGMA table_info({table_name})"
                    )
                }
                assert columns.isdisjoint(forbidden)
    finally:
        runtime.close()

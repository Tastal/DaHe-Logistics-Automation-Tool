from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.engine import Connection, Engine

import dahe.adapters.sqlite.loop3_resource_store as resource_store_module
from dahe.adapters.fake.loop3 import get_loop3_fixture
from dahe.adapters.sqlite.loop3_resource_store import SchedulerLeaseFencingError
from dahe.adapters.sqlite.repository import TemporarySqliteJobRepository
from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    LEASES,
    SHARED_EVIDENCE_WORK,
    STAGE_ATTEMPTS,
)
from dahe.jobs.scheduler import CooperativeScheduler

pytestmark = pytest.mark.integration

RAW_FENCING_TOKEN = "loop4-process-local-raw-fencing-token"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _create_job(repository: TemporarySqliteJobRepository) -> None:
    _, created = repository.create_scheduled_job(
        fixture=get_loop3_fixture("audit-batch-short-002"),
        scope_label="Loop 4 scheduler fencing",
        idempotency_key="loop4-scheduler-fencing",  # gitleaks:allow
        request_hash="loop4-scheduler-fencing-request",
        expected_record_version=0,
    )
    assert created is True


def _running_shared_attempt(
    repository: TemporarySqliteJobRepository,
) -> dict[str, object]:
    with repository.engine.connect() as connection:
        row = (
            connection.execute(
                select(
                    STAGE_ATTEMPTS.c.stage_attempt_id,
                    STAGE_ATTEMPTS.c.owner_id,
                    STAGE_ATTEMPTS.c.stage,
                    STAGE_ATTEMPTS.c.status.label("attempt_status"),
                    LEASES.c.lease_id,
                    LEASES.c.resource_name,
                    LEASES.c.slot_index,
                    LEASES.c.holder_kind,
                    LEASES.c.holder_id,
                    LEASES.c.job_id,
                    LEASES.c.work_item_id,
                    LEASES.c.instance_id,
                    LEASES.c.worker_id,
                    LEASES.c.acquired_sequence,
                    LEASES.c.acquired_at,
                    LEASES.c.heartbeat_at,
                    LEASES.c.expires_at,
                    LEASES.c.generation,
                    LEASES.c.fencing_token,
                    LEASES.c.status.label("lease_status"),
                )
                .join(
                    LEASES,
                    LEASES.c.stage_attempt_id == STAGE_ATTEMPTS.c.stage_attempt_id,
                )
                .where(
                    STAGE_ATTEMPTS.c.owner_kind == "shared_evidence",
                    STAGE_ATTEMPTS.c.status == "running",
                    LEASES.c.status == "active",
                )
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        raise LookupError("no running shared attempt")
    return dict(row)


def _start_shared_attempt(
    repository: TemporarySqliteJobRepository,
) -> dict[str, object]:
    scheduler = CooperativeScheduler(repository)
    for _ in range(10):
        scheduler.tick()
        try:
            return _running_shared_attempt(repository)
        except LookupError:
            continue
    raise AssertionError("shared fake OCR attempt did not start")


def _database_snapshot(
    repository: TemporarySqliteJobRepository,
) -> dict[str, tuple[tuple[object, ...], ...]]:
    with repository.engine.connect() as connection:
        table_names = tuple(
            str(name)
            for (name,) in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        )
        return {
            name: tuple(
                tuple(row)
                for row in connection.exec_driver_sql(f'SELECT * FROM "{name}" ORDER BY rowid')
            )
            for name in table_names
        }


@pytest.fixture
def fenced_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TemporarySqliteJobRepository]:
    monkeypatch.setattr(
        resource_store_module.secrets,
        "token_urlsafe",
        lambda _: RAW_FENCING_TOKEN,
    )
    repository = TemporarySqliteJobRepository(tmp_path)
    try:
        _create_job(repository)
        yield repository
    finally:
        repository.close()


def _assert_rejected_without_writes(
    repository: TemporarySqliteJobRepository,
) -> None:
    before = _database_snapshot(repository)
    with pytest.raises(SchedulerLeaseFencingError):
        repository.scheduler_tick(set())
    assert _database_snapshot(repository) == before


def test_valid_process_local_fencing_token_commits_atomic_result(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)

    assert attempt["fencing_token"] == _digest(RAW_FENCING_TOKEN)
    assert attempt["fencing_token"] != RAW_FENCING_TOKEN

    fenced_repository.scheduler_tick(set())

    with fenced_repository.engine.connect() as connection:
        attempt_status = connection.execute(
            select(STAGE_ATTEMPTS.c.status).where(
                STAGE_ATTEMPTS.c.stage_attempt_id == attempt["stage_attempt_id"]
            )
        ).scalar_one()
        lease_status = connection.execute(
            select(LEASES.c.status).where(LEASES.c.lease_id == attempt["lease_id"])
        ).scalar_one()
        shared_status = connection.execute(
            select(SHARED_EVIDENCE_WORK.c.status).where(
                SHARED_EVIDENCE_WORK.c.shared_work_id == attempt["owner_id"]
            )
        ).scalar_one()
        committed_checkpoints = connection.execute(
            select(func.count())
            .select_from(CHECKPOINTS)
            .where(
                CHECKPOINTS.c.owner_kind == "shared_evidence",
                CHECKPOINTS.c.owner_id == attempt["owner_id"],
                CHECKPOINTS.c.stage == "audit.recognize",
            )
        ).scalar_one()

    assert attempt_status == "succeeded"
    assert lease_status == "released"
    assert shared_status == "succeeded"
    assert committed_checkpoints == 1


def test_old_fencing_token_is_rejected_without_any_result_write(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)
    with fenced_repository.commit_gate.transaction(fenced_repository.engine) as connection:
        connection.execute(
            update(LEASES)
            .where(LEASES.c.lease_id == attempt["lease_id"])
            .values(fencing_token=_digest("replacement-token"))
        )

    _assert_rejected_without_writes(fenced_repository)


def test_old_lease_generation_is_rejected_without_any_result_write(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)
    with fenced_repository.commit_gate.transaction(fenced_repository.engine) as connection:
        connection.execute(
            update(LEASES)
            .where(LEASES.c.lease_id == attempt["lease_id"])
            .values(generation=int(attempt["generation"]) + 1)
        )

    _assert_rejected_without_writes(fenced_repository)


@pytest.mark.parametrize("identity_field", ("instance_id", "worker_id"))
def test_wrong_process_identity_is_rejected_without_any_result_write(
    fenced_repository: TemporarySqliteJobRepository,
    identity_field: str,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)
    resource_store = fenced_repository._loop3._resources
    (grant,) = tuple(
        grant
        for grant in resource_store.process_grants()
        if grant.stage_attempt_id == attempt["stage_attempt_id"]
    )
    resource_store.remember_process_grants(
        (replace(grant, **{identity_field: f"wrong-{identity_field}"}),)
    )

    _assert_rejected_without_writes(fenced_repository)


def test_released_lease_is_rejected_without_any_result_write(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)
    with fenced_repository.commit_gate.transaction(fenced_repository.engine) as connection:
        connection.execute(
            update(LEASES)
            .where(LEASES.c.lease_id == attempt["lease_id"])
            .values(
                status="released",
                released_at=datetime.now(UTC).isoformat(),
                release_reason="test_release",
            )
        )

    _assert_rejected_without_writes(fenced_repository)


def test_expired_lease_is_rejected_without_any_result_write(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)
    with fenced_repository.commit_gate.transaction(fenced_repository.engine) as connection:
        connection.execute(
            update(LEASES)
            .where(LEASES.c.lease_id == attempt["lease_id"])
            .values(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())
        )

    _assert_rejected_without_writes(fenced_repository)


def test_takeover_permanently_fences_the_old_process_token(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    attempt = _start_shared_attempt(fenced_repository)
    now = datetime.now(UTC)
    with fenced_repository.commit_gate.transaction(fenced_repository.engine) as connection:
        connection.execute(
            update(LEASES)
            .where(LEASES.c.lease_id == attempt["lease_id"])
            .values(
                status="expired",
                released_at=now.isoformat(),
                release_reason="taken_over",
            )
        )
        connection.execute(
            LEASES.insert().values(
                lease_id=uuid4().hex,
                resource_name=attempt["resource_name"],
                slot_index=attempt["slot_index"],
                holder_kind=attempt["holder_kind"],
                holder_id=attempt["holder_id"],
                job_id=attempt["job_id"],
                work_item_id=attempt["work_item_id"],
                stage_attempt_id=attempt["stage_attempt_id"],
                instance_id=attempt["instance_id"],
                worker_id=attempt["worker_id"],
                acquired_sequence=attempt["acquired_sequence"],
                acquired_at=now.isoformat(),
                heartbeat_at=now.isoformat(),
                expires_at=(now + timedelta(seconds=30)).isoformat(),
                generation=int(attempt["generation"]) + 1,
                fencing_token=_digest("takeover-token"),
                status="active",
            )
        )

    _assert_rejected_without_writes(fenced_repository)
    _assert_rejected_without_writes(fenced_repository)


class _RollbackAfterPublishGate:
    @contextmanager
    def transaction(self, engine: Engine) -> Iterator[Connection]:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                yield connection
            except BaseException:
                transaction.rollback()
                raise
            else:
                transaction.rollback()
                raise RuntimeError("simulated commit boundary failure")


class _CommitThenRaiseGate:
    @contextmanager
    def transaction(self, engine: Engine) -> Iterator[Connection]:
        with engine.begin() as connection:
            yield connection
        raise RuntimeError("simulated post-commit context failure")


def test_publish_before_commit_rollback_leaves_neither_lease_nor_raw_grant(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    scheduler_store = fenced_repository._loop3._scheduler
    resource_store = fenced_repository._loop3._resources
    scheduler_store._commit_gate = _RollbackAfterPublishGate()

    with pytest.raises(RuntimeError, match="simulated commit boundary failure"):
        fenced_repository.scheduler_tick(set())

    with fenced_repository.engine.connect() as connection:
        active_lease_count = connection.execute(
            select(func.count()).select_from(LEASES).where(LEASES.c.status == "active")
        ).scalar_one()
        attempt_count = connection.execute(
            select(func.count()).select_from(STAGE_ATTEMPTS)
        ).scalar_one()

    assert active_lease_count == 0
    assert attempt_count == 0
    assert resource_store.process_grants() == ()


def test_post_commit_context_failure_reconciles_to_the_committed_active_grant(
    fenced_repository: TemporarySqliteJobRepository,
) -> None:
    scheduler_store = fenced_repository._loop3._scheduler
    resource_store = fenced_repository._loop3._resources
    fenced_repository.scheduler_tick(set())
    (old_grant,) = resource_store.process_grants()
    scheduler_store._commit_gate = _CommitThenRaiseGate()

    with pytest.raises(RuntimeError, match="simulated post-commit context failure"):
        fenced_repository.scheduler_tick(set())

    with fenced_repository.engine.connect() as connection:
        old_attempt_status = connection.execute(
            select(STAGE_ATTEMPTS.c.status).where(
                STAGE_ATTEMPTS.c.stage_attempt_id == old_grant.stage_attempt_id
            )
        ).scalar_one()
        old_lease_status = connection.execute(
            select(LEASES.c.status).where(LEASES.c.lease_id == old_grant.lease_id)
        ).scalar_one()
        active_attempt_ids = {
            str(stage_attempt_id)
            for (stage_attempt_id,) in connection.execute(
                select(LEASES.c.stage_attempt_id).where(LEASES.c.status == "active")
            )
        }

    process_attempt_ids = {grant.stage_attempt_id for grant in resource_store.process_grants()}
    assert old_attempt_status == "succeeded"
    assert old_lease_status == "released"
    assert active_attempt_ids
    assert process_attempt_ids == active_attempt_ids
    assert old_grant.stage_attempt_id not in process_attempt_ids

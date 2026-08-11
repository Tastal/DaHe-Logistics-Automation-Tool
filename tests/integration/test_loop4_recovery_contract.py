from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from dahe.adapters.fake.loop3 import get_loop3_fixture
from dahe.adapters.sqlite.browser_control import (
    BrowserControlError,
    BrowserControlStore,
    NavigationRejectedError,
    RecoveryProofMissingError,
)
from dahe.adapters.sqlite.recovery import (
    LeaseOwnershipError,
    LeaseTakeoverRejected,
    PersistentRecoveryStore,
    RecoveryStoreError,
)
from dahe.adapters.sqlite.repository import (
    SqliteJobRepository,
    TemporarySqliteJobRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.jobs.scheduler import CooperativeScheduler

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 7, 25, 6, 0, tzinfo=UTC)
LEASE_TTL = timedelta(seconds=10)


def _data_root_identity(data_root: Path) -> str:
    canonical = str(data_root.resolve()).casefold().encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _open_runtime(
    data_root: Path,
    *,
    instance_id: str,
) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
    )


def _register_instance(
    store: PersistentRecoveryStore,
    *,
    instance_id: str,
    data_root_identity: str,
    now: datetime,
    pid: int,
) -> None:
    store.register_instance(
        instance_id=instance_id,
        data_root_identity=data_root_identity,
        pid=pid,
        process_started_at=now,
        application_version="0.6.0",
        port=8877,
        now=now,
    )


def _acquire_test_lease(
    store: PersistentRecoveryStore,
    *,
    instance_id: str,
    now: datetime,
    worker_id: str,
) -> object:
    return store.acquire_lease(
        resource_name="gpu_ocr_slot",
        slot_index=0,
        holder_kind="worker",
        holder_id=worker_id,
        instance_id=instance_id,
        worker_id=worker_id,
        now=now,
        ttl=LEASE_TTL,
    )


def test_restart_does_not_commit_a_legacy_running_attempt_as_success(
    tmp_path: Path,
) -> None:
    """A process restart may discard an uncommitted attempt, never bless it."""
    data_root = tmp_path / "legacy-running-attempt"
    fixture = get_loop3_fixture("audit-batch-short-002")
    first_repository = TemporarySqliteJobRepository(data_root)
    try:
        first_repository.create_scheduled_job(
            fixture=fixture,
            scope_label="Loop 4 crash boundary",
            idempotency_key="loop4-running-attempt",
            request_hash="loop4-running-attempt-request",
            expected_record_version=0,
        )
        CooperativeScheduler(first_repository).tick()
        running = first_repository.list_stage_attempts()
        assert len(running) == 1
        assert running[0]["status"] == "running"
        running_attempt_id = str(running[0]["stage_attempt_id"])
    finally:
        first_repository.close()

    restarted_repository = TemporarySqliteJobRepository(data_root)
    try:
        restarted_repository.recover_abandoned_attempts(
            recovering_instance_id="loop4-restarted-instance"
        )
        CooperativeScheduler(restarted_repository).tick()
        restarted_attempt = next(
            attempt
            for attempt in restarted_repository.list_stage_attempts()
            if attempt["stage_attempt_id"] == running_attempt_id
        )
    finally:
        restarted_repository.close()

    assert restarted_attempt["status"] != "succeeded"


def test_formal_repository_recovers_only_an_expired_crashed_owner_attempt(
    tmp_path: Path,
) -> None:
    """The production repository must fence a crash before resuming its stage."""
    data_root = tmp_path / "formal-crash-recovery"
    identity = _data_root_identity(data_root)
    fixture = get_loop3_fixture("audit-batch-short-002")
    old_runtime = _open_runtime(data_root, instance_id="old-instance")
    old_repository = SqliteJobRepository(
        old_runtime,
        scheduler_instance_id="old-instance",
    )
    try:
        recovery = PersistentRecoveryStore(
            old_repository.engine,
            old_repository.commit_gate,
        )
        _register_instance(
            recovery,
            instance_id="old-instance",
            data_root_identity=identity,
            now=T0,
            pid=4051,
        )
        job, created = old_repository.create_scheduled_job(
            fixture=fixture,
            scope_label="Loop 4 formal crash recovery",
            idempotency_key="loop4-formal-crash-recovery",
            request_hash="loop4-formal-crash-recovery-request",
            expected_record_version=0,
        )
        assert created is True
        CooperativeScheduler(old_repository).tick()
        with old_repository.engine.connect() as connection:
            old_attempt = (
                connection.execute(
                    text(
                        """
                        SELECT
                            a.stage_attempt_id,
                            a.owner_id,
                            a.work_item_id,
                            a.stage,
                            a.status,
                            l.lease_id,
                            l.instance_id
                        FROM stage_attempts AS a
                        JOIN leases AS l
                          ON l.stage_attempt_id = a.stage_attempt_id
                        WHERE a.consumer_job_id = :job_id
                          AND a.status = 'running'
                          AND l.status = 'active'
                        """
                    ),
                    {"job_id": job.job_id},
                )
                .mappings()
                .one()
            )
        assert old_attempt["instance_id"] == "old-instance"
    finally:
        old_repository.close()

    new_runtime = _open_runtime(data_root, instance_id="new-instance")
    new_repository = SqliteJobRepository(
        new_runtime,
        scheduler_instance_id="new-instance",
    )
    try:
        recovery = PersistentRecoveryStore(
            new_repository.engine,
            new_repository.commit_gate,
        )
        _register_instance(
            recovery,
            instance_id="new-instance",
            data_root_identity=identity,
            now=T0 + timedelta(seconds=1),
            pid=4052,
        )
        assert recovery.mark_instance_crashed(
            instance_id="old-instance",
            replacement_instance_id="new-instance",
            data_root_identity=identity,
            single_instance_proof=True,
            now=T0 + timedelta(seconds=2),
        )

        future_expiry = datetime.now(UTC) + timedelta(minutes=5)
        with new_repository.commit_gate.transaction(new_repository.engine) as connection:
            connection.execute(
                text(
                    """
                    UPDATE leases
                    SET expires_at = :expires_at
                    WHERE lease_id = :lease_id
                    """
                ),
                {
                    "expires_at": future_expiry.isoformat(),
                    "lease_id": old_attempt["lease_id"],
                },
            )

        assert new_repository.recover_abandoned_attempts(recovering_instance_id="new-instance") == 0
        with new_repository.engine.connect() as connection:
            before_expiry = (
                connection.execute(
                    text(
                        """
                    SELECT a.status AS attempt_status, w.status AS item_status
                    FROM stage_attempts AS a
                    JOIN work_items AS w
                      ON w.work_item_id = a.work_item_id
                    WHERE a.stage_attempt_id = :stage_attempt_id
                    """
                    ),
                    {"stage_attempt_id": old_attempt["stage_attempt_id"]},
                )
                .mappings()
                .one()
            )
        assert before_expiry["attempt_status"] == "running"
        assert before_expiry["item_status"] == "running"

        with new_repository.commit_gate.transaction(new_repository.engine) as connection:
            connection.execute(
                text(
                    """
                    UPDATE leases
                    SET expires_at = :expires_at
                    WHERE lease_id = :lease_id
                    """
                ),
                {
                    "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                    "lease_id": old_attempt["lease_id"],
                },
            )

        assert new_repository.recover_abandoned_attempts(recovering_instance_id="new-instance") == 1
        with new_repository.engine.connect() as connection:
            recovered = (
                connection.execute(
                    text(
                        """
                    SELECT
                        a.status AS attempt_status,
                        a.diagnostic_code,
                        w.status AS item_status,
                        w.current_stage,
                        l.status AS lease_status,
                        l.release_reason
                    FROM stage_attempts AS a
                    JOIN work_items AS w
                      ON w.work_item_id = a.work_item_id
                    JOIN leases AS l
                      ON l.stage_attempt_id = a.stage_attempt_id
                    WHERE a.stage_attempt_id = :stage_attempt_id
                    """
                    ),
                    {"stage_attempt_id": old_attempt["stage_attempt_id"]},
                )
                .mappings()
                .one()
            )
            checkpoint_count = connection.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM checkpoints
                    WHERE owner_kind = 'work_item'
                      AND owner_id = :owner_id
                      AND stage = :stage
                    """
                ),
                {
                    "owner_id": old_attempt["owner_id"],
                    "stage": old_attempt["stage"],
                },
            ).scalar_one()

        assert recovered["attempt_status"] == "abandoned"
        assert recovered["diagnostic_code"] == "LOOP4-ATTEMPT-ABANDONED"
        assert recovered["item_status"] == "queued"
        assert recovered["current_stage"] == old_attempt["stage"]
        assert recovered["lease_status"] == "released"
        assert recovered["release_reason"] == "abandoned_attempt_recovered"
        assert checkpoint_count == 0

        CooperativeScheduler(new_repository).tick()
        with new_repository.engine.connect() as connection:
            resumed = (
                connection.execute(
                    text(
                        """
                        SELECT
                            a.stage_attempt_id,
                            a.stage,
                            a.status AS attempt_status,
                            l.instance_id,
                            l.status AS lease_status,
                            w.status AS item_status
                        FROM stage_attempts AS a
                        JOIN leases AS l
                          ON l.stage_attempt_id = a.stage_attempt_id
                        JOIN work_items AS w
                          ON w.work_item_id = a.work_item_id
                        WHERE a.owner_kind = 'work_item'
                          AND a.owner_id = :owner_id
                          AND a.stage = :stage
                          AND a.stage_attempt_id != :old_attempt_id
                        """
                    ),
                    {
                        "owner_id": old_attempt["owner_id"],
                        "stage": old_attempt["stage"],
                        "old_attempt_id": old_attempt["stage_attempt_id"],
                    },
                )
                .mappings()
                .one()
            )
            checkpoint_count_after_resume = connection.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM checkpoints
                    WHERE owner_kind = 'work_item'
                      AND owner_id = :owner_id
                      AND stage = :stage
                    """
                ),
                {
                    "owner_id": old_attempt["owner_id"],
                    "stage": old_attempt["stage"],
                },
            ).scalar_one()
    finally:
        new_repository.close()

    assert resumed["stage_attempt_id"] != old_attempt["stage_attempt_id"]
    assert resumed["stage"] == old_attempt["stage"]
    assert resumed["attempt_status"] == "running"
    assert resumed["instance_id"] == "new-instance"
    assert resumed["lease_status"] == "active"
    assert resumed["item_status"] == "running"
    assert checkpoint_count_after_resume == 0


def test_takeover_rejects_running_old_instance_after_lease_expiry(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "running-owner"
    identity = _data_root_identity(data_root)
    runtime = _open_runtime(data_root, instance_id="new-instance")
    try:
        store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
        _register_instance(
            store,
            instance_id="old-instance",
            data_root_identity=identity,
            now=T0,
            pid=4101,
        )
        _register_instance(
            store,
            instance_id="new-instance",
            data_root_identity=identity,
            now=T0,
            pid=4102,
        )
        lease = _acquire_test_lease(
            store,
            instance_id="old-instance",
            now=T0,
            worker_id="old-worker",
        )

        with pytest.raises(LeaseTakeoverRejected):
            store.takeover_expired_lease(
                lease_id=lease.lease_id,
                new_instance_id="new-instance",
                data_root_identity=identity,
                now=T0 + LEASE_TTL + timedelta(seconds=1),
            )
    finally:
        runtime.close()


def test_crashed_instance_requires_os_mutex_proof_and_matching_replacement(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "crashed-owner"
    identity = _data_root_identity(data_root)
    runtime = _open_runtime(data_root, instance_id="new-instance")
    try:
        store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
        _register_instance(
            store,
            instance_id="old-instance",
            data_root_identity=identity,
            now=T0,
            pid=4151,
        )
        _register_instance(
            store,
            instance_id="new-instance",
            data_root_identity=identity,
            now=T0,
            pid=4152,
        )

        with pytest.raises(RecoveryStoreError, match="stop proof"):
            store.mark_instance_crashed(
                instance_id="old-instance",
                replacement_instance_id="new-instance",
                data_root_identity=identity,
                single_instance_proof=False,
                now=T0 + timedelta(seconds=1),
            )

        changed = store.mark_instance_crashed(
            instance_id="old-instance",
            replacement_instance_id="new-instance",
            data_root_identity=identity,
            single_instance_proof=True,
            now=T0 + timedelta(seconds=2),
        )
        replay = store.mark_instance_crashed(
            instance_id="old-instance",
            replacement_instance_id="new-instance",
            data_root_identity=identity,
            single_instance_proof=True,
            now=T0 + timedelta(seconds=3),
        )
        with runtime.engine.connect() as connection:
            status = connection.execute(
                text("SELECT status FROM application_instances WHERE instance_id = 'old-instance'")
            ).scalar_one()
    finally:
        runtime.close()

    assert changed is True
    assert replay is False
    assert status == "crashed"


def test_guarded_replacement_marks_all_other_running_instances_crashed(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "all-stale-owners"
    identity = _data_root_identity(data_root)
    runtime = _open_runtime(data_root, instance_id="replacement-instance")
    try:
        store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
        for offset, instance_id in enumerate(
            ("stale-one", "stale-two", "replacement-instance"),
            start=1,
        ):
            _register_instance(
                store,
                instance_id=instance_id,
                data_root_identity=identity,
                now=T0 + timedelta(seconds=offset),
                pid=4200 + offset,
            )

        changed = store.mark_other_instances_crashed(
            replacement_instance_id="replacement-instance",
            data_root_identity=identity,
            single_instance_proof=True,
            now=T0 + timedelta(seconds=10),
        )
        replay = store.mark_other_instances_crashed(
            replacement_instance_id="replacement-instance",
            data_root_identity=identity,
            single_instance_proof=True,
            now=T0 + timedelta(seconds=11),
        )
        with runtime.engine.connect() as connection:
            statuses = {
                str(row["instance_id"]): str(row["status"])
                for row in connection.execute(
                    text(
                        "SELECT instance_id, status FROM application_instances"
                    )
                ).mappings()
            }
    finally:
        runtime.close()

    assert changed == 2
    assert replay == 0
    assert statuses == {
        "replacement-instance": "running",
        "stale-one": "crashed",
        "stale-two": "crashed",
    }


def test_takeover_rejects_unexpired_lease_from_stopped_instance(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "unexpired-lease"
    identity = _data_root_identity(data_root)
    runtime = _open_runtime(data_root, instance_id="new-instance")
    try:
        store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
        _register_instance(
            store,
            instance_id="old-instance",
            data_root_identity=identity,
            now=T0,
            pid=4201,
        )
        _register_instance(
            store,
            instance_id="new-instance",
            data_root_identity=identity,
            now=T0,
            pid=4202,
        )
        lease = _acquire_test_lease(
            store,
            instance_id="old-instance",
            now=T0,
            worker_id="old-worker",
        )
        store.stop_instance(
            instance_id="old-instance",
            now=T0 + timedelta(seconds=1),
        )

        with pytest.raises(LeaseTakeoverRejected):
            store.takeover_expired_lease(
                lease_id=lease.lease_id,
                new_instance_id="new-instance",
                data_root_identity=identity,
                now=T0 + timedelta(seconds=2),
            )
    finally:
        runtime.close()


def test_takeover_requires_same_data_root_and_rotates_fencing_token(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "matching-data-root"
    identity = _data_root_identity(data_root)
    other_identity = hashlib.sha256(b"another-data-root").hexdigest()
    runtime = _open_runtime(data_root, instance_id="new-instance")
    try:
        store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
        _register_instance(
            store,
            instance_id="old-instance",
            data_root_identity=identity,
            now=T0,
            pid=4301,
        )
        _register_instance(
            store,
            instance_id="wrong-root-instance",
            data_root_identity=other_identity,
            now=T0,
            pid=4302,
        )
        _register_instance(
            store,
            instance_id="new-instance",
            data_root_identity=identity,
            now=T0,
            pid=4303,
        )
        lease = _acquire_test_lease(
            store,
            instance_id="old-instance",
            now=T0,
            worker_id="old-worker",
        )
        store.stop_instance(
            instance_id="old-instance",
            now=T0 + timedelta(seconds=1),
        )
        takeover_time = T0 + LEASE_TTL + timedelta(seconds=1)

        with pytest.raises(LeaseTakeoverRejected):
            store.takeover_expired_lease(
                lease_id=lease.lease_id,
                new_instance_id="wrong-root-instance",
                data_root_identity=other_identity,
                now=takeover_time,
            )

        replacement = store.takeover_expired_lease(
            lease_id=lease.lease_id,
            new_instance_id="new-instance",
            data_root_identity=identity,
            now=takeover_time,
        )
    finally:
        runtime.close()

    assert replacement.instance_id == "new-instance"
    assert replacement.generation == lease.generation + 1
    assert replacement.fencing_token != lease.fencing_token


def test_lease_renewal_requires_the_current_owner_and_token(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "lease-renewal"
    identity = _data_root_identity(data_root)
    runtime = _open_runtime(data_root, instance_id="instance-a")
    try:
        store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
        _register_instance(
            store,
            instance_id="instance-a",
            data_root_identity=identity,
            now=T0,
            pid=4401,
        )
        lease = _acquire_test_lease(
            store,
            instance_id="instance-a",
            now=T0,
            worker_id="worker-a",
        )

        with pytest.raises(LeaseOwnershipError):
            store.renew_lease(
                lease_id=lease.lease_id,
                instance_id="instance-a",
                worker_id="forged-worker",
                fencing_token=lease.fencing_token,
                now=T0 + timedelta(seconds=1),
                ttl=LEASE_TTL,
            )

        renewed = store.renew_lease(
            lease_id=lease.lease_id,
            instance_id="instance-a",
            worker_id="worker-a",
            fencing_token=lease.fencing_token,
            now=T0 + timedelta(seconds=1),
            ttl=LEASE_TTL,
        )
    finally:
        runtime.close()

    assert renewed.expires_at > lease.expires_at
    assert renewed.generation == lease.generation
    assert renewed.fencing_token == lease.fencing_token


def test_browser_recovery_fences_the_old_navigation_token(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "browser-fencing", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=LEASE_TTL,
        )
        store.authorize_navigation(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
            now=T0 + timedelta(milliseconds=500),
        )
        with pytest.raises(NavigationRejectedError):
            store.authorize_navigation(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-other",
                control_epoch=grant.control_epoch,
                fencing_token=grant.fencing_token,
                now=T0 + timedelta(milliseconds=500),
            )

        with pytest.raises(BrowserControlError):
            store.begin_automatic_recovery(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-other",
                expected_control_epoch=grant.control_epoch,
                reason="wrong job cannot recover this session",
                now=T0 + timedelta(milliseconds=750),
            )

        recovery = store.begin_automatic_recovery(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_control_epoch=grant.control_epoch,
            reason="worker heartbeat lost",
            now=T0 + timedelta(seconds=1),
        )

        with pytest.raises(NavigationRejectedError):
            store.authorize_navigation(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-a",
                control_epoch=grant.control_epoch,
                fencing_token=grant.fencing_token,
                now=T0 + timedelta(seconds=2),
            )
    finally:
        runtime.close()

    assert recovery.control_epoch > grant.control_epoch
    assert recovery.browser_lifecycle == "recovering"
    assert recovery.browser_control_mode == "idle"


def test_browser_cannot_return_to_automated_without_all_recovery_proofs(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "browser-proof", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=LEASE_TTL,
        )
        recovery = store.begin_automatic_recovery(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_control_epoch=grant.control_epoch,
            reason="connector exited",
            now=T0 + timedelta(seconds=1),
        )

        with pytest.raises(RecoveryProofMissingError):
            store.complete_automatic_recovery(
                session_id=session.session_id,
                expected_control_epoch=recovery.control_epoch,
                instance_id="instance-a",
                worker_id="browser-worker-b",
                job_id="audit-job-a",
                connector_stopped=True,
                context_rebuilt=True,
                read_only_firewall_verified=False,
                now=T0 + timedelta(seconds=2),
                ttl=LEASE_TTL,
            )
        with pytest.raises(BrowserControlError):
            store.acquire_automated(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-b",
                job_id="audit-job-a",
                expected_record_version=recovery.record_version,
                now=T0 + timedelta(days=1),
                ttl=LEASE_TTL,
            )
        with pytest.raises(BrowserControlError):
            store.complete_automatic_recovery(
                session_id=session.session_id,
                expected_control_epoch=recovery.control_epoch,
                instance_id="instance-a",
                worker_id="browser-worker-b",
                job_id="audit-job-other",
                connector_stopped=True,
                context_rebuilt=True,
                read_only_firewall_verified=True,
                now=T0 + timedelta(seconds=2),
                ttl=LEASE_TTL,
            )

        replacement = store.complete_automatic_recovery(
            session_id=session.session_id,
            expected_control_epoch=recovery.control_epoch,
            instance_id="instance-a",
            worker_id="browser-worker-b",
            job_id="audit-job-a",
            connector_stopped=True,
            context_rebuilt=True,
            read_only_firewall_verified=True,
            now=T0 + timedelta(seconds=3),
            ttl=LEASE_TTL,
        )
        store.authorize_navigation(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-b",
            job_id="audit-job-a",
            control_epoch=replacement.control_epoch,
            fencing_token=replacement.fencing_token,
            now=T0 + timedelta(seconds=4),
        )
    finally:
        runtime.close()


def test_human_control_is_not_reclaimed_by_elapsed_time(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "human-control", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        human = store.acquire_human_control(
            session_id=session.session_id,
            control_mode="human_login",
            operator_id="operator-a",
            expected_record_version=ready.record_version,
            now=T0,
        )

        with pytest.raises(BrowserControlError):
            store.acquire_automated(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-a",
                expected_record_version=human.record_version,
                now=T0 + timedelta(days=30),
                ttl=LEASE_TTL,
            )
        with pytest.raises(BrowserControlError):
            store.begin_automatic_recovery(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-a",
                expected_control_epoch=human.control_epoch,
                reason="elapsed time is not authority",
                now=T0 + timedelta(days=30),
            )
    finally:
        runtime.close()


def test_automated_control_release_fences_the_returned_navigation_token(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "browser-release", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=LEASE_TTL,
        )

        with pytest.raises(BrowserControlError):
            store.release_automated(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-other",
                control_epoch=grant.control_epoch,
                fencing_token=grant.fencing_token,
                now=T0 + timedelta(milliseconds=500),
            )

        returned = store.release_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
            now=T0 + timedelta(seconds=1),
        )

        with pytest.raises(NavigationRejectedError):
            store.authorize_navigation(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-a",
                control_epoch=grant.control_epoch,
                fencing_token=grant.fencing_token,
                now=T0 + timedelta(seconds=2),
            )
    finally:
        runtime.close()

    assert returned.browser_control_mode == "idle"
    assert returned.control_epoch == grant.control_epoch + 1
    assert returned.fencing_token is None


def test_expired_automated_browser_grant_cannot_authorize_navigation(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "browser-expired", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=timedelta(seconds=1),
        )

        with pytest.raises(NavigationRejectedError):
            store.authorize_navigation(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-a",
                control_epoch=grant.control_epoch,
                fencing_token=grant.fencing_token,
                now=T0 + timedelta(seconds=1),
            )
    finally:
        runtime.close()


def test_only_the_current_automated_token_can_renew_navigation_control(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "browser-renewal", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=timedelta(seconds=2),
        )

        with pytest.raises(BrowserControlError):
            store.renew_automated(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-a",
                control_epoch=grant.control_epoch,
                fencing_token="stale-token",
                now=T0 + timedelta(seconds=1),
                ttl=timedelta(seconds=10),
            )

        with pytest.raises(BrowserControlError):
            store.renew_automated(
                session_id=session.session_id,
                instance_id="instance-a",
                worker_id="browser-worker-a",
                job_id="audit-job-other",
                control_epoch=grant.control_epoch,
                fencing_token=grant.fencing_token,
                now=T0 + timedelta(seconds=1),
                ttl=timedelta(seconds=10),
            )

        renewed = store.renew_automated(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
            now=T0 + timedelta(seconds=1),
            ttl=timedelta(seconds=10),
        )
        store.authorize_navigation(
            session_id=session.session_id,
            instance_id="instance-a",
            worker_id="browser-worker-a",
            job_id="audit-job-a",
            control_epoch=renewed.control_epoch,
            fencing_token=renewed.fencing_token,
            now=T0 + timedelta(seconds=5),
        )
    finally:
        runtime.close()

    assert renewed.control_epoch == grant.control_epoch
    assert renewed.record_version == grant.record_version + 1
    assert renewed.fencing_token == grant.fencing_token


def test_human_control_requires_an_explicit_matching_return(
    tmp_path: Path,
) -> None:
    runtime = _open_runtime(tmp_path / "human-return", instance_id="instance-a")
    try:
        store = BrowserControlStore(runtime.engine, runtime.commit_gate)
        session = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=session.session_id,
            expected_record_version=session.record_version,
            now=T0,
        )
        human = store.acquire_human_control(
            session_id=session.session_id,
            control_mode="human_login",
            operator_id="operator-a",
            expected_record_version=ready.record_version,
            now=T0,
        )

        with pytest.raises(BrowserControlError):
            store.return_human_control(
                session_id=session.session_id,
                operator_id="operator-b",
                expected_record_version=human.record_version,
                now=T0 + timedelta(seconds=1),
            )

        returned = store.return_human_control(
            session_id=session.session_id,
            operator_id="operator-a",
            expected_record_version=human.record_version,
            now=T0 + timedelta(seconds=2),
        )
    finally:
        runtime.close()

    assert returned.browser_control_mode == "idle"
    assert returned.control_epoch == human.control_epoch + 1
    assert returned.holder_kind is None
    assert returned.holder_id is None

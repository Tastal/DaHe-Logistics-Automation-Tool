from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import delete, select, update

from dahe.adapters.sqlite.browser_control import (
    BrowserControlRecord,
    BrowserControlStore,
    NavigationRejectedError,
)
from dahe.adapters.sqlite.platform_access import (
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    OUTBOX,
    PLATFORM_ACCESS_EVENTS,
    PLATFORM_ACCESS_WINDOWS,
)
from dahe.adapters.sqlite.settlement_capture import (
    SettlementCaptureAccessRolloverRecord,
    SettlementCaptureStartRecord,
    SettlementCaptureStoreConflictError,
    SqliteSettlementCaptureStore,
)
from dahe.application.chengfeng.access_window import (
    AccessPurpose,
    AccessWindowError,
    AccessWindowGrant,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.ports.jobs import IdempotencyConflictError

PROJECT_ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 7, 30, 8, 0, tzinfo=UTC)
ROLLOVER_AT = NOW + timedelta(minutes=61)
SESSION_ID = "loop9-rollover-session"
BUILD_SHA = hashlib.sha256(b"loop9-rollover-build").hexdigest()
CONTRACT_CANONICAL_SHA = hashlib.sha256(
    b"loop9-rollover-contract"
).hexdigest()
CONTRACT_FILE_SHA = hashlib.sha256(
    b"loop9-rollover-contract-file"
).hexdigest()
CONTRACT_SELECTION_SHA = hashlib.sha256(
    b"loop9-rollover-contract-selection"
).hexdigest()
IDENTITY_CONTEXT_SHA = hashlib.sha256(
    b"loop9-rollover-identity"
).hexdigest()


def _runtime(data_root: Path, *, instance_id: str) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
    )


def _start(runtime: SqliteRuntime) -> tuple[
    SettlementCaptureStartRecord,
    BrowserControlStore,
    BrowserControlRecord,
]:
    control = BrowserControlStore(runtime.engine, runtime.commit_gate)
    initial = control.initialize(session_id=SESSION_ID, now=NOW)
    ready = control.mark_ready(
        session_id=SESSION_ID,
        expected_record_version=initial.record_version,
        now=NOW,
    )
    started = SqliteSettlementCaptureStore(runtime).create_start(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        session_id=SESSION_ID,
        source_build_sha256=BUILD_SHA,
        contract_canonical_sha256=CONTRACT_CANONICAL_SHA,
        contract_file_sha256=CONTRACT_FILE_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        identity_context_sha256=IDENTITY_CONTEXT_SHA,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        idempotency_key="loop9-rollover-start",
        request_hash=hashlib.sha256(b"loop9-rollover-start").hexdigest(),
        now=NOW,
    )
    return started, control, ready


def _pause(runtime: SqliteRuntime, job_id: str) -> None:
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id=None,
    )
    job = repository.get_job(job_id)
    requested, replayed = repository.request_job_control(
        job_id=job_id,
        action="pause",
        expected_record_version=job.record_version,
        idempotency_key="loop9-rollover-pause",
        request_hash=hashlib.sha256(b"loop9-rollover-pause").hexdigest(),
    )
    assert replayed is False
    assert requested.status.value == "pause_requested"
    assert CooperativeScheduler(repository).tick() is True
    assert repository.get_job(job_id).status.value == "paused"


def _issue_replacement(
    runtime: SqliteRuntime,
    *,
    key: str = "loop9-rollover-replacement",
    job_id: str,
    purpose: AccessPurpose = AccessPurpose.FORMAL_LOCKED_SET,
    session_id: str = SESSION_ID,
    build_sha256: str = BUILD_SHA,
    now: datetime = ROLLOVER_AT,
) -> AccessWindowGrant:
    return SqlitePlatformAccessRepository(runtime).issue(
        purpose=purpose,
        job_id=job_id,
        session_id=session_id,
        build_sha256=build_sha256,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key=key,
        request_hash=hashlib.sha256(key.encode()).hexdigest(),
        now=now,
    )[0]


def _rebind(
    store: SqliteSettlementCaptureStore,
    *,
    job_id: str,
    access_window_id: str,
    expected_record_version: int,
    expected_browser_record_version: int,
    idempotency_key: str = "loop9-rollover-rebind",
    request_hash: str | None = None,
    session_id: str = SESSION_ID,
    source_build_sha256: str = BUILD_SHA,
    contract_canonical_sha256: str = CONTRACT_CANONICAL_SHA,
    contract_file_sha256: str = CONTRACT_FILE_SHA,
    contract_selection_sha256: str = CONTRACT_SELECTION_SHA,
    now: datetime = ROLLOVER_AT,
) -> SettlementCaptureAccessRolloverRecord:
    return store.rebind_access_window(
        job_id=job_id,
        new_access_window_id=access_window_id,
        expected_invocation_record_version=expected_record_version,
        expected_browser_record_version=expected_browser_record_version,
        session_id=session_id,
        source_build_sha256=source_build_sha256,
        contract_canonical_sha256=contract_canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        contract_selection_sha256=contract_selection_sha256,
        idempotency_key=idempotency_key,
        request_hash=request_hash
        or hashlib.sha256(idempotency_key.encode()).hexdigest(),
        now=now,
    )


def test_paused_capture_rolls_to_new_window_after_restart_without_losing_work(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    first = _runtime(data_root, instance_id="rollover-before-restart")
    started, control, ready = _start(first)
    acquired = control.acquire_automated(
        session_id=SESSION_ID,
        instance_id="rollover-instance",
        worker_id="rollover-worker",
        job_id=started.job_id,
        expected_record_version=ready.record_version,
        now=NOW,
        ttl=timedelta(minutes=5),
    )
    assert acquired.fencing_token is not None
    returned = control.release_automated(
        session_id=SESSION_ID,
        instance_id="rollover-instance",
        worker_id="rollover-worker",
        job_id=started.job_id,
        control_epoch=acquired.control_epoch,
        fencing_token=acquired.fencing_token,
        now=NOW,
    )
    _pause(first, started.job_id)
    with first.engine.connect() as connection:
        checkpoint_before = tuple(
            connection.execute(
                select(CHECKPOINTS).where(
                    CHECKPOINTS.c.job_id == started.job_id
                )
            ).mappings()
        )
    assert checkpoint_before
    first.close()

    restarted = _runtime(
        data_root,
        instance_id="rollover-after-restart",
    )
    try:
        store = SqliteSettlementCaptureStore(restarted)
        assert store.reconcile_terminal_or_expired_access(
            now=ROLLOVER_AT
        ) == (started.job_id,)
        invocation_before = store.get_by_job(started.job_id)
        assert invocation_before.status == "collecting"
        repository = SqliteJobRepository(
            restarted,
            scheduler_instance_id=None,
        )
        assert repository.get_job(started.job_id).status.value == "paused"

        replacement = _issue_replacement(
            restarted,
            job_id=started.job_id,
        )
        result = _rebind(
            store,
            job_id=started.job_id,
            access_window_id=replacement.access_window_id,
            expected_record_version=invocation_before.record_version,
            expected_browser_record_version=returned.record_version,
        )
        assert result.idempotent_replay is False
        assert result.invocation.invocation_id == started.invocation.invocation_id
        assert result.invocation.job_id == started.job_id
        assert (
            result.invocation.access_window_id
            == replacement.access_window_id
        )
        assert (
            result.invocation.record_version
            == invocation_before.record_version + 1
        )
        lineage = store.access_window_lineage(
            started.invocation.invocation_id
        )
        assert lineage.access_window_ids == (
            started.access_window.access_window_id,
            replacement.access_window_id,
        )
        assert lineage.job_id == started.job_id
        assert lineage.session_id == SESSION_ID
        assert lineage.source_build_sha256 == BUILD_SHA
        fenced_browser = BrowserControlStore(
            restarted.engine,
            restarted.commit_gate,
        ).get(SESSION_ID)
        assert fenced_browser.browser_control_mode == "idle"
        assert fenced_browser.control_epoch == returned.control_epoch + 1
        assert fenced_browser.record_version == returned.record_version + 1

        old = SqlitePlatformAccessRepository(restarted).get(
            started.access_window.access_window_id
        )
        assert old.consumed_at == ROLLOVER_AT
        with restarted.engine.connect() as connection:
            access_ids = tuple(
                connection.execute(
                    select(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                    ).where(
                        PLATFORM_ACCESS_WINDOWS.c.job_id == started.job_id
                    )
                ).scalars()
            )
            events = tuple(
                connection.execute(
                    select(PLATFORM_ACCESS_EVENTS.c.event_type).where(
                        PLATFORM_ACCESS_EVENTS.c.access_window_id.in_(
                            access_ids
                        )
                    )
                ).scalars()
            )
            rollover_events = tuple(
                connection.execute(
                    select(OUTBOX.c.event_type).where(
                        OUTBOX.c.aggregate_id == started.job_id,
                        OUTBOX.c.event_type
                        == "settlement_capture.access_window_rebound",
                    )
                ).scalars()
            )
            checkpoint_after = tuple(
                connection.execute(
                    select(CHECKPOINTS).where(
                        CHECKPOINTS.c.job_id == started.job_id
                    )
                ).mappings()
            )
        assert set(access_ids) == {
            started.access_window.access_window_id,
            replacement.access_window_id,
        }
        assert events.count("issued") == 2
        assert events.count("consumed") == 1
        assert rollover_events == (
            "settlement_capture.access_window_rebound",
        )
        assert checkpoint_after == checkpoint_before

        resumed, replayed = repository.request_job_control(
            job_id=started.job_id,
            action="resume",
            expected_record_version=repository.get_job(
                started.job_id
            ).record_version,
            idempotency_key="loop9-rollover-resume",
            request_hash=hashlib.sha256(
                b"loop9-rollover-resume"
            ).hexdigest(),
        )
        assert replayed is False
        assert resumed.status.value == "queued"
        assert repository.list_items(started.job_id)[0].work_item_id == (
            started.work_item_id
        )

        replay = _rebind(
            store,
            job_id=started.job_id,
            access_window_id=replacement.access_window_id,
            expected_record_version=invocation_before.record_version,
            expected_browser_record_version=returned.record_version,
        )
        assert replay.idempotent_replay is True
        assert replay.invocation == result.invocation
        with pytest.raises(IdempotencyConflictError):
            _rebind(
                store,
                job_id=started.job_id,
                access_window_id=replacement.access_window_id,
                expected_record_version=invocation_before.record_version,
                expected_browser_record_version=returned.record_version,
                request_hash=hashlib.sha256(
                    b"changed-rollover-request"
                ).hexdigest(),
            )

        with pytest.raises(AccessWindowError):
            SqlitePlatformAccessRepository(restarted).authorize(
                access_window_id=started.access_window.access_window_id,
                purpose=AccessPurpose.FORMAL_LOCKED_SET,
                job_id=started.job_id,
                session_id=SESSION_ID,
                build_sha256=BUILD_SHA,
                now=ROLLOVER_AT,
            )
        with pytest.raises(NavigationRejectedError):
            BrowserControlStore(
                restarted.engine,
                restarted.commit_gate,
            ).authorize_navigation(
                session_id=SESSION_ID,
                instance_id="rollover-instance",
                worker_id="rollover-worker",
                job_id=started.job_id,
                control_epoch=acquired.control_epoch,
                fencing_token=acquired.fencing_token,
                now=ROLLOVER_AT,
            )
    finally:
        restarted.close()


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "job",
        "session",
        "build",
        "contract_canonical",
        "contract_file",
        "contract_selection",
        "identity_context",
        "authority_digest",
    ),
)
def test_rollover_replay_revalidates_complete_authority(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    runtime = _runtime(
        tmp_path / tamper_kind,
        instance_id=f"rollover-replay-{tamper_kind}",
    )
    try:
        started, _control, ready = _start(runtime)
        _pause(runtime, started.job_id)
        store = SqliteSettlementCaptureStore(runtime)
        store.reconcile_terminal_or_expired_access(now=ROLLOVER_AT)
        replacement = _issue_replacement(
            runtime,
            key=f"replay-replacement-{tamper_kind}",
            job_id=started.job_id,
        )
        key = f"replay-complete-authority-{tamper_kind}"
        result = _rebind(
            store,
            job_id=started.job_id,
            access_window_id=replacement.access_window_id,
            expected_record_version=started.invocation.record_version,
            expected_browser_record_version=ready.record_version,
            idempotency_key=key,
        )
        assert result.idempotent_replay is False

        with runtime.commit_gate.transaction(runtime.engine) as connection:
            if tamper_kind == "job":
                connection.execute(
                    update(PLATFORM_ACCESS_WINDOWS)
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == replacement.access_window_id
                    )
                    .values(job_id="different-job")
                )
            elif tamper_kind == "session":
                connection.execute(
                    update(PLATFORM_ACCESS_WINDOWS)
                    .where(
                        PLATFORM_ACCESS_WINDOWS.c.access_window_id
                        == replacement.access_window_id
                    )
                    .values(session_id="different-session")
                )
            elif tamper_kind == "build":
                connection.exec_driver_sql(
                    """
                    UPDATE settlement_capture_invocations
                    SET source_build_sha256 = ?
                    WHERE job_id = ?
                    """,
                    ("f" * 64, started.job_id),
                )
            elif tamper_kind.startswith("contract_"):
                column = {
                    "contract_canonical": "contract_canonical_sha256",
                    "contract_file": "contract_file_sha256",
                    "contract_selection": "contract_selection_sha256",
                }[tamper_kind]
                connection.exec_driver_sql(
                    (
                        "UPDATE settlement_capture_invocations "
                        f"SET {column} = ? WHERE job_id = ?"
                    ),
                    ("f" * 64, started.job_id),
                )
            elif tamper_kind == "identity_context":
                connection.exec_driver_sql(
                    """
                    UPDATE settlement_capture_invocations
                    SET identity_context_sha256 = ?
                    WHERE job_id = ?
                    """,
                    ("f" * 64, started.job_id),
                )
            else:
                event = (
                    connection.execute(
                        select(OUTBOX).where(
                            OUTBOX.c.aggregate_id == started.job_id,
                            OUTBOX.c.event_type
                            == "settlement_capture.access_window_rebound",
                        )
                    )
                    .mappings()
                    .one()
                )
                payload = json.loads(str(event["payload_json"]))
                payload["authority_sha256"] = "f" * 64
                connection.execute(
                    update(OUTBOX)
                    .where(OUTBOX.c.event_id == event["event_id"])
                    .values(
                        payload_json=json.dumps(
                            payload,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
                )

        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="rollover replay authority",
        ):
            _rebind(
                store,
                job_id=started.job_id,
                access_window_id=replacement.access_window_id,
                expected_record_version=started.invocation.record_version,
                expected_browser_record_version=ready.record_version,
                idempotency_key=key,
            )
    finally:
        runtime.close()


@pytest.mark.parametrize("tamper_kind", ("delete", "reorder"))
def test_multiple_rollover_lineage_rejects_outbox_tampering(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    runtime = _runtime(
        tmp_path / tamper_kind,
        instance_id=f"rollover-lineage-{tamper_kind}",
    )
    second_rollover_at = ROLLOVER_AT + timedelta(minutes=61)
    try:
        started, _control, ready = _start(runtime)
        _pause(runtime, started.job_id)
        store = SqliteSettlementCaptureStore(runtime)
        assert store.reconcile_terminal_or_expired_access(
            now=ROLLOVER_AT
        ) == (started.job_id,)

        replacement = _issue_replacement(
            runtime,
            key=f"lineage-first-window-{tamper_kind}",
            job_id=started.job_id,
        )
        first_rollover = _rebind(
            store,
            job_id=started.job_id,
            access_window_id=replacement.access_window_id,
            expected_record_version=started.invocation.record_version,
            expected_browser_record_version=ready.record_version,
            idempotency_key=f"lineage-first-rebind-{tamper_kind}",
        )

        assert store.reconcile_terminal_or_expired_access(
            now=second_rollover_at
        ) == (started.job_id,)
        final_window = _issue_replacement(
            runtime,
            key=f"lineage-second-window-{tamper_kind}",
            job_id=started.job_id,
            now=second_rollover_at,
        )
        browser = BrowserControlStore(
            runtime.engine,
            runtime.commit_gate,
        ).get(SESSION_ID)
        second_rollover = _rebind(
            store,
            job_id=started.job_id,
            access_window_id=final_window.access_window_id,
            expected_record_version=(
                first_rollover.invocation.record_version
            ),
            expected_browser_record_version=browser.record_version,
            idempotency_key=f"lineage-second-rebind-{tamper_kind}",
            now=second_rollover_at,
        )
        assert second_rollover.invocation.record_version == 3
        assert store.access_window_lineage(
            started.invocation.invocation_id
        ).access_window_ids == (
            started.access_window.access_window_id,
            replacement.access_window_id,
            final_window.access_window_id,
        )

        with runtime.commit_gate.transaction(runtime.engine) as connection:
            events = tuple(
                connection.execute(
                    select(OUTBOX)
                    .where(
                        OUTBOX.c.aggregate_type
                        == "settlement_capture",
                        OUTBOX.c.aggregate_id == started.job_id,
                        OUTBOX.c.event_type
                        == "settlement_capture.access_window_rebound",
                    )
                    .order_by(OUTBOX.c.record_version)
                )
                .mappings()
                .all()
            )
            assert len(events) == 2
            if tamper_kind == "delete":
                connection.execute(
                    delete(OUTBOX).where(
                        OUTBOX.c.event_id == events[0]["event_id"]
                    )
                )
            else:
                connection.execute(
                    update(OUTBOX)
                    .where(
                        OUTBOX.c.event_id == events[0]["event_id"]
                    )
                    .values(payload_json=events[1]["payload_json"])
                )
                connection.execute(
                    update(OUTBOX)
                    .where(
                        OUTBOX.c.event_id == events[1]["event_id"]
                    )
                    .values(payload_json=events[0]["payload_json"])
                )

        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="lineage",
        ):
            store.access_window_lineage(
                started.invocation.invocation_id
            )
    finally:
        runtime.close()


@pytest.mark.parametrize(
    ("purpose", "job_suffix", "session_id", "build_sha256"),
    (
        (
            AccessPurpose.CONTRACT_DISCOVERY,
            "",
            SESSION_ID,
            BUILD_SHA,
        ),
        (
            AccessPurpose.FORMAL_LOCKED_SET,
            "-other",
            SESSION_ID,
            BUILD_SHA,
        ),
        (
            AccessPurpose.FORMAL_LOCKED_SET,
            "",
            "loop9-rollover-other-session",
            BUILD_SHA,
        ),
        (
            AccessPurpose.FORMAL_LOCKED_SET,
            "",
            SESSION_ID,
            "f" * 64,
        ),
    ),
)
def test_rollover_rejects_replacement_authority_changes(
    tmp_path: Path,
    purpose: AccessPurpose,
    job_suffix: str,
    session_id: str,
    build_sha256: str,
) -> None:
    runtime = _runtime(
        tmp_path / purpose.value / session_id / build_sha256[:4],
        instance_id="rollover-mismatch",
    )
    try:
        started, _control, ready = _start(runtime)
        _pause(runtime, started.job_id)
        store = SqliteSettlementCaptureStore(runtime)
        store.reconcile_terminal_or_expired_access(now=ROLLOVER_AT)
        replacement = _issue_replacement(
            runtime,
            key=(
                f"replacement-{purpose.value}-{job_suffix}-"
                f"{session_id}-{build_sha256[:4]}"
            ),
            job_id=f"{started.job_id}{job_suffix}",
            purpose=purpose,
            session_id=session_id,
            build_sha256=build_sha256,
        )
        invocation = store.get_by_job(started.job_id)
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="replacement access window changed capture authority",
        ):
            _rebind(
                store,
                job_id=started.job_id,
                access_window_id=replacement.access_window_id,
                expected_record_version=invocation.record_version,
                expected_browser_record_version=ready.record_version,
            )
    finally:
        runtime.close()


def test_rollover_rejects_active_prior_window_and_contract_change(
    tmp_path: Path,
) -> None:
    active_runtime = _runtime(
        tmp_path / "active",
        instance_id="rollover-active",
    )
    try:
        started, _control, ready = _start(active_runtime)
        _pause(active_runtime, started.job_id)
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="prior access window is still active",
        ):
            _rebind(
                SqliteSettlementCaptureStore(active_runtime),
                job_id=started.job_id,
                access_window_id=started.access_window.access_window_id,
                expected_record_version=started.invocation.record_version,
                expected_browser_record_version=ready.record_version,
                now=NOW + timedelta(minutes=1),
            )
    finally:
        active_runtime.close()

    contract_runtime = _runtime(
        tmp_path / "contract",
        instance_id="rollover-contract",
    )
    try:
        started, _control, ready = _start(contract_runtime)
        _pause(contract_runtime, started.job_id)
        store = SqliteSettlementCaptureStore(contract_runtime)
        store.reconcile_terminal_or_expired_access(now=ROLLOVER_AT)
        replacement = _issue_replacement(
            contract_runtime,
            job_id=started.job_id,
        )
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="capture contract authority changed",
        ):
            _rebind(
                store,
                job_id=started.job_id,
                access_window_id=replacement.access_window_id,
                expected_record_version=started.invocation.record_version,
                expected_browser_record_version=ready.record_version,
                contract_file_sha256="f" * 64,
            )
    finally:
        contract_runtime.close()


def test_rollover_requires_idle_browser_and_single_cas_winner(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path / "cas",
        instance_id="rollover-cas",
    )
    try:
        started, control, ready = _start(runtime)
        _pause(runtime, started.job_id)
        store = SqliteSettlementCaptureStore(runtime)
        store.reconcile_terminal_or_expired_access(now=ROLLOVER_AT)
        replacement = _issue_replacement(
            runtime,
            job_id=started.job_id,
        )
        acquired = control.acquire_automated(
            session_id=SESSION_ID,
            instance_id="cas-instance",
            worker_id="cas-worker",
            job_id=started.job_id,
            expected_record_version=ready.record_version,
            now=ROLLOVER_AT,
            ttl=timedelta(minutes=5),
        )
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="browser must be idle",
        ):
            _rebind(
                store,
                job_id=started.job_id,
                access_window_id=replacement.access_window_id,
                expected_record_version=started.invocation.record_version,
                expected_browser_record_version=acquired.record_version,
            )
        assert acquired.fencing_token is not None
        returned = control.release_automated(
            session_id=SESSION_ID,
            instance_id="cas-instance",
            worker_id="cas-worker",
            job_id=started.job_id,
            control_epoch=acquired.control_epoch,
            fencing_token=acquired.fencing_token,
            now=ROLLOVER_AT,
        )

        def attempt(index: int) -> str:
            try:
                _rebind(
                    store,
                    job_id=started.job_id,
                    access_window_id=replacement.access_window_id,
                    expected_record_version=started.invocation.record_version,
                    expected_browser_record_version=returned.record_version,
                    idempotency_key=f"loop9-rollover-cas-{index}",
                )
            except SettlementCaptureStoreConflictError:
                return "conflict"
            return "success"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(attempt, (1, 2)))
        assert sorted(results) == ["conflict", "success"]
    finally:
        runtime.close()

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread

from fastapi.testclient import TestClient

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserRuntimeLifecycle,
    BrowserRuntimeLifecycleGuard,
)
from dahe.adapters.sqlite.browser_control import BrowserControlStore
from dahe.adapters.sqlite.platform_access import (
    PlatformAccessConflictError,
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.api.app import create_app
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.chengfeng.expiry_reconciler import (
    PlatformAccessExpiryReconciler,
)
from dahe.diagnostics.runtime_log import RuntimeLogStore

PROJECT_ROOT = Path(__file__).parents[2]
BUILD_SHA256 = hashlib.sha256(b"loop9-expiry-reconciler").hexdigest()
SESSION_ID = "expiry-reconciler-session"
JOB_ID = "expiry-reconciler-job"
NOW = datetime(2026, 7, 29, 8, 0, tzinfo=UTC)


class _Browser:
    def __init__(self, *, fail_close: bool = False) -> None:
        self._running = True
        self.fail_close = fail_close
        self.close_count = 0

    @property
    def available(self) -> bool:
        return True

    @property
    def running(self) -> bool:
        return self._running

    @property
    def selected_browser(self) -> str | None:
        return "msedge" if self._running else None

    @property
    def discovery_capturing(self) -> bool:
        return False

    def close(self) -> None:
        self.close_count += 1
        if self.fail_close:
            raise RuntimeError(
                "Authorization=private C:\\private\\browser-profile"
            )
        self._running = False


def _runtime(tmp_path: Path, name: str) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / name,
        project_root=PROJECT_ROOT,
        instance_id=f"instance-{name}",
    )


def _issue(
    access: SqlitePlatformAccessRepository,
    *,
    key: str,
    issued_at: datetime,
    job_id: str = JOB_ID,
) -> str:
    grant, _ = access.issue(
        purpose=AccessPurpose.CONTRACT_DISCOVERY,
        job_id=job_id,
        session_id=SESSION_ID,
        build_sha256=BUILD_SHA256,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key=key,
        request_hash=hashlib.sha256(key.encode()).hexdigest(),
        now=issued_at,
    )
    return grant.access_window_id


def _human_control(
    control: BrowserControlStore,
    *,
    access_window_id: str,
) -> None:
    initial = control.initialize(session_id=SESSION_ID, now=NOW)
    ready = control.mark_ready(
        session_id=SESSION_ID,
        expected_record_version=initial.record_version,
        now=NOW,
    )
    control.acquire_human_session_control(
        session_id=SESSION_ID,
        control_mode="human_login",
        human_session_id=access_window_id,
        expected_record_version=ready.record_version,
        idempotency_key=f"human-{access_window_id}",
        request_hash=hashlib.sha256(access_window_id.encode()).hexdigest(),
        now=NOW,
    )


def _reconciler(
    *,
    access: SqlitePlatformAccessRepository,
    control: BrowserControlStore,
    browser: _Browser,
    lifecycle: BrowserRuntimeLifecycle,
    logs: RuntimeLogStore,
    clock=lambda: NOW,
    interval_seconds: float = 60,
) -> PlatformAccessExpiryReconciler:
    return PlatformAccessExpiryReconciler(
        access_repository=access,
        browser_control=control,
        browser_runtime=browser,  # type: ignore[arg-type]
        browser_lifecycle=lifecycle,
        runtime_log_store=logs,
        session_id=SESSION_ID,
        build_sha256=BUILD_SHA256,
        clock=clock,
        interval_seconds=interval_seconds,
    )


def test_expired_exact_human_window_is_closed_and_retired(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "human")
    try:
        access = SqlitePlatformAccessRepository(runtime)
        window_id = _issue(
            access,
            key="expired-human",
            issued_at=NOW - timedelta(hours=2),
        )
        control = BrowserControlStore(runtime.engine, runtime.commit_gate)
        _human_control(control, access_window_id=window_id)
        browser = _Browser()
        logs = RuntimeLogStore(tmp_path / "logs-human", now=lambda: NOW)
        reconciler = _reconciler(
            access=access,
            control=control,
            browser=browser,
            lifecycle=BrowserRuntimeLifecycleGuard(),
            logs=logs,
        )

        assert reconciler.reconcile_once() == "reconciled"
        assert reconciler.reconcile_once() == "noop"

        assert browser.running is False
        assert browser.close_count == 1
        assert access.get(window_id).consumed_at == NOW
        state = control.get(SESSION_ID)
        assert state.browser_lifecycle == "stopped"
        assert state.browser_control_mode == "idle"
        events = logs.query(limit=20)["events"]
        reconciled_events = [
            event
            for event in events
            if event["event_code"]
            == "platform_access_expiry_reconciled"
        ]
        assert len(reconciled_events) == 1
    finally:
        runtime.close()


def test_expired_exact_automated_window_is_fenced_before_close(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "automated")
    try:
        access = SqlitePlatformAccessRepository(runtime)
        window_id = _issue(
            access,
            key="expired-automated",
            issued_at=NOW - timedelta(hours=2),
        )
        control = BrowserControlStore(runtime.engine, runtime.commit_gate)
        initial = control.initialize(session_id=SESSION_ID, now=NOW)
        ready = control.mark_ready(
            session_id=SESSION_ID,
            expected_record_version=initial.record_version,
            now=NOW,
        )
        control.acquire_automated(
            session_id=SESSION_ID,
            instance_id="expired-instance",
            worker_id="expired-worker",
            job_id=JOB_ID,
            expected_record_version=ready.record_version,
            now=NOW - timedelta(minutes=2),
            ttl=timedelta(minutes=10),
        )
        browser = _Browser()
        reconciler = _reconciler(
            access=access,
            control=control,
            browser=browser,
            lifecycle=BrowserRuntimeLifecycleGuard(),
            logs=RuntimeLogStore(
                tmp_path / "logs-automated",
                now=lambda: NOW,
            ),
        )

        assert reconciler.reconcile_once() == "reconciled"

        assert browser.close_count == 1
        assert access.get(window_id).consumed_at == NOW
        state = control.get(SESSION_ID)
        assert state.browser_lifecycle == "stopped"
        assert state.control_epoch > ready.control_epoch
    finally:
        runtime.close()


class _IssueNewWindowOnHold:
    def __init__(self, access: SqlitePlatformAccessRepository) -> None:
        self._access = access
        self.new_window_id: str | None = None
        self.new_window_rejected = False

    @contextmanager
    def hold(self) -> Iterator[None]:
        try:
            self.new_window_id = _issue(
                self._access,
                key="newer-window",
                issued_at=NOW,
                job_id="newer-job",
            )
        except PlatformAccessConflictError:
            self.new_window_rejected = True
        yield


def test_new_window_cannot_shadow_expired_human_window_during_recheck(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "newer")
    try:
        access = SqlitePlatformAccessRepository(runtime)
        expired_id = _issue(
            access,
            key="older-expired",
            issued_at=NOW - timedelta(hours=2),
        )
        control = BrowserControlStore(runtime.engine, runtime.commit_gate)
        _human_control(control, access_window_id=expired_id)
        browser = _Browser()
        lifecycle = _IssueNewWindowOnHold(access)
        reconciler = _reconciler(
            access=access,
            control=control,
            browser=browser,
            lifecycle=lifecycle,
            logs=RuntimeLogStore(tmp_path / "logs-newer", now=lambda: NOW),
        )

        assert reconciler.reconcile_once() == "reconciled"

        assert lifecycle.new_window_id is None
        assert lifecycle.new_window_rejected is True
        assert browser.close_count == 1
        assert access.get(expired_id).consumed_at == NOW
        state = control.get(SESSION_ID)
        assert state.browser_lifecycle == "stopped"
        assert state.holder_id is None
    finally:
        runtime.close()


def test_mismatched_browser_holder_is_deferred_without_closing(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "mismatch")
    try:
        access = SqlitePlatformAccessRepository(runtime)
        expired_id = _issue(
            access,
            key="expired-mismatch",
            issued_at=NOW - timedelta(hours=2),
        )
        control = BrowserControlStore(runtime.engine, runtime.commit_gate)
        _human_control(control, access_window_id="different-window")
        browser = _Browser()
        logs = RuntimeLogStore(tmp_path / "logs-mismatch", now=lambda: NOW)
        reconciler = _reconciler(
            access=access,
            control=control,
            browser=browser,
            lifecycle=BrowserRuntimeLifecycleGuard(),
            logs=logs,
        )

        assert reconciler.reconcile_once() == "deferred"

        assert browser.close_count == 0
        assert access.get(expired_id).consumed_at is None
        events = logs.query(limit=20)["events"]
        warning = next(
            event
            for event in events
            if event["event_code"] == "platform_access_expiry_deferred"
        )
        assert warning["diagnostic_code"] == (
            "CF-BROWSER-EXPIRY-STATE-UNMATCHED"
        )
    finally:
        runtime.close()


def test_close_failure_is_logged_without_retiring_or_leaking_details(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "failure")
    try:
        access = SqlitePlatformAccessRepository(runtime)
        expired_id = _issue(
            access,
            key="expired-failure",
            issued_at=NOW - timedelta(hours=2),
        )
        control = BrowserControlStore(runtime.engine, runtime.commit_gate)
        _human_control(control, access_window_id=expired_id)
        browser = _Browser(fail_close=True)
        logs = RuntimeLogStore(tmp_path / "logs-failure", now=lambda: NOW)
        reconciler = _reconciler(
            access=access,
            control=control,
            browser=browser,
            lifecycle=BrowserRuntimeLifecycleGuard(),
            logs=logs,
        )

        assert reconciler.reconcile_once() == "failed"

        assert access.get(expired_id).consumed_at is None
        events = logs.query(limit=20)["events"]
        failure = next(
            event
            for event in events
            if event["event_code"] == "platform_access_expiry_failed"
        )
        serialized = str(failure)
        assert "Authorization" not in serialized
        assert "private" not in serialized
        assert failure["diagnostic_code"] == (
            "CF-BROWSER-EXPIRY-RECONCILIATION-FAILED"
        )
    finally:
        runtime.close()


class _BlockingLifecycle:
    def __init__(self) -> None:
        self.entered = Event()
        self.release = Event()

    @contextmanager
    def hold(self) -> Iterator[None]:
        self.entered.set()
        assert self.release.wait(timeout=5)
        yield


def test_shutdown_waits_for_inflight_reconciliation(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "shutdown")
    try:
        access = SqlitePlatformAccessRepository(runtime)
        expired_id = _issue(
            access,
            key="expired-shutdown",
            issued_at=NOW - timedelta(hours=2),
        )
        control = BrowserControlStore(runtime.engine, runtime.commit_gate)
        _human_control(control, access_window_id=expired_id)
        lifecycle = _BlockingLifecycle()
        reconciler = _reconciler(
            access=access,
            control=control,
            browser=_Browser(),
            lifecycle=lifecycle,
            logs=RuntimeLogStore(tmp_path / "logs-shutdown", now=lambda: NOW),
            interval_seconds=0.01,
        )
        reconciler.start()
        assert lifecycle.entered.wait(timeout=5)

        closed = Event()

        def close_reconciler() -> None:
            reconciler.close()
            closed.set()

        closer = Thread(target=close_reconciler)
        closer.start()
        assert not closed.wait(timeout=0.05)
        lifecycle.release.set()
        closer.join(timeout=5)

        assert closed.is_set()
        assert reconciler.running is False
        assert access.get(expired_id).consumed_at == NOW
    finally:
        runtime.close()


def test_reconciler_is_started_and_stopped_with_app_lifespan(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    app = create_app(
        data_root=tmp_path / "app",
        project_root=PROJECT_ROOT,
        instance_id="expiry-lifespan",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_chengfeng_shadow=True,
        platform_build_sha256=BUILD_SHA256,
        browser_runtime=browser,  # type: ignore[arg-type]
    )
    reconciler = app.state.platform_access_expiry_reconciler
    assert reconciler.running is False

    with TestClient(app):
        assert reconciler.running is True

    assert reconciler.running is False

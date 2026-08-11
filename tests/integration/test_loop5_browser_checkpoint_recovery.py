from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

T0 = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def _modules() -> tuple[object, object]:
    ports = importlib.import_module("dahe.ports.chengfeng")
    gate_module = importlib.import_module("dahe.adapters.chengfeng.browser_gate")
    return ports, gate_module


def test_sqlite_navigation_authorizer_fences_job_identity(
    tmp_path: Path,
    project_root: Path,
) -> None:
    ports, gate_module = _modules()
    runtime_module = importlib.import_module("dahe.adapters.sqlite.runtime")
    browser_module = importlib.import_module("dahe.adapters.sqlite.browser_control")
    runtime = runtime_module.SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop5-instance",
    )
    try:
        store = browser_module.BrowserControlStore(runtime.engine, runtime.commit_gate)
        initial = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=initial.session_id,
            expected_record_version=initial.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=ready.session_id,
            instance_id="loop5-instance",
            worker_id="loop5-worker",
            job_id="job-owner",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=timedelta(seconds=30),
        )
        assert grant.fencing_token is not None
        authorizer = gate_module.SqliteBrowserNavigationAuthorizer(store)
        wrong_job = ports.BrowserCommandAuthority(
            session_id=grant.session_id,
            instance_id="loop5-instance",
            worker_id="loop5-worker",
            job_id="job-other",
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
        )

        with pytest.raises(browser_module.NavigationRejectedError):
            authorizer.authorize(wrong_job, now=T0 + timedelta(seconds=1))
    finally:
        runtime.close()


def test_sqlite_navigation_authorizer_rejects_old_token_after_recovery(
    tmp_path: Path,
    project_root: Path,
) -> None:
    ports, gate_module = _modules()
    runtime_module = importlib.import_module("dahe.adapters.sqlite.runtime")
    browser_module = importlib.import_module("dahe.adapters.sqlite.browser_control")
    runtime = runtime_module.SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop5-instance",
    )
    try:
        store = browser_module.BrowserControlStore(runtime.engine, runtime.commit_gate)
        initial = store.initialize(session_id="chengfeng_session", now=T0)
        ready = store.mark_ready(
            session_id=initial.session_id,
            expected_record_version=initial.record_version,
            now=T0,
        )
        old_grant = store.acquire_automated(
            session_id=ready.session_id,
            instance_id="loop5-instance",
            worker_id="loop5-worker",
            job_id="job-owner",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=timedelta(seconds=30),
        )
        assert old_grant.fencing_token is not None
        recovery = store.begin_automatic_recovery(
            session_id=old_grant.session_id,
            instance_id="loop5-instance",
            worker_id="loop5-worker",
            job_id="job-owner",
            expected_control_epoch=old_grant.control_epoch,
            reason="synthetic browser closed",
            now=T0 + timedelta(seconds=1),
        )
        store.complete_automatic_recovery(
            session_id=recovery.session_id,
            expected_control_epoch=recovery.control_epoch,
            instance_id="loop5-instance",
            worker_id="loop5-worker-rebuilt",
            job_id="job-owner",
            connector_stopped=True,
            context_rebuilt=True,
            read_only_firewall_verified=True,
            now=T0 + timedelta(seconds=2),
            ttl=timedelta(seconds=30),
        )
        stale = ports.BrowserCommandAuthority(
            session_id=old_grant.session_id,
            instance_id="loop5-instance",
            worker_id="loop5-worker",
            job_id="job-owner",
            control_epoch=old_grant.control_epoch,
            fencing_token=old_grant.fencing_token,
        )

        with pytest.raises(browser_module.NavigationRejectedError):
            gate_module.SqliteBrowserNavigationAuthorizer(store).authorize(
                stale,
                now=T0 + timedelta(seconds=3),
            )
    finally:
        runtime.close()


def test_real_navigation_authorizer_rechecks_access_window_before_each_command(
    tmp_path: Path,
    project_root: Path,
) -> None:
    ports, gate_module = _modules()
    runtime_module = importlib.import_module("dahe.adapters.sqlite.runtime")
    browser_module = importlib.import_module(
        "dahe.adapters.sqlite.browser_control"
    )
    access_module = importlib.import_module(
        "dahe.adapters.sqlite.platform_access"
    )
    window_module = importlib.import_module(
        "dahe.application.chengfeng.access_window"
    )
    runtime = runtime_module.SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop9-access-instance",
    )
    build_sha256 = "a" * 64
    try:
        access = access_module.SqlitePlatformAccessRepository(runtime)
        window, _ = access.issue(
            purpose=window_module.AccessPurpose.PRODUCTION_SHADOW,
            job_id="job-owner",
            session_id="chengfeng_session",
            build_sha256=build_sha256,
            duration_minutes=1,
            legacy_idle_confirmed=True,
            no_settlement_or_payment_confirmed=True,
            same_account_session_risk_accepted=True,
            run_mode="shadow",
            idempotency_key="real-navigation-window",
            request_hash="b" * 64,
            now=T0,
        )
        store = browser_module.BrowserControlStore(
            runtime.engine,
            runtime.commit_gate,
        )
        initial = store.initialize(
            session_id="chengfeng_session",
            now=T0,
        )
        ready = store.mark_ready(
            session_id=initial.session_id,
            expected_record_version=initial.record_version,
            now=T0,
        )
        grant = store.acquire_automated(
            session_id=ready.session_id,
            instance_id="loop9-access-instance",
            worker_id="loop9-access-worker",
            job_id="job-owner",
            expected_record_version=ready.record_version,
            now=T0,
            ttl=timedelta(minutes=2),
        )
        assert grant.fencing_token is not None
        authority = ports.BrowserCommandAuthority(
            session_id=grant.session_id,
            instance_id="loop9-access-instance",
            worker_id="loop9-access-worker",
            job_id="job-owner",
            control_epoch=grant.control_epoch,
            fencing_token=grant.fencing_token,
        )
        valid = gate_module.SqliteBrowserNavigationAuthorizer(
            store,
            access_repository=access,
            build_sha256=build_sha256,
            clock=lambda: T0 + timedelta(seconds=30),
        )
        valid.authorize(authority)

        expired = gate_module.SqliteBrowserNavigationAuthorizer(
            store,
            access_repository=access,
            build_sha256=build_sha256,
            clock=lambda: T0 + timedelta(minutes=1),
        )
        with pytest.raises(
            browser_module.NavigationRejectedError,
            match="access window",
        ):
            expired.authorize(authority)

        assert access.get(window.access_window_id).consumed_at is None
    finally:
        runtime.close()
